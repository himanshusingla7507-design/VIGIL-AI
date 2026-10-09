"""Automated tests for VIGIL Live Threat Intelligence Feed and SSE Pipeline."""
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from threat_intel.models import RawThreatRecord, StreamEvent, ThreatIndicator
from threat_intel.pipeline import ThreatIntelPipeline, safe_normalize_url
from threat_intel.providers.base import parse_flexible_utc_timestamp
from threat_intel.providers.openphish import OpenPhishProvider
from threat_intel.providers.phishing_database import PhishingDatabaseProvider
from threat_intel.providers.phishtank import PhishTankProvider
from threat_intel.providers.urlhaus import URLhausProvider
from threat_intel.storage import ThreatStorage, compute_indicator_hash
from threat_intel.stream import ThreatStreamBroadcaster


class TestThreatStorageAndDeduplication(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        self.temp_db.close()
        self.storage = ThreatStorage(db_path=self.temp_db.name)

    def tearDown(self):
        try:
            os.remove(self.temp_db.name)
        except OSError:
            pass

    def test_upsert_and_multisource_deduplication(self):
        # 1. First ingestion from URLhaus
        raw1 = RawThreatRecord(
            url="http://malicious-bank-login.xyz/verify",
            source="urlhaus",
            indicator_type="malware_url",
            status="online",
            source_timestamp="2026-10-09T12:00:00Z",
            threat_type="malware_download",
            tags=["emotet", "malware"],
        )
        norm_url, host = safe_normalize_url(raw1.url)
        ind1, is_new1 = self.storage.upsert_indicator(raw1, norm_url, host)
        self.assertTrue(is_new1)
        self.assertEqual(ind1.primary_source, "urlhaus")
        self.assertEqual(ind1.sources, ["urlhaus"])
        self.assertEqual(ind1.source_timestamp, "2026-10-09T12:00:00Z")

        # 2. Second ingestion of SAME normalized URL from OpenPhish
        raw2 = RawThreatRecord(
            url="http://malicious-bank-login.xyz/verify",
            source="openphish",
            indicator_type="phishing_url",
            status="active",
            source_timestamp=None,
            threat_type="banking_phish",
            tags=["banking", "phishing"],
        )
        ind2, is_new2 = self.storage.upsert_indicator(raw2, norm_url, host)
        self.assertFalse(is_new2)  # Should NOT be counted as new, but as update/cross-attributed
        self.assertEqual(ind2.id, ind1.id)
        self.assertEqual(set(ind2.sources), {"urlhaus", "openphish"})
        self.assertIn("emotet", ind2.tags)
        self.assertIn("banking", ind2.tags)
        # Original source_timestamp must be preserved and not overwritten with None
        self.assertEqual(ind2.source_timestamp, "2026-10-09T12:00:00Z")

    def test_query_indicators_with_filtering_and_search(self):
        # Insert 3 different indicators
        for i, (url, src, cat) in enumerate([
            ("http://paypal-security-fake.com/login", "phishing_database", "phishing_url"),
            ("http://evil-payload-dist.top/agent.exe", "urlhaus", "malware_url"),
            ("http://account-support-verify.com/auth", "openphish", "phishing_url"),
        ]):
            raw = RawThreatRecord(url=url, source=src, indicator_type=cat)
            norm, host = safe_normalize_url(url)
            self.storage.upsert_indicator(raw, norm, host)

        # Filter by category
        malware_items, total_m = self.storage.query_indicators(category="malware_url")
        self.assertEqual(total_m, 1)
        self.assertEqual(malware_items[0].primary_source, "urlhaus")

        # Filter by source
        openphish_items, total_o = self.storage.query_indicators(source="openphish")
        self.assertEqual(total_o, 1)
        self.assertEqual(openphish_items[0].url, "http://account-support-verify.com/auth")

        # Search query by keyword
        paypal_items, total_p = self.storage.query_indicators(search="paypal")
        self.assertEqual(total_p, 1)
        self.assertIn("paypal", paypal_items[0].url)

    def test_stats_aggregation(self):
        raw1 = RawThreatRecord(url="http://threat1.com/a", source="urlhaus", indicator_type="malware_url")
        raw2 = RawThreatRecord(url="http://threat2.com/b", source="openphish", indicator_type="phishing_url")
        norm1, host1 = safe_normalize_url(raw1.url)
        norm2, host2 = safe_normalize_url(raw2.url)
        self.storage.upsert_indicator(raw1, norm1, host1)
        self.storage.upsert_indicator(raw2, norm2, host2)

        stats = self.storage.get_feed_stats(active_stream_clients=2)
        self.assertEqual(stats.total_indicators, 2)
        self.assertEqual(stats.active_stream_clients, 2)
        self.assertEqual(stats.by_source.get("urlhaus"), 1)
        self.assertEqual(stats.by_source.get("openphish"), 1)
        self.assertEqual(stats.by_category.get("malware_url"), 1)
        self.assertEqual(stats.by_category.get("phishing_url"), 1)


class TestThreatProviders(unittest.TestCase):
    def test_urlhaus_provider_parsing(self):
        provider = URLhausProvider()
        mock_payload = json.dumps({
            "query_status": "ok",
            "urls": [
                {
                    "id": "2837482",
                    "url": "http://192.168.1.1/malware.bin",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": "elf,mirai",
                    "dateadded": "2026-10-09 10:15:30 UTC",
                    "reporter": "abuse_bot",
                }
            ]
        }).encode("utf-8")

        with patch.object(provider, "fetch_http", return_value=mock_payload):
            records = provider.fetch_records(limit=10)
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec.url, "http://192.168.1.1/malware.bin")
            self.assertEqual(rec.source, "urlhaus")
            self.assertEqual(rec.indicator_type, "malware_url")
            self.assertEqual(rec.source_timestamp, "2026-10-09T10:15:30Z")
            self.assertIn("mirai", rec.tags)

    def test_phishing_database_parsing(self):
        provider = PhishingDatabaseProvider()
        mock_text = (
            "# Phishing Database Active Links\n"
            "http://login-appleid-verify.com/auth\n"
            "secure-bank-update.xyz/token\n"
        ).encode("utf-8")

        with patch.object(provider, "fetch_http", return_value=mock_text):
            records = provider.fetch_records(limit=10)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].url, "http://login-appleid-verify.com/auth")
            self.assertEqual(records[1].url, "http://secure-bank-update.xyz/token")
            self.assertEqual(records[0].indicator_type, "phishing_url")

    def test_openphish_parsing(self):
        provider = OpenPhishProvider()
        mock_text = (
            "https://netflix-account-reactivate.com/login\n"
            "http://chase-bank-alert.com/signin\n"
        ).encode("utf-8")

        with patch.object(provider, "fetch_http", return_value=mock_text):
            records = provider.fetch_records(limit=10)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].source, "openphish")
            self.assertEqual(records[0].indicator_type, "phishing_url")

    def test_flexible_utc_timestamp_parser(self):
        self.assertEqual(parse_flexible_utc_timestamp("2026-10-09T14:30:00Z"), "2026-10-09T14:30:00Z")
        self.assertEqual(parse_flexible_utc_timestamp("2026-10-09 14:30:00 UTC"), "2026-10-09T14:30:00Z")
        self.assertEqual(parse_flexible_utc_timestamp("2026-10-09"), "2026-10-09T00:00:00Z")
        self.assertIsNone(parse_flexible_utc_timestamp(""))
        self.assertIsNone(parse_flexible_utc_timestamp(None))


class TestStreamBroadcaster(unittest.TestCase):
    def test_broadcast_and_client_delivery(self):
        broadcaster = ThreatStreamBroadcaster()
        cid1, q1 = broadcaster.subscribe()
        cid2, q2 = broadcaster.subscribe()
        self.assertEqual(broadcaster.client_count, 2)

        event = StreamEvent(
            event_id="evt_101",
            event_type="indicator.new",
            indicator={"url": "http://threat-live.com"},
            stats=None,
            source_health=None,
            source_timestamp=None,
            ingested_at="2026-10-09T15:00:00Z",
            persisted_at="2026-10-09T15:00:00Z",
            emitted_at="2026-10-09T15:00:00Z",
        )
        delivered = broadcaster.broadcast(event)
        self.assertEqual(delivered, 2)

        ev1 = q1.get_nowait()
        ev2 = q2.get_nowait()
        self.assertEqual(ev1.event_id, "evt_101")
        self.assertEqual(ev2.event_id, "evt_101")

        broadcaster.unsubscribe(cid1)
        self.assertEqual(broadcaster.client_count, 1)
        broadcaster.unsubscribe(cid2)
        self.assertEqual(broadcaster.client_count, 0)


class TestPipelineTestInjection(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        self.temp_db.close()
        self.storage = ThreatStorage(db_path=self.temp_db.name)
        self.broadcaster = ThreatStreamBroadcaster()
        self.pipeline = ThreatIntelPipeline(storage=self.storage, broadcaster=self.broadcaster)

    def tearDown(self):
        try:
            os.remove(self.temp_db.name)
        except OSError:
            pass

    def test_test_injection_broadcasts_to_stream(self):
        cid, q = self.broadcaster.subscribe()

        ind = self.pipeline.inject_test_indicator(
            url="https://live-e2e-threat.com/credential-harvest",
            source="e2e_tester",
            indicator_type="phishing_url",
            threat_type="credential_harvesting",
        )

        self.assertIsNotNone(ind.id)
        self.assertEqual(ind.url, "https://live-e2e-threat.com/credential-harvest")

        # Check that indicator event was received
        ev = q.get_nowait()
        self.assertEqual(ev.event_type, "indicator.new")
        self.assertEqual(ev.indicator["url"], "https://live-e2e-threat.com/credential-harvest")
        self.assertIn("emitted_at", ev.to_dict()["timestamps"])


if __name__ == "__main__":
    unittest.main()

