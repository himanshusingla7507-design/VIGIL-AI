"""Threat intelligence ingestion pipeline with normalization, deduplication, and streaming."""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from threat_intel.models import RawThreatRecord, StreamEvent, ThreatIndicator, ThreatSourceStatus, utc_now_iso
from threat_intel.providers.base import BaseThreatProvider
from threat_intel.storage import ThreatStorage
from threat_intel.stream import ThreatStreamBroadcaster

logger = logging.getLogger("threat_intel.pipeline")


def safe_normalize_url(raw_url: str) -> Tuple[str, str]:
    """
    Safely normalize URL for deduplication and extract hostname.
    Returns (normalized_url, hostname).
    """
    cleaned = raw_url.strip()
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"http://{cleaned}"

    try:
        from feature_extractor import normalize_url
        norm = normalize_url(cleaned)
        parsed = urlsplit(norm)
        host = parsed.hostname or "unknown"
        return norm, host
    except Exception:
        # Fallback safe normalization if feature_extractor rejects unusual syntax
        parsed = urlsplit(cleaned)
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or "unknown").lower()
        path = parsed.path or "/"
        norm = f"{scheme}://{netloc}{path}"
        if parsed.query:
            norm += f"?{parsed.query}"
        host = parsed.hostname or netloc.split(":")[0]
        return norm, host


class ThreatIntelPipeline:
    """Core orchestration pipeline coordinating provider ingestion, storage, and live streaming."""

    def __init__(self, storage: Optional[ThreatStorage] = None, broadcaster: Optional[ThreatStreamBroadcaster] = None):
        self.storage = storage or ThreatStorage()
        self.broadcaster = broadcaster or ThreatStreamBroadcaster()

    def process_raw_records(
        self,
        provider: BaseThreatProvider,
        records: List[RawThreatRecord],
    ) -> Tuple[int, int]:
        """
        Process, normalize, persist, and broadcast a batch of raw records from a provider.
        Returns (new_indicators_count, updated_indicators_count).
        """
        ingest_start_iso = utc_now_iso()
        new_count = 0
        updated_count = 0

        for raw in records:
            if not raw.url or not isinstance(raw.url, str):
                continue

            try:
                normalized_url, hostname = safe_normalize_url(raw.url)
            except Exception as exc:
                logger.debug("Skipping unparseable URL %s: %s", raw.url, exc)
                continue

            # Ingest into SQLite storage
            indicator, is_new = self.storage.upsert_indicator(
                raw=raw,
                normalized_url=normalized_url,
                hostname=hostname,
                ingested_at=ingest_start_iso,
            )

            persisted_iso = utc_now_iso()
            emitted_iso = utc_now_iso()

            if is_new:
                new_count += 1
            else:
                updated_count += 1

            # Broadcast live SSE event immediately for real-time streaming
            event = StreamEvent(
                event_id=f"evt_{indicator.id}_{int(time.time()*1000)}",
                event_type="indicator.new" if is_new else "indicator.update",
                indicator=indicator.to_dict(),
                stats=None,
                source_health=None,
                source_timestamp=indicator.source_timestamp,
                ingested_at=ingest_start_iso,
                persisted_at=persisted_iso,
                emitted_at=emitted_iso,
            )
            self.broadcaster.broadcast(event)

        # Broadcast updated stats event
        stats = self.storage.get_feed_stats(active_stream_clients=self.broadcaster.client_count)
        stats_event = StreamEvent(
            event_id=f"stats_{int(time.time()*1000)}",
            event_type="stats.update",
            indicator=None,
            stats=stats.to_dict(),
            source_health=provider.get_source_status().to_dict(),
            source_timestamp=None,
            ingested_at=ingest_start_iso,
            persisted_at=utc_now_iso(),
            emitted_at=utc_now_iso(),
        )
        self.broadcaster.broadcast(stats_event)

        return new_count, updated_count

    def sync_provider(self, provider: BaseThreatProvider, limit: int = 150) -> Dict[str, Any]:
        """Fetch and ingest data from a specific provider with resilient error handling."""
        status = provider.get_source_status()
        provider.last_fetch_attempt = utc_now_iso()

        if not provider.is_configured:
            provider.last_error = "Provider is awaiting configuration or credentials"
            self.storage.save_source_status(provider.get_source_status())
            return {"provider": provider.provider_id, "status": "awaiting_config", "new": 0, "updated": 0}

        if not provider.is_enabled:
            return {"provider": provider.provider_id, "status": "disabled", "new": 0, "updated": 0}

        try:
            records = provider.fetch_records(limit=limit)
            provider.last_successful_fetch = utc_now_iso()
            provider.last_error = None
            provider.consecutive_failures = 0
            provider.total_indicators_fetched += len(records)

            new_count, updated_count = self.process_raw_records(provider, records)
            self.storage.save_source_status(provider.get_source_status())

            logger.info(
                "Provider %s sync complete: %d records fetched (%d new, %d updated)",
                provider.provider_id,
                len(records),
                new_count,
                updated_count,
            )
            return {
                "provider": provider.provider_id,
                "status": "success",
                "fetched": len(records),
                "new": new_count,
                "updated": updated_count,
            }
        except Exception as exc:
            provider.consecutive_failures += 1
            provider.last_error = str(exc)
            self.storage.save_source_status(provider.get_source_status())
            logger.warning("Provider %s sync failed: %s", provider.provider_id, exc)
            return {
                "provider": provider.provider_id,
                "status": "error",
                "error": str(exc),
                "new": 0,
                "updated": 0,
            }

    def inject_test_indicator(
        self,
        url: str,
        source: str = "test_feed",
        indicator_type: str = "phishing_url",
        threat_type: str = "synthetic_threat_test",
        tags: Optional[List[str]] = None,
        source_timestamp: Optional[str] = None,
        status: str = "active",
    ) -> ThreatIndicator:
        """
        Explicit test injection helper for automated testing and e2e live-stream verification.
        Emits live SSE event so connected clients update in real-time without refreshing.
        """
        ingest_start_iso = utc_now_iso()
        norm_url, hostname = safe_normalize_url(url)
        raw = RawThreatRecord(
            url=url,
            source=source,
            indicator_type=indicator_type,
            status=status,
            source_id=f"test_{uuid.uuid4().hex[:8]}",
            source_timestamp=source_timestamp or ingest_start_iso,
            threat_type=threat_type,
            tags=tags or ["test_injection", "e2e_verification"],
            confidence=0.99,
            metadata={"test_injection": True, "created_at": ingest_start_iso},
        )

        indicator, is_new = self.storage.upsert_indicator(
            raw=raw,
            normalized_url=norm_url,
            hostname=hostname,
            ingested_at=ingest_start_iso,
        )

        persisted_iso = utc_now_iso()
        emitted_iso = utc_now_iso()

        event = StreamEvent(
            event_id=f"test_evt_{indicator.id}_{int(time.time()*1000)}",
            event_type="indicator.new" if is_new else "indicator.update",
            indicator=indicator.to_dict(),
            stats=None,
            source_health=None,
            source_timestamp=indicator.source_timestamp,
            ingested_at=ingest_start_iso,
            persisted_at=persisted_iso,
            emitted_at=emitted_iso,
        )
        self.broadcaster.broadcast(event)

        # Broadcast updated stats
        stats = self.storage.get_feed_stats(active_stream_clients=self.broadcaster.client_count)
        stats_event = StreamEvent(
            event_id=f"stats_{int(time.time()*1000)}",
            event_type="stats.update",
            indicator=None,
            stats=stats.to_dict(),
            source_health=None,
            source_timestamp=None,
            ingested_at=ingest_start_iso,
            persisted_at=utc_now_iso(),
            emitted_at=utc_now_iso(),
        )
        self.broadcaster.broadcast(stats_event)

        return indicator

