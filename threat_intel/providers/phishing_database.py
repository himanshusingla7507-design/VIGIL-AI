"""Phishing.Database Threat Intelligence Provider Adapter."""
from __future__ import annotations

import logging
import os
from typing import List

from threat_intel.models import RawThreatRecord
from threat_intel.providers.base import BaseThreatProvider

logger = logging.getLogger("threat_intel.provider.phishing_database")

PHISHING_DB_NEW_LAST_HOUR_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-last-hour.txt"
PHISHING_DB_NEW_TODAY_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt"
PHISHING_DB_ACTIVE_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"


class PhishingDatabaseProvider(BaseThreatProvider):
    """Adapter for Phishing.Database active and hourly newly discovered phishing feeds."""

    def __init__(self):
        super().__init__(
            provider_id="phishing_database",
            display_name="Phishing.Database",
            update_cadence_seconds=3600,  # 1 hour
            cadence_human="Hourly update",
            documentation_url="https://github.com/Phishing-Database/Phishing.Database",
            terms_note="Phishing.Database open intelligence dataset under MIT / open community research terms.",
            request_timeout_seconds=12,
        )

    @property
    def is_configured(self) -> bool:
        return True

    def fetch_records(self, limit: int = 200) -> List[RawThreatRecord]:
        # Prefer the hourly new feed for live updates, fallback to today or active feed
        feed_url = os.getenv("VIGIL_PHISHING_DB_URL", PHISHING_DB_NEW_LAST_HOUR_URL)

        try:
            body = self.fetch_http(feed_url)
            lines = [l for l in body.decode("utf-8", errors="replace").splitlines() if l.strip() and not l.strip().startswith("#")]
            if not lines and feed_url == PHISHING_DB_NEW_LAST_HOUR_URL:
                feed_url = PHISHING_DB_NEW_TODAY_URL
                body = self.fetch_http(feed_url)
                lines = [l for l in body.decode("utf-8", errors="replace").splitlines() if l.strip() and not l.strip().startswith("#")]
            if not lines and feed_url == PHISHING_DB_NEW_TODAY_URL:
                feed_url = PHISHING_DB_ACTIVE_URL
                body = self.fetch_http(feed_url)
                lines = [l for l in body.decode("utf-8", errors="replace").splitlines() if l.strip() and not l.strip().startswith("#")]
        except RuntimeError as exc:
            if "404" in str(exc) or "400" in str(exc):
                logger.info("Hourly feed returned %s; falling back to today feed", exc)
                feed_url = PHISHING_DB_NEW_TODAY_URL
                body = self.fetch_http(feed_url)
                lines = body.decode("utf-8", errors="replace").splitlines()
            else:
                raise

        records: List[RawThreatRecord] = []

        for line in lines:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#") or cleaned.startswith("//"):
                continue

            # Ensure valid protocol if raw domain or incomplete scheme
            target_url = cleaned
            if not (target_url.startswith("http://") or target_url.startswith("https://")):
                target_url = f"http://{target_url}"

            records.append(
                RawThreatRecord(
                    url=target_url,
                    source="phishing_database",
                    indicator_type="phishing_url",
                    status="active",
                    source_id=None,
                    source_timestamp=None,  # Not provided in plain text lines
                    threat_type="credential_phish",
                    tags=["phishing", "community_feed"],
                    confidence=0.90,
                    metadata={"feed_resource": feed_url.rsplit("/", 1)[-1]},
                )
            )
            if len(records) >= limit:
                break

        return records

