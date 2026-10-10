"""OpenPhish Threat Intelligence Provider Adapter."""
from __future__ import annotations

import logging
import os
from typing import List

from threat_intel.models import RawThreatRecord
from threat_intel.providers.base import BaseThreatProvider

logger = logging.getLogger("threat_intel.provider.openphish")

OPENPHISH_COMMUNITY_FEED_URL = "https://openphish.com/feed.txt"


class OpenPhishProvider(BaseThreatProvider):
    """Adapter for OpenPhish community feed and optional premium feed."""

    def __init__(self):
        super().__init__(
            provider_id="openphish",
            display_name="OpenPhish",
            update_cadence_seconds=21600,  # 6 hours community feed cadence
            cadence_human="Every 6-12 hours (Community)",
            documentation_url="https://openphish.com/phishing_feeds.html",
            terms_note="OpenPhish free community feed. Premium feed available with commercial license.",
            request_timeout_seconds=12,
        )

    @property
    def is_configured(self) -> bool:
        return True

    def fetch_records(self, limit: int = 150) -> List[RawThreatRecord]:
        feed_url = os.getenv("OPENPHISH_PREMIUM_URL") or os.getenv("VIGIL_OPENPHISH_URL", OPENPHISH_COMMUNITY_FEED_URL)
        is_premium = bool(os.getenv("OPENPHISH_PREMIUM_URL"))

        body = self.fetch_http(feed_url)
        lines = body.decode("utf-8", errors="replace").splitlines()

        records: List[RawThreatRecord] = []
        for line in lines:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue

            target_url = cleaned
            if not (target_url.startswith("http://") or target_url.startswith("https://")):
                target_url = f"http://{target_url}"

            records.append(
                RawThreatRecord(
                    url=target_url,
                    source="openphish",
                    indicator_type="phishing_url",
                    status="active",
                    source_id=None,
                    source_timestamp=None,
                    threat_type="targeted_phish",
                    tags=["openphish", "verified_phish", "premium" if is_premium else "community"],
                    confidence=0.92,
                    metadata={"feed_type": "premium" if is_premium else "community"},
                )
            )
            if len(records) >= limit:
                break

        return records

