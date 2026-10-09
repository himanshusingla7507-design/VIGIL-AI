"""PhishTank Threat Intelligence Provider Adapter."""
from __future__ import annotations

import json
import logging
import os
from typing import List

from threat_intel.models import RawThreatRecord
from threat_intel.providers.base import BaseThreatProvider, parse_flexible_utc_timestamp

logger = logging.getLogger("threat_intel.provider.phishtank")

PHISHTANK_DEFAULT_JSON_URL = "http://data.phishtank.com/data/online-valid.json"


class PhishTankProvider(BaseThreatProvider):
    """Adapter for PhishTank developer-authenticated feeds and verified lookups."""

    def __init__(self):
        super().__init__(
            provider_id="phishtank",
            display_name="PhishTank",
            update_cadence_seconds=14400,  # 4 hours
            cadence_human="Every 4-12 hours",
            documentation_url="https://phishtank.org/api_info.php",
            terms_note="PhishTank verified community phishing submissions. Developer App Key required for production feed access.",
            request_timeout_seconds=15,
        )

    @property
    def is_configured(self) -> bool:
        # Check if developer key or feed url is provided
        return bool(os.getenv("PHISHTANK_APP_KEY") or os.getenv("PHISHTANK_FEED_URL"))

    def fetch_records(self, limit: int = 150) -> List[RawThreatRecord]:
        if not self.is_configured:
            logger.info("PhishTank is awaiting configuration (PHISHTANK_APP_KEY not set)")
            return []

        app_key = os.getenv("PHISHTANK_APP_KEY", "")
        feed_url = os.getenv("PHISHTANK_FEED_URL")
        if not feed_url:
            if app_key:
                feed_url = f"http://data.phishtank.com/data/{app_key}/online-valid.json"
            else:
                feed_url = PHISHTANK_DEFAULT_JSON_URL

        headers = {
            "User-Agent": f"phishtank/VIGIL-AI-ThreatIntel ({app_key or 'community'})",
        }

        body = self.fetch_http(feed_url, headers=headers)
        data = json.loads(body.decode("utf-8", errors="replace"))

        records: List[RawThreatRecord] = []
        if isinstance(data, list):
            for item in data[:limit]:
                if not isinstance(item, dict):
                    continue
                raw_url = item.get("url")
                if not raw_url or not isinstance(raw_url, str):
                    continue

                phish_id = str(item.get("phish_id")) if item.get("phish_id") is not None else None
                submission_time = parse_flexible_utc_timestamp(item.get("submission_time"))
                verified = str(item.get("verified", "yes")).lower() == "yes"
                target = item.get("target")

                records.append(
                    RawThreatRecord(
                        url=raw_url.strip(),
                        source="phishtank",
                        indicator_type="phishing_url",
                        status="verified" if verified else "unverified",
                        source_id=phish_id,
                        source_timestamp=submission_time,
                        threat_type=f"targeted_phish: {target}" if target else "phishing_url",
                        tags=["phishtank", "verified" if verified else "unverified"] + ([target] if target else []),
                        confidence=0.96 if verified else 0.80,
                        metadata={
                            "phish_id": phish_id,
                            "target_brand": target,
                            "phish_detail_url": item.get("phish_detail_url"),
                        },
                    )
                )

        return records

