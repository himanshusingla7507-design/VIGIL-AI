"""CERT-In (Indian Computer Emergency Response Team) Threat & Vulnerability Advisory Provider."""
from __future__ import annotations

import logging
import os
import re
from typing import List

from threat_intel.models import RawThreatRecord
from threat_intel.providers.base import BaseThreatProvider, parse_flexible_utc_timestamp

logger = logging.getLogger("threat_intel.provider.cert_in")

CERT_IN_ADVISORIES_URL = "https://www.cert-in.org.in/"


class CERTInProvider(BaseThreatProvider):
    """Adapter for official CERT-In cyber-threat advisories and security vulnerability alerts."""

    def __init__(self):
        super().__init__(
            provider_id="cert_in",
            display_name="CERT-In (Govt of India)",
            update_cadence_seconds=7200,  # 2 hours
            cadence_human="Every 2 hours",
            documentation_url="https://www.cert-in.org.in/",
            terms_note="Official Indian Computer Emergency Response Team (CERT-In), Ministry of Electronics and Information Technology public advisories.",
            request_timeout_seconds=12,
        )

    @property
    def is_configured(self) -> bool:
        return True

    def fetch_records(self, limit: int = 50) -> List[RawThreatRecord]:
        custom_url = os.getenv("VIGIL_CERTIN_FEED_URL", CERT_IN_ADVISORIES_URL)

        records: List[RawThreatRecord] = []
        try:
            body = self.fetch_http(custom_url)
            text = body.decode("utf-8", errors="replace")

            # Extract documented advisory links and indicators
            # E.g. CIAD-2024-XXXX alerts or CIVN-2024-XXXX vulnerability warnings
            matches = re.findall(r"(CI[A-Z]{2}-\d{4}-\d{4})", text)
            seen_advisories = list(dict.fromkeys(matches))

            for adv_id in seen_advisories[:limit]:
                records.append(
                    RawThreatRecord(
                        url=f"https://www.cert-in.org.in/advisories/{adv_id}",
                        source="cert_in",
                        indicator_type="scam_campaign_url",
                        status="verified",
                        source_id=adv_id,
                        source_timestamp=None,
                        threat_type="governmental_cyber_advisory",
                        tags=["cert_in", "advisory", "official_alert", adv_id.lower()],
                        confidence=1.0,
                        metadata={"advisory_id": adv_id, "agency": "CERT-In (MeitY)"},
                    )
                )
        except Exception as exc:
            logger.debug("CERT-In live portal fetch: %s", exc)

        return records
