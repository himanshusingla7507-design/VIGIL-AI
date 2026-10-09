"""URLhaus (abuse.ch) Threat Intelligence Provider Adapter."""
from __future__ import annotations

import csv
import json
import logging
import os
from typing import List, Optional

from threat_intel.models import RawThreatRecord
from threat_intel.providers.base import BaseThreatProvider, parse_flexible_utc_timestamp

logger = logging.getLogger("threat_intel.provider.urlhaus")

URLHAUS_RECENT_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLHAUS_API_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


class URLhausProvider(BaseThreatProvider):
    """Adapter for abuse.ch URLhaus active malware URL dataset."""

    def __init__(self):
        super().__init__(
            provider_id="urlhaus",
            display_name="URLhaus (abuse.ch)",
            update_cadence_seconds=300,  # 5 minutes
            cadence_human="Every 5 minutes",
            documentation_url="https://urlhaus.abuse.ch/api/",
            terms_note="abuse.ch free malware URL dataset. Use according to abuse.ch terms for defensive security research.",
            max_response_bytes=15 * 1024 * 1024,
            request_timeout_seconds=15,
        )

    @property
    def is_configured(self) -> bool:
        # Public CSV dataset does not require auth; custom API token can be provided
        return True

    def fetch_records(self, limit: int = 150) -> List[RawThreatRecord]:
        api_key = os.getenv("URLHAUS_API_KEY")
        custom_endpoint = os.getenv("VIGIL_URLHAUS_ENDPOINT")

        if custom_endpoint:
            target_url = custom_endpoint
        elif api_key:
            target_url = URLHAUS_API_RECENT_URL
        else:
            target_url = URLHAUS_RECENT_CSV_URL

        headers = {}
        if api_key:
            headers["Auth-Key"] = api_key

        body = self.fetch_http(target_url, headers=headers)
        text_content = body.decode("utf-8", errors="replace").strip()

        records: List[RawThreatRecord] = []

        # Check if response is JSON (e.g. from API or custom JSON endpoint)
        if text_content.startswith("{") or text_content.startswith("["):
            try:
                data = json.loads(text_content)
                records = self._parse_json_records(data, limit=limit)
                return records
            except json.JSONDecodeError:
                pass

        # Otherwise parse as CSV dataset (standard abuse.ch CSV format)
        records = self._parse_csv_records(text_content, limit=limit)
        return records

    def _parse_json_records(self, data: object, limit: int) -> List[RawThreatRecord]:
        records: List[RawThreatRecord] = []
        raw_items = []
        if isinstance(data, dict):
            if "urls" in data and isinstance(data["urls"], list):
                raw_items = data["urls"]
            else:
                for key, val in data.items():
                    if isinstance(val, list):
                        raw_items.extend(val)
                    elif isinstance(val, dict) and "url" in val:
                        raw_items.append(val)
        elif isinstance(data, list):
            raw_items = data

        for item in raw_items[:limit]:
            if not isinstance(item, dict):
                continue
            raw_url = item.get("url")
            if not raw_url or not isinstance(raw_url, str):
                continue

            source_id = str(item.get("id")) if item.get("id") is not None else None
            date_added = parse_flexible_utc_timestamp(item.get("dateadded") or item.get("date_added"))
            url_status = str(item.get("url_status", "online")).lower()
            threat = item.get("threat") or "malware_download"
            tags = item.get("tags")
            if isinstance(tags, str):
                tag_list = [t.strip() for t in tags.split(",") if t.strip() and t.lower() != "none"]
            elif isinstance(tags, list):
                tag_list = [str(t) for t in tags if t and str(t).lower() != "none"]
            else:
                tag_list = []

            reporter = item.get("reporter")
            meta = {
                "reporter": reporter,
                "urlhaus_reference": item.get("urlhaus_reference") or item.get("urlhaus_link"),
                "threat_desc": threat,
            }

            records.append(
                RawThreatRecord(
                    url=raw_url.strip(),
                    source="urlhaus",
                    indicator_type="malware_url",
                    status=url_status if url_status in {"online", "offline"} else "active",
                    source_id=source_id,
                    source_timestamp=date_added,
                    threat_type=threat,
                    tags=tag_list,
                    confidence=0.95,
                    metadata=meta,
                )
            )
        return records

    def _parse_csv_records(self, csv_text: str, limit: int) -> List[RawThreatRecord]:
        records: List[RawThreatRecord] = []
        # Filter comment and blank lines
        lines = [line for line in csv_text.splitlines() if line and not line.startswith("#")]
        if not lines:
            return records

        reader = csv.reader(lines)
        for row in reader:
            if len(records) >= limit:
                break
            if not row or len(row) < 3:
                continue

            # Standard CSV Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            source_id = row[0].strip() if len(row) > 0 else None
            date_added_raw = row[1].strip() if len(row) > 1 else None
            raw_url = row[2].strip() if len(row) > 2 else None
            url_status_raw = row[3].strip().lower() if len(row) > 3 else "online"
            threat = row[5].strip() if len(row) > 5 and row[5].strip() else "malware_download"
            tags_raw = row[6].strip() if len(row) > 6 else ""
            urlhaus_link = row[7].strip() if len(row) > 7 else ""
            reporter = row[8].strip() if len(row) > 8 else ""

            if not raw_url or not (raw_url.startswith("http://") or raw_url.startswith("https://")):
                continue

            date_added = parse_flexible_utc_timestamp(date_added_raw)
            tag_list = [t.strip() for t in tags_raw.split(",") if t.strip() and t.strip().lower() != "none"]

            meta = {
                "reporter": reporter if reporter else None,
                "urlhaus_reference": urlhaus_link if urlhaus_link else None,
                "threat_desc": threat,
            }

            records.append(
                RawThreatRecord(
                    url=raw_url,
                    source="urlhaus",
                    indicator_type="malware_url",
                    status=url_status_raw if url_status_raw in {"online", "offline"} else "active",
                    source_id=source_id,
                    source_timestamp=date_added,
                    threat_type=threat,
                    tags=tag_list,
                    confidence=0.95,
                    metadata=meta,
                )
            )
        return records
