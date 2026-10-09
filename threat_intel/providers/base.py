"""Base threat provider adapter with resilient HTTP and normalization helpers."""
from __future__ import annotations

import logging
import os
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from threat_intel.models import RawThreatRecord, ThreatSourceStatus, utc_now_iso

logger = logging.getLogger("threat_intel.provider")


def parse_flexible_utc_timestamp(val: Optional[str]) -> Optional[str]:
    """Parse various upstream timestamp formats to ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ)."""
    if not val or not isinstance(val, str):
        return None
    cleaned = val.strip()
    if not cleaned:
        return None

    # Try standard ISO-8601
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(cleaned, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


class BaseThreatProvider(ABC):
    """Abstract base class for threat intelligence source adapters."""

    def __init__(
        self,
        provider_id: str,
        display_name: str,
        update_cadence_seconds: int,
        cadence_human: str,
        documentation_url: str,
        terms_note: str,
        max_response_bytes: int = 15 * 1024 * 1024,  # 15 MB safety limit
        request_timeout_seconds: int = 12,
    ):
        self.provider_id = provider_id
        self.display_name = display_name
        self.update_cadence_seconds = update_cadence_seconds
        self.cadence_human = cadence_human
        self.documentation_url = documentation_url
        self.terms_note = terms_note
        self.max_response_bytes = max_response_bytes
        self.request_timeout_seconds = request_timeout_seconds

        self.last_fetch_attempt: Optional[str] = None
        self.last_successful_fetch: Optional[str] = None
        self.last_error: Optional[str] = None
        self.total_indicators_fetched: int = 0
        self.consecutive_failures: int = 0

    @property
    def is_enabled(self) -> bool:
        """Whether this provider is enabled by configuration."""
        env_key = f"VIGIL_SOURCE_{self.provider_id.upper()}_ENABLED"
        val = os.getenv(env_key, "true").lower()
        return val in {"1", "true", "yes", "on"}

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Whether required credentials/URLs are present."""
        pass

    @property
    def operational_status(self) -> str:
        """Return healthy, stale, error, awaiting_config, or rate_limited."""
        if not self.is_configured:
            return "awaiting_config"
        if not self.is_enabled:
            return "disabled"
        if self.last_error:
            if "429" in self.last_error or "rate" in self.last_error.lower():
                return "rate_limited"
            if self.consecutive_failures >= 3:
                return "error"
        if self.last_successful_fetch:
            try:
                dt = datetime.strptime(self.last_successful_fetch, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                age_seconds = (datetime.now(timezone.utc) - dt).total_seconds()
                # If age is > 3x expected cadence and at least 30 mins, mark stale
                if age_seconds > max(self.update_cadence_seconds * 3, 1800):
                    return "stale"
            except Exception:
                pass
            return "healthy"
        return "healthy" if self.last_fetch_attempt is None else "error"

    def get_source_status(self) -> ThreatSourceStatus:
        return ThreatSourceStatus(
            id=self.provider_id,
            name=self.display_name,
            enabled=self.is_enabled and self.is_configured,
            status=self.operational_status,
            update_cadence_seconds=self.update_cadence_seconds,
            cadence_human=self.cadence_human,
            last_fetch_attempt=self.last_fetch_attempt,
            last_successful_fetch=self.last_successful_fetch,
            last_error=self.last_error,
            total_indicators_fetched=self.total_indicators_fetched,
            documentation_url=self.documentation_url,
            terms_note=self.terms_note,
            metadata={
                "consecutive_failures": self.consecutive_failures,
                "is_configured": self.is_configured,
            },
        )

    def fetch_http(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
        data: Optional[bytes] = None,
    ) -> bytes:
        """Perform a robust, timeout-bounded HTTP request."""
        req_headers = {
            "User-Agent": "VIGIL-AI-ThreatIntel/1.0 (+https://github.com/adity/VIGIL-AI)",
            "Accept": "*/*",
        }
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, headers=req_headers, method=method, data=data)
        ssl_context = None
        try:
            import certifi
            import ssl
            ssl_context = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            pass

        try:
            kwargs = {"timeout": self.request_timeout_seconds}
            if ssl_context is not None and url.lower().startswith("https://"):
                kwargs["context"] = ssl_context
            with urllib.request.urlopen(req, **kwargs) as response:
                body = response.read(self.max_response_bytes + 1)
                if len(body) > self.max_response_bytes:
                    raise ValueError(f"Response exceeded size limit ({self.max_response_bytes} bytes)")
                return body
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error: {exc.reason}") from exc
        except Exception as exc:
            raise RuntimeError(f"Request failed: {str(exc)}") from exc

    @abstractmethod
    def fetch_records(self, limit: int = 100) -> List[RawThreatRecord]:
        """Fetch latest raw threat indicators from upstream source."""
        pass

