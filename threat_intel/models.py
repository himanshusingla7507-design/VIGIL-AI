"""Data structures and types for the VIGIL Threat Intelligence Feed."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    """Return current UTC timestamp formatted as ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class RawThreatRecord:
    """Raw indicator record emitted by a threat provider adapter."""
    url: str
    source: str
    indicator_type: str = "phishing_url"
    status: str = "active"
    source_id: Optional[str] = None
    source_timestamp: Optional[str] = None
    threat_type: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    confidence: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIndicator:
    """Persisted, normalized, multi-source threat indicator."""
    id: Optional[int]
    indicator_hash: str
    url: str
    normalized_url: str
    hostname: str
    indicator_type: str  # phishing_url, malware_url, phishing_domain, suspicious_url
    primary_source: str
    sources: List[str]
    first_seen_at: str
    last_seen_at: str
    source_timestamp: Optional[str]
    status: str  # active, online, offline, verified, unverified
    threat_type: Optional[str]
    tags: List[str]
    metadata: Dict[str, Any]
    ingested_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "indicator_hash": self.indicator_hash,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "hostname": self.hostname,
            "indicator_type": self.indicator_type,
            "primary_source": self.primary_source,
            "sources": self.sources,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "source_timestamp": self.source_timestamp,
            "status": self.status,
            "threat_type": self.threat_type,
            "tags": self.tags,
            "metadata": self.metadata,
            "ingested_at": self.ingested_at,
        }


@dataclass
class ThreatSourceStatus:
    """Operational health record for an upstream threat provider."""
    id: str
    name: str
    enabled: bool
    status: str  # healthy, stale, error, awaiting_config, rate_limited
    update_cadence_seconds: int
    cadence_human: str
    last_fetch_attempt: Optional[str]
    last_successful_fetch: Optional[str]
    last_error: Optional[str]
    total_indicators_fetched: int
    documentation_url: str
    terms_note: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatFeedStats:
    """Real-time aggregated statistics for the global intelligence feed."""
    total_indicators: int
    new_last_24h: int
    new_last_1h: int
    by_source: Dict[str, int]
    by_category: Dict[str, int]
    by_status: Dict[str, int]
    active_stream_clients: int
    latest_ingested_at: Optional[str]
    configured_sources: int
    healthy_sources: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StreamEvent:
    """Live SSE payload with high-precision timestamps for latency measurement."""
    event_id: str
    event_type: str  # indicator.new, indicator.update, stats.update, source.health
    indicator: Optional[Dict[str, Any]]
    stats: Optional[Dict[str, Any]]
    source_health: Optional[Dict[str, Any]]
    source_timestamp: Optional[str]
    ingested_at: str
    persisted_at: str
    emitted_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "indicator": self.indicator,
            "stats": self.stats,
            "source_health": self.source_health,
            "timestamps": {
                "source_timestamp": self.source_timestamp,
                "ingested_at": self.ingested_at,
                "persisted_at": self.persisted_at,
                "emitted_at": self.emitted_at,
            },
        }

