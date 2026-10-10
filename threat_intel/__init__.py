"""VIGIL AI Live Threat Intelligence Module."""
from __future__ import annotations

import os
from typing import Optional

from threat_intel.models import (
    RawThreatRecord,
    StreamEvent,
    ThreatFeedStats,
    ThreatIndicator,
    ThreatSourceStatus,
)
from threat_intel.pipeline import ThreatIntelPipeline
from threat_intel.scheduler import ThreatIngestionScheduler
from threat_intel.storage import ThreatStorage
from threat_intel.stream import ThreatStreamBroadcaster

_storage: Optional[ThreatStorage] = None
_broadcaster: Optional[ThreatStreamBroadcaster] = None
_pipeline: Optional[ThreatIntelPipeline] = None
_scheduler: Optional[ThreatIngestionScheduler] = None


def get_threat_storage() -> ThreatStorage:
    global _storage
    if _storage is None:
        db_path = os.getenv("VIGIL_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "vigil_history.sqlite3"))
        _storage = ThreatStorage(db_path=db_path)
    return _storage


def get_threat_broadcaster() -> ThreatStreamBroadcaster:
    global _broadcaster
    if _broadcaster is None:
        _broadcaster = ThreatStreamBroadcaster()
    return _broadcaster


def get_threat_pipeline() -> ThreatIntelPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = ThreatIntelPipeline(
            storage=get_threat_storage(),
            broadcaster=get_threat_broadcaster(),
        )
    return _pipeline


def get_threat_scheduler() -> ThreatIngestionScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = ThreatIngestionScheduler(
            pipeline=get_threat_pipeline(),
        )
    return _scheduler


__all__ = [
    "ThreatIndicator",
    "ThreatSourceStatus",
    "ThreatFeedStats",
    "StreamEvent",
    "RawThreatRecord",
    "ThreatStorage",
    "ThreatStreamBroadcaster",
    "ThreatIntelPipeline",
    "ThreatIngestionScheduler",
    "get_threat_storage",
    "get_threat_broadcaster",
    "get_threat_pipeline",
    "get_threat_scheduler",
]

