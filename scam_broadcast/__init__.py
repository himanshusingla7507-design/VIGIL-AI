"""Cyber Scam Case Broadcast package."""
from __future__ import annotations

import os
from typing import Optional
from scam_broadcast.models import ScamCaseBroadcast
from scam_broadcast.storage import ScamCaseStorage

_storage: Optional[ScamCaseStorage] = None


def get_scam_case_storage() -> ScamCaseStorage:
    global _storage
    if _storage is None:
        db_path = os.getenv("VIGIL_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "vigil_history.sqlite3"))
        _storage = ScamCaseStorage(db_path=db_path)
    return _storage


__all__ = ["ScamCaseBroadcast", "ScamCaseStorage", "get_scam_case_storage"]
