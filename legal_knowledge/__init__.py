"""India Digital Rights & Cyber Law Knowledge Center package."""
from __future__ import annotations

from typing import Optional
from legal_knowledge.models import (
    CitizenActionGuide,
    GlossaryTerm,
    LegalInstrument,
    LegalScenario,
)
from legal_knowledge.storage import LegalKnowledgeStorage

_storage: Optional[LegalKnowledgeStorage] = None


def get_legal_knowledge_storage() -> LegalKnowledgeStorage:
    global _storage
    if _storage is None:
        _storage = LegalKnowledgeStorage()
    return _storage


__all__ = [
    "LegalInstrument",
    "LegalScenario",
    "GlossaryTerm",
    "CitizenActionGuide",
    "LegalKnowledgeStorage",
    "get_legal_knowledge_storage",
]
