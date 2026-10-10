"""In-memory and indexed query engine for India Cyber Law & Digital Rights Knowledge."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from legal_knowledge.data import (
    CITIZEN_ACTION_GUIDES,
    GLOSSARY_TERMS,
    LEGAL_INSTRUMENTS,
    LEGAL_SCENARIOS,
)
from legal_knowledge.models import (
    CitizenActionGuide,
    GlossaryTerm,
    LegalInstrument,
    LegalScenario,
)


class LegalKnowledgeStorage:
    def __init__(self):
        self._instruments = {inst.id: inst for inst in LEGAL_INSTRUMENTS}
        self._scenarios = {sc.id: sc for sc in LEGAL_SCENARIOS}
        self._glossary = {g.id: g for g in GLOSSARY_TERMS}
        self._guides = {gd.id: gd for gd in CITIZEN_ACTION_GUIDES}

    def get_all_instruments(
        self,
        category: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[LegalInstrument]:
        results = list(self._instruments.values())
        if category and category.upper() != "ALL":
            results = [x for x in results if x.category == category]
        if search and search.strip():
            term = search.strip().lower()
            results = [
                x
                for x in results
                if term in x.title.lower()
                or term in x.short_title.lower()
                or term in x.summary.lower()
                or term in x.why_it_matters_online.lower()
                or any(
                    term in p.get("heading", "").lower()
                    or term in p.get("plain_explanation", "").lower()
                    or term in p.get("applicability_and_scope", "").lower()
                    for p in x.provisions
                )
                or any(term in s.lower() for s in x.real_world_scenarios)
            ]
        return results

    def get_instrument(self, id: str) -> Optional[LegalInstrument]:
        return self._instruments.get(id)

    def get_all_scenarios(self, search: Optional[str] = None) -> List[LegalScenario]:
        results = list(self._scenarios.values())
        if search and search.strip():
            term = search.strip().lower()
            results = [
                x
                for x in results
                if term in x.title.lower()
                or term in x.user_situation.lower()
                or term in x.what_is_happening.lower()
                or any(term in law["law"].lower() or term in law["relevance"].lower() for law in x.potentially_applicable_laws)
            ]
        return results

    def get_scenario(self, id: str) -> Optional[LegalScenario]:
        return self._scenarios.get(id)

    def get_glossary(self, search: Optional[str] = None) -> List[GlossaryTerm]:
        results = list(self._glossary.values())
        if search and search.strip():
            term = search.strip().lower()
            results = [
                x
                for x in results
                if term in x.term.lower()
                or term in x.plain_definition.lower()
                or term in x.legal_definition.lower()
            ]
        return results

    def get_guides(self, category: Optional[str] = None) -> List[CitizenActionGuide]:
        results = list(self._guides.values())
        if category and category.upper() != "ALL":
            results = [x for x in results if x.category == category]
        return results

    def search_all(self, query: str) -> Dict[str, Any]:
        if not query or not query.strip():
            return {
                "instruments": [x.to_dict() for x in self.get_all_instruments()[:5]],
                "scenarios": [x.to_dict() for x in self.get_all_scenarios()[:3]],
                "glossary": [x.to_dict() for x in self.get_glossary()[:3]],
                "guides": [x.to_dict() for x in self.get_guides()[:2]],
            }

        return {
            "instruments": [x.to_dict() for x in self.get_all_instruments(search=query)],
            "scenarios": [x.to_dict() for x in self.get_all_scenarios(search=query)],
            "glossary": [x.to_dict() for x in self.get_glossary(search=query)],
            "guides": [x.to_dict() for x in self.get_guides() if query.lower() in x.title.lower() or query.lower() in x.summary.lower()],
        }
