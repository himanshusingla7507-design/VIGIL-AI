"""Data structures for India Digital Rights & Cyber Law Knowledge Center."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LegalProvision:
    section_or_article: str
    heading: str
    plain_explanation: str
    applicability_and_scope: str
    penalties_or_remedy: str
    official_source_ref: str


@dataclass
class LegalInstrument:
    id: str
    title: str
    short_title: str
    year: int
    instrument_type: str  # constitution_provision, act, rules, regulation, master_direction, landmark_judgment
    category: str  # constitutional_rights, cyber_crimes, data_privacy, digital_payments, consumer_protection, telecom_evidence
    responsible_authority: str  # e.g., "Ministry of Electronics and Information Technology (MeitY)", "Supreme Court of India", "Reserve Bank of India (RBI)"
    commencement_status: str  # in_force, phased_commencement, uncommenced_rules_pending, active_regulation
    commencement_note: str
    summary: str
    why_it_matters_online: str
    who_it_applies_to: str
    provisions: List[Dict[str, Any]]
    real_world_scenarios: List[str]
    limits_and_exceptions: List[str]
    citizen_remedies: List[str]
    official_source_url: str
    last_verified_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LegalScenario:
    id: str
    title: str
    icon_name: str
    user_situation: str
    what_is_happening: str
    potentially_applicable_laws: List[Dict[str, str]]
    immediate_citizen_actions: List[str]
    evidence_preservation_tips: List[str]
    official_reporting_portal: str
    portal_url: str
    helpline_number: Optional[str]
    legal_caveat: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GlossaryTerm:
    id: str
    term: str
    plain_definition: str
    legal_definition: str
    statutory_reference: str
    example: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CitizenActionGuide:
    id: str
    title: str
    category: str
    urgency_level: str  # immediate_golden_hour, priority_24h, standard_procedure
    summary: str
    step_by_step: List[Dict[str, str]]
    dos_and_donts: Dict[str, List[str]]
    official_channels: List[Dict[str, str]]
    disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
