"""Data models for Cyber Scam Case Broadcast module."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ScamAttackStep:
    step_number: int
    stage_name: str
    description: str
    attacker_action: str
    victim_experience: str


@dataclass
class ScamCaseBroadcast:
    id: str
    slug: str
    title: str
    status: str  # confirmed_active, under_verification, ongoing_campaign, mitigated, historical
    severity: str  # critical, high, medium, informational
    scam_type: str  # upi_qr_fraud, digital_arrest, banking_kyc_takeover, investment_part_time_job, fake_customer_support, courier_customs_fraud, deepfake_impersonation, malicious_apk, sim_swap_identity, govt_scheme_fraud, crypto_drainer
    category_display: str
    summary: str
    what_happened: str
    attack_chain: List[Dict[str, Any]]
    target_audience: str
    warning_signs: List[str]
    technical_indicators: List[Dict[str, Any]]  # [{ type: "url"|"domain"|"sms_header"|"apk_hash", value: "...", safe_display: "...", linked_indicator_id: null }]
    documented_impact: str
    protection_steps: List[str]
    victim_recovery_steps: List[str]
    legal_provisions: List[Dict[str, str]]  # [{ instrument_id: "...", provision: "Section 66D, IT Act 2000", title: "Cheating by Personation", summary: "..." }]
    primary_source: str  # e.g., "I4C / National Cyber Crime Reporting Portal", "CERT-In Advisory", "RBI Public Alert", "MHA Cyber Safety"
    source_url: str
    published_at: str
    last_verified_at: str
    is_breaking: bool = False
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
