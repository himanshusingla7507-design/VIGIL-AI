export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'PHISHING'

export interface Evidence {
  id: string
  severity: string
  polarity: string
  title: string
  detail: string
  feature: string | null
  value: string | number | null
}

export interface ScanResult {
  id?: number
  request_id: string
  url: string
  normalized_url: string
  label: Verdict
  risk_score: number
  probability: number
  model_probability: number
  effective_probability: number
  probability_source: 'model' | 'verified_official_route_policy' | 'local_host_policy'
  reputation: { applied: boolean; host: string; source: string; reason?: string; model_probability: number; effective_probability: number }
  evidence: Evidence[]
  features: Record<string, string | number>
  model_version: string
  thresholds: { safe: number; phishing: number }
  scanned_at: string
  model_fingerprint: string
  backend: {
    api_endpoint: string
    backend_pid: number
    backend_instance_id: string
  }
  diagnostics?: {
    hostname?: string
    raw_fold_probabilities?: number[]
    calibrated_probability?: number
    raw_model_probability?: number
    effective_probability?: number
    client_scan_id?: string
    cache_hit?: boolean
  }
}

export interface ModelInfo {
  model_version?: string
  model_type?: string
  dataset_rows?: number
  feature_count?: number
  train_rows?: number
  test_rows?: number
  threshold_rows?: number
  thresholds?: Record<string, number>
  threshold_selection?: string
  calibration?: string
  [key: string]: unknown
}

export interface HealthResponse {
  status: string
  model_loaded: boolean
  model_version?: string | null
  model_fingerprint?: string
  backend?: {
    api_endpoint: string
    backend_pid: number
    backend_instance_id: string
  }
}

// ==========================================
// MODULE 1: GLOBAL SCAMWATCH LIVE TYPES
// ==========================================

export type IndicatorCategory = 'phishing_url' | 'malware_url' | 'phishing_domain' | 'scam_campaign_url' | 'suspicious_url'

export interface ThreatIndicator {
  id: number
  indicator_hash: string
  url: string
  normalized_url: string
  hostname: string
  indicator_type: IndicatorCategory
  primary_source: string
  sources: string[]
  first_seen_at: string
  last_seen_at: string
  source_timestamp: string | null
  status: string
  threat_type: string | null
  tags: string[]
  metadata: Record<string, any>
  ingested_at: string
  // Client-side transient fields
  _isLiveNew?: boolean
  _renderLatencyMs?: number
}

export interface ThreatSourceStatus {
  id: string
  name: string
  enabled: boolean
  status: 'healthy' | 'stale' | 'error' | 'awaiting_config' | 'rate_limited' | 'disabled'
  update_cadence_seconds: number
  cadence_human: string
  last_fetch_attempt: string | null
  last_successful_fetch: string | null
  last_error: string | null
  total_indicators_fetched: number
  documentation_url: string
  terms_note: string
  metadata: Record<string, any>
}

export interface ThreatFeedStats {
  total_indicators: number
  new_last_24h: number
  new_last_1h: number
  by_source: Record<string, number>
  by_category: Record<string, number>
  by_status: Record<string, number>
  active_stream_clients: number
  latest_ingested_at: string | null
  configured_sources: number
  healthy_sources: number
}

export interface ThreatIndicatorsResponse {
  indicators: ThreatIndicator[]
  total: number
  page: number
  limit: number
  total_pages: number
}

export interface StreamEventPayload {
  event_id: string
  event_type: 'indicator.new' | 'indicator.update' | 'stats.update' | 'source.health'
  indicator: ThreatIndicator | null
  stats: ThreatFeedStats | null
  source_health: ThreatSourceStatus | null
  timestamps: {
    source_timestamp: string | null
    ingested_at: string
    persisted_at: string
    emitted_at: string
  }
}

// ==========================================
// MODULE 2: CYBER SCAM CASE BROADCAST TYPES
// ==========================================

export interface ScamAttackStep {
  step_number: number
  stage_name: string
  description: string
  attacker_action: string
  victim_experience: string
}

export interface TechnicalIndicatorItem {
  type: string
  value: string
  safe_display: string
  linked_indicator_id: number | null
}

export interface LegalProvisionRef {
  instrument_id: string
  provision: string
  title: string
  summary: string
}

export interface ScamCaseBroadcast {
  id: string
  slug: string
  title: string
  status: 'confirmed_active' | 'under_verification' | 'ongoing_campaign' | 'mitigated' | 'historical'
  severity: 'critical' | 'high' | 'medium' | 'informational'
  scam_type: string
  category_display: string
  summary: string
  what_happened: string
  attack_chain: ScamAttackStep[]
  target_audience: string
  warning_signs: string[]
  technical_indicators: TechnicalIndicatorItem[]
  documented_impact: string
  protection_steps: string[]
  victim_recovery_steps: string[]
  legal_provisions: LegalProvisionRef[]
  primary_source: string
  source_url: string
  published_at: string
  last_verified_at: string
  is_breaking: boolean
}

export interface ScamCasesResponse {
  cases: ScamCaseBroadcast[]
  total: number
  page: number
  limit: number
  total_pages: number
}

export interface ScamCaseStats {
  total_cases: number
  by_type: Record<string, number>
  by_status: Record<string, number>
  by_severity: Record<string, number>
  breaking_count: number
}

// ==========================================
// MODULE 3: INDIA DIGITAL RIGHTS & CYBER LAW TYPES
// ==========================================

export interface LegalProvisionItem {
  section_or_article: string
  heading: string
  plain_explanation: string
  applicability_and_scope: string
  penalties_or_remedy: string
  official_source_ref: string
}

export interface LegalInstrument {
  id: string
  title: string
  short_title: string
  year: number
  instrument_type: 'constitution_provision' | 'act' | 'rules' | 'regulation' | 'master_direction' | 'landmark_judgment'
  category: 'constitutional_rights' | 'cyber_crimes' | 'data_privacy' | 'digital_payments' | 'consumer_protection' | 'telecom_evidence'
  responsible_authority: string
  commencement_status: 'in_force' | 'phased_commencement' | 'uncommenced_rules_pending' | 'active_regulation'
  commencement_note: string
  summary: string
  why_it_matters_online: string
  who_it_applies_to: string
  provisions: LegalProvisionItem[]
  real_world_scenarios: string[]
  limits_and_exceptions: string[]
  citizen_remedies: string[]
  official_source_url: string
  last_verified_at: string
}

export interface LegalScenario {
  id: string
  title: string
  icon_name: string
  user_situation: string
  what_is_happening: string
  potentially_applicable_laws: { law: string; relevance: string }[]
  immediate_citizen_actions: string[]
  evidence_preservation_tips: string[]
  official_reporting_portal: string
  portal_url: string
  helpline_number: string | null
  legal_caveat: string
}

export interface GlossaryTerm {
  id: string
  term: string
  plain_definition: string
  legal_definition: string
  statutory_reference: string
  example: string
}

export interface CitizenActionGuide {
  id: string
  title: string
  category: string
  urgency_level: 'immediate_golden_hour' | 'priority_24h' | 'standard_procedure'
  summary: string
  step_by_step: { step: string; action: string }[]
  dos_and_donts: { dos: string[]; donts: string[] }
  official_channels: { channel: string; value: string }[]
  disclaimer: string
}

export interface LegalSearchResult {
  instruments: LegalInstrument[]
  scenarios: LegalScenario[]
  glossary: GlossaryTerm[]
  guides: CitizenActionGuide[]
}
