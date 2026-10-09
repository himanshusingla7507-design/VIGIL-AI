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
  probability_source?: string
  reputation?: { applied: boolean; host: string; source: string; reason?: string; model_probability: number; effective_probability?: number }
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
