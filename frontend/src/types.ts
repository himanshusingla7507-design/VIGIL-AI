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
  url: string
  normalized_url: string
  label: Verdict
  risk_score: number
  probability: number
  evidence: Evidence[]
  features: Record<string, string | number>
  model_version: string
  thresholds: { safe: number; phishing: number }
  scanned_at: string
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

export interface HealthResponse { status: string; model_loaded: boolean; model_version?: string | null }
