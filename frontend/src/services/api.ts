import type { HealthResponse, ModelInfo, ScanResult } from '../types'

const baseUrl = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${baseUrl}${path}`, { ...init, headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) } })
  } catch {
    throw new Error('VIGIL could not reach the analysis service.')
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) throw new Error(body?.message || 'Analysis failed. Try again.')
  return body as T
}

export const api = {
  scanUrl: async (url: string) => {
    const requestId = globalThis.crypto?.randomUUID?.()
    const result = await request<ScanResult>('/scan', {
      method: 'POST',
      headers: requestId ? { 'X-Vigil-Request-Id': requestId } : undefined,
      body: JSON.stringify({ url }),
    })
    if (import.meta.env.DEV) {
      console.info('[VIGIL scan]', JSON.stringify({
        normalized_url: result.normalized_url,
        hostname: new URL(result.normalized_url).hostname,
        api_endpoint: result.backend.api_endpoint,
        request_id: result.request_id,
        client_scan_id: requestId || null,
        backend_pid: result.backend.backend_pid,
        backend_instance_id: result.backend.backend_instance_id,
        model_version: result.model_version,
        model_fingerprint: result.model_fingerprint,
        raw_fold_probabilities: result.diagnostics?.raw_fold_probabilities || null,
        calibrated_probability: result.probability,
        thresholds: result.thresholds,
        verdict: result.label,
        risk_score: result.risk_score,
        cache_hit: false,
      }))
    }
    return result
  },
  getHistory: () => request<ScanResult[]>('/history'),
  getHistoryItem: (id: number) => request<ScanResult>(`/history/${id}`),
  clearHistory: () => request<{ status: string }>('/history', { method: 'DELETE' }),
  getModelInfo: () => request<ModelInfo>('/model-info'),
  getHealth: () => request<HealthResponse>('/health'),
}
