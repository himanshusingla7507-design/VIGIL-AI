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
  scanUrl: (url: string) => request<ScanResult>('/scan', { method: 'POST', body: JSON.stringify({ url }) }),
  getHistory: () => request<ScanResult[]>('/history'),
  getHistoryItem: (id: number) => request<ScanResult>(`/history/${id}`),
  clearHistory: () => request<{ status: string }>('/history', { method: 'DELETE' }),
  getModelInfo: () => request<ModelInfo>('/model-info'),
  getHealth: () => request<HealthResponse>('/health'),
}
