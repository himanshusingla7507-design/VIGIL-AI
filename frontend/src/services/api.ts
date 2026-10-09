import type {
  CitizenActionGuide,
  GlossaryTerm,
  HealthResponse,
  LegalInstrument,
  LegalScenario,
  LegalSearchResult,
  ModelInfo,
  ScanResult,
  ScamCaseBroadcast,
  ScamCasesResponse,
  ScamCaseStats,
  StreamEventPayload,
  ThreatFeedStats,
  ThreatIndicatorsResponse,
  ThreatSourceStatus,
} from '../types'

const baseUrl = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), 15000)
  try {
    response = await fetch(`${baseUrl}${path}`, {
      ...init,
      signal: init?.signal || controller.signal,
      headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw new Error('The analysis service took too long to respond.')
    throw new Error('VIGIL could not reach the backend service.')
  } finally {
    window.clearTimeout(timeout)
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) throw new Error(body?.message || 'Request failed. Try again.')
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
    return result
  },
  getHistory: () => request<ScanResult[]>('/history'),
  getHistoryItem: (id: number) => request<ScanResult>(`/history/${id}`),
  clearHistory: () => request<{ status: string }>('/history', { method: 'DELETE' }),
  getModelInfo: () => request<ModelInfo>('/model-info'),
  getHealth: () => request<HealthResponse>('/health'),

  // MODULE 1: Threat Intelligence Feed API
  getThreatIndicators: (params?: {
    page?: number
    limit?: number
    source?: string
    category?: string
    status?: string
    q?: string
  }) => {
    const query = new URLSearchParams()
    if (params?.page) query.set('page', String(params.page))
    if (params?.limit) query.set('limit', String(params.limit))
    if (params?.source && params.source !== 'ALL') query.set('source', params.source)
    if (params?.category && params.category !== 'ALL') query.set('category', params.category)
    if (params?.status && params.status !== 'ALL') query.set('status', params.status)
    if (params?.q?.trim()) query.set('q', params.q.trim())
    const qStr = query.toString()
    return request<ThreatIndicatorsResponse>(`/threat-feed/indicators${qStr ? `?${qStr}` : ''}`)
  },

  getThreatStats: () => request<ThreatFeedStats>('/threat-feed/stats'),
  getThreatSources: () => request<ThreatSourceStatus[]>('/threat-feed/sources'),
  triggerThreatSync: (limit = 150) =>
    request<{ status: string; results: any[] }>(`/threat-feed/sync?limit=${limit}`, { method: 'POST' }),
  injectTestIndicator: (payload: {
    url: string
    source?: string
    indicator_type?: string
    threat_type?: string
    tags?: string[]
  }) =>
    request<{ status: string; indicator: any }>('/threat-feed/test-inject', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  subscribeThreatStream: (
    onEvent: (event: StreamEventPayload) => void,
    onStatusChange: (status: 'LIVE' | 'RECONNECTING' | 'DISCONNECTED') => void
  ) => {
    let lastEventId: string | null = null
    let eventSource: EventSource | null = null
    let reconnectTimeout: number | null = null
    let isExplicitlyClosed = false
    let retryDelay = 1000

    const connect = () => {
      if (isExplicitlyClosed) return

      const streamUrl = new URL(`${baseUrl}/threat-feed/stream`)
      if (lastEventId) {
        streamUrl.searchParams.set('last_event_id', lastEventId)
      }

      eventSource = new EventSource(streamUrl.toString())

      eventSource.onopen = () => {
        retryDelay = 1000
        onStatusChange('LIVE')
      }

      const handlePayload = (e: MessageEvent) => {
        if (!e.data) return
        try {
          if (e.lastEventId) lastEventId = e.lastEventId
          const data: StreamEventPayload = JSON.parse(e.data)
          if (data.event_id) lastEventId = data.event_id
          onEvent(data)
        } catch (err) {
          console.warn('[SSE Parse Error]', err)
        }
      }

      eventSource.addEventListener('indicator.new', handlePayload)
      eventSource.addEventListener('indicator.update', handlePayload)
      eventSource.addEventListener('stats.update', handlePayload)
      eventSource.addEventListener('connect', () => {
        onStatusChange('LIVE')
      })

      eventSource.onerror = () => {
        if (isExplicitlyClosed) return
        onStatusChange('RECONNECTING')
        eventSource?.close()
        eventSource = null

        const nextDelay = Math.min(retryDelay, 10000)
        retryDelay = Math.min(retryDelay * 1.5, 10000)
        reconnectTimeout = window.setTimeout(connect, nextDelay)
      }
    }

    connect()

    return () => {
      isExplicitlyClosed = true
      if (reconnectTimeout) window.clearTimeout(reconnectTimeout)
      if (eventSource) {
        eventSource.close()
        eventSource = null
      }
      onStatusChange('DISCONNECTED')
    }
  },

  // MODULE 2: Cyber Scam Case Broadcast API
  getScamCases: (params?: {
    page?: number
    limit?: number
    scam_type?: string
    status?: string
    severity?: string
    q?: string
  }) => {
    const query = new URLSearchParams()
    if (params?.page) query.set('page', String(params.page))
    if (params?.limit) query.set('limit', String(params.limit))
    if (params?.scam_type && params.scam_type !== 'ALL') query.set('scam_type', params.scam_type)
    if (params?.status && params.status !== 'ALL') query.set('status', params.status)
    if (params?.severity && params.severity !== 'ALL') query.set('severity', params.severity)
    if (params?.q?.trim()) query.set('q', params.q.trim())
    const qStr = query.toString()
    return request<ScamCasesResponse>(`/scam-cases${qStr ? `?${qStr}` : ''}`)
  },

  getScamCaseDetail: (idOrSlug: string) => request<ScamCaseBroadcast>(`/scam-cases/${idOrSlug}`),
  getScamStats: () => request<ScamCaseStats>('/scam-cases/stats'),

  // MODULE 3: India Digital Rights & Cyber Law Knowledge API
  getLegalInstruments: (params?: { category?: string; q?: string }) => {
    const query = new URLSearchParams()
    if (params?.category && params.category !== 'ALL') query.set('category', params.category)
    if (params?.q?.trim()) query.set('q', params.q.trim())
    const qStr = query.toString()
    return request<LegalInstrument[]>(`/legal-knowledge/instruments${qStr ? `?${qStr}` : ''}`)
  },

  getLegalInstrumentDetail: (id: string) => request<LegalInstrument>(`/legal-knowledge/instruments/${id}`),
  getLegalScenarios: (search?: string) => {
    const qStr = search?.trim() ? `?q=${encodeURIComponent(search.trim())}` : ''
    return request<LegalScenario[]>(`/legal-knowledge/scenarios${qStr}`)
  },
  getLegalScenarioDetail: (id: string) => request<LegalScenario>(`/legal-knowledge/scenarios/${id}`),
  getLegalGlossary: (search?: string) => {
    const qStr = search?.trim() ? `?q=${encodeURIComponent(search.trim())}` : ''
    return request<GlossaryTerm[]>(`/legal-knowledge/glossary${qStr}`)
  },
  getCitizenGuides: (category?: string) => {
    const qStr = category && category !== 'ALL' ? `?category=${category}` : ''
    return request<CitizenActionGuide[]>(`/legal-knowledge/guides${qStr}`)
  },
  searchLegalKnowledge: (query: string) =>
    request<LegalSearchResult>(`/legal-knowledge/search?q=${encodeURIComponent(query || '')}`),
}
