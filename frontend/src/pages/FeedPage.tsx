import { useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  Activity,
  AlertOctagon,
  ArrowUpRight,
  Check,
  ChevronRight,
  Clock,
  Copy,
  Database,
  ExternalLink,
  Filter,
  Flame,
  Globe,
  LoaderCircle,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Zap,
} from 'lucide-react'
import type { StreamEventPayload, ThreatFeedStats, ThreatIndicator, ThreatSourceStatus } from '../types'
import { api } from '../services/api'

interface FeedPageProps {
  onInspectUrl: (url: string) => void
}

function timeAgo(dateString: string | null): string {
  if (!dateString) return 'Unknown'
  const date = new Date(dateString)
  const now = new Date()
  const diffSeconds = Math.max(0, Math.floor((now.getTime() - date.getTime()) / 1000))

  if (diffSeconds < 5) return 'just now'
  if (diffSeconds < 60) return `${diffSeconds}s ago`
  const diffMinutes = Math.floor(diffSeconds / 60)
  if (diffMinutes < 60) return `${diffMinutes}m ago`
  const diffHours = Math.floor(diffMinutes / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  return `${diffDays}d ago`
}

export function FeedPage({ onInspectUrl }: FeedPageProps) {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([])
  const [bufferedIndicators, setBufferedIndicators] = useState<ThreatIndicator[]>([])
  const [stats, setStats] = useState<ThreatFeedStats | null>(null)
  const [sources, setSources] = useState<ThreatSourceStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState('')

  // Stream state
  const [streamStatus, setStreamStatus] = useState<'LIVE' | 'RECONNECTING' | 'DISCONNECTED'>('DISCONNECTED')
  const [isPaused, setIsPaused] = useState(false)
  const [measuredLatency, setMeasuredLatency] = useState<number | null>(null)
  const [selectedDetail, setSelectedDetail] = useState<ThreatIndicator | null>(null)
  const [copiedId, setCopiedId] = useState<string | number | null>(null)

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedSource, setSelectedSource] = useState<string>('ALL')
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL')
  const [, setTick] = useState(0)

  // Update relative timestamps every 5 seconds
  useEffect(() => {
    const timer = setInterval(() => setTick(t => t + 1), 5000)
    return () => clearInterval(timer)
  }, [])

  // Initial load
  const loadInitialData = async () => {
    try {
      setLoading(true)
      const [res, statsRes, sourcesRes] = await Promise.all([
        api.getThreatIndicators({ limit: 100 }),
        api.getThreatStats(),
        api.getThreatSources(),
      ])
      setIndicators(res.indicators)
      setStats(statsRes)
      setSources(sourcesRes)
      setError('')
    } catch (err: any) {
      setError(err.message || 'Could not load threat intelligence feed')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadInitialData()
  }, [])

  // Ref to track pause state in stream callback
  const isPausedRef = useRef(isPaused)
  useEffect(() => {
    isPausedRef.current = isPaused
  }, [isPaused])

  // Setup live SSE stream subscription
  useEffect(() => {
    const unsubscribe = api.subscribeThreatStream(
      (event: StreamEventPayload) => {
        const now = Date.now()

        // Calculate real latency from backend emit to client reception
        if (event.timestamps?.emitted_at) {
          const emittedTime = new Date(event.timestamps.emitted_at).getTime()
          const latency = Math.max(1, Math.min(now - emittedTime, 5000))
          setMeasuredLatency(latency)
        }

        if (event.event_type === 'indicator.new' && event.indicator) {
          const newInd: ThreatIndicator = {
            ...event.indicator,
            _isLiveNew: true,
            _renderLatencyMs: measuredLatency || undefined,
          }

          if (isPausedRef.current) {
            setBufferedIndicators(prev => [newInd, ...prev.slice(0, 199)])
          } else {
            setIndicators(prev => {
              // Avoid duplicates
              if (prev.some(x => x.indicator_hash === newInd.indicator_hash)) {
                return prev.map(x => (x.indicator_hash === newInd.indicator_hash ? newInd : x))
              }
              return [newInd, ...prev.slice(0, 199)]
            })
          }
        }

        if (event.event_type === 'indicator.update' && event.indicator) {
          const updated = event.indicator
          setIndicators(prev =>
            prev.map(item => (item.indicator_hash === updated.indicator_hash ? { ...item, ...updated } : item))
          )
        }

        if (event.stats) {
          setStats(event.stats)
        }

        if (event.source_health) {
          setSources(prev =>
            prev.map(s => (s.id === event.source_health?.id ? event.source_health : s))
          )
        }
      },
      status => {
        setStreamStatus(status)
      }
    )

    return () => {
      unsubscribe()
    }
  }, [])

  const handleResume = () => {
    if (bufferedIndicators.length > 0) {
      setIndicators(prev => {
        const combined = [...bufferedIndicators, ...prev]
        const seen = new Set<string>()
        const deduped: ThreatIndicator[] = []
        for (const item of combined) {
          if (!seen.has(item.indicator_hash)) {
            seen.add(item.indicator_hash)
            deduped.push(item)
          }
        }
        return deduped.slice(0, 200)
      })
      setBufferedIndicators([])
    }
    setIsPaused(false)
  }

  const handleCopyUrl = (url: string, id: number | string) => {
    navigator.clipboard?.writeText(url)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  const handleManualSync = async () => {
    setSyncing(true)
    try {
      await api.triggerThreatSync(150)
      const [res, statsRes, sourcesRes] = await Promise.all([
        api.getThreatIndicators({ limit: 100 }),
        api.getThreatStats(),
        api.getThreatSources(),
      ])
      setIndicators(res.indicators)
      setStats(statsRes)
      setSources(sourcesRes)
    } catch (err: any) {
      console.warn('Sync warning:', err)
    } finally {
      setSyncing(false)
    }
  }

  const handleSimulateTest = async () => {
    try {
      const sampleDomains = [
        'secure-paypal-verification.auth-check.xyz',
        'microsoft-365-security-alert.update-pass.top',
        'chase-online-account-restore.login-auth.com',
        'apple-id-suspended-verify.support-portal.club',
      ]
      const targetDomain = sampleDomains[Math.floor(Math.random() * sampleDomains.length)]
      const testUrl = `http://${targetDomain}/verify?session=${Math.random().toString(36).slice(2, 9)}`
      await api.injectTestIndicator({
        url: testUrl,
        source: 'urlhaus',
        indicator_type: 'phishing_url',
        threat_type: 'credential_harvesting',
        tags: ['e2e_live_test', 'phishing'],
      })
    } catch (err) {
      console.warn('Simulate failed:', err)
    }
  }

  // Filtered indicators
  const filteredIndicators = useMemo(() => {
    return indicators.filter(item => {
      const matchesSearch =
        !searchQuery.trim() ||
        item.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (item.threat_type && item.threat_type.toLowerCase().includes(searchQuery.toLowerCase()))

      const matchesSource =
        selectedSource === 'ALL' || item.primary_source === selectedSource || item.sources.includes(selectedSource)

      const matchesCategory = selectedCategory === 'ALL' || item.indicator_type === selectedCategory

      return matchesSearch && matchesSource && matchesCategory
    })
  }, [indicators, searchQuery, selectedSource, selectedCategory])

  return (
    <div className="page-container feed-page">
      {/* Top Banner & Header */}
      <div className="feed-header">
        <div>
          <div className="kicker">
            <span className="kicker-line" />
            <Radio size={13} aria-hidden="true" />
            <span>Global Threat Intelligence</span>
          </div>
          <h1>
            Live Phishing Feed<br />
            <em>Real-Time Stream</em>
          </h1>
          <p>
            Continuous, multi-source ingestion of active malicious URLs, phishing domains, and malware distribution points.
          </p>
        </div>

        {/* Real-time Status Card */}
        <div className="feed-telemetry-card">
          <div className="stream-badge-row">
            <span className={`stream-pill ${streamStatus.toLowerCase()}`}>
              <span className="pulse-beacon" />
              {streamStatus === 'LIVE' ? 'LIVE STREAM CONNECTED' : streamStatus === 'RECONNECTING' ? 'RECONNECTING…' : 'DISCONNECTED'}
            </span>
            {measuredLatency !== null && (
              <span className="latency-pill" title="Measured backend SSE emission to browser render latency">
                <Zap size={12} />
                {measuredLatency} ms latency
              </span>
            )}
          </div>

          <div className="feed-stats-mini-grid">
            <div>
              <span>Active Indicators</span>
              <strong>{stats?.total_indicators?.toLocaleString() ?? '—'}</strong>
            </div>
            <div>
              <span>New (24h)</span>
              <strong className="text-emerald">{stats?.new_last_24h?.toLocaleString() ?? '—'}</strong>
            </div>
            <div>
              <span>Healthy Feeds</span>
              <strong>{sources.filter(s => s.status === 'healthy').length} / {sources.length}</strong>
            </div>
            <div>
              <span>Live Clients</span>
              <strong>{stats?.active_stream_clients ?? 1}</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Control Strip */}
      <div className="feed-controls-strip">
        <div className="search-box">
          <Search size={16} aria-hidden="true" />
          <input
            type="text"
            placeholder="Search hostname, URL, or threat signature…"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button className="clear-search" onClick={() => setSearchQuery('')} aria-label="Clear search">
              ×
            </button>
          )}
        </div>

        <div className="filter-group">
          <select
            value={selectedSource}
            onChange={e => setSelectedSource(e.target.value)}
            className="feed-select"
            aria-label="Filter by provider"
          >
            <option value="ALL">All Sources</option>
            <option value="urlhaus">URLhaus (abuse.ch)</option>
            <option value="phishing_database">Phishing.Database</option>
            <option value="openphish">OpenPhish</option>
            <option value="phishtank">PhishTank</option>
          </select>

          <select
            value={selectedCategory}
            onChange={e => setSelectedCategory(e.target.value)}
            className="feed-select"
            aria-label="Filter by category"
          >
            <option value="ALL">All Categories</option>
            <option value="phishing_url">Phishing URLs</option>
            <option value="malware_url">Malware URLs</option>
            <option value="phishing_domain">Phishing Domains</option>
            <option value="suspicious_url">Suspicious URLs</option>
          </select>
        </div>

        <div className="feed-actions-group">
          {isPaused ? (
            <button className="feed-btn warning" onClick={handleResume} title="Resume live stream and display buffered items">
              <Play size={14} />
              <span>Resume Stream {bufferedIndicators.length > 0 ? `(${bufferedIndicators.length} new)` : ''}</span>
            </button>
          ) : (
            <button className="feed-btn" onClick={() => setIsPaused(true)} title="Pause list updates to inspect an item safely">
              <Pause size={14} />
              <span>Pause Updates</span>
            </button>
          )}

          <button className="feed-btn" onClick={handleManualSync} disabled={syncing} title="Trigger upstream provider sync">
            <RefreshCw size={14} className={syncing ? 'spin' : ''} />
            <span>{syncing ? 'Syncing…' : 'Sync Sources'}</span>
          </button>

          <button className="feed-btn special" onClick={handleSimulateTest} title="Inject a synthetic threat into live pipeline to test zero-refresh SSE update">
            <Sparkles size={14} />
            <span>Simulate Live Event</span>
          </button>
        </div>
      </div>

      {/* Main Content Layout */}
      <div className="feed-layout">
        {/* Left / Main: Indicator List */}
        <div className="feed-main-col">
          <div className="feed-list-header">
            <div>
              <h2>Global Indicators Feed</h2>
              <span className="muted">
                Showing {filteredIndicators.length} {filteredIndicators.length === 1 ? 'indicator' : 'indicators'}
                {isPaused && <strong className="pause-indicator"> · [PAUSED - BUFFERING]</strong>}
              </span>
            </div>
            <div className="legend-strip">
              <span className="legend-item"><span className="cat-dot phishing" />Phishing</span>
              <span className="legend-item"><span className="cat-dot malware" />Malware</span>
            </div>
          </div>

          {loading ? (
            <div className="center-state">
              <LoaderCircle className="spin" size={24} />
              <span>Connecting to Global Threat Intel Feed…</span>
            </div>
          ) : error ? (
            <div className="error-panel">{error}</div>
          ) : filteredIndicators.length === 0 ? (
            <div className="large-empty">
              <Globe size={32} />
              <h2>No indicators match your filter</h2>
              <p>Try broadening your search query or selecting All Sources.</p>
            </div>
          ) : (
            <div className="feed-indicator-list" role="feed" aria-busy={loading}>
              <AnimatePresence initial={false}>
                {filteredIndicators.map(item => {
                  const isPhish = item.indicator_type === 'phishing_url' || item.indicator_type === 'phishing_domain'
                  const isMalware = item.indicator_type === 'malware_url'
                  const categoryLabel = isPhish ? 'PHISHING' : isMalware ? 'MALWARE' : 'SUSPICIOUS'

                  return (
                    <motion.div
                      key={item.id ?? item.indicator_hash}
                      className={`feed-indicator-row ${item.indicator_type} ${item._isLiveNew ? 'live-arrival' : ''}`}
                      initial={{ opacity: 0, y: -12, scale: 0.98 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      transition={{ duration: 0.3 }}
                      layout="position"
                    >
                      {/* Left: Category Badge & Host */}
                      <div className="indicator-row-main">
                        <div className="indicator-badges">
                          <span className={`cat-pill ${item.indicator_type}`}>
                            {isPhish ? <ShieldAlert size={12} /> : isMalware ? <AlertOctagon size={12} /> : <ShieldCheck size={12} />}
                            {categoryLabel}
                          </span>

                          {item._isLiveNew && (
                            <span className="live-new-badge">
                              <span className="pulse-dot" />
                              NEW ARRIVAL
                            </span>
                          )}

                          <div className="sources-pills">
                            {item.sources.map(src => (
                              <span key={src} className={`source-pill ${src}`}>
                                {src === 'urlhaus' ? 'URLhaus' : src === 'phishing_database' ? 'Phishing.DB' : src === 'openphish' ? 'OpenPhish' : src === 'phishtank' ? 'PhishTank' : src}
                              </span>
                            ))}
                          </div>

                          {item.status && (
                            <span className={`status-pill ${item.status}`}>
                              {item.status}
                            </span>
                          )}
                        </div>

                        {/* URL Block */}
                        <div className="indicator-url-block">
                          <span className="hostname-highlight">{item.hostname}</span>
                          <code className="url-display" title={item.url}>
                            {item.url}
                          </code>
                        </div>

                        {/* Threat Type & Tags */}
                        {item.threat_type && (
                          <div className="indicator-meta-chips">
                            <span className="meta-chip threat-type">Type: {item.threat_type}</span>
                            {item.tags?.slice(0, 3).map(tag => (
                              <span key={tag} className="meta-chip tag">#{tag}</span>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Right: Timestamps & Actions */}
                      <div className="indicator-row-actions">
                        <div className="indicator-time-col">
                          <time title={`Ingested at: ${item.ingested_at}${item.source_timestamp ? ` · Provider timestamp: ${item.source_timestamp}` : ''}`}>
                            <Clock size={12} />
                            {timeAgo(item.source_timestamp || item.ingested_at)}
                          </time>
                          <span className="time-sub">
                            {item.source_timestamp ? 'Verified Source Time' : 'Ingested UTC'}
                          </span>
                        </div>

                        <div className="action-buttons-strip">
                          <button
                            className="feed-icon-btn"
                            onClick={() => handleCopyUrl(item.url, item.id ?? item.indicator_hash)}
                            title="Safe copy URL"
                            aria-label="Copy threat URL"
                          >
                            {copiedId === (item.id ?? item.indicator_hash) ? <Check size={14} className="text-emerald" /> : <Copy size={14} />}
                          </button>

                          <button
                            className="feed-icon-btn highlight"
                            onClick={() => onInspectUrl(item.url)}
                            title="Analyze in VIGIL ML Scanner"
                            aria-label="Inspect with VIGIL"
                          >
                            <ArrowUpRight size={14} />
                          </button>

                          <button
                            className="feed-icon-btn"
                            onClick={() => setSelectedDetail(item)}
                            title="View Forensics & Metadata"
                            aria-label="View forensics"
                          >
                            <ChevronRight size={14} />
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )
                })}
              </AnimatePresence>
            </div>
          )}
        </div>

        {/* Right: Sidebar with Source Health Radar & Threat Stats */}
        <div className="feed-sidebar-col">
          {/* Source Health Radar */}
          <section className="panel source-radar-panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Upstream Radar</p>
                <h2>Threat Sources</h2>
              </div>
              <span className="muted">{sources.length} Configured</span>
            </div>

            <div className="source-radar-list">
              {sources.map(src => {
                const isHealthy = src.status === 'healthy'
                const isStale = src.status === 'stale'
                const isAwaiting = src.status === 'awaiting_config'
                const isError = src.status === 'error'

                return (
                  <div key={src.id} className={`source-radar-card ${src.status}`}>
                    <div className="source-radar-top">
                      <strong>{src.name}</strong>
                      <span className={`status-badge-mini ${src.status}`}>
                        {isHealthy ? 'HEALTHY' : isStale ? 'STALE' : isAwaiting ? 'AWAITING KEY' : isError ? 'ERROR' : src.status.toUpperCase()}
                      </span>
                    </div>

                    <div className="source-radar-meta">
                      <div>
                        <span>Cadence</span>
                        <strong>{src.cadence_human}</strong>
                      </div>
                      <div>
                        <span>Ingested</span>
                        <strong>{src.total_indicators_fetched?.toLocaleString() ?? 0}</strong>
                      </div>
                    </div>

                    <div className="source-radar-footer">
                      <span>Last sync: {timeAgo(src.last_successful_fetch)}</span>
                      <a href={src.documentation_url} target="_blank" rel="noopener noreferrer" className="source-doc-link" title="Provider documentation">
                        <ExternalLink size={11} />
                      </a>
                    </div>
                  </div>
                )
              })}
            </div>
          </section>

          {/* Category Distribution Breakdown */}
          <section className="panel category-distribution-panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Telemetry</p>
                <h2>Threat Categories</h2>
              </div>
            </div>

            <div className="category-stats-list">
              {Object.entries(stats?.by_category ?? { phishing_url: 0, malware_url: 0 }).map(([cat, count]) => {
                const total = stats?.total_indicators || 1
                const pct = ((count / total) * 100).toFixed(1)
                const isPhish = cat.includes('phish')
                const isMal = cat.includes('malware')

                return (
                  <div key={cat} className="category-stat-row">
                    <div className="cat-stat-head">
                      <span>{isPhish ? 'Phishing URLs' : isMal ? 'Malware URLs' : cat}</span>
                      <strong>{count} ({pct}%)</strong>
                    </div>
                    <div className="cat-progress-bar">
                      <div
                        className={`cat-progress-fill ${isPhish ? 'phishing' : isMal ? 'malware' : 'suspicious'}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </section>
        </div>
      </div>

      {/* Forensic Details Modal / Drawer */}
      <AnimatePresence>
        {selectedDetail && (
          <div className="modal-backdrop" onClick={() => setSelectedDetail(null)}>
            <motion.div
              className="modal-content forensic-modal"
              onClick={e => e.stopPropagation()}
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
            >
              <div className="modal-header">
                <div>
                  <span className="eyebrow">Threat Intelligence Record #{selectedDetail.id}</span>
                  <h2>{selectedDetail.hostname}</h2>
                </div>
                <button className="modal-close-btn" onClick={() => setSelectedDetail(null)} aria-label="Close details">
                  ×
                </button>
              </div>

              <div className="modal-body">
                <div className="forensic-section">
                  <span className="eyebrow">Reported URL</span>
                  <code className="forensic-code-block">{selectedDetail.url}</code>
                </div>

                <div className="forensic-grid">
                  <div>
                    <span>Primary Provider</span>
                    <strong>{selectedDetail.primary_source}</strong>
                  </div>
                  <div>
                    <span>All Reporting Sources</span>
                    <strong>{selectedDetail.sources.join(', ')}</strong>
                  </div>
                  <div>
                    <span>Indicator Category</span>
                    <strong>{selectedDetail.indicator_type}</strong>
                  </div>
                  <div>
                    <span>Status</span>
                    <strong>{selectedDetail.status}</strong>
                  </div>
                  <div>
                    <span>Provider Discovered Time</span>
                    <strong>{selectedDetail.source_timestamp ? new Date(selectedDetail.source_timestamp).toLocaleString() : 'Not supplied by provider'}</strong>
                  </div>
                  <div>
                    <span>Backend Ingestion Time</span>
                    <strong>{new Date(selectedDetail.ingested_at).toLocaleString()}</strong>
                  </div>
                </div>

                {selectedDetail.metadata && Object.keys(selectedDetail.metadata).length > 0 && (
                  <div className="forensic-section">
                    <span className="eyebrow">Provider Raw Forensics & Metadata</span>
                    <pre className="forensic-json-block">
                      {JSON.stringify(selectedDetail.metadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>

              <div className="modal-footer">
                <button
                  className="primary-button"
                  onClick={() => {
                    onInspectUrl(selectedDetail.url)
                    setSelectedDetail(null)
                  }}
                >
                  <ArrowUpRight size={16} />
                  <span>Analyze URL in VIGIL Scanner</span>
                </button>
                <button className="quiet-button" onClick={() => setSelectedDetail(null)}>
                  Close
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  )
}

