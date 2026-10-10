import { useEffect, useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronRight,
  Copy,
  ExternalLink,
  Flame,
  Info,
  Layers,
  PhoneCall,
  Radio,
  Scale,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Tv,
} from 'lucide-react'
import type { ScamCaseBroadcast, ScamCaseStats } from '../types'
import { api } from '../services/api'

interface ScamBroadcastPageProps {
  onInspectUrl: (url: string) => void
  onNavigateToLaw: (instrumentId?: string) => void
}

export function ScamBroadcastPage({ onInspectUrl, onNavigateToLaw }: ScamBroadcastPageProps) {
  const [cases, setCases] = useState<ScamCaseBroadcast[]>([])
  const [stats, setStats] = useState<ScamCaseStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedCase, setSelectedCase] = useState<ScamCaseBroadcast | null>(null)
  const [copiedText, setCopiedText] = useState<string | null>(null)

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedType, setSelectedType] = useState<string>('ALL')
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL')

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true)
        const [res, statsRes] = await Promise.all([
          api.getScamCases({ limit: 50 }),
          api.getScamStats(),
        ])
        setCases(res.cases)
        setStats(statsRes)
        if (res.cases.length > 0 && !selectedCase) {
          setSelectedCase(res.cases[0])
        }
      } catch (err: any) {
        setError(err.message || 'Could not load scam cases')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard?.writeText(text)
    setCopiedText(id)
    setTimeout(() => setCopiedText(null), 1500)
  }

  const filteredCases = useMemo(() => {
    return cases.filter(item => {
      const matchesSearch =
        !searchQuery.trim() ||
        item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.target_audience.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.warning_signs.some(w => w.toLowerCase().includes(searchQuery.toLowerCase()))

      const matchesType = selectedType === 'ALL' || item.scam_type === selectedType
      const matchesSeverity = selectedSeverity === 'ALL' || item.severity === selectedSeverity

      return matchesSearch && matchesType && matchesSeverity
    })
  }, [cases, searchQuery, selectedType, selectedSeverity])

  const breakingCase = useMemo(() => cases.find(c => c.is_breaking) || cases[0], [cases])

  return (
    <div className="page-container broadcast-page">
      {/* Header */}
      <div className="broadcast-header">
        <div>
          <div className="kicker">
            <span className="kicker-line" />
            <Tv size={13} aria-hidden="true" />
            <span>Public Awareness & Incident Intelligence</span>
          </div>
          <h1>
            Cyber Scam Broadcast<br />
            <em>Verified Incident Newsroom</em>
          </h1>
          <p>
            Documented real-world cyber fraud campaigns, step-by-step attack chains, warning signs, and official recovery procedures.
          </p>
        </div>

        {/* Quick Stats Pill */}
        <div className="broadcast-stats-strip">
          <div>
            <span>Documented Cases</span>
            <strong>{stats?.total_cases ?? '—'}</strong>
          </div>
          <div>
            <span>Active Campaigns</span>
            <strong className="text-amber">{stats?.by_status?.['ongoing_campaign'] ?? '—'}</strong>
          </div>
          <div>
            <span>Critical Severity</span>
            <strong className="text-red">{stats?.by_severity?.['critical'] ?? '—'}</strong>
          </div>
        </div>
      </div>

      {/* Emergency Helpline Banner */}
      <div className="emergency-alert-strip">
        <div className="emergency-lead">
          <PhoneCall size={20} className="pulse-phone" />
          <div>
            <strong>National Financial Cyber Fraud Helpline: Call 1930</strong>
            <p>If you have lost money via UPI or net banking, dial 1930 immediately within the Golden Hour to freeze transactions.</p>
          </div>
        </div>
        <a
          href="https://cybercrime.gov.in"
          target="_blank"
          rel="noopener noreferrer"
          className="emergency-portal-link"
        >
          <span>cybercrime.gov.in</span>
          <ExternalLink size={13} />
        </a>
      </div>

      {/* Breaking Spotlight Banner */}
      {breakingCase && (
        <div className="breaking-spotlight-card">
          <div className="spotlight-badge-row">
            <span className="breaking-pill">
              <span className="flame-icon">🔥</span> ACTIVE HIGH-IMPACT THREAT
            </span>
            <span className="source-tag">Source: {breakingCase.primary_source}</span>
          </div>
          <h2>{breakingCase.title}</h2>
          <p className="spotlight-summary">{breakingCase.summary}</p>
          <div className="spotlight-actions">
            <button className="primary-button" onClick={() => setSelectedCase(breakingCase)}>
              <span>Inspect Full Attack Chain & Protection Steps</span>
              <ArrowRight size={16} />
            </button>
          </div>
        </div>
      )}

      {/* Control / Filter Strip */}
      <div className="feed-controls-strip">
        <div className="search-box">
          <Search size={16} aria-hidden="true" />
          <input
            type="text"
            placeholder="Search scam type, modus operandi, warning sign, or keyword…"
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
            value={selectedType}
            onChange={e => setSelectedType(e.target.value)}
            className="feed-select"
            aria-label="Filter by scam category"
          >
            <option value="ALL">All Scam Types</option>
            <option value="digital_arrest">Digital Arrest & Police Impersonation</option>
            <option value="upi_qr_fraud">UPI & QR Code Deception</option>
            <option value="malicious_apk">Malicious Banking APKs & KYC</option>
            <option value="investment_part_time_job">Task-Based Job & Crypto Investment</option>
          </select>

          <select
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="feed-select"
            aria-label="Filter by severity"
          >
            <option value="ALL">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
        </div>
      </div>

      {/* Main Broadcast Layout */}
      <div className="broadcast-layout">
        {/* Left Column: List of Verified Cases */}
        <div className="broadcast-list-col">
          {loading ? (
            <div className="center-state">Loading verified cyber scam cases…</div>
          ) : error ? (
            <div className="error-panel">{error}</div>
          ) : filteredCases.length === 0 ? (
            <div className="large-empty">
              <h2>No documented cases match your filter</h2>
            </div>
          ) : (
            <div className="broadcast-card-deck">
              {filteredCases.map(item => {
                const isSelected = selectedCase?.id === item.id
                return (
                  <article
                    key={item.id}
                    className={`broadcast-card ${item.severity} ${isSelected ? 'selected' : ''}`}
                    onClick={() => setSelectedCase(item)}
                  >
                    <div className="card-top-row">
                      <span className={`status-badge-mini ${item.status}`}>
                        {item.status.replace('_', ' ').toUpperCase()}
                      </span>
                      <span className={`severity-pill ${item.severity}`}>
                        {item.severity.toUpperCase()} SEVERITY
                      </span>
                      <time className="case-time">{new Date(item.published_at).toLocaleDateString()}</time>
                    </div>

                    <h3 className="case-title">{item.title}</h3>
                    <p className="case-snippet">{item.summary}</p>

                    <div className="case-target-chip">
                      <strong>Target:</strong> {item.target_audience}
                    </div>

                    <div className="card-footer-row">
                      <span className="source-cite">Published by {item.primary_source}</span>
                      <button className="view-case-btn" onClick={() => setSelectedCase(item)}>
                        <span>View Attack Chain</span>
                        <ChevronRight size={14} />
                      </button>
                    </div>
                  </article>
                )
              })}
            </div>
          )}
        </div>

        {/* Right Column: Case Deep-Dive Inspector */}
        <div className="broadcast-detail-col">
          {selectedCase ? (
            <section className="panel case-inspector-panel">
              <div className="inspector-head">
                <span className="eyebrow">Incident Deep-Dive & Forensic Breakdown</span>
                <h2>{selectedCase.title}</h2>
                <div className="inspector-meta-bar">
                  <span className={`status-badge-mini ${selectedCase.status}`}>
                    {selectedCase.status.replace('_', ' ').toUpperCase()}
                  </span>
                  <span>Verified: {new Date(selectedCase.last_verified_at).toLocaleDateString()}</span>
                  <a
                    href={selectedCase.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="official-source-link"
                  >
                    <span>{selectedCase.primary_source}</span>
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>

              {/* What Happened */}
              <div className="inspector-section">
                <h3>What Happened</h3>
                <p className="narrative-text">{selectedCase.what_happened}</p>
              </div>

              {/* Step-by-Step Attack Chain */}
              <div className="inspector-section">
                <h3>Step-by-Step Attack Chain</h3>
                <div className="attack-chain-steps">
                  {selectedCase.attack_chain.map(step => (
                    <div key={step.step_number} className="attack-step-card">
                      <div className="step-num-badge">{step.step_number}</div>
                      <div className="step-body">
                        <strong>{step.stage_name}</strong>
                        <p>{step.description}</p>
                        <div className="step-attacker-tag">
                          <span>Attacker Action:</span> {step.attacker_action}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Warning Signs */}
              <div className="inspector-section">
                <h3>Key Warning Signs</h3>
                <ul className="warning-signs-list">
                  {selectedCase.warning_signs.map((sign, idx) => (
                    <li key={idx}>
                      <AlertTriangle size={15} className="text-amber" />
                      <span>{sign}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Technical Indicators */}
              {selectedCase.technical_indicators?.length > 0 && (
                <div className="inspector-section">
                  <h3>Technical Indicators & Phishing Targets</h3>
                  <div className="tech-indicators-list">
                    {selectedCase.technical_indicators.map((ind, idx) => (
                      <div key={idx} className="tech-indicator-row">
                        <code>{ind.safe_display || ind.value}</code>
                        <div className="indicator-actions">
                          <button
                            className="icon-button"
                            onClick={() => handleCopy(ind.value, `ind-${idx}`)}
                            title="Safe copy"
                          >
                            {copiedText === `ind-${idx}` ? <Check size={14} className="text-emerald" /> : <Copy size={14} />}
                          </button>
                          {ind.type === 'url' && (
                            <button
                              className="primary-button mini"
                              onClick={() => onInspectUrl(ind.value)}
                              title="Inspect URL structure with VIGIL AI model"
                            >
                              <ArrowUpRight size={13} />
                              <span>VIGIL Scan</span>
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Documented Losses / Impact */}
              {selectedCase.documented_impact && (
                <div className="inspector-section impact-box">
                  <strong>Documented Scope & Losses:</strong>
                  <p>{selectedCase.documented_impact}</p>
                </div>
              )}

              {/* Actionable Protection Steps */}
              <div className="inspector-section">
                <h3>Actionable Protection Rules</h3>
                <ul className="action-rules-list">
                  {selectedCase.protection_steps.map((step, idx) => (
                    <li key={idx}>
                      <ShieldCheck size={16} className="text-emerald" />
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Victim Recovery Steps */}
              <div className="inspector-section recovery-box">
                <h3>If You Are Already a Victim</h3>
                <ol className="recovery-steps-list">
                  {selectedCase.victim_recovery_steps.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ol>
              </div>

              {/* Applicable Indian Cyber Laws */}
              <div className="inspector-section">
                <h3>Applicable Indian Laws & Statutory Penalties</h3>
                <div className="legal-cards-grid">
                  {selectedCase.legal_provisions.map((leg, idx) => (
                    <div key={idx} className="legal-ref-card">
                      <div className="legal-ref-head">
                        <Scale size={15} />
                        <strong>{leg.provision}</strong>
                      </div>
                      <span className="legal-ref-title">{leg.title}</span>
                      <p>{leg.summary}</p>
                      <button
                        className="legal-learn-btn"
                        onClick={() => onNavigateToLaw(leg.instrument_id)}
                      >
                        <span>Learn in Cyber Law Center</span>
                        <ArrowRight size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          ) : (
            <div className="large-empty">
              <p>Select a case on the left to inspect its complete attack chain and recovery playbook.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
