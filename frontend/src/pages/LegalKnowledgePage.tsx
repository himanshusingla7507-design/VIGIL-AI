import { useEffect, useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  CreditCard,
  ExternalLink,
  HelpCircle,
  Info,
  Layers,
  Lock,
  PhoneCall,
  Scale,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import type { CitizenActionGuide, GlossaryTerm, LegalInstrument, LegalScenario } from '../types'
import { api } from '../services/api'
import { getOfficialLegalSourceUrl } from '../utils'

interface LegalKnowledgePageProps {
  initialInstrumentId?: string
}

export function LegalKnowledgePage({ initialInstrumentId }: LegalKnowledgePageProps) {
  const [activeTab, setActiveTab] = useState<'acts' | 'scenarios' | 'guides' | 'glossary'>('acts')
  const [instruments, setInstruments] = useState<LegalInstrument[]>([])
  const [scenarios, setScenarios] = useState<LegalScenario[]>([])
  const [guides, setGuides] = useState<CitizenActionGuide[]>([])
  const [glossary, setGlossary] = useState<GlossaryTerm[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL')
  const [expandedInstrumentId, setExpandedInstrumentId] = useState<string | null>(initialInstrumentId || null)
  const [selectedScenario, setSelectedScenario] = useState<LegalScenario | null>(null)

  useEffect(() => {
    const loadAll = async () => {
      try {
        setLoading(true)
        const [insts, scens, gds, gloss] = await Promise.all([
          api.getLegalInstruments(),
          api.getLegalScenarios(),
          api.getCitizenGuides(),
          api.getLegalGlossary(),
        ])
        setInstruments(insts)
        setScenarios(scens)
        setGuides(gds)
        setGlossary(gloss)
        if (initialInstrumentId) {
          setExpandedInstrumentId(initialInstrumentId)
          setActiveTab('acts')
        } else if (insts.length > 0 && !expandedInstrumentId) {
          setExpandedInstrumentId(insts[0].id)
        }
        if (scens.length > 0) {
          setSelectedScenario(scens[0])
        }
      } catch (err: any) {
        setError(err.message || 'Could not load legal knowledge database')
      } finally {
        setLoading(false)
      }
    }
    loadAll()
  }, [initialInstrumentId])

  const filteredInstruments = useMemo(() => {
    return instruments.filter(inst => {
      const matchesCat = selectedCategory === 'ALL' || inst.category === selectedCategory
      const matchesSearch =
        !searchQuery.trim() ||
        inst.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inst.short_title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inst.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inst.provisions.some(p => p.heading.toLowerCase().includes(searchQuery.toLowerCase()) || p.section_or_article.toLowerCase().includes(searchQuery.toLowerCase()))
      return matchesCat && matchesSearch
    })
  }, [instruments, selectedCategory, searchQuery])

  const filteredScenarios = useMemo(() => {
    return scenarios.filter(sc => {
      return (
        !searchQuery.trim() ||
        sc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        sc.user_situation.toLowerCase().includes(searchQuery.toLowerCase()) ||
        sc.potentially_applicable_laws.some(l => l.law.toLowerCase().includes(searchQuery.toLowerCase()))
      )
    })
  }, [scenarios, searchQuery])

  const filteredGlossary = useMemo(() => {
    return glossary.filter(g => {
      return (
        !searchQuery.trim() ||
        g.term.toLowerCase().includes(searchQuery.toLowerCase()) ||
        g.plain_definition.toLowerCase().includes(searchQuery.toLowerCase()) ||
        g.statutory_reference.toLowerCase().includes(searchQuery.toLowerCase())
      )
    })
  }, [glossary, searchQuery])

  const selectedInst = useMemo(
    () => instruments.find(i => i.id === expandedInstrumentId) || instruments[0],
    [instruments, expandedInstrumentId]
  )
  const officialSourceUrl = getOfficialLegalSourceUrl(selectedInst?.official_source_url)

  return (
    <div className="page-container legal-knowledge-page">
      {/* Header */}
      <div className="legal-header">
        <div>
          <div className="kicker">
            <span className="kicker-line" />
            <Scale size={13} aria-hidden="true" />
            <span>Authoritative Digital Rights & Cyber Jurisprudence</span>
          </div>
          <h1>
            India Cyber Law &amp;<br />
            <em>Digital Rights Knowledge Center</em>
          </h1>
          <p>
            Plain-language explanations of Indian constitutional protections, cybersecurity statutes, data privacy rules, banking liability circulars, and citizen reporting procedures.
          </p>
        </div>

        {/* Legal Disclaimer Box */}
        <div className="legal-disclaimer-box">
          <Info size={18} className="text-blue flex-shrink-0" />
          <p>
            <strong>Educational Legal Resource:</strong> Citations verified against India Code, MeitY, and Supreme Court judgments. This portal provides public legal awareness and does not constitute individualized legal advice.
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="legal-tabs-bar">
        <button
          className={`legal-tab-btn ${activeTab === 'acts' ? 'active' : ''}`}
          onClick={() => setActiveTab('acts')}
        >
          <BookOpen size={16} />
          <span>Acts &amp; Cyber Laws Library</span>
        </button>
        <button
          className={`legal-tab-btn ${activeTab === 'scenarios' ? 'active' : ''}`}
          onClick={() => setActiveTab('scenarios')}
        >
          <HelpCircle size={16} />
          <span>Scenario-to-Law Matrix</span>
        </button>
        <button
          className={`legal-tab-btn ${activeTab === 'guides' ? 'active' : ''}`}
          onClick={() => setActiveTab('guides')}
        >
          <ShieldCheck size={16} />
          <span>Citizen Action Guides</span>
        </button>
        <button
          className={`legal-tab-btn ${activeTab === 'glossary' ? 'active' : ''}`}
          onClick={() => setActiveTab('glossary')}
        >
          <Layers size={16} />
          <span>Digital Rights Glossary</span>
        </button>
      </div>

      {/* Search and Category Filter */}
      <div className="feed-controls-strip">
        <div className="search-box">
          <Search size={16} aria-hidden="true" />
          <input
            type="text"
            placeholder="Search by Section (e.g. 66D), Act, Fundamental Right, or situation…"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button className="clear-search" onClick={() => setSearchQuery('')} aria-label="Clear search">
              ×
            </button>
          )}
        </div>

        {activeTab === 'acts' && (
          <div className="filter-group">
            <select
              value={selectedCategory}
              onChange={e => setSelectedCategory(e.target.value)}
              className="feed-select"
              aria-label="Filter legal category"
            >
              <option value="ALL">All Legal Categories</option>
              <option value="constitutional_rights">Constitutional Rights (Articles 14, 19, 21, 32)</option>
              <option value="cyber_crimes">Cyber Crimes (IT Act 2000 &amp; BNS 2023)</option>
              <option value="data_privacy">Data Privacy (DPDP Act 2023 &amp; Rules)</option>
              <option value="digital_payments">Digital Payments (RBI Master Directions)</option>
              <option value="telecom_evidence">Digital Evidence (BSA 2023 Sec 61 &amp; 63)</option>
            </select>
          </div>
        )}
      </div>

      {/* TAB 1: ACTS & RULES LIBRARY */}
      {activeTab === 'acts' && (
        <div className="legal-acts-layout">
          {/* Left Column: Acts List */}
          <div className="legal-acts-list-col">
            <div className="acts-list-stack">
              {filteredInstruments.map(inst => {
                const isSelected = expandedInstrumentId === inst.id
                return (
                  <button
                    key={inst.id}
                    className={`act-item-card ${isSelected ? 'selected' : ''}`}
                    onClick={() => setExpandedInstrumentId(inst.id)}
                  >
                    <div className="act-card-head">
                      <span className={`commencement-pill ${inst.commencement_status}`}>
                        {inst.commencement_status.replace('_', ' ').toUpperCase()}
                      </span>
                      <span className="year-pill">{inst.year}</span>
                    </div>
                    <strong>{inst.short_title}</strong>
                    <p>{inst.summary}</p>
                    <div className="act-card-foot">
                      <span>{inst.responsible_authority}</span>
                      <span className="provisions-count">{inst.provisions.length} Key Provisions</span>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Right Column: Structured Act Deep Dive */}
          <div className="legal-act-viewer-col">
            {selectedInst ? (
              <article className="panel act-full-view">
                <div className="act-view-header">
                  <div className="act-status-meta">
                    <span className={`commencement-pill ${selectedInst.commencement_status}`}>
                      {selectedInst.commencement_status.replace('_', ' ').toUpperCase()}
                    </span>
                    <span className="responsible-tag">Authority: {selectedInst.responsible_authority}</span>
                    <span className="verified-date">Verified: {new Date(selectedInst.last_verified_at).toLocaleDateString()}</span>
                  </div>
                  <h2>{selectedInst.title}</h2>
                  <p className="commencement-note">
                    <strong>Commencement Note:</strong> {selectedInst.commencement_note}
                  </p>
                </div>

                {/* Structured 8-Step Breakdown */}
                <div className="structured-legal-block">
                  <div className="legal-facet">
                    <h3>1. What It Is</h3>
                    <p>{selectedInst.summary}</p>
                  </div>

                  <div className="legal-facet">
                    <h3>2. Why It Matters Online</h3>
                    <p>{selectedInst.why_it_matters_online}</p>
                  </div>

                  <div className="legal-facet">
                    <h3>3. Who It Applies To</h3>
                    <p>{selectedInst.who_it_applies_to}</p>
                  </div>

                  <div className="legal-facet">
                    <h3>4. Relevant Key Provisions &amp; Sections</h3>
                    <div className="provisions-accordion">
                      {selectedInst.provisions.map((p, idx) => (
                        <div key={idx} className="provision-card">
                          <div className="provision-title-bar">
                            <span className="section-pill">{p.section_or_article}</span>
                            <strong>{p.heading}</strong>
                          </div>
                          <p className="plain-text">{p.plain_explanation}</p>
                          <div className="provision-meta-grid">
                            <div>
                              <span>Applicability:</span>
                              <p>{p.applicability_and_scope}</p>
                            </div>
                            <div>
                              <span>Penalties / Remedy:</span>
                              <p className="text-amber">{p.penalties_or_remedy}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="legal-facet">
                    <h3>5. Real-World Digital Scenarios</h3>
                    <ul className="scenarios-bullets">
                      {selectedInst.real_world_scenarios.map((sc, idx) => (
                        <li key={idx}>
                          <CheckCircle2 size={15} className="text-blue" />
                          <span>{sc}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="legal-facet">
                    <h3>6. Limits &amp; Exceptions</h3>
                    <ul className="limits-bullets">
                      {selectedInst.limits_and_exceptions.map((lim, idx) => (
                        <li key={idx}>
                          <AlertTriangle size={15} className="text-amber" />
                          <span>{lim}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="legal-facet">
                    <h3>7. What an Affected Citizen Can Do</h3>
                    <ul className="remedies-bullets">
                      {selectedInst.citizen_remedies.map((rem, idx) => (
                        <li key={idx}>
                          <ShieldCheck size={16} className="text-emerald" />
                          <span>{rem}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="legal-facet official-source-facet">
                    <h3>8. Authoritative Primary Source</h3>
                    <div className="source-link-box">
                      <p>View the official statutory gazette notification and legal text:</p>
                      {officialSourceUrl ? (
                        <a
                          href={officialSourceUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="primary-button"
                        >
                          <span>Open Primary Legal Source</span>
                          <ExternalLink size={14} />
                        </a>
                      ) : (
                        <p className="source-link-error" role="alert">
                          The official source link is missing or could not be validated.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </article>
            ) : (
              <div className="large-empty">Select an Act on the left to view its structured analysis.</div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: SCENARIO-TO-LAW MATRIX */}
      {activeTab === 'scenarios' && (
        <div className="legal-scenarios-layout">
          <div className="scenarios-list-col">
            {filteredScenarios.map(sc => {
              const isSelected = selectedScenario?.id === sc.id
              return (
                <button
                  key={sc.id}
                  className={`scenario-card ${isSelected ? 'selected' : ''}`}
                  onClick={() => setSelectedScenario(sc)}
                >
                  <div className="scenario-head">
                    <ShieldAlert size={18} className="text-amber" />
                    <strong>{sc.title}</strong>
                  </div>
                  <p className="scenario-user-q">"{sc.user_situation}"</p>
                  <div className="scenario-card-foot">
                    <span>{sc.potentially_applicable_laws.length} Applicable Laws Mapped</span>
                    <span className="helpline-badge">Helpline: {sc.helpline_number || '1930'}</span>
                  </div>
                </button>
              )
            })}
          </div>

          <div className="scenario-detail-col">
            {selectedScenario ? (
              <section className="panel scenario-inspector-panel">
                <div className="scenario-inspector-head">
                  <span className="eyebrow">Real-World Scenario Guidance</span>
                  <h2>{selectedScenario.title}</h2>
                  <div className="user-quote-box">
                    <strong>Citizen Situation:</strong>
                    <p>"{selectedScenario.user_situation}"</p>
                  </div>
                </div>

                <div className="scenario-section">
                  <h3>What Is Legally Happening</h3>
                  <p>{selectedScenario.what_is_happening}</p>
                </div>

                <div className="scenario-section">
                  <h3>Mapped Legal Provisions</h3>
                  <div className="mapped-laws-grid">
                    {selectedScenario.potentially_applicable_laws.map((law, idx) => (
                      <div key={idx} className="mapped-law-card">
                        <strong>{law.law}</strong>
                        <p>{law.relevance}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="scenario-section">
                  <h3>Immediate Citizen Action Steps</h3>
                  <ol className="action-steps-numbered">
                    {selectedScenario.immediate_citizen_actions.map((act, idx) => (
                      <li key={idx}>{act}</li>
                    ))}
                  </ol>
                </div>

                <div className="scenario-section">
                  <h3>Evidence Preservation Tips (BSA 2023)</h3>
                  <ul className="evidence-tips-list">
                    {selectedScenario.evidence_preservation_tips.map((tip, idx) => (
                      <li key={idx}>
                        <CheckCircle2 size={15} className="text-emerald" />
                        <span>{tip}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="scenario-reporting-box">
                  <div>
                    <strong>Official Reporting Channel:</strong>
                    <p>{selectedScenario.official_reporting_portal} {selectedScenario.helpline_number ? `(Helpline: ${selectedScenario.helpline_number})` : ''}</p>
                  </div>
                  <a
                    href={selectedScenario.portal_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="primary-button"
                  >
                    <span>Open Official Portal</span>
                    <ExternalLink size={14} />
                  </a>
                </div>

                <div className="legal-caveat-note">
                  <Info size={14} className="text-amber" />
                  <span>{selectedScenario.legal_caveat}</span>
                </div>
              </section>
            ) : (
              <div className="large-empty">Select a scenario to view applicable laws and action steps.</div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: CITIZEN ACTION GUIDES */}
      {activeTab === 'guides' && (
        <div className="citizen-guides-layout">
          {guides.map(guide => (
            <section key={guide.id} className="panel guide-full-card">
              <div className="guide-header">
                <span className={`urgency-pill ${guide.urgency_level}`}>
                  {guide.urgency_level === 'immediate_golden_hour' ? '⚡ IMMEDIATE GOLDEN HOUR ACTION' : 'PRIORITY PROCEDURE'}
                </span>
                <h2>{guide.title}</h2>
                <p className="guide-summary">{guide.summary}</p>
              </div>

              <div className="guide-steps-grid">
                {guide.step_by_step.map((st, idx) => (
                  <div key={idx} className="guide-step-card">
                    <strong>{st.step}</strong>
                    <p>{st.action}</p>
                  </div>
                ))}
              </div>

              <div className="dos-donts-grid">
                <div className="dos-box">
                  <h3>DOs (Crucial Steps)</h3>
                  <ul>
                    {guide.dos_and_donts.dos.map((d, idx) => (
                      <li key={idx}>
                        <CheckCircle2 size={15} className="text-emerald" />
                        <span>{d}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="donts-box">
                  <h3>DON'Ts (Avoid Common Mistakes)</h3>
                  <ul>
                    {guide.dos_and_donts.donts.map((d, idx) => (
                      <li key={idx}>
                        <AlertTriangle size={15} className="text-red" />
                        <span>{d}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="guide-channels-bar">
                <div className="channels-list">
                  {guide.official_channels.map((ch, idx) => (
                    <div key={idx} className="channel-chip">
                      <span>{ch.channel}:</span>
                      <strong>{ch.value}</strong>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          ))}
        </div>
      )}

      {/* TAB 4: GLOSSARY */}
      {activeTab === 'glossary' && (
        <div className="glossary-layout">
          <div className="glossary-grid">
            {filteredGlossary.map(item => (
              <div key={item.id} className="glossary-card">
                <h3>{item.term}</h3>
                <div className="plain-def-box">
                  <span>Plain Language:</span>
                  <p>{item.plain_definition}</p>
                </div>
                <div className="legal-def-box">
                  <span>Statutory Reference &amp; Context:</span>
                  <p>{item.legal_definition}</p>
                  <code>{item.statutory_reference}</code>
                </div>
                <div className="example-box">
                  <span>Real-World Example:</span>
                  <p>"{item.example}"</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
