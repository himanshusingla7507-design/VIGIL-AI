import { useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { ChevronDown, Clipboard, Check, ExternalLink } from 'lucide-react'
import type { ScanResult } from '../types'
import { formatProbability } from '../utils'
import { StatusBadge } from './StatusBadge'
import { RiskMeter } from './RiskMeter'
import { EvidenceList } from './EvidenceList'
import { FeatureGrid } from './FeatureGrid'

export function ScanResultCard({ result }: { result: ScanResult }) {
  const [open, setOpen] = useState(false); const [copied, setCopied] = useState(false)
  const copy = async () => { await navigator.clipboard?.writeText(result.url); setCopied(true); window.setTimeout(() => setCopied(false), 1400) }
  const description = result.label === 'SAFE' ? 'Low-risk URL characteristics detected.' : result.label === 'SUSPICIOUS' ? 'Review the evidence before proceeding.' : 'High-risk URL characteristics detected.'
  return <motion.article className={`result-card ${result.label.toLowerCase()}`} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
    <div className="result-card__header"><div><p className="eyebrow">Classification</p><StatusBadge verdict={result.label} /><p className="result-summary">{description}</p></div><div className="probability"><span>{result.probability_source === 'verified_exact_host_policy' ? 'Effective probability' : 'Model probability'}</span><strong>{formatProbability(result.probability)}</strong>{result.probability_source === 'verified_exact_host_policy' && <small>Raw model: {formatProbability(result.model_probability)}</small>}</div></div>
    <RiskMeter score={result.risk_score} verdict={result.label} />
    <div className="result-url"><div><span className="eyebrow">Analyzed URL</span><code>{result.url}</code></div><button className="icon-button" onClick={copy} aria-label="Copy analyzed URL" title="Copy URL">{copied ? <Check size={16} /> : <Clipboard size={16} />}</button></div>
    <section className="result-section"><div className="section-heading"><div><p className="eyebrow">Why this result?</p><h2>Evidence</h2></div><span className="muted">{result.evidence.length} signal{result.evidence.length === 1 ? '' : 's'}</span></div><EvidenceList evidence={result.evidence} /></section>
    <button className="technical-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>{open ? 'Hide technical analysis' : 'Show technical analysis'}<ChevronDown size={17} className={open ? 'rotate' : ''} /></button>
    <AnimatePresence>{open && <motion.section className="technical-section" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}><FeatureGrid features={result.features} /><div className="technical-meta"><span>Model <code>{result.model_version}</code></span><span>Request <code>{result.request_id}</code></span><span>Artifact <code>{result.model_fingerprint.slice(0, 12)}</code></span><span>Scanned <code>{new Date(result.scanned_at).toLocaleString()}</code></span></div></motion.section>}</AnimatePresence>
    <div className="result-footer"><span>VIGIL analyzes URL structure only.</span><span className="footer-note"><ExternalLink size={13} aria-hidden="true" />Never opens the submitted URL</span></div>
  </motion.article>
}
