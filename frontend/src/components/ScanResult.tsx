import { useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Clipboard,
  Cpu,
  ExternalLink,
  Fingerprint,
  Info,
  Layers,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
import type { ScanResult } from '../types'
import { formatProbability } from '../utils'
import { StatusBadge } from './StatusBadge'
import { RiskMeter } from './RiskMeter'
import { EvidenceList } from './EvidenceList'
import { FeatureGrid } from './FeatureGrid'

export function ScanResultCard({ result }: { result: ScanResult }) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard?.writeText(result.url)
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      // clipboard fallback
    }
  }

  const description =
    result.label === 'SAFE'
      ? 'Low-risk lexical and structural characteristics detected. Consistent with verified legitimate routing patterns.'
      : result.label === 'SUSPICIOUS'
      ? 'Anomalous patterns, high lexical entropy, or unusual structural traits detected. Review evidence before navigating.'
      : 'Critical phishing indicators identified. High probability of credential harvesting, brand spoofing, or social engineering.'

  return (
    <motion.article
      className={`result-card ${result.label.toLowerCase()}`}
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: 'easeOut' }}
    >
      <div className="result-card__header">
        <div className="result-card__summary-block">
          <div className="result-tagline-row">
            <span className="eyebrow">Verdict Classification</span>
            <span className="result-engine-tag">Engine v{result.model_version}</span>
          </div>
          <div className="result-badge-row">
            <StatusBadge verdict={result.label} />
          </div>
          <p className="result-summary">{description}</p>
        </div>

        <div className="result-probability-card">
          <span className="prob-label">
            {result.probability_source === 'model' ? 'Model Probability' : 'Effective Probability'}
          </span>
          <strong className="prob-value">{formatProbability(result.effective_probability)}</strong>
          {result.reputation?.applied ? (
            <small className="prob-subtext">Raw model inference: {formatProbability(result.model_probability)}</small>
          ) : (
            <small className="prob-subtext">Calibrated risk score: {result.risk_score}/100</small>
          )}
        </div>
      </div>

      <RiskMeter score={result.risk_score} verdict={result.label} />

      <div className="result-url-panel">
        <div className="url-display-wrap">
          <span className="eyebrow">Analyzed Target URL</span>
          <code className="analyzed-url-string">{result.url}</code>
        </div>
        <button
          className={`copy-url-btn ${copied ? 'copied' : ''}`}
          onClick={copy}
          aria-label="Copy analyzed URL"
          title={copied ? 'Copied to clipboard' : 'Copy URL to clipboard'}
        >
          {copied ? (
            <>
              <Check size={14} />
              <span>Copied</span>
            </>
          ) : (
            <>
              <Clipboard size={14} />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Evidence Section */}
      <section className="result-section">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Diagnostic Signals</p>
            <h2>Contributing Evidence</h2>
          </div>
          <span className="signal-count-badge">
            {result.evidence.length} signal{result.evidence.length === 1 ? '' : 's'} evaluated
          </span>
        </div>
        <EvidenceList evidence={result.evidence} />
      </section>

      {/* Collapsible Technical Feature Analysis */}
      <button
        className="technical-toggle"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
      >
        <div className="toggle-left">
          <Layers size={16} />
          <span>{open ? 'Hide Technical Feature Matrix' : 'Inspect Technical Feature Matrix'}</span>
        </div>
        <ChevronDown size={18} className={`toggle-chevron ${open ? 'rotate' : ''}`} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.section
            className="technical-section"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: 'easeOut' }}
          >
            <FeatureGrid features={result.features} />
            <div className="technical-meta-grid">
              <div className="tech-meta-item">
                <Cpu size={14} />
                <span>Model Version: <code>{result.model_version}</code></span>
              </div>
              <div className="tech-meta-item">
                <Fingerprint size={14} />
                <span>Artifact: <code>{result.model_fingerprint?.slice(0, 12)}</code></span>
              </div>
              <div className="tech-meta-item">
                <Info size={14} />
                <span>Request ID: <code>{result.request_id}</code></span>
              </div>
              <div className="tech-meta-item">
                <ShieldCheck size={14} />
                <span>Timestamp: <code>{new Date(result.scanned_at).toLocaleTimeString()}</code></span>
              </div>
            </div>
          </motion.section>
        )}
      </AnimatePresence>

      <div className="result-footer">
        <div className="footer-pill">
          <ExternalLink size={13} aria-hidden="true" />
          <span>Zero-Execution: URL string evaluated without fetching or executing remote DOM</span>
        </div>
      </div>
    </motion.article>
  )
}
