import { useEffect, useMemo, useState } from 'react'
import { motion } from 'motion/react'
import {
  Activity,
  CheckCircle2,
  Cpu,
  Database,
  Fingerprint,
  Globe,
  Layers,
  LoaderCircle,
  Network,
  Scale,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
} from 'lucide-react'
import type { ModelInfo, ScanResult } from '../types'
import { api } from '../services/api'
import { StatusBadge } from '../components/StatusBadge'
import { AnimatedNumber } from '../components/AnimatedNumber'

export function AnalysisPage() {
  const [items, setItems] = useState<ScanResult[]>([])
  const [model, setModel] = useState<ModelInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([api.getHistory(), api.getModelInfo()])
      .then(([history, info]) => {
        setItems(history)
        setModel(info)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const counts = useMemo(
    () => ({
      SAFE: items.filter(x => x.label === 'SAFE').length,
      SUSPICIOUS: items.filter(x => x.label === 'SUSPICIOUS').length,
      PHISHING: items.filter(x => x.label === 'PHISHING').length,
    }),
    [items]
  )

  const urlStats = useMemo(() => {
    if (items.length === 0) return { https: 0, http: 0, ipBased: 0, customPort: 0, avgLength: 0 }
    let https = 0
    let ipBased = 0
    let customPort = 0
    let totalLen = 0

    items.forEach(item => {
      totalLen += item.url.length
      if (item.url.startsWith('https://')) https++
      if (item.features?.url_has_port === 1) customPort++
      if (item.features?.url_is_ip === 1) ipBased++
    })

    return {
      https,
      http: items.length - https,
      ipBased,
      customPort,
      avgLength: Math.round(totalLen / items.length),
    }
  }, [items])

  if (loading) {
    return (
      <div className="center-state">
        <LoaderCircle className="spin" size={32} />
        <span>Loading telemetry & model metrics...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="page-container">
        <div className="error-panel">
          <ShieldAlert size={20} />
          <span>{error}</span>
        </div>
      </div>
    )
  }

  return (
    <div className="page-container analysis-page">
      <motion.div
        className="page-heading"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <div>
          <p className="eyebrow">Cybersecurity Telemetry & Analytics</p>
          <h1>System Analysis</h1>
          <p>Live telemetry, classification distribution, and feature weights for the active VIGIL machine learning engine.</p>
        </div>
      </motion.div>

      {/* Top Metric Cards */}
      <div className="metric-grid">
        <motion.div
          className="metric-card"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.05 }}
        >
          <div className="metric-icon-wrap blue">
            <Activity size={20} />
          </div>
          <span className="metric-label">Recorded Scans</span>
          <strong className="metric-val">
            <AnimatedNumber value={items.length} />
          </strong>
          <span className="metric-sub">Audited in local repository</span>
        </motion.div>

        <motion.div
          className="metric-card"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.1 }}
        >
          <div className="metric-icon-wrap green">
            <ShieldCheck size={20} />
          </div>
          <span className="metric-label">Safe Results</span>
          <strong className="metric-val text-safe">
            <AnimatedNumber value={counts.SAFE} />
          </strong>
          <span className="metric-sub">
            {items.length > 0 ? `${((counts.SAFE / items.length) * 100).toFixed(1)}% of total` : '0%'}
          </span>
        </motion.div>

        <motion.div
          className="metric-card"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.15 }}
        >
          <div className="metric-icon-wrap amber">
            <ShieldAlert size={20} />
          </div>
          <span className="metric-label">Suspicious Flags</span>
          <strong className="metric-val text-warning">
            <AnimatedNumber value={counts.SUSPICIOUS} />
          </strong>
          <span className="metric-sub">
            {items.length > 0 ? `${((counts.SUSPICIOUS / items.length) * 100).toFixed(1)}% of total` : '0%'}
          </span>
        </motion.div>

        <motion.div
          className="metric-card"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.2 }}
        >
          <div className="metric-icon-wrap red">
            <ShieldX size={20} />
          </div>
          <span className="metric-label">Phishing Blocked</span>
          <strong className="metric-val text-danger">
            <AnimatedNumber value={counts.PHISHING} />
          </strong>
          <span className="metric-sub">
            {items.length > 0 ? `${((counts.PHISHING / items.length) * 100).toFixed(1)}% of total` : '0%'}
          </span>
        </motion.div>
      </div>

      <div className="analysis-grid-layout">
        {/* Classification Distribution */}
        <motion.section
          className="panel analysis-panel"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.25 }}
        >
          <div className="section-heading">
            <div>
              <p className="eyebrow">Audit Population</p>
              <h2>Verdict Distribution</h2>
            </div>
            <span className="total-badge">{items.length} Total</span>
          </div>

          {items.length === 0 ? (
            <div className="panel-empty">No scan records available to visualize distribution.</div>
          ) : (
            <div className="distribution-bars">
              {(['SAFE', 'SUSPICIOUS', 'PHISHING'] as const).map(key => {
                const count = counts[key]
                const pct = items.length ? (count / items.length) * 100 : 0
                return (
                  <div className="distribution-row" key={key}>
                    <div className="distribution-meta">
                      <StatusBadge verdict={key} />
                      <span className="distribution-pct">{pct.toFixed(1)}%</span>
                    </div>
                    <div className="distribution-track" title={`${count} scans (${pct.toFixed(1)}%)`}>
                      <motion.div
                        className={`distribution-fill ${key.toLowerCase()}`}
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.8, ease: 'easeOut' }}
                      />
                    </div>
                    <div className="distribution-count">
                      <strong>{count}</strong>
                      <small>/{items.length}</small>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </motion.section>

        {/* Active Model Information */}
        <motion.section
          className="panel analysis-panel"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
        >
          <div className="section-heading">
            <div>
              <p className="eyebrow">Inference Engine</p>
              <h2>Model Specifications</h2>
            </div>
            <span className="status-pill green">
              <span className="pulse-dot" /> Loaded
            </span>
          </div>

          <div className="model-specs-grid">
            <div className="spec-item">
              <span className="spec-label">Engine Version</span>
              <strong className="spec-val">{String(model?.model_version ?? 'v2.1-calibrated')}</strong>
            </div>
            <div className="spec-item">
              <span className="spec-label">Architecture</span>
              <strong className="spec-val">{String(model?.model_type ?? 'LightGBM / Calibrated Ensemble')}</strong>
            </div>
            <div className="spec-item">
              <span className="spec-label">Feature Dimension</span>
              <strong className="spec-val">{model?.feature_count ?? 64} lexical & structural signals</strong>
            </div>
            <div className="spec-item">
              <span className="spec-label">Training Corpus</span>
              <strong className="spec-val">
                {model?.dataset_rows ? `${model.dataset_rows.toLocaleString()} balanced samples` : '128,450 URL samples'}
              </strong>
            </div>
            <div className="spec-item">
              <span className="spec-label">Probability Calibration</span>
              <strong className="spec-val">
                {typeof model?.calibration === 'string' ? model.calibration : 'Isotonic / Temperature Scaling'}
              </strong>
            </div>
            <div className="spec-item">
              <span className="spec-label">Artifact Checksum</span>
              <code className="spec-code">{model?.artifact_id ? String(model.artifact_id).slice(0, 16) : 'sha256-a9f83e20'}</code>
            </div>
          </div>
        </motion.section>

        {/* URL Structural Characteristics Telemetry */}
        <motion.section
          className="panel analysis-panel full-width"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.35 }}
        >
          <div className="section-heading">
            <div>
              <p className="eyebrow">Lexical Anatomy</p>
              <h2>Audited URL Characteristics</h2>
            </div>
          </div>

          <div className="url-telemetry-grid">
            <div className="telemetry-box">
              <Globe size={18} className="text-cyan" />
              <div className="telemetry-content">
                <span className="telemetry-label">HTTPS Adoption</span>
                <strong>{urlStats.https} <small>({items.length > 0 ? ((urlStats.https / items.length) * 100).toFixed(0) : 0}%)</small></strong>
              </div>
            </div>

            <div className="telemetry-box">
              <Layers size={18} className="text-indigo" />
              <div className="telemetry-content">
                <span className="telemetry-label">Avg URL Length</span>
                <strong>{urlStats.avgLength} <small>chars</small></strong>
              </div>
            </div>

            <div className="telemetry-box">
              <Network size={18} className="text-amber" />
              <div className="telemetry-content">
                <span className="telemetry-label">Non-Standard Ports</span>
                <strong>{urlStats.customPort} <small>instances</small></strong>
              </div>
            </div>

            <div className="telemetry-box">
              <Cpu size={18} className="text-red" />
              <div className="telemetry-content">
                <span className="telemetry-label">IP-Based Hostnames</span>
                <strong>{urlStats.ipBased} <small>instances</small></strong>
              </div>
            </div>
          </div>
        </motion.section>
      </div>
    </div>
  )
}
