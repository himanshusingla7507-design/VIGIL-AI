import { useEffect, useState } from 'react'
import { motion } from 'motion/react'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  Fingerprint,
  LoaderCircle,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
import type { ModelInfo, ScanAnalytics, ScanResult, Verdict } from '../types'
import { api } from '../services/api'
import { AnimatedNumber } from '../components/AnimatedNumber'
import { StatusBadge } from '../components/StatusBadge'

const verdicts: Verdict[] = ['SAFE', 'SUSPICIOUS', 'PHISHING']

function displayCount(value: number | null | undefined) {
  return typeof value === 'number' ? value.toLocaleString() : 'Unavailable'
}

function displayPercent(value: number | null | undefined) {
  return typeof value === 'number' ? `${(value * 100).toFixed(2)}%` : 'Unavailable'
}

function displayDate(value: string | null | undefined) {
  if (!value) return 'Unavailable'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toLocaleString()
}

function displayUrl(item: ScanResult) {
  return item.url || item.normalized_url || 'Unknown URL'
}

export function AnalysisPage() {
  const [history, setHistory] = useState<ScanResult[]>([])
  const [model, setModel] = useState<ModelInfo | null>(null)
  const [analytics, setAnalytics] = useState<ScanAnalytics | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    let active = true
    const refresh = refreshKey > 0
    if (refresh) setRefreshing(true)
    else setLoading(true)
    setError('')

    Promise.all([api.getHistory(), api.getModelInfo(), api.getScanAnalytics()])
      .then(([recent, modelInfo, scanAnalytics]) => {
        if (!active) return
        setHistory(recent)
        setModel(modelInfo)
        setAnalytics(scanAnalytics)
      })
      .catch(reason => {
        if (active) setError(reason instanceof Error ? reason.message : 'Analysis data could not be loaded.')
      })
      .finally(() => {
        if (!active) return
        setLoading(false)
        setRefreshing(false)
      })

    return () => {
      active = false
    }
  }, [refreshKey])

  if (loading) {
    return (
      <div className="center-state">
        <LoaderCircle className="spin" size={32} />
        <span>Loading model intelligence and scan analytics...</span>
      </div>
    )
  }

  if (error || !model || !analytics) {
    return (
      <div className="page-container analysis-page">
        <div className="error-panel" role="alert">
          <ShieldAlert size={20} />
          <span>{error || 'The backend returned incomplete analysis data.'}</span>
          <button className="analysis-refresh" onClick={() => setRefreshKey(value => value + 1)}>
            <RefreshCw size={15} /> Retry
          </button>
        </div>
      </div>
    )
  }

  const training = model.training
  const evaluation = model.evaluation
  const maxDailyScans = Math.max(1, ...analytics.trend.daily.map(day => day.total))
  const lastSuccessfulLoad = displayDate(model.last_successful_load_at)
  const fullChecksum = model.artifact_sha256

  return (
    <div className="page-container analysis-page">
      <motion.div
        className="page-heading analysis-heading"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <div>
          <p className="eyebrow">Cybersecurity Telemetry & Analytics</p>
          <h1>System Analysis</h1>
          <p>Artifact-backed model details, recorded runtime usage, and offline evaluation—kept as separate evidence.</p>
        </div>
        <button
          className="analysis-refresh"
          onClick={() => setRefreshKey(value => value + 1)}
          disabled={refreshing}
          aria-label="Refresh analysis data"
        >
          <RefreshCw size={16} className={refreshing ? 'analysis-refreshing' : undefined} />
          {refreshing ? 'Refreshing' : 'Refresh data'}
        </button>
      </motion.div>

      <motion.section
        className="panel analysis-panel analysis-section"
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.05 }}
        aria-labelledby="model-intelligence-title"
      >
        <div className="section-heading">
          <div>
            <p className="eyebrow">Active artifact · {model.model_load_status || 'status unavailable'}</p>
            <h2 id="model-intelligence-title">Model Intelligence</h2>
          </div>
          <span className={`status-pill ${model.model_load_status === 'loaded' ? 'green' : ''}`}>
            {model.model_load_status === 'loaded' ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
            {model.model_load_status === 'loaded' ? 'Loaded' : 'Status unavailable'}
          </span>
        </div>

        <div className="analysis-fact-grid">
          <div className="analysis-fact-card primary-fact">
            <Database size={18} />
            <span title="Training samples are the train split only; calibration, validation and test rows are separate.">Training samples</span>
            <strong>
              {training?.sample_count == null ? 'Unavailable' : <AnimatedNumber value={training.sample_count} />}
            </strong>
          </div>
          <div className="analysis-fact-card">
            <ShieldCheck size={18} className="text-safe" />
            <span title="Legitimate URLs in the active model's training split.">Legitimate training</span>
            <strong>{displayCount(training?.legitimate_samples)}</strong>
          </div>
          <div className="analysis-fact-card">
            <ShieldX size={18} className="text-danger" />
            <span title="Phishing URLs in the active model's training split.">Phishing training</span>
            <strong>{displayCount(training?.phishing_samples)}</strong>
          </div>
          <div className="analysis-fact-card">
            <Fingerprint size={18} className="text-cyan" />
            <span title="Unique registered domains among URLs in the training split.">Training domains</span>
            <strong>{displayCount(training?.registered_domains)}</strong>
          </div>
        </div>

        <div className="analysis-spec-grid">
          <div className="analysis-spec">
            <span>Active version</span>
            <strong>{model.model_version || 'Unavailable'}</strong>
          </div>
          <div className="analysis-spec">
            <span>Artifact path</span>
            <code>{model.model_path || 'Unavailable'}</code>
          </div>
          <div className="analysis-spec">
            <span>Dataset rows <small title="All rows in the source dataset across train, calibration, validation and test splits.">ⓘ</small></span>
            <strong>{displayCount(training?.dataset_rows)}</strong>
          </div>
          <div className="analysis-spec">
            <span>Calibration split <small title="Held-out rows used to fit the probability calibrator.">ⓘ</small></span>
            <strong>{displayCount(training?.calibration_samples)}</strong>
          </div>
          <div className="analysis-spec">
            <span>Validation split <small title="Held-out rows used for threshold selection and validation metrics.">ⓘ</small></span>
            <strong>{displayCount(training?.validation_samples)}</strong>
          </div>
          <div className="analysis-spec">
            <span>Test split <small title="Held-out evaluation rows; not used for threshold selection.">ⓘ</small></span>
            <strong>{displayCount(training?.test_samples)}</strong>
          </div>
          <div className="analysis-spec">
            <span>Unique training URLs</span>
            <strong>{displayCount(training?.unique_urls)}</strong>
          </div>
          <div className="analysis-spec">
            <span>Model features</span>
            <strong>{displayCount(model.feature_count)}</strong>
          </div>
          <div className="analysis-spec feature-names-spec">
            <span>Exact feature names</span>
            {model.features?.length ? (
              <details>
                <summary>{model.features.length} active features</summary>
                <ul>{model.features.map(feature => <li key={feature}><code>{feature}</code></li>)}</ul>
              </details>
            ) : <strong>Unavailable</strong>}
          </div>
          <div className="analysis-spec">
            <span>Architecture</span>
            <strong>{model.model_architecture || model.model_type || 'Unavailable'}</strong>
          </div>
          <div className="analysis-spec">
            <span>Calibration method</span>
            <strong>{model.calibration_method || 'Unavailable'}</strong>
          </div>
          <div className="analysis-spec">
            <span>Last successful load</span>
            <strong>{lastSuccessfulLoad}</strong>
          </div>
          <div className="analysis-spec checksum-spec">
            <span>Active artifact SHA-256</span>
            {fullChecksum ? (
              <details>
                <summary><code>{fullChecksum.slice(0, 16)}…</code> <small>Show full checksum</small></summary>
                <code className="analysis-full-checksum">{fullChecksum}</code>
              </details>
            ) : <strong>Unavailable</strong>}
          </div>
          <div className="analysis-spec data-source-spec">
            <span>Training data provenance</span>
            <code>{training?.dataset_path || 'Unavailable'}</code>
            <strong>Source status: {training?.dataset_source_status || 'Unavailable'}</strong>
            <small title="SHA-256 checksum of the source dataset recorded with the active model.">
              Dataset SHA-256: {training?.dataset_sha256 || 'Unavailable'}
            </small>
          </div>
        </div>
        <p className="analysis-footnote">
          Dataset rows are not the training count. Train, calibration, validation, and test samples are distinct splits.
          Missing artifact metadata is shown as unavailable; no display fallback is used.
        </p>
      </motion.section>

      <motion.section
        className="panel analysis-panel analysis-section"
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.1 }}
        aria-labelledby="runtime-analytics-title"
      >
        <div className="section-heading">
          <div>
            <p className="eyebrow">Persistent scan history · {analytics.source}</p>
            <h2 id="runtime-analytics-title">Runtime Scan Analytics</h2>
          </div>
          <span className="total-badge"><AnimatedNumber value={analytics.total_scans} /> recorded events</span>
        </div>

        <div className="analysis-verdict-grid">
          {verdicts.map(verdict => {
            const count = analytics.verdict_counts[verdict]
            const percent = analytics.verdict_percentages[verdict]
            const Icon = verdict === 'SAFE' ? ShieldCheck : verdict === 'SUSPICIOUS' ? ShieldAlert : ShieldX
            return (
              <div className={`analysis-verdict-card ${verdict.toLowerCase()}`} key={verdict}>
                <Icon size={18} />
                <span>{verdict === 'SAFE' ? 'Safe' : verdict === 'SUSPICIOUS' ? 'Suspicious' : 'Phishing'}</span>
                <strong><AnimatedNumber value={count} /></strong>
                <small>{percent == null ? '— of recorded scans' : `${percent.toFixed(1)}% of recorded scans`}</small>
              </div>
            )
          })}
        </div>

        <div className="analysis-runtime-grid">
          <div className="analysis-subpanel">
            <div className="analysis-subheading">
              <div>
                <h3>Scans over time</h3>
                <p>Daily recorded events · UTC · {analytics.trend.start_date} to {analytics.trend.end_date}</p>
              </div>
              <Activity size={17} />
            </div>
            {analytics.trend.daily.length === 0 ? (
              <div className="panel-empty">No trend data is available for this range.</div>
            ) : (
              <div className="analysis-trend-chart" aria-label="Seven-day scan activity by verdict">
                {analytics.trend.daily.map(day => (
                  <div className="analysis-trend-column" key={day.date} title={`${day.date}: ${day.total} scans`}>
                    <strong>{day.total}</strong>
                    <div className="analysis-trend-bar">
                      {verdicts.map(verdict => {
                        const amount = day.verdict_counts[verdict]
                        const height = amount ? (amount / maxDailyScans) * 100 : 0
                        return (
                          <motion.span
                            key={verdict}
                            className={`trend-${verdict.toLowerCase()}`}
                            initial={{ height: 0 }}
                            animate={{ height: `${height}%` }}
                            transition={{ duration: 0.5, ease: 'easeOut' }}
                          />
                        )
                      })}
                    </div>
                    <small>{new Date(`${day.date}T00:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })}</small>
                  </div>
                ))}
              </div>
            )}
            <div className="analysis-chart-legend">
              {verdicts.map(verdict => <span key={verdict} className={`legend-${verdict.toLowerCase()}`}>{verdict.toLowerCase()}</span>)}
            </div>
          </div>

          <div className="analysis-subpanel">
            <div className="analysis-subheading">
              <div>
                <h3>Recent scan activity</h3>
                <p>Latest events from scan history</p>
              </div>
              <Clock3 size={17} />
            </div>
            {history.length === 0 ? (
              <div className="panel-empty">No scans have been recorded yet.</div>
            ) : (
              <ul className="analysis-recent-list">
                {history.slice(0, 8).map(item => (
                  <li key={item.id ?? item.request_id}>
                    <StatusBadge verdict={item.label} />
                    <span className="analysis-recent-url" title={displayUrl(item)}>{displayUrl(item)}</span>
                    <time dateTime={item.scanned_at}>{displayDate(item.scanned_at)}</time>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
        <p className="analysis-footnote">
          Counts and percentages are aggregated over all recorded database events. Recent activity is a separate, latest-100 view.
          These verdict proportions describe usage and are not model accuracy.
        </p>
      </motion.section>

      <motion.section
        className="panel analysis-panel analysis-section"
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.15 }}
        aria-labelledby="model-evaluation-title"
      >
        <div className="section-heading">
          <div>
            <p className="eyebrow">Offline labeled holdout · Not runtime telemetry</p>
            <h2 id="model-evaluation-title">Model Evaluation</h2>
          </div>
          <span className="total-badge">
            {evaluation ? `${displayCount(evaluation.sample_count)} test samples` : 'Unavailable'}
          </span>
        </div>

        {!evaluation || evaluation.sample_count == null ? (
          <div className="panel-empty">No verifiable labeled evaluation results are recorded for the active model.</div>
        ) : (
          <>
            <div className="analysis-eval-grid">
              {[
                ['Precision', evaluation.precision, 'Share of predicted phishing samples that are phishing.'],
                ['Recall', evaluation.recall, 'Share of labeled phishing samples detected.'],
                ['False-positive rate', evaluation.false_positive_rate, 'Share of legitimate test samples marked phishing.'],
                ['False-negative rate', evaluation.false_negative_rate, 'Share of phishing test samples missed.'],
                ['F1 score', evaluation.f1_score, 'Harmonic mean of precision and recall.'],
                ['ROC-AUC', evaluation.roc_auc, 'Area under the receiver operating characteristic curve.'],
                ['PR-AUC', evaluation.pr_auc, 'Area under the precision-recall curve. Not recorded in the active metadata.'],
              ].map(([label, value, explanation]) => (
                <div className="analysis-eval-card" key={String(label)} title={String(explanation)}>
                  <span>{label}</span>
                  <strong>{displayPercent(typeof value === 'number' ? value : null)}</strong>
                </div>
              ))}
            </div>
            {evaluation.confusion_matrix && (
              <div className="analysis-confusion">
                <h3>Confusion matrix <small>(actual rows × predicted columns)</small></h3>
                <table>
                  <thead><tr><th>Actual / predicted</th><th>Legitimate</th><th>Phishing</th></tr></thead>
                  <tbody>
                    <tr><th>Legitimate</th><td>{displayCount(evaluation.confusion_matrix[0]?.[0])}</td><td>{displayCount(evaluation.confusion_matrix[0]?.[1])}</td></tr>
                    <tr><th>Phishing</th><td>{displayCount(evaluation.confusion_matrix[1]?.[0])}</td><td>{displayCount(evaluation.confusion_matrix[1]?.[1])}</td></tr>
                  </tbody>
                </table>
              </div>
            )}
            <div className="analysis-evaluation-notes">
              <p><strong>Evaluation dataset:</strong> {evaluation.dataset_path || 'Unavailable'}</p>
              <p><strong>Evaluation date:</strong> {displayDate(evaluation.evaluated_at)}</p>
              {evaluation.limitations.map(note => <p key={note}><AlertTriangle size={14} /> {note}</p>)}
            </div>
          </>
        )}
      </motion.section>
    </div>
  )
}
