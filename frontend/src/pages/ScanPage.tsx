import { FormEvent, useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  ArrowRight,
  CheckCircle2,
  Cpu,
  Layers,
  LoaderCircle,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import type { ScanResult } from '../types'
import { api } from '../services/api'
import { validateUrl } from '../utils'
import { ScanResultCard } from '../components/ScanResult'

const SAMPLE_URLS = [
  { label: 'Legitimate Service', url: 'https://fast.com/' },
  { label: 'Suspicious Target', url: 'https://paypal-login.example.com/verify-account' },
  { label: 'Phishing Pattern', url: 'http://microsoft-security.example.com/login' },
]

const SCAN_STAGES = [
  { id: 1, label: 'Validating URL syntax & structure', icon: Search },
  { id: 2, label: 'Extracting lexical & structural features', icon: Layers },
  { id: 3, label: 'Evaluating ML model risk signals', icon: Cpu },
  { id: 4, label: 'Synthesizing decision policy & verdict', icon: ShieldCheck },
]

export function ScanPage({
  result,
  onResult,
  initialUrl,
}: {
  result: ScanResult | null
  onResult: (result: ScanResult) => void
  initialUrl?: string
}) {
  const [value, setValue] = useState(initialUrl || '')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [currentStage, setCurrentStage] = useState(0)

  const triggerScan = async (urlToScan: string) => {
    const trimmed = urlToScan.trim()
    const message = validateUrl(trimmed)
    if (message) {
      setError(message)
      return
    }
    setError('')
    setLoading(true)
    setCurrentStage(1)

    // Stage progression interval during live request
    const stageTimer = setInterval(() => {
      setCurrentStage(prev => (prev < 4 ? prev + 1 : prev))
    }, 180)

    try {
      const scanRes = await api.scanUrl(trimmed)
      clearInterval(stageTimer)
      setCurrentStage(4)
      onResult(scanRes)
    } catch (err) {
      clearInterval(stageTimer)
      setError(err instanceof Error ? err.message : 'Analysis failed. Try again.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (initialUrl && initialUrl !== value) {
      setValue(initialUrl)
      triggerScan(initialUrl)
    }
  }, [initialUrl])

  const submit = async (event?: FormEvent) => {
    event?.preventDefault()
    await triggerScan(value)
  }

  const handleSampleClick = (sampleUrl: string) => {
    setValue(sampleUrl)
    setError('')
    triggerScan(sampleUrl)
  }

  return (
    <div className="page-container scan-page">
      {/* Hero Section */}
      <motion.section
        className="scan-hero"
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, ease: 'easeOut' }}
      >
        <div className="hero-kicker">
          <span className="hero-kicker-dot" />
          <Sparkles size={13} aria-hidden="true" />
          <span>ZERO-EXECUTION THREAT INTELLIGENCE</span>
        </div>
        <h1 className="hero-title">
          Analyze a URL.<br />
          <span className="hero-gradient-text">Understand the risk.</span>
        </h1>
        <p className="hero-desc">
          VIGIL inspects URL anatomy, lexical signals, and machine-learning risk patterns before navigation.
        </p>
      </motion.section>

      {/* URL Scanner Panel */}
      <motion.form
        className={`scan-form ${error ? 'has-error' : ''} ${loading ? 'is-scanning' : ''}`}
        onSubmit={submit}
        animate={error ? { x: [0, -6, 6, -3, 3, 0] } : { x: 0 }}
        transition={{ duration: 0.28 }}
        aria-label="Analyze a URL"
      >
        <div className="scan-form-header">
          <label htmlFor="url-input">URL to analyze</label>
          <span className="scan-hotkey-badge">Press ↵ Enter to scan</span>
        </div>

        <div className="input-row">
          <div className="input-icon-wrap">
            <ScanLine size={19} aria-hidden="true" />
          </div>
          <input
            id="url-input"
            type="url"
            inputMode="url"
            value={value}
            onChange={e => {
              setValue(e.target.value)
              setError('')
            }}
            placeholder="https://verify-banking.example.com/login"
            disabled={loading}
            autoComplete="url"
            spellCheck="false"
            aria-describedby="url-hint"
          />
          <button
            className="primary-scan-button"
            type="submit"
            disabled={loading || !value.trim()}
          >
            {loading ? (
              <>
                <LoaderCircle className="spin" size={17} />
                <span>Analyzing</span>
              </>
            ) : (
              <>
                <span>Scan URL</span>
                <ArrowRight size={17} />
              </>
            )}
          </button>
        </div>

        {error && (
          <motion.p
            className="form-error"
            role="alert"
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <ShieldAlert size={15} />
            <span>{error}</span>
          </motion.p>
        )}

        {/* Quick Test Chips */}
        <div className="quick-samples">
          <span className="quick-samples-label">Quick test vectors:</span>
          {SAMPLE_URLS.map(sample => (
            <button
              key={sample.url}
              type="button"
              className="sample-chip"
              onClick={() => handleSampleClick(sample.url)}
              disabled={loading}
            >
              {sample.label}
            </button>
          ))}
        </div>

        <p id="url-hint" className="form-hint">
          HTTP & HTTPS URLs accepted · Analysis executes strictly on URL string without browser execution or page fetching
        </p>
      </motion.form>

      {/* Live Scan Execution Stages Animation */}
      <AnimatePresence>
        {loading && (
          <motion.div
            className="scan-execution-panel"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25 }}
          >
            <div className="execution-header">
              <div className="execution-spinner">
                <LoaderCircle className="spin" size={16} />
              </div>
              <span className="execution-title">Pipeline Active: Inspecting URL Signals</span>
            </div>
            <div className="execution-stages">
              {SCAN_STAGES.map(stage => {
                const isPassed = currentStage > stage.id
                const isCurrent = currentStage === stage.id
                const Icon = stage.icon

                return (
                  <div
                    key={stage.id}
                    className={`stage-item ${isPassed ? 'passed' : isCurrent ? 'current' : 'pending'}`}
                  >
                    <div className="stage-status-icon">
                      {isPassed ? (
                        <CheckCircle2 size={15} className="text-safe" />
                      ) : isCurrent ? (
                        <div className="stage-pulse-dot" />
                      ) : (
                        <span className="stage-num">{stage.id}</span>
                      )}
                    </div>
                    <Icon size={15} className="stage-icon" />
                    <span className="stage-label">{stage.label}</span>
                  </div>
                )
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Result Section */}
      {result ? (
        <ScanResultCard result={result} />
      ) : !loading ? (
        <motion.div
          className="scan-empty-state"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.15 }}
        >
          <div className="empty-state-shield">
            <ScanLine size={32} />
          </div>
          <h3>Awaiting target URL</h3>
          <p>Submit a URL or select a sample vector to generate a calibrated risk decomposition.</p>
        </motion.div>
      ) : null}
    </div>
  )
}
