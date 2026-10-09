import { useEffect, useRef, useState } from 'react'
import { motion } from 'motion/react'
import {
  AlertTriangle,
  Camera,
  CheckCircle2,
  ExternalLink,
  LoaderCircle,
  QrCode,
  ShieldAlert,
  ShieldCheck,
  StopCircle,
  Upload,
} from 'lucide-react'
import { BrowserQRCodeReader } from '@zxing/browser'
import type { IScannerControls } from '@zxing/browser'
import { EvidenceList } from '../components/EvidenceList'
import { RiskMeter } from '../components/RiskMeter'
import { api } from '../services/api'
import type { ScanResult } from '../types'
import { formatProbability } from '../utils'
import { classifyQrPayload } from '../utils/qrPayload'
import type { QrPayload } from '../utils/qrPayload'

const MAX_IMAGE_BYTES = 10 * 1024 * 1024
const MAX_IMAGE_PIXELS = 25_000_000

type ScannerState = 'idle' | 'starting' | 'scanning' | 'decoding' | 'analyzing' | 'complete' | 'error'

function cameraErrorMessage(error: unknown): string {
  const name = error instanceof DOMException ? error.name : ''
  if (name === 'NotAllowedError' || name === 'SecurityError') {
    return 'Camera access was denied. Allow camera access in your browser settings, then try again.'
  }
  if (name === 'NotFoundError' || name === 'DevicesNotFoundError') {
    return 'No camera was found. Connect a camera or upload a QR image instead.'
  }
  if (name === 'NotReadableError' || name === 'TrackStartError') {
    return 'The camera is busy in another app. Close it there and try again.'
  }
  if (name === 'OverconstrainedError') {
    return 'No compatible camera is available. Try another device or upload a QR image.'
  }
  return 'The camera could not be started. Check browser permissions or upload a QR image instead.'
}

function verdictText(result: ScanResult): string {
  if (result.label === 'SAFE') return 'LOW RISK'
  if (result.label === 'SUSPICIOUS') return 'SUSPICIOUS'
  return 'PHISHING / HIGH RISK'
}

function payloadType(payload: QrPayload): string {
  switch (payload.kind) {
    case 'url': return 'Web destination'
    case 'wifi': return 'Wi-Fi configuration'
    case 'email': return 'Email'
    case 'telephone': return 'Telephone number'
    case 'payment': return 'UPI payment request'
    case 'text': return 'Plain text'
    case 'unsupported': return 'Unsupported link or content'
  }
}

export function QrScannerPage() {
  const [state, setState] = useState<ScannerState>('idle')
  const [error, setError] = useState('')
  const [payload, setPayload] = useState<QrPayload | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const videoRef = useRef<HTMLVideoElement>(null)
  const controlsRef = useRef<IScannerControls | null>(null)
  const mediaStreamRef = useRef<MediaStream | null>(null)
  const sessionRef = useRef(0)
  const decodedInSessionRef = useRef(false)
  const mountedRef = useRef(true)

  const stopCamera = () => {
    const video = videoRef.current
    const attachedStream = video?.srcObject
    if (attachedStream && typeof attachedStream !== 'string' && 'getTracks' in attachedStream) {
      mediaStreamRef.current = attachedStream
    }
    controlsRef.current?.stop()
    controlsRef.current = null
    mediaStreamRef.current?.getTracks().forEach(track => track.stop())
    mediaStreamRef.current = null
    if (video) video.srcObject = null
  }

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      sessionRef.current += 1
      stopCamera()
    }
  }, [])

  const analyzePayload = async (raw: string, session: number, controls?: IScannerControls) => {
    if (!mountedRef.current || session !== sessionRef.current || decodedInSessionRef.current) return
    decodedInSessionRef.current = true
    controls?.stop()
    stopCamera()
    setError('')
    setResult(null)

    const classified = classifyQrPayload(raw)
    setPayload(classified)
    if (classified.kind !== 'url') {
      setState(classified.kind === 'unsupported' ? 'error' : 'complete')
      if (classified.kind === 'unsupported') setError(classified.reason)
      return
    }

    setState('analyzing')
    try {
      const scanResult = await api.scanUrl(classified.url)
      if (!mountedRef.current || session !== sessionRef.current) return
      setResult(scanResult)
      setState('complete')
    } catch (scanError) {
      if (!mountedRef.current || session !== sessionRef.current) return
      setError(scanError instanceof Error ? scanError.message : 'URL analysis failed. Try again.')
      setState('error')
    }
  }

  const startCamera = async () => {
    if (!navigator.mediaDevices?.getUserMedia || !window.isSecureContext) {
      setError('Camera scanning requires a secure context (HTTPS or localhost). You can upload a QR image instead.')
      setState('error')
      return
    }
    stopCamera()
    const session = sessionRef.current + 1
    sessionRef.current = session
    decodedInSessionRef.current = false
    setPayload(null)
    setResult(null)
    setError('')
    setState('starting')

    const reader = new BrowserQRCodeReader()
    try {
      const video = videoRef.current
      if (!video) throw new Error('Camera preview is unavailable.')
      const controls = await reader.decodeFromVideoDevice(undefined, video, (decoded, _decodeError, callbackControls) => {
        if (decoded) void analyzePayload(decoded.getText(), session, callbackControls)
      })
      const attachedStream = video.srcObject
      if (attachedStream && typeof attachedStream !== 'string' && 'getTracks' in attachedStream) {
        mediaStreamRef.current = attachedStream
      }
      if (!mountedRef.current || session !== sessionRef.current || decodedInSessionRef.current) {
        controls.stop()
        return
      }
      controlsRef.current = controls
      setState('scanning')
    } catch (cameraError) {
      if (!mountedRef.current || session !== sessionRef.current) return
      stopCamera()
      setError(cameraErrorMessage(cameraError))
      setState('error')
    }
  }

  const stopScanning = () => {
    sessionRef.current += 1
    decodedInSessionRef.current = true
    stopCamera()
    setState(payload ? 'complete' : 'idle')
  }

  const resetScanner = () => {
    sessionRef.current += 1
    decodedInSessionRef.current = false
    stopCamera()
    setPayload(null)
    setResult(null)
    setError('')
    setState('idle')
  }

  const handleImageUpload = async (file?: File) => {
    if (!file) return
    sessionRef.current += 1
    const session = sessionRef.current
    decodedInSessionRef.current = false
    stopCamera()
    setPayload(null)
    setResult(null)
    setError('')

    if (!file.type.startsWith('image/')) {
      setError('Choose an image file containing a QR code.')
      setState('error')
      return
    }
    if (file.size > MAX_IMAGE_BYTES) {
      setError('Image is larger than 10 MB. Choose a smaller QR image.')
      setState('error')
      return
    }

    setState('decoding')
    const image = new Image()
    let objectUrl: string | null = null
    try {
      objectUrl = URL.createObjectURL(file)
      image.src = objectUrl
      await image.decode()
      if (image.naturalWidth * image.naturalHeight > MAX_IMAGE_PIXELS) {
        throw new Error('Image dimensions are too large. Choose an image under 25 megapixels.')
      }
      const reader = new BrowserQRCodeReader()
      const decoded = await reader.decodeFromImageElement(image)
      await analyzePayload(decoded.getText(), session)
    } catch (imageError) {
      if (!mountedRef.current || session !== sessionRef.current) return
      setError(imageError instanceof Error && imageError.message.includes('megapixels')
        ? imageError.message
        : 'No readable QR code was found in this image. Try a clearer image or use the camera.')
      setState('error')
    } finally {
      if (objectUrl) URL.revokeObjectURL(objectUrl)
      image.src = ''
    }
  }

  const retryAnalysis = () => {
    if (payload?.kind !== 'url') return
    const session = sessionRef.current + 1
    sessionRef.current = session
    decodedInSessionRef.current = false
    void analyzePayload(payload.raw, session)
  }

  const busy = state === 'starting' || state === 'decoding' || state === 'analyzing'
  const cameraActive = state === 'starting' || state === 'scanning'

  return (
    <div className="page-container qr-page">
      <motion.header
        className="qr-hero"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <div className="hero-kicker">
          <span className="hero-kicker-dot" />
          <QrCode size={14} aria-hidden="true" />
          <span>ZERO-EXECUTION QR INSPECTION</span>
        </div>
        <h1 className="hero-title">
          Scan the code.<br />
          <span className="hero-gradient-text">Inspect the destination.</span>
        </h1>
        <p className="hero-desc">
          Decode QR content on your device and analyze web destinations with VIGIL’s existing risk engine.
          Nothing opens automatically.
        </p>
      </motion.header>

      <section className="qr-workspace" aria-label="QR code scanner">
        <div className={`qr-camera-panel ${cameraActive ? 'is-active' : ''}`}>
          <div className={`qr-target-frame ${cameraActive ? 'is-active' : ''} ${state === 'complete' ? 'is-detected' : ''}`}>
            <video
              ref={videoRef}
              className={`qr-camera-video ${cameraActive ? 'visible' : ''}`}
              muted
              playsInline
              autoPlay
              aria-label="Live QR scanner camera preview"
            />
            <div className="qr-target-corners" aria-hidden="true">
              <span className="qr-corner corner-top-left" />
              <span className="qr-corner corner-top-right" />
              <span className="qr-corner corner-bottom-left" />
              <span className="qr-corner corner-bottom-right" />
            </div>
            {!cameraActive && (
              <div className="qr-camera-placeholder">
                {state === 'decoding' ? (
                  <LoaderCircle size={30} className="qr-state-spinner" />
                ) : state === 'complete' ? (
                  <CheckCircle2 size={30} />
                ) : (
                  <QrCode size={34} />
                )}
                <strong>
                  {state === 'decoding' ? 'Reading QR image…'
                    : state === 'analyzing' ? 'Analyzing destination…'
                    : state === 'complete' ? 'QR content detected'
                    : state === 'error' ? 'Scanner needs attention'
                    : 'Camera preview'}
                </strong>
                <span>Keep the code centered and in focus</span>
              </div>
            )}
            {cameraActive && (
              <div className="qr-camera-caption">
                <span className="qr-live-indicator" />
                {state === 'starting' ? 'Requesting camera access' : 'Camera live · Point at a QR code'}
              </div>
            )}
          </div>

          <div className="qr-controls">
            {cameraActive ? (
              <button className="qr-secondary-button" type="button" onClick={stopScanning}>
                <StopCircle size={17} />
                <span>Stop camera</span>
              </button>
            ) : (
              <button className="qr-primary-button" type="button" onClick={() => void startCamera()} disabled={busy}>
                <Camera size={17} />
                <span>{state === 'complete' ? 'Scan another code' : 'Start camera'}</span>
              </button>
            )}
            <label className={`qr-secondary-button qr-upload-button ${busy ? 'disabled' : ''}`}>
              <Upload size={17} />
              <span>Upload QR image</span>
              <input
                type="file"
                accept="image/*"
                aria-label="Upload QR image"
                disabled={busy}
                onChange={event => {
                  void handleImageUpload(event.currentTarget.files?.[0])
                  event.currentTarget.value = ''
                }}
              />
            </label>
            {payload && (
              <button className="qr-text-button" type="button" onClick={resetScanner}>
                Clear result
              </button>
            )}
          </div>

          {error && (
            <motion.div className="qr-error-message" role="alert" initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
              <ShieldAlert size={17} />
              <span>{error}</span>
              {payload?.kind === 'url' && state === 'error' && (
                <button type="button" onClick={retryAnalysis}>Retry analysis</button>
              )}
            </motion.div>
          )}
        </div>

        <aside className="qr-safety-panel">
          <div className="qr-safety-icon"><ShieldCheck size={18} /></div>
          <div>
            <strong>Decoded locally. Never auto-opened.</strong>
            <p>VIGIL reads the QR contents on this device. Only HTTP(S) destinations are sent to the existing URL analysis service.</p>
          </div>
        </aside>
      </section>

      {payload && (
        <motion.section
          className="qr-result-panel"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.28 }}
          aria-live="polite"
        >
          <div className="qr-result-heading">
            <div>
              <span className="eyebrow">Decoded content</span>
              <h2>{payloadType(payload)}</h2>
            </div>
            <span className={`qr-state-badge ${result ? `verdict-${result.label.toLowerCase()}` : ''}`}>
              {state === 'analyzing' ? 'ANALYZING'
                : payload.kind === 'url' && result ? verdictText(result)
                : payload.kind === 'unsupported' ? 'UNSUPPORTED'
                : payload.kind === 'url' && state === 'error' ? 'ANALYSIS FAILED'
                : 'NOT RISK-RATED'}
            </span>
          </div>

          {payload.kind === 'url' && (
            <>
              <div className="qr-destination-card">
                <span className="eyebrow">Destination URL</span>
                <code>{payload.url}</code>
                <span className="qr-hostname">Hostname: {new URL(payload.url).hostname}</span>
              </div>
              {result ? (
                <>
                  <div className={`qr-verdict-card verdict-${result.label.toLowerCase()}`}>
                    <div>
                      <span className="eyebrow">VIGIL model verdict</span>
                      <strong>{verdictText(result)}</strong>
                    </div>
                    <div className="qr-risk-stats">
                      <span>Risk score <b>{result.risk_score}/100</b></span>
                      <span>Model probability <b>{formatProbability(result.model_probability)}</b></span>
                    </div>
                  </div>
                  <RiskMeter score={result.risk_score} verdict={result.label} />
                  <div className="qr-evidence">
                    <div className="section-heading">
                      <div><p className="eyebrow">Diagnostic signals</p><h3>Evidence from the analysis</h3></div>
                      <span className="signal-count-badge">{result.evidence.length} signals</span>
                    </div>
                    <EvidenceList evidence={result.evidence} />
                  </div>
                  {result.label !== 'SAFE' && (
                    <div className="qr-open-warning" role="alert">
                      <AlertTriangle size={20} />
                      <div>
                        <strong>VIGIL flags this destination as {result.label === 'PHISHING' ? 'high risk' : 'suspicious'}.</strong>
                        <p>Do not enter passwords, payment details, or verification codes. Review the evidence before deciding whether to continue.</p>
                      </div>
                    </div>
                  )}
                  <div className="qr-open-row">
                    <p>Risk analysis is an estimate, not a guarantee that a website is safe.</p>
                    <a className="qr-open-button" href={payload.url} target="_blank" rel="noopener noreferrer">
                      Open destination <ExternalLink size={15} />
                    </a>
                  </div>
                </>
              ) : state === 'analyzing' ? (
                <div className="qr-analysis-progress"><LoaderCircle size={18} className="qr-state-spinner" /> Checking with VIGIL’s URL risk engine…</div>
              ) : state === 'error' ? (
                <div className="qr-analysis-progress"><AlertTriangle size={18} /> Analysis did not complete. Retry when the service is available.</div>
              ) : null}
            </>
          )}

          {payload.kind !== 'url' && (
            <NonUrlDetails payload={payload} />
          )}
        </motion.section>
      )}
    </div>
  )
}

function NonUrlDetails({ payload }: { payload: Exclude<QrPayload, { kind: 'url' }> }) {
  if (payload.kind === 'unsupported') {
    return <p className="qr-payload-notice">{payload.reason} This content was not treated as safe.</p>
  }
  if (payload.kind === 'wifi') {
    return (
      <>
        <dl className="qr-details-grid">
          <Detail label="Network name (SSID)" value={payload.ssid} />
          <Detail label="Security" value={payload.security} />
          <Detail label="Hidden network" value={payload.hidden ? 'Yes' : 'No'} />
          <Detail label="Password in QR" value={payload.passwordIncluded ? 'Included (not displayed)' : 'Not included'} />
        </dl>
        <p className="qr-payload-notice">This Wi-Fi configuration was decoded, not verified. Confirm the network before connecting; VIGIL does not join networks.</p>
      </>
    )
  }
  if (payload.kind === 'payment') {
    return (
      <>
        <dl className="qr-details-grid">
          <Detail label="Recipient / VPA" value={payload.recipient} />
          <Detail label="Recipient name" value={payload.recipientName} />
          <Detail label="Amount" value={payload.amount === 'Not specified' ? payload.amount : `${payload.amount} ${payload.currency}`} />
          <Detail label="Payment note" value={payload.note} />
        </dl>
        <div className="qr-open-warning" role="alert">
          <AlertTriangle size={20} />
          <div><strong>Verify payment details before paying.</strong><p>QR decoding does not verify the recipient. Confirm the name, payment address, and amount in your trusted payment app before authorizing a transaction.</p></div>
        </div>
      </>
    )
  }
  if (payload.kind === 'email') {
    return (
      <>
        <dl className="qr-details-grid">
          <Detail label="Recipient" value={payload.recipient} />
          <Detail label="Subject" value={payload.subject} />
        </dl>
        <p className="qr-payload-notice">This email content was decoded but not verified. VIGIL does not compose or send messages.</p>
      </>
    )
  }
  if (payload.kind === 'telephone') {
    return (
      <>
        <dl className="qr-details-grid"><Detail label="Telephone number" value={payload.number} /></dl>
        <p className="qr-payload-notice">This number was decoded but not verified. VIGIL does not place calls.</p>
      </>
    )
  }
  return (
    <>
      <div className="qr-destination-card"><span className="eyebrow">Text content</span><code>{payload.raw}</code></div>
      <p className="qr-payload-notice">This content is not a web destination. VIGIL’s URL model did not analyze it, so it is not classified as safe.</p>
    </>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>
}
