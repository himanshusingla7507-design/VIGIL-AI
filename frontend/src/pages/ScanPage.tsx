import { FormEvent, useState } from 'react'
import { motion } from 'motion/react'
import { ArrowRight, LoaderCircle, ScanLine } from 'lucide-react'
import type { ScanResult } from '../types'
import { api } from '../services/api'
import { validateUrl } from '../utils'
import { ScanResultCard } from '../components/ScanResult'

export function ScanPage({ result, onResult }: { result: ScanResult | null; onResult: (result: ScanResult) => void }) {
  const [value, setValue] = useState(''); const [error, setError] = useState(''); const [loading, setLoading] = useState(false)
  const submit = async (event?: FormEvent) => { event?.preventDefault(); const message = validateUrl(value); if (message) { setError(message); return }; setError(''); setLoading(true); try { onResult(await api.scanUrl(value.trim())) } catch (err) { setError(err instanceof Error ? err.message : 'Analysis failed. Try again.') } finally { setLoading(false) } }
  return <div className="page-container scan-page"><section className="scan-intro"><div className="kicker"><span className="kicker-line" />URL intelligence</div><h1>Analyze a URL<br /><em>before you trust it.</em></h1><p>VIGIL examines URL structure and security indicators to identify phishing risk. Fast, transparent, and built for careful decisions.</p></section>
    <motion.form className={`scan-form ${error ? 'has-error' : ''}`} onSubmit={submit} animate={error ? { x: [0, -4, 4, 0] } : { x: 0 }} aria-label="Analyze a URL"><label htmlFor="url-input">URL to analyze</label><div className="input-row"><ScanLine size={19} aria-hidden="true" /><input id="url-input" type="text" inputMode="url" value={value} onChange={e => { setValue(e.target.value); setError('') }} placeholder="https://example.com" disabled={loading} autoComplete="url" /><button className="primary-button" type="submit" disabled={loading || !value.trim()}>{loading ? <><LoaderCircle className="spin" size={17} />Analyzing</> : <>Scan URL <ArrowRight size={17} /> </>}</button></div>{error && <p className="form-error" role="alert">{error}</p>}<p className="form-hint">Press Enter to scan · HTTP and HTTPS URLs accepted</p></motion.form>
    {loading && <div className="loading-strip" role="status"><span className="loading-pulse" />Analyzing URL structure<span className="loading-dots">...</span></div>}
    {result ? <ScanResultCard result={result} /> : <div className="scan-empty"><div className="empty-rule" /><p>Paste a URL above to begin a focused risk analysis.</p></div>}
  </div>
}
