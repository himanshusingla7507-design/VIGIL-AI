import { useEffect, useState } from 'react'
import { Clock3, LoaderCircle, Trash2 } from 'lucide-react'
import type { ScanResult } from '../types'
import { api } from '../services/api'
import { formatDate, formatProbability } from '../utils'
import { StatusBadge } from '../components/StatusBadge'
import { ScanResultCard } from '../components/ScanResult'

export function HistoryPage() { const [items, setItems] = useState<ScanResult[]>([]); const [selected, setSelected] = useState<ScanResult | null>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState('')
  const load = () => { setLoading(true); api.getHistory().then(setItems).catch(e => setError(e.message)).finally(() => setLoading(false)) }; useEffect(load, [])
  const clear = async () => { await api.clearHistory(); setItems([]); setSelected(null) }
  return <div className="page-container"><div className="page-heading"><div><p className="eyebrow">Investigation record</p><h1>Scan history</h1><p>Review analyses returned by the VIGIL service.</p></div>{items.length > 0 && <button className="quiet-button danger-button" onClick={clear}><Trash2 size={15} />Clear history</button>}</div>{loading ? <div className="center-state"><LoaderCircle className="spin" />Loading history</div> : error ? <div className="error-panel">{error}</div> : items.length === 0 ? <div className="large-empty"><Clock3 size={28} /><h2>No scans yet</h2><p>Start by analyzing a URL from the Scan page.</p></div> : <div className="history-layout"><div className="history-list" aria-label="Previous scans">{items.map(item => <button className={`history-item ${selected?.id === item.id ? 'selected' : ''}`} key={item.id} onClick={() => setSelected(item)}><div className="history-item__top"><StatusBadge verdict={item.label} /><time>{formatDate(item.scanned_at)}</time></div><code>{item.url}</code><div className="history-item__meta"><span>Risk {item.risk_score}/100</span><span>{formatProbability(item.probability)}</span></div></button>)}</div><div className="history-detail">{selected ? <ScanResultCard result={selected} /> : <div className="large-empty compact"><p>Select an investigation record to inspect its evidence.</p></div>}</div></div>}</div>
}
