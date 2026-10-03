import type { Verdict } from '../types'
import { ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react'

export function StatusBadge({ verdict }: { verdict: Verdict }) {
  const Icon = verdict === 'SAFE' ? ShieldCheck : verdict === 'SUSPICIOUS' ? ShieldAlert : ShieldX
  return <span className={`status-badge ${verdict.toLowerCase()}`}><Icon size={15} aria-hidden="true" />{verdict}</span>
}
