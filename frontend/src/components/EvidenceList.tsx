import { motion } from 'motion/react'
import { AlertTriangle, CheckCircle2, Info } from 'lucide-react'
import type { Evidence } from '../types'

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  return <div className="evidence-list">{evidence.map((item, index) => {
    const Icon = item.severity === 'danger' ? AlertTriangle : item.severity === 'warning' ? AlertTriangle : item.polarity === 'neutral' ? Info : CheckCircle2
    return <motion.div className={`evidence-item ${item.severity}`} key={`${item.id}-${index}`} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * .04 }}>
      <Icon size={17} aria-hidden="true" /><div><strong>{item.title}</strong><p>{item.detail}</p></div>
    </motion.div>
  })}</div>
}
