import { motion, useReducedMotion } from 'motion/react'

export function RiskMeter({ score, verdict }: { score: number; verdict: string }) {
  const reduced = useReducedMotion()
  return <div className={`risk-meter ${verdict.toLowerCase()}`} aria-label={`Risk score ${score} out of 100`}>
    <div className="risk-meter__top"><span>Risk score</span><strong>{score}<small>/100</small></strong></div>
    <div className="risk-meter__track"><motion.div className="risk-meter__fill" initial={reduced ? { width: `${score}%` } : { width: 0 }} animate={{ width: `${score}%` }} transition={{ duration: .65, ease: 'easeOut' }} /></div>
    <div className="risk-meter__scale"><span>Low risk</span><span>High risk</span></div>
  </div>
}
