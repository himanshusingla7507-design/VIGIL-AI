import { useEffect, useState } from 'react'
import { motion } from 'motion/react'
import { api } from './services/api'
import type { ScanResult } from './types'
import { Shell, type Page } from './components/Shell'
import { ScanPage } from './pages/ScanPage'
import { HistoryPage } from './pages/HistoryPage'
import { AnalysisPage } from './pages/AnalysisPage'
import { AboutPage } from './pages/AboutPage'

export default function App() { const [page, setPage] = useState<Page>('scan'); const [result, setResult] = useState<ScanResult | null>(null); const [health, setHealth] = useState<boolean | null>(null)
  useEffect(() => { api.getHealth().then(value => setHealth(value.status === 'ok' && value.model_loaded)).catch(() => setHealth(false)) }, [])
  const content = page === 'scan' ? <ScanPage result={result} onResult={setResult} /> : page === 'history' ? <HistoryPage /> : page === 'analysis' ? <AnalysisPage /> : <AboutPage />
  return <Shell page={page} onNavigate={setPage} health={health}><motion.div key={page} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .2 }}>{content}</motion.div></Shell>
}
