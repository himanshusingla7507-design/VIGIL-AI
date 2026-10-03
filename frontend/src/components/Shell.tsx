import { Activity, BookOpen, History, ScanLine, Shield } from 'lucide-react'
import type { ReactNode } from 'react'

export type Page = 'scan' | 'history' | 'analysis' | 'about'
export function Shell({ page, onNavigate, health, children }: { page: Page; onNavigate: (page: Page) => void; health: boolean | null; children: ReactNode }) {
  const links: [Page, string, typeof ScanLine][] = [['scan', 'Scan', ScanLine], ['history', 'History', History], ['analysis', 'Analysis', Activity], ['about', 'About', BookOpen]]
  return <div className="app-shell"><header className="topbar"><button className="brand" onClick={() => onNavigate('scan')} aria-label="VIGIL scan home"><span className="brand-mark"><Shield size={18} /></span><span>VIGIL</span></button><nav aria-label="Primary navigation">{links.map(([key, label, Icon]) => <button className={page === key ? 'active' : ''} key={key} onClick={() => onNavigate(key)}><Icon size={16} />{label}</button>)}</nav><div className="service-state" aria-label={`Backend ${health === true ? 'online' : health === false ? 'offline' : 'checking'}`}><span className={`state-dot ${health === true ? 'online' : health === false ? 'offline' : ''}`} />{health === true ? 'Service online' : health === false ? 'Service offline' : 'Checking service'}</div></header><main>{children}</main><footer className="site-footer"><span>VIGIL · URL risk analysis</span><span>URL-only analysis · No pages opened</span></footer></div>
}
