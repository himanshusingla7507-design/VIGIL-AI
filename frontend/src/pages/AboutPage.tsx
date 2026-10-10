import { motion } from 'motion/react'
import {
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Cpu,
  Database,
  ExternalLink,
  EyeOff,
  Layers,
  LockKeyhole,
  Radio,
  Scale,
  SearchCheck,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'

const PIPELINE_STEPS = [
  { step: '01', title: 'URL Ingestion', desc: 'Syntax validation & scheme normalization' },
  { step: '02', title: 'Feature Extraction', desc: '64 lexical, structural & entropy signals' },
  { step: '03', title: 'ML Inference', desc: 'Calibrated tree ensemble probability' },
  { step: '04', title: 'Policy Engine', desc: 'Reputation, localhost & safe route constraints' },
  { step: '05', title: 'Actionable Verdict', desc: 'Risk score, diagnostic evidence & signals' },
]

export function AboutPage() {
  return (
    <div className="page-container about-page">
      <motion.div
        className="page-heading"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <div>
          <p className="eyebrow">Architecture & Security Specification</p>
          <h1>About VIGIL AI</h1>
          <p>A precision URL threat detection engine designed for zero-execution cyber protection and threat intelligence.</p>
        </div>
      </motion.div>

      {/* Technical Pipeline Flow */}
      <motion.section
        className="about-pipeline-section"
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.1 }}
      >
        <div className="pipeline-header">
          <Sparkles size={16} className="text-cyan" />
          <h2>Detection Pipeline Architecture</h2>
        </div>
        <div className="pipeline-flow-grid">
          {PIPELINE_STEPS.map((item, idx) => (
            <div className="pipeline-card" key={item.step}>
              <div className="pipeline-card-top">
                <span className="pipeline-step-num">{item.step}</span>
                {idx < PIPELINE_STEPS.length - 1 && (
                  <ArrowRight size={14} className="pipeline-connector-arrow" />
                )}
              </div>
              <h3 className="pipeline-card-title">{item.title}</h3>
              <p className="pipeline-card-desc">{item.desc}</p>
            </div>
          ))}
        </div>
      </motion.section>

      {/* Deep-Dive Grid */}
      <div className="about-grid">
        <motion.section
          className="panel about-block"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.15 }}
        >
          <div className="about-icon-wrap cyan">
            <SearchCheck size={22} />
          </div>
          <h2>What VIGIL Analyzes</h2>
          <p>
            VIGIL inspects URL anatomy: hostname composition, path depth, character entropy, query parameters, hex encoding, non-standard ports, punycode IDN markers, and brand token distributions.
          </p>
          <ul className="about-list">
            <li><CheckCircle2 size={13} /> Lexical & structural token analysis</li>
            <li><CheckCircle2 size={13} /> Shannon entropy on domain & path strings</li>
            <li><CheckCircle2 size={13} /> Multi-level subdomain depth & TLD reputation</li>
          </ul>
        </motion.section>

        <motion.section
          className="panel about-block"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
        >
          <div className="about-icon-wrap green">
            <ShieldCheck size={22} />
          </div>
          <h2>Classification Hierarchy</h2>
          <p>
            Scans produce three unambiguous verdict categories backed by calibrated probability distributions:
          </p>
          <div className="verdict-explain-grid">
            <div className="verdict-explain-item safe">
              <strong>SAFE</strong>
              <span>Low-risk characteristics consistent with verified routes.</span>
            </div>
            <div className="verdict-explain-item warning">
              <strong>SUSPICIOUS</strong>
              <span>Anomalous structure or entropy requiring manual review.</span>
            </div>
            <div className="verdict-explain-item danger">
              <strong>PHISHING</strong>
              <span>High-risk credential harvesting or impersonation patterns.</span>
            </div>
          </div>
        </motion.section>

        <motion.section
          className="panel about-block"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.25 }}
        >
          <div className="about-icon-wrap indigo">
            <LockKeyhole size={22} />
          </div>
          <h2>Zero-Execution Privacy</h2>
          <p>
            Submitted URLs are analyzed purely as static strings. VIGIL never establishes a browser connection to target hosts, never downloads malicious binaries, never executes untrusted JavaScript, and stores zero session cookies.
          </p>
          <ul className="about-list">
            <li><CheckCircle2 size={13} /> Air-gapped static lexical inference</li>
            <li><CheckCircle2 size={13} /> SHA-256 deduplicated query privacy</li>
            <li><CheckCircle2 size={13} /> Zero drive-by download or exploit exposure</li>
          </ul>
        </motion.section>

        <motion.section
          className="panel about-block"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
        >
          <div className="about-icon-wrap violet">
            <Radio size={22} />
          </div>
          <h2>Global Threat Intelligence</h2>
          <p>
            VIGIL's backend continuously ingests active threat feeds from verified global repositories including URLhaus, Phishing.Database, OpenPhish, PhishTank, and CERT-In national advisories with real-time SSE streaming.
          </p>
          <ul className="about-list">
            <li><CheckCircle2 size={13} /> Continuous background ingestion pipeline</li>
            <li><CheckCircle2 size={13} /> Server-Sent Events (SSE) live push</li>
            <li><CheckCircle2 size={13} /> Real provenance & provider timestamp retention</li>
          </ul>
        </motion.section>
      </div>

      {/* Scope and Limitations Banner */}
      <motion.div
        className="about-disclaimer-panel"
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.35 }}
      >
        <div className="disclaimer-header">
          <BookOpen size={18} />
          <h3>Operational Scope & Limitations</h3>
        </div>
        <p>
          URL-only lexical analysis inspects structure prior to navigation. While highly effective at identifying deceptive patterns, it cannot verify dynamic server-side behavior, compromised legitimate websites, or ephemeral cloaking pages without full content inspection. Always use VIGIL alongside multi-layered endpoint security and human judgment.
        </p>
      </motion.div>
    </div>
  )
}
