import { useEffect, useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import {
  ArrowUpDown,
  Clock3,
  Filter,
  LoaderCircle,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Trash2,
  X,
} from 'lucide-react'
import type { ScanResult, Verdict } from '../types'
import { api } from '../services/api'
import { formatDate, formatProbability } from '../utils'
import { StatusBadge } from '../components/StatusBadge'
import { ScanResultCard } from '../components/ScanResult'
import { ConfirmModal } from '../components/ConfirmModal'

type SortOption = 'newest' | 'oldest' | 'highest-risk' | 'lowest-risk'

export function HistoryPage() {
  const [items, setItems] = useState<ScanResult[]>([])
  const [selected, setSelected] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [filterVerdict, setFilterVerdict] = useState<string>('ALL')
  const [sortOption, setSortOption] = useState<SortOption>('newest')
  const [showClearModal, setShowClearModal] = useState(false)

  const load = () => {
    setLoading(true)
    api.getHistory()
      .then(data => {
        setItems(data)
        if (data.length > 0 && !selected) {
          setSelected(data[0])
        }
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const handleConfirmClear = async () => {
    try {
      await api.clearHistory()
      setItems([])
      setSelected(null)
      setShowClearModal(false)
    } catch (e: any) {
      setError(e.message || 'Failed to clear history')
    }
  }

  const filteredAndSortedItems = useMemo(() => {
    let result = items.filter(item => {
      const matchesSearch = item.url.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesFilter = filterVerdict === 'ALL' || item.label === filterVerdict
      return matchesSearch && matchesFilter
    })

    result.sort((a, b) => {
      if (sortOption === 'newest') {
        return new Date(b.scanned_at).getTime() - new Date(a.scanned_at).getTime()
      }
      if (sortOption === 'oldest') {
        return new Date(a.scanned_at).getTime() - new Date(b.scanned_at).getTime()
      }
      if (sortOption === 'highest-risk') {
        return b.risk_score - a.risk_score
      }
      if (sortOption === 'lowest-risk') {
        return a.risk_score - b.risk_score
      }
      return 0
    })

    return result
  }, [items, searchTerm, filterVerdict, sortOption])

  // Maintain valid selected record if items change
  useEffect(() => {
    if (filteredAndSortedItems.length > 0) {
      const stillPresent = filteredAndSortedItems.find(
        i => (i.id && i.id === selected?.id) || (i.request_id && i.request_id === selected?.request_id)
      )
      if (!stillPresent) {
        setSelected(filteredAndSortedItems[0])
      }
    } else {
      setSelected(null)
    }
  }, [filteredAndSortedItems])

  return (
    <div className="page-container history-page">
      <motion.div
        className="page-heading"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <div>
          <p className="eyebrow">Audit & Investigation Trail</p>
          <h1>Scan History</h1>
          <p>Review and audit previous URL analyses evaluated by the VIGIL detection engine.</p>
        </div>
        {items.length > 0 && (
          <button
            className="clear-history-button"
            onClick={() => setShowClearModal(true)}
            aria-label="Clear scan history"
          >
            <Trash2 size={15} />
            <span>Clear History</span>
          </button>
        )}
      </motion.div>

      {/* Filter and Search Bar */}
      {items.length > 0 && (
        <motion.div
          className="history-controls"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <div className="history-search-wrap">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              placeholder="Search audited URLs..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="history-search-input"
            />
            {searchTerm && (
              <button
                className="search-clear-btn"
                onClick={() => setSearchTerm('')}
                aria-label="Clear search"
              >
                <X size={14} />
              </button>
            )}
          </div>

          <div className="history-filters-row">
            <div className="verdict-filter-group">
              {(['ALL', 'SAFE', 'SUSPICIOUS', 'PHISHING'] as const).map(verdict => (
                <button
                  key={verdict}
                  className={`filter-chip ${filterVerdict === verdict ? 'active' : ''} ${verdict.toLowerCase()}`}
                  onClick={() => setFilterVerdict(verdict)}
                >
                  {verdict === 'ALL' ? 'All Records' : verdict}
                </button>
              ))}
            </div>

            <div className="sort-dropdown-wrap">
              <ArrowUpDown size={14} />
              <select
                value={sortOption}
                onChange={e => setSortOption(e.target.value as SortOption)}
                aria-label="Sort records"
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="highest-risk">Highest Risk</option>
                <option value="lowest-risk">Lowest Risk</option>
              </select>
            </div>
          </div>
        </motion.div>
      )}

      {loading ? (
        <div className="center-state">
          <LoaderCircle className="spin" size={28} />
          <span>Loading historical investigation records...</span>
        </div>
      ) : error ? (
        <div className="error-panel">
          <ShieldAlert size={20} />
          <span>{error}</span>
        </div>
      ) : items.length === 0 ? (
        <motion.div
          className="large-empty"
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <div className="empty-icon-wrap">
            <Clock3 size={36} />
          </div>
          <h2>No Audit Records Yet</h2>
          <p>Scan records will automatically be logged here for offline inspection and verification.</p>
        </motion.div>
      ) : filteredAndSortedItems.length === 0 ? (
        <div className="panel-empty">
          <p>No audit records match the current filter or search criteria.</p>
          <button
            className="secondary-button"
            onClick={() => {
              setSearchTerm('')
              setFilterVerdict('ALL')
            }}
          >
            Reset Filters
          </button>
        </div>
      ) : (
        <div className="history-master-detail">
          {/* Master List */}
          <div className="history-list" aria-label="Audited scans list">
            <div className="history-list-header">
              <span>{filteredAndSortedItems.length} Record{filteredAndSortedItems.length === 1 ? '' : 's'}</span>
            </div>
            {filteredAndSortedItems.map((item, index) => {
              const isSelected =
                selected?.id === item.id ||
                (selected?.request_id === item.request_id && !item.id)

              return (
                <motion.button
                  className={`history-card-item ${isSelected ? 'selected' : ''} ${item.label.toLowerCase()}`}
                  key={item.id ?? item.request_id ?? index}
                  onClick={() => setSelected(item)}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2, delay: Math.min(index * 0.03, 0.3) }}
                >
                  <div className="history-card-top">
                    <StatusBadge verdict={item.label} />
                    <time className="history-time">{formatDate(item.scanned_at)}</time>
                  </div>
                  <code className="history-card-url">{item.url}</code>
                  <div className="history-card-footer">
                    <span className="history-risk-badge">
                      Risk Score: <strong>{item.risk_score}</strong>/100
                    </span>
                    <span className="history-prob-badge">
                      Prob: {formatProbability(item.effective_probability ?? item.probability)}
                    </span>
                  </div>
                </motion.button>
              )
            })}
          </div>

          {/* Detail View */}
          <div className="history-detail-panel">
            <AnimatePresence mode="wait">
              {selected ? (
                <motion.div
                  key={selected.id ?? selected.request_id}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -10 }}
                  transition={{ duration: 0.2 }}
                >
                  <ScanResultCard result={selected} />
                </motion.div>
              ) : (
                <div className="history-detail-empty">
                  <p>Select an audited scan from the left list to review its diagnostic signals.</p>
                </div>
              )}
            </AnimatePresence>
          </div>
        </div>
      )}

      {/* Clear History Confirmation Modal */}
      <ConfirmModal
        isOpen={showClearModal}
        title="Clear Scan History?"
        description="This will remove all locally recorded investigation traces and URL audit records. This action cannot be undone."
        confirmLabel="Yes, Clear All"
        cancelLabel="Keep History"
        isDestructive={true}
        onConfirm={handleConfirmClear}
        onCancel={() => setShowClearModal(false)}
      />
    </div>
  )
}
