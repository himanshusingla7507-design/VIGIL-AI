import { useEffect, useRef } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { AlertTriangle, X } from 'lucide-react'

interface ConfirmModalProps {
  isOpen: boolean
  title: string
  description: string
  confirmLabel?: string
  cancelLabel?: string
  isDestructive?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export function ConfirmModal({
  isOpen,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  isDestructive = true,
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  const confirmBtnRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (isOpen) {
      confirmBtnRef.current?.focus()
      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') onCancel()
      }
      window.addEventListener('keydown', handleKeyDown)
      return () => window.removeEventListener('keydown', handleKeyDown)
    }
  }, [isOpen, onCancel])

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onCancel}
          />
          <motion.div
            className="modal-content"
            initial={{ opacity: 0, scale: 0.95, y: 12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 12 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="modal-header">
              <div className="modal-icon-wrap danger">
                <AlertTriangle size={20} />
              </div>
              <div className="modal-text">
                <h3 id="modal-title">{title}</h3>
                <p>{description}</p>
              </div>
              <button
                className="modal-close"
                onClick={onCancel}
                aria-label="Close dialog"
              >
                <X size={18} />
              </button>
            </div>

            <div className="modal-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={onCancel}
              >
                {cancelLabel}
              </button>
              <button
                type="button"
                ref={confirmBtnRef}
                className={isDestructive ? 'danger-action-button' : 'primary-button'}
                onClick={onConfirm}
              >
                {confirmLabel}
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}

