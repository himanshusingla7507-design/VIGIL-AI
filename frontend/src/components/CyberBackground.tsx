import { motion, useReducedMotion } from 'motion/react'

export function CyberBackground() {
  const reducedMotion = useReducedMotion()

  return (
    <div className="cyber-ambient-bg" aria-hidden="true">
      {/* Dynamic Radial Ambient Spotlight */}
      <motion.div
        className="cyber-spotlight-primary"
        animate={
          reducedMotion
            ? { opacity: 0.7 }
            : {
                x: [-20, 20, -10, -20],
                y: [0, -15, 10, 0],
                opacity: [0.6, 0.8, 0.65, 0.6],
              }
        }
        transition={{
          duration: 18,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />
      <div className="cyber-spotlight-secondary" />

      {/* Grid Pattern Overlay */}
      <div className="cyber-grid-overlay" />
    </div>
  )
}

