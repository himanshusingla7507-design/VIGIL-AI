import { useEffect, useState } from 'react'

interface AnimatedNumberProps {
  value: number
  duration?: number
  format?: (n: number) => string
}

export function AnimatedNumber({ value, duration = 600, format }: AnimatedNumberProps) {
  const [displayValue, setDisplayValue] = useState(value)

  useEffect(() => {
    let startTimestamp: number | null = null
    const startValue = displayValue
    const endValue = value

    if (startValue === endValue) return

    let animationFrameId: number

    const step = (timestamp: number) => {
      if (!startTimestamp) startTimestamp = timestamp
      const progress = Math.min((timestamp - startTimestamp) / duration, 1)
      const easeOutQuad = (t: number) => t * (2 - t)
      const current = Math.round(startValue + (endValue - startValue) * easeOutQuad(progress))

      setDisplayValue(current)

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(step)
      } else {
        setDisplayValue(endValue)
      }
    }

    animationFrameId = requestAnimationFrame(step)

    return () => {
      if (animationFrameId) cancelAnimationFrame(animationFrameId)
    }
  }, [value, duration])

  return (
    <span className="tabular-nums">
      {format ? format(displayValue) : displayValue.toLocaleString()}
    </span>
  )
}

