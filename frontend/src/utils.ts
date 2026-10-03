import type { Verdict } from './types'

export function validateUrl(value: string): string | null {
  if (!value.trim()) return 'Enter a URL to scan.'
  try {
    const url = new URL(value.trim())
    if (!['http:', 'https:'].includes(url.protocol)) return 'Use an HTTP or HTTPS URL.'
    if (!url.hostname) return 'Enter a valid URL with a hostname.'
    return null
  } catch { return 'Enter a valid HTTP or HTTPS URL.' }
}

export function formatProbability(value: number) { return `${(value * 100).toFixed(1)}%` }
export function formatDate(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) }
export function verdictTone(verdict: Verdict) { return verdict.toLowerCase() }
