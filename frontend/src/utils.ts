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

const officialLegalSourceDomains = [
  'indiacode.nic.in',
  'meity.gov.in',
  'egazette.gov.in',
  'gazette.nic.in',
  'rbi.org.in',
  'cert-in.org.in',
  'sci.gov.in',
]

export function getOfficialLegalSourceUrl(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null

  try {
    const url = new URL(value.trim())
    const isOfficialHost = officialLegalSourceDomains.some(
      domain => url.hostname === domain || url.hostname.endsWith(`.${domain}`)
    )
    if (url.protocol !== 'https:' || !isOfficialHost || url.username || url.password) return null
    return url.toString()
  } catch {
    return null
  }
}

export function formatProbability(value: number) { return `${(value * 100).toFixed(1)}%` }
export function formatDate(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) }
export function verdictTone(verdict: Verdict) { return verdict.toLowerCase() }
