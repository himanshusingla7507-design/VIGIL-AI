import { describe, expect, it } from 'vitest'
import { formatProbability, getOfficialLegalSourceUrl, validateUrl } from './utils'

describe('frontend URL handling', () => {
  it('accepts HTTP and HTTPS URLs', () => {
    expect(validateUrl('https://fast.com/')).toBeNull()
    expect(validateUrl('http://example.com/path')).toBeNull()
  })
  it('rejects empty and unsupported URLs', () => {
    expect(validateUrl('')).toBe('Enter a URL to scan.')
    expect(validateUrl('javascript:alert(1)')).toBe('Use an HTTP or HTTPS URL.')
  })
  it('formats model probabilities as percentages', () => {
    expect(formatProbability(0.003954)).toBe('0.4%')
  })
})

describe('official legal source URLs', () => {
  it('accepts HTTPS URLs on official legal-source domains', () => {
    expect(getOfficialLegalSourceUrl('https://www.indiacode.nic.in/handle/123456789/1999'))
      .toBe('https://www.indiacode.nic.in/handle/123456789/1999')
    expect(getOfficialLegalSourceUrl('https://www.rbi.org.in/scripts/BS_CircularIndexDisplay.aspx?Id=11040'))
      .toBe('https://www.rbi.org.in/scripts/BS_CircularIndexDisplay.aspx?Id=11040')
  })

  it('rejects missing, malformed, insecure, and non-official URLs', () => {
    expect(getOfficialLegalSourceUrl(undefined)).toBeNull()
    expect(getOfficialLegalSourceUrl('not a URL')).toBeNull()
    expect(getOfficialLegalSourceUrl('http://www.indiacode.nic.in/')).toBeNull()
    expect(getOfficialLegalSourceUrl('https://example.com/legal')).toBeNull()
  })
})
