import { describe, expect, it } from 'vitest'
import { formatProbability, validateUrl } from './utils'

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
