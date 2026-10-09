import { describe, expect, it } from 'vitest'
import { classifyQrPayload } from './qrPayload'

describe('QR payload classification', () => {
  it('classifies web URLs without treating the protocol or brand as a safety signal', () => {
    expect(classifyQrPayload('https://paypal.example.invalid/login')).toMatchObject({
      kind: 'url',
      url: 'https://paypal.example.invalid/login',
    })
    expect(classifyQrPayload('Visit https://example.com/path.')).toMatchObject({
      kind: 'url',
      url: 'https://example.com/path',
    })
  })

  it('extracts Wi-Fi configuration without revealing its password', () => {
    expect(classifyQrPayload('WIFI:T:WPA;S:Office Network;P:secret;H:true;;')).toMatchObject({
      kind: 'wifi',
      ssid: 'Office Network',
      security: 'WPA',
      hidden: true,
      passwordIncluded: true,
    })
  })

  it('extracts email, telephone, and UPI payment details', () => {
    expect(classifyQrPayload('mailto:help@example.com?subject=Account%20help')).toMatchObject({
      kind: 'email',
      recipient: 'help@example.com',
      subject: 'Account help',
    })
    expect(classifyQrPayload('tel:+911234567890')).toMatchObject({
      kind: 'telephone',
      number: '+911234567890',
    })
    expect(classifyQrPayload('upi://pay?pa=shop%40bank&pn=Corner%20Shop&am=75.00&cu=INR&tn=Tea')).toMatchObject({
      kind: 'payment',
      recipient: 'shop@bank',
      recipientName: 'Corner Shop',
      amount: '75.00',
      currency: 'INR',
      note: 'Tea',
    })
  })

  it('keeps plain text and unsupported schemes distinct from analyzed URLs', () => {
    expect(classifyQrPayload('Meeting room 4')).toEqual({ kind: 'text', raw: 'Meeting room 4' })
    expect(classifyQrPayload('javascript:alert(1)')).toMatchObject({
      kind: 'unsupported',
      reason: 'This link type is not supported for URL risk analysis.',
    })
  })

  it('rejects oversized or malformed web destinations', () => {
    expect(classifyQrPayload(`https://example.com/${'x'.repeat(8200)}`).kind).toBe('unsupported')
    expect(classifyQrPayload('https://[invalid')).toMatchObject({ kind: 'unsupported' })
  })
})
