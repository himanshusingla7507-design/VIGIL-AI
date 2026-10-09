const MAX_QR_PAYLOAD_LENGTH = 8192

export type QrPayload =
  | { kind: 'url'; raw: string; url: string }
  | { kind: 'wifi'; raw: string; ssid: string; security: string; hidden: boolean; passwordIncluded: boolean }
  | { kind: 'email'; raw: string; recipient: string; subject: string }
  | { kind: 'telephone'; raw: string; number: string }
  | {
      kind: 'payment'
      raw: string
      recipient: string
      recipientName: string
      amount: string
      currency: string
      note: string
    }
  | { kind: 'text'; raw: string }
  | { kind: 'unsupported'; raw: string; reason: string }

const embeddedUrlPattern = /https?:\/\/[^\s<>"']+/i
const supportedUrlSchemes = new Set(['http:', 'https:'])

function cleanCandidateUrl(candidate: string): string {
  return candidate.replace(/[.,;:!?)}\]]+$/, '')
}

function unsupported(raw: string, reason: string): QrPayload {
  return { kind: 'unsupported', raw, reason }
}

export function classifyQrPayload(value: string): QrPayload {
  const raw = value.trim()
  if (!raw) return unsupported(raw, 'This QR code is empty.')
  if (raw.length > MAX_QR_PAYLOAD_LENGTH) {
    return unsupported(raw.slice(0, MAX_QR_PAYLOAD_LENGTH), 'This QR payload is too large to analyze safely.')
  }
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(raw)) {
    return unsupported(raw, 'This QR code contains unsupported control characters.')
  }

  if (/^WIFI:/i.test(raw)) {
    const fields = new Map<string, string>()
    const contents = raw.slice(raw.indexOf(':') + 1).replace(/;;$/, '')
    for (const field of contents.matchAll(/(?:^|;)([A-Z]):((?:\\.|[^;])*)/gi)) {
      fields.set(field[1].toUpperCase(), field[2].replace(/\\([\\;,:"])/g, '$1'))
    }
    const security = fields.get('T') || 'Unknown'
    return {
      kind: 'wifi',
      raw,
      ssid: fields.get('S') || 'Not provided',
      security: security.toUpperCase() === 'NOPASS' ? 'Open network' : security,
      hidden: fields.get('H')?.toLowerCase() === 'true',
      passwordIncluded: Boolean(fields.get('P')),
    }
  }

  if (/^upi:\/\/pay(?:[/?#]|$)/i.test(raw)) {
    try {
      const paymentUrl = new URL(raw)
      return {
        kind: 'payment',
        raw,
        recipient: paymentUrl.searchParams.get('pa') || 'Not provided',
        recipientName: paymentUrl.searchParams.get('pn') || 'Not provided',
        amount: paymentUrl.searchParams.get('am') || 'Not specified',
        currency: paymentUrl.searchParams.get('cu') || 'Not specified',
        note: paymentUrl.searchParams.get('tn') || 'Not provided',
      }
    } catch {
      return unsupported(raw, 'The payment QR details could not be parsed.')
    }
  }

  if (/^mailto:/i.test(raw)) {
    try {
      const email = new URL(raw)
      return {
        kind: 'email',
        raw,
        recipient: decodeURIComponent(email.pathname) || 'Not provided',
        subject: email.searchParams.get('subject') || 'Not specified',
      }
    } catch {
      return unsupported(raw, 'The email QR details could not be parsed.')
    }
  }

  if (/^tel:/i.test(raw)) {
    return { kind: 'telephone', raw, number: raw.slice(raw.indexOf(':') + 1) || 'Not provided' }
  }

  const candidate = embeddedUrlPattern.exec(raw)?.[0]
  if (candidate) {
    const urlValue = cleanCandidateUrl(candidate)
    try {
      const url = new URL(urlValue)
      if (!supportedUrlSchemes.has(url.protocol) || !url.hostname) {
        return unsupported(raw, 'Only complete HTTP and HTTPS destinations can be analyzed.')
      }
      return { kind: 'url', raw, url: url.toString() }
    } catch {
      return unsupported(raw, 'The web destination in this QR code is malformed.')
    }
  }

  if (/^[a-z][a-z\d+.-]*:/i.test(raw)) {
    return unsupported(raw, 'This link type is not supported for URL risk analysis.')
  }

  return { kind: 'text', raw }
}
