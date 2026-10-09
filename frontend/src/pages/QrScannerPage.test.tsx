import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../services/api'
import type { ScanResult } from '../types'
import { QrScannerPage } from './QrScannerPage'

const decoder = vi.hoisted(() => ({
  callback: null as null | ((result: { getText: () => string } | undefined, error: unknown, controls: { stop: () => void }) => void),
  stop: vi.fn(),
  cameraError: null as Error | null,
  stream: null as null | { getTracks: () => { stop: () => void }[] },
  imageText: 'https://example.com/',
}))

vi.mock('@zxing/browser', () => ({
  BrowserQRCodeReader: class {
    decodeFromVideoDevice = async (
      _deviceId: string | undefined,
      _video: HTMLVideoElement,
      callback: (result: { getText: () => string } | undefined, error: unknown, controls: { stop: () => void }) => void
    ) => {
      decoder.callback = callback
      if (decoder.stream) {
        Object.defineProperty(_video, 'srcObject', {
          configurable: true,
          writable: true,
          value: decoder.stream,
        })
      }
      if (decoder.cameraError) throw decoder.cameraError
      return { stop: decoder.stop }
    }

    decodeFromImageElement = async () => ({ getText: () => decoder.imageText })
  },
}))

vi.mock('../services/api', () => ({ api: { scanUrl: vi.fn() } }))

function resultFor(url: string, label: ScanResult['label']): ScanResult {
  const probability = label === 'SAFE' ? 0.02 : label === 'SUSPICIOUS' ? 0.55 : 0.97
  return {
    request_id: 'request-1',
    url,
    normalized_url: url,
    label,
    risk_score: Math.round(probability * 100),
    probability,
    model_probability: probability,
    effective_probability: probability,
    probability_source: 'model',
    reputation: {
      applied: false,
      host: new URL(url).hostname,
      source: 'model',
      model_probability: probability,
      effective_probability: probability,
    },
    evidence: [{
      id: 'signal-1',
      severity: label === 'SAFE' ? 'info' : 'danger',
      polarity: label === 'SAFE' ? 'positive' : 'negative',
      title: 'Test signal',
      detail: 'Test evidence detail',
      feature: null,
      value: null,
    }],
    features: {},
    model_version: 'test',
    thresholds: { safe: 0.2, phishing: 0.8 },
    scanned_at: new Date().toISOString(),
    model_fingerprint: 'fingerprint',
    backend: { api_endpoint: '/scan', backend_pid: 1, backend_instance_id: 'test' },
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  decoder.callback = null
  decoder.cameraError = null
  decoder.stream = null
  decoder.imageText = 'https://example.com/'
  vi.mocked(api.scanUrl).mockResolvedValue(resultFor('https://example.com/', 'SAFE'))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('QR scanner', () => {
  it('requests camera access only on demand and stops the scanner on unmount', async () => {
    const trackStop = vi.fn()
    class FakeMediaStream {
      getTracks = () => [{ stop: trackStop }]
    }
    decoder.stream = new FakeMediaStream()
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia: vi.fn() },
    })
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true })
    const { unmount } = render(<QrScannerPage />)

    expect(decoder.callback).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Start camera' }))
    await screen.findByText('Camera live · Point at a QR code')
    expect(decoder.callback).not.toBeNull()

    unmount()
    expect(decoder.stop).toHaveBeenCalled()
    expect(trackStop).toHaveBeenCalled()
  })

  it.each([
    { url: 'https://fast.com/', label: 'SAFE' as const, verdict: 'LOW RISK' },
    { url: 'https://account-check.example.invalid/', label: 'SUSPICIOUS' as const, verdict: 'SUSPICIOUS' },
  ])('shows the backend $label verdict for $url', async ({ url, label, verdict }) => {
    decoder.imageText = url
    vi.mocked(api.scanUrl).mockResolvedValue(resultFor(url, label))
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn().mockReturnValue('blob:qr-test') })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() })
    vi.stubGlobal('Image', class {
      src = ''
      naturalWidth = 240
      naturalHeight = 240
      decode = vi.fn().mockResolvedValue(undefined)
    })
    render(<QrScannerPage />)
    fireEvent.change(screen.getByLabelText('Upload QR image'), {
      target: { files: [new File(['qr image'], 'site.png', { type: 'image/png' })] },
    })

    expect((await screen.findAllByText(verdict, { exact: true })).length).toBeGreaterThan(0)
    expect(api.scanUrl).toHaveBeenCalledWith(url)
  })

  it('analyzes a decoded deceptive-domain URL and warns before opening a high-risk result', async () => {
    const deceptiveUrl = 'https://paypal.example.invalid/verify'
    vi.mocked(api.scanUrl).mockResolvedValue(resultFor(deceptiveUrl, 'PHISHING'))
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia: vi.fn() },
    })
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true })
    render(<QrScannerPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Start camera' }))
    await screen.findByText('Camera live · Point at a QR code')

    const decodedQr = { getText: () => deceptiveUrl }
    const controls = { stop: decoder.stop }
    act(() => {
      decoder.callback?.(decodedQr, undefined, controls)
      decoder.callback?.(decodedQr, undefined, controls)
    })

    expect((await screen.findAllByText('PHISHING / HIGH RISK')).length).toBeGreaterThan(0)
    expect(screen.getByText(/VIGIL flags this destination as high risk/)).toBeInTheDocument()
    expect(screen.getByText('Hostname: paypal.example.invalid')).toBeInTheDocument()
    expect(api.scanUrl).toHaveBeenCalledTimes(1)
    expect(api.scanUrl).toHaveBeenCalledWith(deceptiveUrl)
    expect(screen.getByRole('link', { name: /Open destination/ })).toHaveAttribute('href', deceptiveUrl)
  })

  it('decodes an uploaded QR image and displays non-URL payloads without calling the backend', async () => {
    decoder.imageText = 'upi://pay?pa=corner%40bank&pn=Corner%20Shop&am=45&cu=INR'
    const createObjectUrl = vi.fn().mockReturnValue('blob:qr-test')
    const revokeObjectUrl = vi.fn()
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectUrl })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectUrl })
    vi.stubGlobal('Image', class {
      src = ''
      naturalWidth = 240
      naturalHeight = 240
      decode = vi.fn().mockResolvedValue(undefined)
    })
    render(<QrScannerPage />)
    const file = new File(['qr image'], 'payment.png', { type: 'image/png' })
    fireEvent.change(screen.getByLabelText('Upload QR image'), { target: { files: [file] } })

    expect(await screen.findByText('UPI payment request')).toBeInTheDocument()
    expect(screen.getByText('corner@bank')).toBeInTheDocument()
    expect(screen.getByText('Corner Shop')).toBeInTheDocument()
    expect(screen.getByText('45 INR')).toBeInTheDocument()
    expect(screen.getByText('Verify payment details before paying.')).toBeInTheDocument()
    expect(api.scanUrl).not.toHaveBeenCalled()
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:qr-test')
  })

  it('surfaces backend failures and offers retry instead of opening the decoded URL', async () => {
    vi.mocked(api.scanUrl).mockRejectedValueOnce(new Error('Analysis service unavailable.'))
    decoder.imageText = 'https://fast.com/'
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn().mockReturnValue('blob:qr-test') })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() })
    vi.stubGlobal('Image', class {
      src = ''
      naturalWidth = 240
      naturalHeight = 240
      decode = vi.fn().mockResolvedValue(undefined)
    })
    render(<QrScannerPage />)
    fireEvent.change(screen.getByLabelText('Upload QR image'), {
      target: { files: [new File(['qr image'], 'site.png', { type: 'image/png' })] },
    })

    expect(await screen.findByText('Analysis service unavailable.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry analysis' })).toBeInTheDocument()
    expect(api.scanUrl).toHaveBeenCalledWith('https://fast.com/')
  })

  it('recovers from camera permission denial', async () => {
    decoder.cameraError = new DOMException('Denied', 'NotAllowedError')
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia: vi.fn() },
    })
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true })
    render(<QrScannerPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Start camera' }))

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/Camera access was denied/))
    expect(screen.getByLabelText('Upload QR image')).toBeEnabled()
  })

  it('explains when the device has no camera and leaves image upload available', async () => {
    decoder.cameraError = new DOMException('No camera', 'NotFoundError')
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia: vi.fn() },
    })
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true })
    render(<QrScannerPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Start camera' }))

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/No camera was found/))
    expect(screen.getByLabelText('Upload QR image')).toBeEnabled()
  })

  it('recovers when the uploaded file is not a decodable QR image', async () => {
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn().mockReturnValue('blob:invalid-image') })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() })
    vi.stubGlobal('Image', class {
      src = ''
      naturalWidth = 0
      naturalHeight = 0
      decode = vi.fn().mockRejectedValue(new DOMException('Invalid image'))
    })
    render(<QrScannerPage />)
    fireEvent.change(screen.getByLabelText('Upload QR image'), {
      target: { files: [new File(['not an image'], 'broken.png', { type: 'image/png' })] },
    })

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/No readable QR code was found/))
    expect(screen.getByLabelText('Upload QR image')).toBeEnabled()
    expect(api.scanUrl).not.toHaveBeenCalled()
  })
})
