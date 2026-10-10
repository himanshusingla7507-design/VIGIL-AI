import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AnalysisPage } from './AnalysisPage'
import { api } from '../services/api'
import type { ModelInfo, ScanAnalytics, ScanResult } from '../types'

vi.mock('../services/api', () => ({
  api: {
    getHistory: vi.fn(),
    getModelInfo: vi.fn(),
    getScanAnalytics: vi.fn(),
  },
}))

const modelInfo: ModelInfo = {
  model_version: 'v3.0.0',
  model_path: 'phishing_model.pkl',
  model_architecture: 'HistGradientBoostingClassifier',
  calibration_method: 'LogisticRegression',
  model_load_status: 'loaded',
  last_successful_load_at: '2026-10-10T00:00:00+00:00',
  artifact_sha256: 'a'.repeat(64),
  feature_count: 29,
  training: {
    dataset_rows: 11510,
    dataset_path: 'experiments/auto_ml/realworld_v3/sampled_dataset.csv',
    dataset_sha256: 'b'.repeat(64),
    dataset_source_status: 'verified',
    sample_count: 7772,
    legitimate_samples: 3886,
    phishing_samples: 3886,
    calibration_samples: 640,
    validation_samples: 1020,
    test_samples: 2078,
    unique_urls: 7772,
    registered_domains: 2852,
    split_counts: { train: 7772, calibration: 640, validation: 1020, test: 2078 },
  },
  evaluation: {
    type: 'offline_held_out_test',
    sample_count: 2078,
    dataset_path: 'experiments/auto_ml/realworld_v3/sampled_dataset.csv',
    evaluated_at: null,
    precision: 0.9616,
    recall: 0.7238,
    false_positive_rate: 0.0289,
    false_negative_rate: 0.2762,
    f1_score: 0.8259,
    roc_auc: 0.9533,
    pr_auc: null,
    confusion_matrix: [[1009, 30], [287, 752]],
    limitations: ['Balanced domain-disjoint test set.'],
  },
}

const analytics: ScanAnalytics = {
  source: 'vigil_history.sqlite3:scans',
  total_scans: 472,
  verdict_counts: { SAFE: 282, SUSPICIOUS: 106, PHISHING: 84 },
  verdict_percentages: { SAFE: 59.7, SUSPICIOUS: 22.5, PHISHING: 17.8 },
  trend: {
    range: 'last_7_utc_calendar_days',
    start_date: '2026-10-04',
    end_date: '2026-10-10',
    daily: Array.from({ length: 7 }, (_, index) => ({
      date: `2026-10-${String(index + 4).padStart(2, '0')}`,
      total: index === 6 ? 5 : 0,
      verdict_counts: { SAFE: index === 6 ? 3 : 0, SUSPICIOUS: index === 6 ? 1 : 0, PHISHING: index === 6 ? 1 : 0 },
    })),
  },
}

const recentScan: ScanResult = {
  id: 1,
  request_id: 'scan-1',
  url: 'https://example.com/',
  normalized_url: 'https://example.com/',
  label: 'SAFE',
  risk_score: 0,
  probability: 0.1,
  model_probability: 0.1,
  effective_probability: 0.1,
  probability_source: 'model',
  reputation: { applied: false, host: 'example.com', source: 'model', model_probability: 0.1, effective_probability: 0.1 },
  evidence: [],
  features: {},
  model_version: 'v3.0.0',
  thresholds: { safe: 0.25, phishing: 0.9 },
  scanned_at: '2026-10-10T00:00:00+00:00',
  model_fingerprint: 'fingerprint',
  backend: { api_endpoint: '/scan', backend_pid: 1, backend_instance_id: 'backend' },
}

describe('AnalysisPage', () => {
  afterEach(cleanup)

  beforeEach(() => {
    vi.mocked(api.getHistory).mockResolvedValue([recentScan])
    vi.mocked(api.getModelInfo).mockResolvedValue(modelInfo)
    vi.mocked(api.getScanAnalytics).mockResolvedValue(analytics)
  })

  it('uses all-history scan analytics and active model training metadata, not history length', async () => {
    render(<AnalysisPage />)

    expect(await screen.findByText('Model Intelligence')).toBeDefined()
    expect(screen.getByText('472')).toBeDefined()
    expect(screen.getAllByText('7,772')).toHaveLength(2)
    expect(screen.getAllByText('3,886')).toHaveLength(2)
    expect(screen.getByText('59.7% of recorded scans')).toBeDefined()
    expect(screen.getByText('Offline labeled holdout · Not runtime telemetry')).toBeDefined()
    expect(screen.getByText('2,078 test samples')).toBeDefined()
    expect(screen.getByText('https://example.com/')).toBeDefined()
  })

  it('fetches fresh backend values when the dashboard is refreshed', async () => {
    render(<AnalysisPage />)
    await screen.findByText('Model Intelligence')

    fireEvent.click(screen.getAllByRole('button', { name: 'Refresh analysis data' })[0])

    await waitFor(() => {
      expect(api.getHistory).toHaveBeenCalledTimes(2)
      expect(api.getModelInfo).toHaveBeenCalledTimes(2)
      expect(api.getScanAnalytics).toHaveBeenCalledTimes(2)
    })
  })

  it('shows missing training and evaluation metadata as unavailable, never as fabricated zeroes', async () => {
    vi.mocked(api.getModelInfo).mockResolvedValue({
      model_version: 'unknown-training',
      model_load_status: 'loaded',
      training: {
        dataset_rows: null,
        dataset_path: null,
        dataset_sha256: null,
        dataset_source_status: 'source_unavailable',
        sample_count: null,
        legitimate_samples: null,
        phishing_samples: null,
        calibration_samples: null,
        validation_samples: null,
        test_samples: null,
        unique_urls: null,
        registered_domains: null,
        split_counts: {},
      },
      evaluation: undefined,
    })

    render(<AnalysisPage />)

    await screen.findByText('No verifiable labeled evaluation results are recorded for the active model.')
    expect(document.querySelector('.analysis-fact-card strong')?.textContent).toBe('Unavailable')
  })
})
