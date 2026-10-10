# VIGIL API

The Flask API runs on `http://127.0.0.1:5000` by default (`VIGIL_PORT` changes the port). All JSON responses use the fields produced by `api.py` and `service.py`.

## `GET /health`

Returns `200` when the model bundle loads:

```json
{"status":"ok","model_loaded":true,"model_version":"v3.0.0"}
```

Returns `503` with `status: "degraded"` when the bundle is unavailable.

## `GET /model-info`

Returns metadata from the currently loaded root-level model bundle (`phishing_model.pkl`, `feature_names.pkl`, and `model_metadata.json`). The response preserves the recorded metadata and adds the following dashboard contract:

```json
{
  "model_version": "v3.0.0",
  "model_path": "phishing_model.pkl",
  "model_load_status": "loaded",
  "last_successful_load_at": "2026-10-10T05:00:00+00:00",
  "model_architecture": "HistGradientBoostingClassifier",
  "calibration_method": "Sigmoid (LogisticRegression)",
  "feature_count": 29,
  "artifact_sha256": "<full SHA-256 of the active model file>",
  "training": {
    "dataset_path": "experiments\\\\auto_ml\\\\realworld_v3\\\\sampled_dataset.csv",
    "dataset_sha256": "<SHA-256 of the recorded source dataset>",
    "dataset_source_status": "verified",
    "dataset_rows": 11510,
    "sample_count": 7772,
    "legitimate_samples": 3886,
    "phishing_samples": 3886,
    "calibration_samples": 640,
    "validation_samples": 1020,
    "test_samples": 2078,
    "unique_urls": 7772,
    "registered_domains": 2852
  },
  "evaluation": {
    "type": "offline_held_out_test",
    "sample_count": 2078,
    "dataset_path": "experiments\\\\auto_ml\\\\realworld_v3\\\\sampled_dataset.csv",
    "evaluated_at": null,
    "precision": 0.9616368286,
    "recall": 0.7237728585,
    "false_positive_rate": 0.0288739172,
    "false_negative_rate": 0.2762271415,
    "f1_score": 0.8259,
    "roc_auc": 0.9533246689,
    "pr_auc": null,
    "confusion_matrix": [[1009, 30], [287, 752]],
    "limitations": [
      "The held-out test split is balanced and domain-disjoint; population precision may differ at real-world prevalence.",
      "The test split was not used for threshold selection."
    ]
  }
}
```

Counts, features, checksums, and evaluation values come from the active bundle's metadata; the architecture and calibration class are read from that loaded pickle. Fields that are not recorded or cannot be established are `null`, not guessed. `training.sample_count` is the train split, not all rows in the four-way dataset. The reported test metrics are offline results and are not runtime scan statistics. The response returns `503` if the active bundle cannot be loaded.

The checked-in v3.0.0 metadata identifies `experiments/auto_ml/realworld_v3/sampled_dataset.csv` (11,510 rows; 7,772 train rows) as its dataset. The repository also has a separate 854,870-row `data/processed/clean_dataset.csv`; `reports/existing_artifact_evaluation.json` associates that larger file with a different candidate artifact that is marked missing. The larger corpus is therefore not reported as the active v3.0.0 model's direct fit count.

## `GET /analysis/scan-analytics`

Aggregates every row in the `scans` table (not the `/history` endpoint's latest-100 response). Counts and percentages share the same all-history denominator. Percentages are `null` when there are no recorded scans.
The following response shows a live-data snapshot; the counts change whenever scan events are recorded.

```json
{
  "source": "vigil_history.sqlite3:scans",
  "total_scans": 473,
  "verdict_counts": {"SAFE": 283, "SUSPICIOUS": 106, "PHISHING": 84},
  "verdict_percentages": {"SAFE": 59.8, "SUSPICIOUS": 22.4, "PHISHING": 17.8},
  "trend": {
    "range": "last_7_utc_calendar_days",
    "start_date": "2026-10-04",
    "end_date": "2026-10-10",
    "daily": [
      {"date": "2026-10-04", "total": 0, "verdict_counts": {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0}}
    ]
  }
}
```

The `daily` list always contains seven UTC calendar days, including zero-count days. `/history` remains a latest-100-item API for the history UI and recent-activity display; it must not be used as an all-time total.

## `POST /scan`

Request:

```json
{"url":"https://example.com"}
```

Response shape:

```json
{
  "url": "https://example.com",
  "normalized_url": "https://example.com",
  "label": "SAFE",
  "risk_score": 0,
  "probability": 0.165493,
  "model_probability": 0.165493,
  "effective_probability": 0.165493,
  "probability_source": "model",
  "reputation": {"applied": false, "host": "example.com", "source": "model", "model_probability": 0.165493, "effective_probability": 0.165493},
  "evidence": [{
    "id": "intermediate_model_score",
    "severity": "warning",
    "polarity": "negative",
    "title": "Intermediate model score",
    "detail": "The calibrated model score is above the SAFE threshold but below the PHISHING threshold.",
    "feature": null,
    "value": 0.165493
  }],
  "features": {"URLLength": 20},
  "model_version": "v3.0.0",
  "thresholds": {"safe": 0.25, "phishing": 0.9106962115698227},
  "scanned_at": "2026-10-04T00:00:00+00:00"
}
```

The exact evidence and feature map vary by URL. `model_probability` is the calibrated model output. Usually `probability` is the same value and `probability_source` is `model`; when a documented policy applies, `model_probability` remains available for audit while `probability`, `label`, and `risk_score` describe the effective decision. `risk_score` maps the effective probability between the configured SAFE and PHISHING thresholds to 0–100.

## History

The policy name and contract in the preceding legacy note are superseded by the current decision contract below.

### Current decision contract

`model_probability` is the raw calibrated output. `effective_probability` is the value used for `label` and `risk_score`; legacy `probability` is the same effective value for compatibility. `verified_official_route_policy` retains the raw score and applies only to exact approved HTTPS hosts and routes, rejecting redirect-like destinations and authority tricks. For Amazon, only `amazon.com` and `www.amazon.com` shopping routes (home, search, cart, product detail, and the standard buy handler) qualify; lookalike/subdomains, malformed product IDs, and URLs with redirect destinations still use the model score. `local_host_policy` prevents loopback IP addresses (`127.0.0.0/8` and `::1`) and the reserved `localhost`/`.localhost` names from being blocked by URL-only model scores; the raw model probability is still returned for audit. Other private-network IPs continue to use the model. The extension consumes the backend `label` without recalculating a verdict.

- `GET /history` returns up to the latest 100 stored scans.
- `GET /history/<id>` returns one scan or `404` with `{"error":"not_found",...}`.
- `DELETE /history` clears local history and returns `{"status":"cleared"}`.

Before persistence, query strings and fragments are removed to avoid storing common secret-bearing URL components. The API does not provide authentication; keep it bound to a trusted local environment unless deployment controls are added.

## Common errors

`400` is used for invalid JSON, missing/empty URLs, invalid URLs, and unsupported schemes. `413` is used for URLs over 2048 characters or oversized request bodies. `503` means the model bundle is unavailable. Unexpected scan failures return `500` without exposing filesystem details.
