# VIGIL API

The Flask API runs on `http://127.0.0.1:5000` by default (`VIGIL_PORT` changes the port). All JSON responses use the fields produced by `api.py` and `service.py`.

## `GET /health`

Returns `200` when the model bundle loads:

```json
{"status":"ok","model_loaded":true,"model_version":"v2.1.0"}
```

Returns `503` with `status: "degraded"` when the bundle is unavailable.

## `GET /model-info`

Returns the tracked model metadata, including version, dataset summary, features, thresholds, evaluation metadata, and artifact hashes. Returns `503` if the bundle cannot be loaded.

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
  "label": "SUSPICIOUS",
  "risk_score": 6,
  "probability": 0.165493,
  "model_probability": 0.165493,
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
  "model_version": "v2.1.0",
  "thresholds": {"safe": 0.13140956380602112, "phishing": 0.6961575221255231},
  "scanned_at": "2026-10-04T00:00:00+00:00"
}
```

The exact evidence and feature map vary by URL. `probability` is the calibrated phishing probability; `risk_score` maps the configured SAFE and PHISHING thresholds to 0–100.

## History

- `GET /history` returns up to the latest 100 stored scans.
- `GET /history/<id>` returns one scan or `404` with `{"error":"not_found",...}`.
- `DELETE /history` clears local history and returns `{"status":"cleared"}`.

Before persistence, query strings and fragments are removed to avoid storing common secret-bearing URL components. The API does not provide authentication; keep it bound to a trusted local environment unless deployment controls are added.

## Common errors

`400` is used for invalid JSON, missing/empty URLs, invalid URLs, and unsupported schemes. `413` is used for URLs over 2048 characters or oversized request bodies. `503` means the model bundle is unavailable. Unexpected scan failures return `500` without exposing filesystem details.
