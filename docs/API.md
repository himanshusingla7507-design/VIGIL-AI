# VIGIL API

The Flask API runs on `http://127.0.0.1:5000` by default (`VIGIL_PORT` changes the port). All JSON responses use the fields produced by `api.py` and `service.py`.

## `GET /health`

Returns `200` when the model bundle loads:

```json
{"status":"ok","model_loaded":true,"model_version":"v3.0.0"}
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
