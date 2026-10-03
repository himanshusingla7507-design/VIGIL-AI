# Inspection and implementation plan
# Inspection and implementation plan

> Initial inspection notes from an earlier pass. Current architecture, test results, and remaining gaps are summarized in [ml-evaluation.md](ml-evaluation.md).

> Initial inspection notes from an earlier pass. Current architecture, test results, and remaining gaps are summarized in [ml-evaluation.md](ml-evaluation.md).

## Plan

1. Preserve and record the original artifacts; inspect the current pipeline.
2. Reproduce the `fast.com` behavior and compare URL variants.
3. Make normalization and feature extraction deterministic for training and serving.
4. Centralize inference, calibration output, risk, labels, and evidence in `service.py`.
5. Retrain and record random/domain-aware metrics.
6. Harden the Flask API, extension boundary, tests, and documentation.

## Findings

The repository was a small Flask/Streamlit prototype. `feature_extractor.py` computed URL features; `phishing_detector.py` loaded the pickle, added a trusted-domain shortcut and arbitrary evidence score; `api.py` exposed `/scan`; `app.py` called the detector; and the extension duplicated trusted-domain, fake-brand, TLD, blocking, and threshold logic. There was no frontend directory, no persisted history API, and CORS allowed every origin.

The dataset is `final_dataset_v2.csv` with 235,370 rows and two columns (`url`, `label`); labels are 134,850 legitimate (`0`) and 100,520 phishing (`1`). The current environment is Python 3.13.15, pandas 3.0.6, NumPy 2.5.3, scikit-learn 1.9.1, Flask 3.1.3, and pytest 9.1.1. Node 26.5.0 is present; PowerShell blocks the `npm.ps1` shim, so `npm.cmd` is the compatible invocation.

The original model and feature list were copied into `models/` before retraining. The active model remains at the legacy root paths for compatibility with the existing Streamlit app and tests.

## Risks found

- The old model treated `www` and a root slash differently from the bare host.
- An exact trusted-domain allowlist bypassed inference and was not generalizable.
- Heuristic score additions silently changed the model probability into a different risk number.
- The old training script selected thresholds from the test split; its metrics are therefore not a clean final holdout claim.
- The extension auto-navigated to a block page and contained duplicated scoring rules.
- URL-only analysis cannot inspect page content or live reputation.
