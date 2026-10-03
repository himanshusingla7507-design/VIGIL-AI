# Final engineering report
# Final engineering report

> Superseded report from an earlier pass. Several counts, test results, thresholds, and extension statements below are stale; the current verified report is [ml-evaluation.md](ml-evaluation.md).

> Superseded report from an earlier pass. Several counts, test results, thresholds, and extension statements below are stale; the current verified report is [ml-evaluation.md](ml-evaluation.md).

## Delivered

The project now has a shared `service.py` for URL validation, feature extraction, model inference, calibrated probability, monotonic risk score, final label, and structured evidence. `phishing_detector.py` is a compatibility facade. The API has `/scan`, `/health`, `/model-info`, and SQLite-backed history endpoints. URL submission is never fetched or opened.

The root cause of the fast.com issue was inconsistent `www`/root-slash feature representation, made worse by a trusted-domain bypass and arbitrary score logic. After retraining, `fast.com`, `fast.com/`, and `www.fast.com/` all return SAFE with probability 0.003762 and risk 0.

The original artifacts were backed up in `models/` before retraining. The new extractor has 35 ordered features. The selected model was calibrated histogram gradient boosting. Random and domain-aware metrics are recorded in `docs/MODEL_REPORT.md`; no external validation was performed.

Verification run: `python -m pytest -q` passed 4 tests. `python train_model.py` completed and wrote the active model, feature list, metadata, and feature importance CSV. `python scripts\\validation_report.py` passed 11/13 rows; two expected-SUSPICIOUS synthetic rows were classified PHISHING and are recorded rather than tuned away. The validation report script was added but frontend scaffolding and the complete React test suite were not implemented in this pass. The extension still requires a follow-up rewrite to remove its duplicated blocking logic. These are known remaining items, not verified claims.

## Commands

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python train_model.py
python -m pytest -q
python scripts\validation_report.py
python api.py
```

## Limitations and next steps

The model is URL-only, dataset-biased, and not a substitute for page-content sandboxing or live reputation. The next engineering step should separate a validation-only threshold split from the final test set, emit a materialized cleaned dataset and audit counts, complete the React frontend, and replace the extension’s duplicated rules with a pure `/scan` client.
