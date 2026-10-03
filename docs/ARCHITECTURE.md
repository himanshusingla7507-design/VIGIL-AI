# Architecture

VIGIL keeps all prediction decisions in one Python service so the React frontend and browser extension consume the same behavior.

```text
React frontend ─────┐
                    ├──> api.py (Flask, CORS, validation, history)
Browser extension ──┘                 │
                                      v
                          service.py (single inference path)
                                      │
                    normalize_url + extract_features
                                      │
                                      v
                    calibrated scikit-learn model bundle
                                      │
                                      v
                    probability → label/risk → evidence
                                      │
                                      v
                             JSON response / SQLite history
```

The training path is separate from serving:

```text
final_dataset_v2.csv
        │
        v
prepare_dataset.py → data/processed/clean_dataset.csv + dataset_summary.json
        │
        v
train_model.py → phishing_model.pkl, feature_names.pkl, model_metadata.json
        │
        v
evaluate_model.py → reports/metrics.json
```

`service.py` checks model artifact hashes recorded in `model_metadata.json`, validates feature compatibility, loads the calibrated model, and produces structured evidence. The API persists a sanitized history record in `vigil_history.sqlite3`.
