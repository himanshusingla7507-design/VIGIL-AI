# Final Training Comparison

## DO NOT PROMOTE

Selected model: `hist_gradient_boosting`. Production artifacts updated: `False`.

Training rows: **337,123**; legitimate: **134,849**; phishing: **202,274**. New Phishing.Database rows selected: **102,690**.

The external 154,931-row phishing-only holdout was not used for fitting, calibration, feature selection, or threshold selection. External FPR is undefined because the external holdout contains phishing URLs only.

| Model | Recall | FNR | FPR | PR-AUC | F1 | Brier | ECE | Median ms | Size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.8240 | 0.1760 | 0.0746 | 0.9543 | 0.8789 | 0.1021 | 0.0278 | 0.551 | 1,938 |
| random_forest | 0.8301 | 0.1699 | 0.0643 | 0.9610 | 0.8859 | 0.0949 | 0.0198 | 15.279 | 43,001,793 |
| hist_gradient_boosting | 0.8364 | 0.1636 | 0.0640 | 0.9624 | 0.8897 | 0.0920 | 0.0206 | 1.536 | 369,200 |

External recall: **0.9138**; external FNR: **0.0862**. Fast.com gate: **PASS**. External FPR is undefined because the holdout is phishing-only.

## Verification

- Backend pytest: **15 passed**.
- Frontend Vitest: **3 passed**; TypeScript/Vite build: **PASS**.
- Extension tests: **8 passed**; JavaScript syntax checks: **PASS**.
- API contracts `/scan`, `/health`, `/model-info`, and `/history`: **PASS**.

Production artifacts were restored unchanged after the candidate failed the domain-grouped FPR gate. The active production hashes are recorded in `reports/final_training_comparison.json`.
