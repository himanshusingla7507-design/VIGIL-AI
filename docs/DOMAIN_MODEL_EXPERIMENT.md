# Domain Model Experiment

Freshly measured URL-only experiment. The Phishing.Database holdout was not used for training, calibration, or threshold selection. Production artifacts were not modified.

Selected character n-gram range: `(2, 6)`. Ensemble weight: 70% current model + 30% calibrated domain model.

| Model | Random PR-AUC | Domain PR-AUC | External PR-AUC | Domain recall | Domain FNR | Domain FPR | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| current_model | 0.9941 | 0.9939 | 1.0000 | 0.8769 | 0.1231 | 0.0103 | 0.0644 | 0.0517 |
| domain_only_model | 0.9974 | 0.9967 | 1.0000 | 0.9321 | 0.0679 | 0.0086 | 0.0372 | 0.0079 |
| ensemble | 0.9979 | 0.9977 | 1.0000 | 0.8961 | 0.1039 | 0.0109 | 0.0288 | 0.0119 |

External FPR is undefined because the holdout contains phishing URLs only. The candidate was not promoted.
