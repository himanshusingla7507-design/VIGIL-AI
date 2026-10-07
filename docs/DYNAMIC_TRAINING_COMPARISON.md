# VIGIL Dynamic URL Training

## DO NOT PROMOTE

Selected model: `random_forest`

Total training rows: **1,021,986**

Legitimate: **301,968**

Phishing: **720,018**

Verified dynamic legitimate URLs: **167,119**

| Model | Recall | FNR | FPR | PR-AUC | F1 | Brier | ECE | Median ms | Size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.8632 | 0.1368 | 0.2668 | 0.9610 | 0.8748 | 0.1165 | 0.0352 | 0.582 | 1,938 |
| random_forest | 0.8986 | 0.1014 | 0.1686 | 0.9788 | 0.9131 | 0.0860 | 0.0206 | 14.861 | 248,367,873 |
| hist_gradient_boosting | 0.8907 | 0.1093 | 0.1667 | 0.9773 | 0.9091 | 0.0889 | 0.0206 | 1.599 | 372,224 |

## External Holdout

Recall: **0.7017**

FNR: **0.2983**

External FPR is undefined because the holdout contains phishing URLs only.
