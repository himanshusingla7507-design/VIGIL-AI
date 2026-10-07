# Dynamic URL False Positive Analysis

## DO NOT PROMOTE

### Root cause

The current 29-feature URL model learned a one-sided training pattern: legitimate training URLs are homepages, while every labeled URL with a path or query is phishing. Its tree splits consequently treat /search and simple query punctuation as decisive phishing signals.

Counterfactuals isolate the features: YouTube changes from probability 0.167584 to 0.738847 when its ordinary `?feature=ytca` query is added. Google changes from 0.174197 to 0.998018 when the `/search` path is added; its query does not cause the increase.

### Labeled data and cohorts

The prepared corpus contains 854,870 unique URLs. All legitimate labels are from the existing PhiUSIIL source. No URL has been assigned a new label.

| URL cohort | Legitimate | Phishing |
|---|---:|---:|
| homepage | 134,849 | 220,445 |
| path only | 0 | 377,872 |
| query only | 0 | 9,800 |
| path plus query | 0 | 111,720 |
| long query over 100 chars | 0 | 42,549 |
| multiple query parameters | 0 | 48,999 |
| encoded characters | 0 | 15,440 |
| long url over 200 chars | 0 | 40,014 |
| high entropy over 4 | 32,086 | 574,757 |
| redirect or tracking parameter | 0 | 4,527 |
| fragment | 0 | 831 |
| repeated punctuation | 1 | 24,787 |

The legitimate cohort has 134,849 homepage URLs and zero path-only, query-only, or path-plus-query examples. The existing labeled corpus therefore cannot supervise a model to distinguish ordinary dynamic legitimate URLs from malicious dynamic URLs.

The original PhiUSIIL CSV was also checked (235,795 rows; source label 1 means legitimate): it contains 0 legitimate dynamic URLs. This is not a cleaning-stage loss.

All 854,870 eligible rows were retained in candidate fitting. The Phishing.Database-only source was sample-weighted to the prior 1.5:1 phishing-to-legitimate policy instead of being selected by row count. Source weights and raw source counts are recorded in the JSON report.

### Controlled production feature changes

| URL | Hostname only | Host + path | Host + path + query |
|---|---:|---:|---:|
| Google search q=test | 0.174197 | 0.998018 | 0.998018 |
| Google search q=cybersecurity | 0.174197 | 0.998018 | 0.997715 |
| YouTube feature=ytca | 0.167584 | 0.167584 | 0.738847 |
| Google homepage | 0.174197 | 0.174197 | 0.174197 |

Per-feature one-at-a-time substitutions from hostname-only vectors are recorded in JSON. They identify `PathLength` and `QueryLength` as the largest independent score shifts for these examples; tree feature interactions mean the individual effects are not additive.

### Candidate regression scores

| URL | Production probability | Improved URL probability | Hostname probability | Combined probability | Combined verdict |
|---|---:|---:|---:|---:|---|
| `https://www.google.com/` | 0.174197 | 0.999290 | 0.574287 | 0.998759 | PHISHING |
| `https://www.google.com/search?q=test` | 0.998018 | 0.999290 | 0.574287 | 0.998759 | PHISHING |
| `https://www.google.com/search?q=cybersecurity` | 0.997715 | 0.999290 | 0.574287 | 0.998759 | PHISHING |
| `https://www.youtube.com/` | 0.167584 | 0.999290 | 0.508045 | 0.998266 | PHISHING |
| `https://www.youtube.com/?feature=ytca` | 0.738847 | 0.999290 | 0.508045 | 0.998266 | PHISHING |
| `https://fast.com/` | 0.060029 | 0.999290 | 0.988661 | 0.999847 | PHISHING |

Existing phishing fixtures were kept out of fitting and evaluated after training:

| Phishing regression URL | Production probability | Improved URL probability | Hostname probability | Combined probability | Combined verdict |
|---|---:|---:|---:|---:|---|
| `http://secure-login-paypal-account.xyz` | 0.958286 | 0.999290 | 0.989909 | 0.999848 | PHISHING |
| `http://verify-your-bank-update.ml` | 0.979292 | 0.999290 | 0.989901 | 0.999848 | PHISHING |
| `http://amazon-security-alert.ga/login` | 0.997792 | 0.999290 | 0.989883 | 0.999848 | PHISHING |
| `http://free-bonus-crypto.xyz/claim` | 0.997802 | 0.999290 | 0.989883 | 0.999848 | PHISHING |
| `http://google-account-verify.cf` | 0.996937 | 0.999290 | 0.989909 | 0.999848 | PHISHING |
| `https://paypal-login.example.com/verify-account` | 0.997742 | 0.999290 | 0.989419 | 0.999848 | PHISHING |
| `http://secure-bank-login.example.com/update-account` | 0.997742 | 0.999290 | 0.989692 | 0.999848 | PHISHING |
| `http://microsoft-security.example.com/login` | 0.997715 | 0.999290 | 0.989153 | 0.999848 | PHISHING |
| `http://free-iphone-winner.example.com/claim` | 0.997750 | 0.999290 | 0.985430 | 0.999845 | PHISHING |
| `http://account-verify.example.com/signin/password` | 0.997742 | 0.999290 | 0.989396 | 0.999848 | PHISHING |

### Candidate models

| Model | Test FPR | Phishing recall | FNR | PR-AUC | Brier | ECE | Median latency (ms) | Size (bytes) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| current_production | 0.01031348543869412 | 0.876936 | 0.123064 | 0.993901 | 0.064382 | 0.051695 | 7.9308 | 1,100,240 |
| improved_url_features | 0.010647375255054721 | 0.993686 | 0.006314 | 0.999682 | 0.006544 | 0.005487 | 5.6851 | 448,544 |
| hostname_character_model | 0.009905397885364497 | 0.911283 | 0.088717 | 0.996733 | 0.040080 | 0.029182 | 6.7247 | 4,584,775 |
| combined_url_hostname | 0.009868299016879986 | 0.996059 | 0.003941 | 0.999865 | 0.005316 | 0.004642 | 5.8841 | 5,033,237 |

Thresholds used to report candidate verdict/FPR/recall are selected on a separate domain-grouped threshold partition and are research-only; production thresholds were not changed.

### Phishing-only external holdout

The 154,931-row external holdout remained byte-for-byte unchanged and was evaluated only after training. Recall/FNR:

| Model | Recall | FNR | FPR |
|---|---:|---:|---:|
| current_production | 0.912400 | 0.087600 | undefined |
| improved_url_features | 0.993713 | 0.006287 | undefined |
| hostname_character_model | 0.960886 | 0.039114 | undefined |
| combined_url_hostname | 0.996411 | 0.003589 | undefined |

External FPR is undefined because the external holdout contains phishing URLs only.

### Regressions and decision

All manually observed Google, YouTube, and fast.com URLs were used only for regression scoring. Existing project phishing URLs were also scored after fitting. No domains are allowlisted and no exceptions or score boosts are added.

**DO NOT PROMOTE**

Tests: pytest PASS (15 passed); frontend_vitest PASS (3 passed); frontend_build_typescript_vite PASS; extension_tests PASS (23 passed); javascript_syntax_checks PASS

Promotion is blocked because the verified legitimate dynamic-URL cohort is empty: its FPR cannot be demonstrated within budget, and the provided real dynamic URLs must not be used as training labels. Production model artifacts, feature names, metadata, thresholds, frontend, and extension are not changed by this experiment.
