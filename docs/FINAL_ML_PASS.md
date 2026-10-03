# Final ML Data and Generalization Pass

This pass evaluates the URL-only model and keeps the existing model unless a candidate improves independent holdouts. It does not change the frontend or add domain-specific allowlists. All URLs below were analyzed as strings; none were opened or fetched.

## Baseline preservation and outcome

Before analysis, the active model, feature names, metadata, feature-importance CSV, and random-holdout metrics were copied to [`models/baseline/20261004-pre-ml-pass/`](../models/baseline/20261004-pre-ml-pass/). The model, feature-name, feature-importance, and metrics file hashes still match that snapshot. The root `model_metadata.json` was extended with this pass's report references; the baseline copy remains unchanged.

The selected model remains `CalibratedHistGradientBoosting` v2.1.0 with 29 model features. No candidate passed the independent-holdout recall/F1 gate, so the active pickle and feature-name artifact were not replaced. The detailed reports are:

- [All validation false positives/false negatives, vectors, probabilities, risk, thresholds, and evidence](../reports/error_analysis.json)
- [Model-family and feature-candidate comparison](../reports/model_comparison.json)
- [External-candidate provenance, overlap, and blocker](../reports/external_validation.json)
- [Calibration, threshold sweeps, and legitimate-complexity cohorts](../reports/calibration.json)

## OLD BASELINE and NEW MODEL

The new model is the retained baseline: no candidate was shown to be better on both untouched evaluation splits. Metrics below use the binary diagnostic threshold `p(phishing) >= 0.5`; PR-AUC, ROC-AUC, and Brier score do not depend on that decision threshold. ECE is measured on the corresponding held-out probabilities.

| Split | Model | PR-AUC | ROC-AUC | F1 | FPR | FNR | Brier | ECE |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Random | Old baseline | 0.900621 | 0.884580 | 0.811604 | 2.399% | 29.487% | 0.108365 | 0.004762 |
| Random | New (retained) | 0.900621 | 0.884580 | 0.811604 | 2.399% | 29.487% | 0.108365 | 0.004762 |
| Domain-isolated | Old baseline | 0.906192 | 0.887490 | 0.821024 | 2.804% | 27.824% | 0.106739 | 0.006705 |
| Domain-isolated | New (retained) | 0.906192 | 0.887490 | 0.821024 | 2.804% | 27.824% | 0.106739 | 0.006705 |
| External | Old baseline | Not measured | Not measured | Not measured | Not measured | Not measured | Not measured | Not measured |
| External | New (retained) | Not measured | Not measured | Not measured | Not measured | Not measured | Not measured | Not measured |

The random test contains 46,887 rows. The registered-domain-isolated test contains 47,901 rows and has zero registered domains in common with its training partition. These are two separate evaluations; the external row is deliberately not populated with in-sample or proxy results.

## Error investigation

The report serializes every false positive and false negative on both held-out splits, at both the 0.5 diagnostic cutoff and the configured PHISHING cutoff. Each record includes the URL, registered domain, full 29-feature inference vector, model probability, service-rounded probability, risk score, thresholds, label, error type, and extracted evidence.

| Split | Errors at 0.5 | At configured PHISHING threshold |
|---|---:|---:|
| Random | 647 FP; 5,873 FN | 281 FP; 6,369 FN |
| Domain-isolated | 759 FP; 5,796 FN | 340 FP; 6,282 FN |

Representative domain-isolated errors (dataset labels, not independently adjudicated ground truth):

| Error | URL | Probability | Observed feature evidence |
|---|---|---:|---|
| False positive | `https://www.thefeedbackloop.xyz` | 0.9966 | `HasSuspiciousTLD=1`; no path or suspicious lexical token. The service evidence reports a high model score and HTTPS, while the full vector is in the JSON report. |
| False positive | `https://www.spaceprof.xyz` | 0.9955 | `HasSuspiciousTLD=1`; no path or suspicious lexical token. |
| False positive | `https://www.goncharov.xyz` | 0.9955 | `HasSuspiciousTLD=1`; no path or suspicious lexical token. |
| False negative | `http://www.dh.net.br` | 0.0505 | Short, pathless URL with no suspicious token or digits; only the HTTP evidence rule fires. |
| False negative | `http://www.a.coka.la` | 0.0505 | Short, pathless URL with no suspicious token or digits; only the HTTP evidence rule fires. |
| False negative | `http://www.f.coka.la` | 0.0506 | Short, pathless URL with no suspicious token or digits; only the HTTP evidence rule fires. |

The patterns point to feature and source limitations, not a single threshold defect:

- **Feature weakness / dataset bias:** Domain-aware validation permutation importance is led by `PathLength` (0.21675), `NoOfDigitsInURL` (0.06801), `DotCount` (0.04688), `URLLength` (0.04499), and `HasSuspiciousTLD` (0.03815). Missed phishing URLs have median URL length 22, path length 0, and digit count 0; correctly detected phishing URLs have median URL length 39–41 and median digit count 2. The highest-confidence false positives shown above all have the `.xyz` feature set. These observations are predictive associations in this corpus, not causal or reputation evidence.
- **Class imbalance:** The retained data has 134,849 benign (57.5%) and 99,583 phishing (42.5%) rows. This is moderate rather than extreme imbalance and does not alone explain the missed, short, feature-sparse phishing URLs. HistGradientBoosting does not use class weighting; logistic regression and random forest were tested with their existing balanced class-weight settings.
- **Domain generalization:** Domain isolation did not produce a collapse: PR-AUC is 0.9062 domain-isolated versus 0.9006 random, and FNR is 27.82% versus 29.49% at 0.5. Domain-isolated FPR is somewhat higher (2.80% versus 2.40%). Domain memorization is therefore not supported as the main explanation for this FNR, although the source itself may have collection bias.
- **Label noise:** Preparation removed one conflicting normalized-URL group (two rows). The input has no upstream provenance, so remaining label errors cannot be independently identified or quantified.
- **Redundancy / transport:** Exact aliases and constant features remain excluded; HTTPS is not a model input. The extractor hash and feature order match the retained artifact.
- **Model limitation:** URL-only features cannot distinguish a short phishing host from a structurally similar benign host when there is no path, suspicious token, or other discriminating signal. No web-page, DNS, hosting, or reputation information is available.

The source's legitimate URL complexity is not representative enough to validate every requested case. The domain holdout contains benign examples with digits (670) and hyphens (2,008), and benign subdomains (4,228), but no benign examples with a path of at least 40 characters or parsed query parameters. Thus this dataset cannot substantiate a claim that long paths or query-heavy legitimate URLs are safe. The report gives the per-cohort probability distributions and exposes these zero-count cohorts rather than synthesizing labels.

## Threshold and calibration assessment

The current thresholds are `SAFE=0.13140956` and `PHISHING=0.69615752`. Re-running threshold selection on its separate random threshold-validation partition reproduced both values exactly. A separate domain-aware validation partition selected approximately `SAFE=0.13027`, `PHISHING=0.74986`; this pair was not substituted into the model because its independent domain test trades away recall for a small FPR decrease.

The thresholds have different jobs:

- Increasing SAFE reclassifies more URLs as SAFE, but rapidly increases phishing that is incorrectly shown SAFE. On separate random threshold validation, false-SAFE rate rises from 1.90% at SAFE 0.1314 to 14.51% at 0.18; domain-aware validation rises from 1.99% at SAFE 0.1303 to 13.23% at 0.18. The corresponding holdout rates are 2.19% to 15.35% random and 3.32% to 14.80% domain-isolated (the domain holdout table uses the domain-tuned SAFE threshold). The seven named legitimate references other than fast.com have probabilities 0.1561–0.1803, so raising SAFE enough to mark them SAFE would violate the validation false-SAFE budget. They were inspected post hoc and were not used to tune thresholds.
- Lowering PHISHING from 0.6962 to 0.5 on the domain holdout changes FPR from 1.26% (340 false positives) to 2.80% (759), while FNR improves from 30.16% (6,282 false negatives) to 27.82% (5,796). Raising it to 0.8 reduces FPR to 0.76% but increases FNR to 31.53%. This is a real trade-off, not a simultaneous improvement.

Calibration on untouched holdouts is Brier 0.108365 / ECE 0.004762 random and Brier 0.106739 / ECE 0.006705 domain-isolated. ECE uses 10 equal-width probability bins; reliability bins and threshold sweeps are in `calibration.json`.

## Model and URL-feature experiments

Logistic Regression, Random Forest, and HistGradientBoosting were compared on the same domain-aware validation split, with candidate binary metrics at 0.5:

| Model | PR-AUC | F1 | FPR | FNR | Brier | Fit (s) | Median one-row (ms) | Serialized model |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.907896 | 0.826703 | 5.577% | 25.013% | 0.117390 | 0.796 | 0.452 | 1,542 B |
| Random Forest | 0.919679 | 0.839430 | 4.545% | 23.884% | 0.106696 | 10.567 | 26.178 | 169,620,393 B |
| HistGradientBoosting | 0.922619 | 0.840344 | 2.431% | 25.506% | 0.101912 | 1.121 | 1.548 | 367,843 B |

Random Forest lowers validation FNR but has materially higher FPR, lower PR-AUC/F1 than HistGradientBoosting, much larger serialized size, and higher one-row latency. HistGradientBoosting remains the better balanced candidate under the project's stated criteria.

Six URL-only extensions were tested: hostname/path/query entropy, path-token count, path digit ratio, and punycode-label count. They were generated from the same normalized representation as inference to avoid train/serve skew. Although validation PR-AUC and FPR moved slightly in the favorable direction, F1/FNR regressed on both untouched holdouts:

| Split | Baseline PR-AUC / F1 / FPR / FNR / Brier | Extended-feature candidate PR-AUC / F1 / FPR / FNR / Brier |
|---|---|---|
| Domain validation | 0.922619 / 0.840344 / 2.431% / 25.506% / 0.101912 | 0.92327 / 0.84052 / 2.366% / 25.533% / 0.10173 |
| Random holdout | 0.900621 / 0.811604 / 2.399% / 29.487% / 0.108365 | 0.90087 / 0.81131 / 2.240% / 29.678% / 0.10824 |
| Domain-isolated holdout | 0.906192 / 0.821024 / 2.804% / 27.824% / 0.106739 | 0.90636 / 0.82048 / 2.649% / 28.045% / 0.10672 |

The candidate did not reduce FNR or improve F1 on either holdout, so the six features were not retained. The original 29-feature schema, feature list, model, and thresholds remain active.

The calibrated candidate bundle was 1,107,569 bytes versus 1,100,240 bytes for the retained artifact; measured direct-prediction median was 6.47 ms versus 6.95 ms. Its small size/latency improvement does not outweigh the FNR/F1 regressions.

## External-data validation and temporal status

The candidate examined was the **PhiUSIIL Phishing URL Dataset — IF3070 coursework split**, from [the documented coursework repository](https://github.com/fetiai/phiusiil-if3070-stei-itb-2024-2025-1), which identifies [UCI dataset ID 967](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) as its upstream source. Its README cites the 2024 PhiUSIIL publication and declares CC BY 4.0. The coursework README describes 140,404 labelled rows; label `1` is legitimate and label `0` phishing, opposite to VIGIL's convention. The URL field is compatible with URL-only features in principle, but 43,487 rows have no usable URL and its page-derived columns cannot be reproduced by VIGIL.

The downloaded candidate contained 96,917 rows with usable URL strings and 93,773 registered domains. Normalized URL overlap with VIGIL's local dataset was 96,915/96,917 (99.9979%); all overlapping labels agree after reversing polarity. This is a resampled split of the same upstream corpus, not independent evidence. It was kept out of training and external scoring. Consequently all external precision/recall/F1/ROC-AUC/PR-AUC/FPR/FNR/Brier/ECE fields are null in `external_validation.json`, not fabricated or reported as zero.

The second candidate, **ISCX-URL-2016** ([official CIC page](https://www.unb.ca/cic/datasets/url-2016.html)), is described as having distinct benign, phishing, spam, malware, and defacement classes. It was not used: the official download was not available for inspection in the existing source check, no reuse license was verified, and collapsing its non-phishing classes into benign would be inappropriate. The corpus cannot supply valid external metrics until access, licensing, URL rows, and overlap can be verified.

No temporal validation was run. VIGIL's local CSV contains no reliable collection dates, and the coursework split provides no per-URL collection dates. Dates were not inferred or fabricated.

## Artifacts, regressions, and limitations

- `phishing_model.pkl`: retained baseline artifact, 1,100,240 bytes; the SHA-256 matches the frozen baseline.
- `feature_names.pkl`: retained 29-feature list; the SHA-256 matches the frozen baseline.
- `model_metadata.json`: updated with final-pass metrics, report paths, thresholds, and inference timing.
- `feature_importance.csv`: retained for the active model; its SHA-256 matches the frozen baseline. The fresh domain-validation importance ranking is also in `error_analysis.json`.
- `fast.com` regression: `https://fast.com/`, `https://fast.com`, and `https://www.fast.com/` all return SAFE with probability 0.060029 and risk score 0. No domain rule was added.
- Inference timing on this local Windows environment: `predict_proba` median 6.95 ms / p95 9.77 ms; end-to-end cached service median 7.22 ms / p95 9.18 ms. These timings are local measurements, not deployment guarantees.
- Regression suite: 15/15 tests passed, including a new canonicalization regression for experimental URL features. No existing test expectation was weakened or changed.

Remaining limitations are the undocumented single-source local corpus, undetected label noise, absence of date metadata, sparse legitimate examples with long paths/queries, residual high FNR, threshold-dependent false-positive/false-negative trade-offs, and lack of independent external validation. This URL-only classifier is not a guarantee of safety or maliciousness.
