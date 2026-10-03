# Model evaluation

This report describes the latest checked-in metadata for model `v2.1.0` (`CalibratedHistGradientBoosting`). The machine-readable source is [`reports/metrics.json`](../reports/metrics.json); training metadata is [`model_metadata.json`](../model_metadata.json).

## Dataset

The prepared dataset contains 234,432 rows from the local `final_dataset_v2.csv`: 134,849 label `0` and 99,583 label `1`, with 197,707 unique registered domains. Preparation removed 936 duplicate rows and 2 rows from one conflicting-label group. The source has no upstream provenance, license fields, or collection dates. No external dataset was merged.

The extractor computes 29 URL-structure features. Examples include URL and hostname lengths, path/query structure, digit and letter ratios, subdomain depth, percent encoding, userinfo, explicit ports, IP hosts, shortened URLs, suspicious TLDs/tokens, and entropy. `IsHTTPS` is retained for evidence but excluded from training after protocol counterfactuals showed a spurious probability shift.

## Holdout results

| Evaluation | Rows | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Stratified random holdout | 46,887 | 0.861 | 0.956 | 0.705 | 0.812 | 0.885 | 2.4% |
| Registered-domain-aware holdout | 47,901 | 0.863 | 0.952 | 0.722 | 0.821 | 0.887 | 2.8% |

The random split has 3,272 overlapping registered domains between train and test. The domain-aware split uses `GroupShuffleSplit` by registered domain and reports zero overlapping domains, making it the more informative generalization check in this repository. Neither result is a real-world accuracy estimate.

## Calibration and external checks

The random holdout expected calibration error is 0.0048 and the Brier score is 0.1084. Thresholds recorded by training are `safe = 0.1314095638` and `phishing = 0.6961575221`; the service maps the interval between them to the intermediate `SUSPICIOUS` state.

Temporal evaluation was not run because no usable collection dates are present. External validation is not currently reported because an independently licensed compatible source was not integrated. Synthetic regression examples are kept separately in `validation_report.md` and should not be confused with an independent test set.

## Interpretation

The evaluation supports the engineering behavior of the current pipeline on its prepared data. It does not establish performance against current live phishing, unseen campaigns, changing URL conventions, or a production prevalence distribution. Future reports should preserve the split strategy, dataset hash, feature-extractor hash, and provenance information.
