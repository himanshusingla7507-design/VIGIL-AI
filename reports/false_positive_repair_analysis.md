# VIGIL-AI false-positive repair results

## Executive result

The requested baseline is confirmed in [`auto_ml_final_evaluation.json`](./auto_ml_final_evaluation.json): the selected `realworld_v3` model had 34/600 legitimate false positives (5.67%) and 301/392 phishing detections (76.79%) on benchmark v1. Its internal domain-disjoint test had 94/1,039 legitimate false positives (9.05%) and 781/1,039 phishing detections (75.17%).

Five controlled experiments were run with a maximum budget of 15. The best candidate by validation-only selection is the character 3–5-gram TF-IDF plus numeric-feature logistic model. It improves phishing recall and probability ranking, but **does not reduce false positives at its validation-selected operating point**: on the internal test it has 162/1,039 legitimate false positives (15.59%), and on benchmark v1 51/600 (8.50%). Recall is 96.92% internal and 97.19% on benchmark v1. It fails promotion gates and remains isolated; no production artifact was changed.

Benchmark v1 and the old internal test have been reported in prior work, so the benchmark is regression-only and the internal test is a repeatability check, not a newly sourced independent lockbox. Independent hard-phishing recall is therefore **UNVERIFIED**.

## Data, provenance, and split checks

Inputs were the provenance-bearing [`legitimate_urls_realworld_v3.csv`](../legitimate_urls_realworld_v3.csv) and [`phishing_database_active.txt`](../data/external/phishing_database_active.txt), loaded through the existing normalizer/registered-domain functions in [`run_realworld_experiments.py`](../experiments/auto_ml/run_realworld_experiments.py).

| Input | Raw rows | Retained unique normalized URLs | Registered domains |
|---|---:|---:|---:|
| Legitimate, label 0 | 138,030 | 136,700 | 189 |
| Active phishing feed, label 1 | 789,054 | 751,113 | 323,196 |

The collector retained legitimate source name, source page, category, and verification method. Its largest legitimate sources by row count were NASA (29,545), GOV.UK (20,012), The GitHub Blog (18,497), and RFC Editor (10,252). The feed labels identify listing in the active phishing feed; they are not independent verification of current live behavior.

There were zero normalized legitimate duplicates, 79 normalized phishing duplicates removed, 674 invalid/non-HTTP phishing feed lines discarded, and zero exact normalized-URL label conflicts. Any conflict would exclude the legitimate copy in favor of the phishing-feed label. Benchmark reservation excluded 1,330 legitimate and 37,188 phishing rows across 407 registered domains. All four registered-domain splits are disjoint. The selected sample is balanced by row count, but its train split contains 129 legitimate versus 2,723 phishing domains; calibration contains 10 versus 255, and validation 19 versus 420. Equal row quotas therefore do not mean equal source/domain coverage.

The full legitimate set remains skewed to content paths (126,271 category rows). Sparse structures include tracking (77), login/account (119), search (133), long queries (234), encoding (343), pagination (593), and fragments (477). The sampled internal test has only 1 legitimate pagination URL and no fragment URLs, so those cohort results cannot establish reliability.

The runner checked feature parity against `service.scan()` on 50 identical URLs: all extracted features matched. Training and serving both use `extract_features` from [`feature_extractor.py`](../feature_extractor.py); there is no separate experimental feature extractor in the new path.

## Metrics on identical examples

The previous candidate's original config phishing cutoff was 0.85. New candidates fit a sigmoid calibrator on calibration domains and choose the phishing cutoff using validation only, subject to `PHISHING > SAFE=0.45`. The selected n-gram model's cutoff is 0.481771. The 0.85 rows below are the original candidate at its historical cutoff; do not confuse them with the new model's validation-selected operating point.

### Internal domain-disjoint test

| Model / policy | Legitimate FP | Phishing FN | Recall | Precision | Brier | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Historical `realworld_v3`, original cutoff 0.85 | 94/1,039 (9.05%) | 258/1,039 (24.83%) | 75.17% | 89.26% | 0.1158 | 0.9285 |
| Best repair candidate, validation cutoff 0.481771 | 162/1,039 (15.59%) | 32/1,039 (3.08%) | 96.92% | 86.14% | 0.0658 | 0.9760 |
| Production service, metadata cutoff 0.696158 | 1,013/1,039 (97.50%) | 9/1,039 (0.87%) | 99.13% | 50.42% | 0.4889 | — |

The internal set contains 1,039 URLs per class, from 24 legitimate and 793 phishing registered domains. It is cohort/class sampled, not a natural-prevalence test.

### Fixed benchmark v1 (regression-only)

| Model / policy | Legitimate FP | Phishing FN | Recall | Precision | Brier | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Historical `realworld_v3`, original cutoff 0.85 | 34/600 (5.67%) | 91/392 (23.21%) | 76.79% | 89.85% | 0.0995 | 0.9314 |
| Best repair candidate, validation cutoff 0.481771 | 51/600 (8.50%) | 11/392 (2.81%) | 97.19% | 88.19% | 0.0470 | 0.9792 |
| Production service, metadata cutoff 0.696158 | 599/600 (99.83%) | 0/392 (0%) | 100% | 39.56% | 0.6008 | — |

On the 16-URL core legitimate regression set, the historical candidate had 1 PHISHING verdict; the repair candidate has 4. The benchmark candidate recall exceeds 97% numerically but is not evidence of independent hard-phishing performance because benchmark v1 has been repeatedly reported.

### Validation-led experiment results

The threshold rule searches validation probabilities only. If validation cannot reach 98% phishing recall while keeping the phishing cutoff above the safe cutoff, it chooses maximum attainable validation recall and then minimum false-positive rate. The n-gram candidate could not reach 98% on validation: it produced 18/510 legitimate FPs (3.53%), 492/510 recall (96.47%), and precision 96.47%.

| New experiment | Validation FP | Validation recall | Outcome |
|---|---:|---:|---|
| HGB baseline, domain-weighted | 57/510 (11.18%) | 474/510 (92.94%) | No meaningful improvement |
| HGB without dynamic-structure group | 50/510 (9.80%) | 469/510 (91.96%) | Meaningful validation improvement; became incumbent |
| HGB without suspicious-token/TLD indicators | 99/510 (19.41%) | 461/510 (90.39%) | Rejected; worse |
| HGB without inverse domain weights | 109/510 (21.37%) | 472/510 (92.55%) | Rejected; worse |
| Character 3–5-grams + numeric features | 18/510 (3.53%) | 492/510 (96.47%) | Best validation objective; selected for one final evaluation |

On those same 1,020 validation examples, production at its metadata cutoff produced 490/510 legitimate false positives (96.08%) and 9/510 phishing false negatives (1.76%). Candidate and production source/domain/structure error groupings are stored in every trial report. Final test and fixed-benchmark results were opened only after validation-based selection; they were not used to choose the candidate or its threshold.

All candidate configurations, artifacts, dataset manifests, validation metrics, and validation failure reports are under [`false_positive_repair_20261009T084933Z`](../experiments/auto_ml/false_positive_repair_20261009T084933Z/). The run completed five predeclared controlled hypotheses and stopped under condition D: there is no new independent hard-phishing lockbox, and the existing final datasets have prior exposure. The 15-experiment ceiling was not treated as a reason to invent more trials against reused validation data.

## Error patterns and evidence

Candidate false-positive and false-negative cohort counts on the internal test are overlapping: a URL may belong to multiple cohorts.

| Structure | Legitimate FPs | Phishing FNs |
|---|---:|---:|
| Query | 99/172 (57.56%) | 6/214 |
| Multiple parameters | 50/98 (51.02%) | 3/116 |
| Percent-encoded | 32/49 (65.31%) | 0/50 |
| Long query | 10/24 (41.67%) | 3/45 |
| Long URL | 3/14 (21.43%) | 2/29 |
| Content path | 159/1,004 (15.84%) | 29/985 |
| Login/account | 29/177 (16.38%) | 4/178 |
| Docs | 0/172 | 4/92 |
| Tracking | 0/22 | 2/23 |
| API endpoint | 1/46 (2.17%) | 3/43 |

The largest legitimate false-positive sources were The GitHub Blog (`github.blog`, 134/222), Stanford (`stanford.edu`, 9/38), JSONPlaceholder (`typicode.com`, 6/7), and Wells Fargo (`wellsfargo.com`, 11/91). All 32 internal-test phishing false negatives are from the active feed. The error table and up to 100 actual examples per error class are in [`false_positive_repair_failure_analysis.json`](./false_positive_repair_failure_analysis.json).

Examples from the provenance-bearing legitimate test rows that the selected candidate flagged include:

- `https://github.blog/wp-content/uploads/2023/06/15.0@2x.png?resize=1024,565` (query; score 0.9671).
- `https://github.blog/wp-content/uploads/2020/05/Blog-1200x630-Satellite-Recap@2x.png?fit=2400%2C1260` (encoded query; score 0.9665).
- `https://jsonplaceholder.typicode.com/posts/1` (content path; score 0.9594).

Feed-listed phishing examples missed by the selected candidate include `https://www.cashum.unam.mx/wp-content/backups-dup/imports/index.htm`, `https://cyberschoke.net/freegift`, and `https://whattssapp.com`. Their provenance is the phishing feed, not an independently verified live phishing outcome.

The selected model's false-positive rows have higher mean digit ratio (0.156 vs 0.032 for correct legitimate rows), obfuscation flag frequency (0.198 vs 0.019), and lower trusted-TLD indicator frequency (0.173 vs 0.899). These are associations, not proof that any one feature caused a verdict. In validation-only one-feature permutation of the reference HGB, hostname length and trusted-TLD status had the largest average-precision drops; correlated signals make this diagnostic non-causal. Removing suspicious-token/TLD indicators as a group made validation FPR worse (19.41%), so broad removal is not supported.

The measured query/multiple-parameter/encoding FPRs remain high. The data establishes strong structure/source association; it does **not** establish that the structure alone caused each prediction. The concentrated `github.blog` errors, sparse verified dynamic sources, and source/domain imbalance make collection/sampling bias a credible hypothesis that needs new unseen-source examples.

## Calibration, thresholds, timing, and artifacts

- Best validation candidate (not production-recommended): [`best_validation_candidate.joblib`](../experiments/auto_ml/false_positive_repair_20261009T084933Z/best_validation_candidate.joblib), SHA-256 `06e7e19c7552809e1cbca87a3f2d1586731107bc00c397330efb225e69a7fa1e`, 458,096 bytes.
- On the internal test: Brier 0.0658 and 10-bin expected calibration error 0.0599. On benchmark v1: Brier 0.0470 and ECE 0.0490. These are balanced/curated evaluation sets; calibration at production prevalence is unverified.
- Inference with feature extraction: median 5.09 ms/URL, p95 6.10 ms/URL over 300 internal-test URLs.
- Candidate artifact hash was verified after reload and predictions reproduced. Production hashes before and after matched exactly:

| Protected file | SHA-256 |
|---|---|
| `phishing_model.pkl` | `5f16e09d5f6fb613d391051b2b5693cf47478356d77cec8c8e52f5b309159ba2` |
| `feature_names.pkl` | `d02a7c9cd2cb5b73c2bbccc7347c240fed6d77593b8e7d602dbb67f424099da9` |
| `model_metadata.json` | `76f11a2883837c0226898d9a37d28a58475d5bdedc013e9f7969a43a493feba9` |
| `feature_extractor.py` | `826436788ddf02e2dfe76c55cf6e062bab297c3cf1ead4602e4533c446733874` |
| `service.py` | `10834ae85143560c5fe3defc665f31ab0eeed9b6ce6f3a19f8e0ed582328cf23` |
| `config.py` | `23ef9dfe2390e605ab866d99abd5ba7b4e6a7cc7bc09a7a15497991d1ecc7dfb` |

## Tests and acceptance gates

- Backend pipeline: **14 passed, 1 failed**. The existing failure is `ModuleNotFoundError: No module named 'scripts.final_ml_pass'` in `test_experimental_url_features_share_serving_canonicalization`. It is a pre-existing missing module; no unrelated module was created.
- Extension: **23 passed, 0 failed** (`node --test extension.test.mjs background.runtime.test.mjs`).
- Domain split/label conflict checks: PASS; zero registered-domain overlaps and zero exact normalized-URL label conflicts.
- Feature extraction parity: PASS, 50 URLs matched `service.scan()`.
- Candidate artifact integrity and latency collection: PASS.
- Core legitimate zero-PHISHING gate: FAIL (4/16).
- Benchmark legitimate FPR ≤0.5%: FAIL (51/600 = 8.50%).
- Internal domain-disjoint recall ≥98%: FAIL (1,007/1,039 = 96.92%).
- Independent hard-phishing benchmark recall ≥97%: UNVERIFIED (benchmark v1 is not independent).
- Major hard-phishing cohort regression: FAIL; long-query recall is 6.67 percentage points below production on 45 phishing rows.
- No systematic dynamic-structure false-positive signal: FAIL; query, multiple-parameter, and encoded legitimate cohorts exceed 5% FPR.
- Overall candidate eligibility: **FAIL**. Candidate not promoted or deployed.

## Next engineering action

Do not adjust production thresholds or deploy this candidate. The highest-value next step is to add independently collected, provenance-reviewed legitimate search/query/encoded/account URLs across many new first-party domains, plus an independently sourced domain-disjoint hard-phishing lockbox. Reserve both at domain/source level before any further model or threshold selection. Then rerun the same bounded, validation-only process and report the lockbox once.
