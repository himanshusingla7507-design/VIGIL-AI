# VIGIL-AI: evidence-based next-experiment plan

## Scope and conclusion

This is an analysis of the completed `realworld_v3` run, not a new training run. No production files, feature code, thresholds, datasets, or extension behavior were changed. The selected candidate is `hist_gradient_regularized_calibrated` in [`realworld_v3`](../experiments/auto_ml/realworld_v3/experiment_report.json); its implementation and sampling logic are in [`run_realworld_experiments.py`](../experiments/auto_ml/run_realworld_experiments.py).

The candidate improves ranking and legitimate false positives over the production model on the examples inspected, but it misses too much phishing to satisfy the recall gates. Query-bearing legitimate errors are real and concentrated in a few sources/domains, but available evidence does not isolate query features as their sole cause. Hostname length and trusted-TLD status had the strongest individual permutation effects on validation; feature correlation means these are importance signals, not causal explanations.

## Same-example comparison

The internal domain-disjoint test has 1,039 legitimate and 1,039 phishing rows. The fixed benchmark has 600 legitimate and 392 phishing rows. Both are balanced/curated evaluation sets, not estimates of deployment prevalence.

The experiment candidate used `SAFE=0.45` and `PHISHING=0.85` from the experiment configuration. Production `service.scan()` instead uses metadata thresholds `SAFE=0.1314096` and `PHISHING=0.6961575`. Probability metrics are threshold-independent; verdict comparisons below distinguish the common `0.85` phishing cutoff from the production service's actual metadata cutoff.

| Evaluation | Model / decision policy | Legitimate false positives | Phishing false negatives | Recall | Precision | Brier | PR-AUC |
|---|---|---:|---:|---:|---:|---:|---:|
| Internal test | Candidate, `PHISHING=0.85` | 94/1,039 (9.05%) | 258/1,039 (24.83%) | 75.17% | 89.26% | 0.1158 | 0.9285 |
| Internal test | Production, common `PHISHING=0.85` | 1,013/1,039 (97.50%) | 10/1,039 (0.96%) | 99.04% | — | 0.4889 | 0.5206 |
| Internal test | Production, service metadata `PHISHING=0.6962` | 1,013/1,039 (97.50%) | 9/1,039 (0.87%) | 99.13% | 50.42% | 0.4889 | 0.5206 |
| Fixed benchmark | Candidate, `PHISHING=0.85` | 34/600 (5.67%) | 91/392 (23.21%) | 76.79% | 89.85% | 0.0995 | 0.9314 |
| Fixed benchmark | Production, common `PHISHING=0.85` | 598/600 (99.67%) | 0/392 (0%) | 100% | — | 0.6008 | 0.3873 |
| Fixed benchmark | Production, service metadata `PHISHING=0.6962` | 599/600 (99.83%) | 0/392 (0%) | 100% | 39.56% | 0.6008 | 0.3873 |

Common-cutoff rows compare the models at the same phishing decision boundary. Service-cutoff rows show the deployed production behavior. Do not interpret the earlier production verdict counts in the final evaluation report as service-native: that report applied config thresholds to saved production scores, while `service.scan()` uses the metadata values above. This changes the production count by one false positive on the benchmark and by one false negative on the internal test.

The candidate's domain-disjoint validation result was 5/510 legitimate false positives (0.98%) and 109/510 phishing false negatives (21.37%), with Brier 0.0677, PR-AUC 0.9746, and ROC-AUC 0.9691. Its later internal-test FPR/recall deterioration is substantial. No model passes the acceptance gates.

## Error structure and provenance

### Candidate errors on the internal test

The following URL-structure cohorts overlap; their counts are not additive. Rates use each cohort's class-specific denominator.

| Cohort | Legitimate false positives | Phishing recall errors |
|---|---:|---:|
| Query | 78/172 (45.35%) | 49/214 false negatives |
| Multiple parameters | 38/98 (38.78%) | 23/116 false negatives |
| Percent-encoded | 19/49 (38.78%) | 11/50 false negatives |
| Long query | 5/24 (20.83%) | 5/45 false negatives |
| Long URL | 2/14 (14.29%) | 1/29 false negatives |
| Tracking | 1/22 (4.55%) | 9/23 false negatives |
| Docs | 0/172 | 27/92 false negatives |
| Login/account | 2/177 (1.13%) | 35/178 false negatives |
| Fragment | 0 legitimate rows | 0 phishing rows |
| API endpoint | 0/46 | 11/43 false negatives |

The test lacks fragment examples, and several cohorts are small; zero observed errors is not evidence of zero risk.

False positives by source/domain:

| Source / registered domain | False positives / legitimate rows |
|---|---:|
| The GitHub Blog / `github.blog` | 74/222 (33.3%) |
| `merriam-webster.com` | 7/43 (16.3%) |
| JSONPlaceholder / `typicode.com` | 6/7 (85.7%) |
| `stanford.edu` | 4/38 (10.5%) |
| `wellsfargo.com` | 2/91 (2.2%) |
| `ucla.edu` | 1/45 (2.2%) |

Actual observed legitimate examples include:

- `https://github.blog/wp-content/uploads/2023/06/15.0@2x.png?resize=1024,565` — candidate score 0.940.
- `https://github.blog/wp-content/uploads/2022/04/microsoft-logo.png?w=100&h=100&crop=1` — score 0.907.
- `https://github.blog/wp-content/uploads/2019/05/satellite-blog-2.png?fit=2400%2C1260` — score 0.859.
- `https://jsonplaceholder.typicode.com/` — score 0.943.
- `https://www.merriam-webster.com/about-us` — score 0.882.

The source/domain rows are from the sampled internal test and carry source metadata; source and domain are not model input features. Within the 94 candidate legitimate false positives, 78 are query URLs, 38 have multiple parameters, and 19 are encoded (overlapping cohorts). Of the query false positives, 71/78 are from `github.blog`; all 19 encoded false positives and 36/38 multiple-parameter false positives are also from that domain. This concentration supports a source/structure coverage hypothesis, not a domain-specific model mechanism.

The 258 candidate phishing false negatives all come from the active phishing feed. Most frequent registered domains in those misses are `tamparealu.com` (14), `jadwaah.com` (7), `iguidetours.ca` (6), and `taplink.cc` (5). These are counts, not domain-specific error rates; the report does not provide stable denominators for these small test-domain groups.

On the fixed benchmark, 34 candidate legitimate false positives are concentrated in `djangoproject.com` (19), `wikipedia.org` (13), and `mozilla.org` (2). The 70 curated counterfactual rows are benchmark transformations, not observed URLs and not training examples. Three were classified PHISHING, all derived from a Stack Overflow base: the `/search` variant (0.894), `?q=test&page=2` (0.917), and `?q=cyber%20security` (0.857). This is evidence of sensitivity to these particular transformations only.

### Feature evidence and limitations

On the internal test, candidate false positives versus correctly non-PHISHING legitimate URLs had higher average feature values: `NoOfDigitsInURL` 19.12 vs 3.80; `URLLength` 80.73 vs 69.44; `QueryLength` 18.80 vs 7.68; and `QueryParameterCount` 1.56 vs 0.26. `IsTrustedTLD` averaged 0.21 vs 0.84. These are associations among observed errors, not isolated feature effects.

As a diagnostic only, individual-feature permutation on the candidate's 510/510 validation set (12 shuffles per feature, candidate fixed at `PHISHING=0.85`) reduced average precision by 0.2470 for `HostnameLength` and 0.0357 for `IsTrustedTLD`; the corresponding mean drops were 0.0023 for `QueryLength`, 0.0011 for `NoOfDigitsInURL`, 0.0004 for `URLLength`, and 0.0003 for `QueryParameterCount`. Correlated URL features make independent permutation disruptive and these results are not causal or an ablation experiment. They do not support claiming that query count alone drives the false positives.

## Labels, sampling, calibration, and thresholds

- The input legitimate set had 138,030 rows from 210 source names. After reserving benchmark domains, 136,700 legitimate URLs across 189 registered domains remained. The phishing feed had 789,054 lines; 674 invalid/non-HTTP rows and 79 normalized duplicates were removed, leaving 751,113 rows across 323,196 registered domains after benchmark-domain reservation. The run recorded no exact normalized-URL label conflicts.
- Domain assignment was deterministic and the recorded train/calibration/validation/test registered-domain overlaps were empty. The internal test is class/cohort sampled (1,039 rows per label), not a natural prevalence sample.
- The selected training sample had equal positive/negative row quotas (3,886 each), but only 129 legitimate versus 2,723 phishing registered domains; calibration had 10 versus 255. Thus class balance at row level did not provide comparable source/domain breadth. Per-cohort selection and domain caps further shaped the sample. This can contribute to structural generalization gaps; it does not prove label error.
- No use of source/category/domain as model inputs was found in the recorded 29-feature candidate. Legitimate and phishing provenance nevertheless have very different domain breadth and collection processes; distribution shift is plausible.
- The candidate calibrator was fitted on a domain-disjoint, 50/50 class-balanced calibration sample. Its validation Brier score (0.0677) worsened to 0.1158 internally and 0.0995 on the fixed benchmark. Calibration quality at real-world prevalence is unverified. The production model's Brier scores (0.4889 internal, 0.6008 benchmark) and service-level verdicts indicate its stored probabilities/metadata cutoffs are not appropriate for these evaluation examples.
- The `config.py` SAFE/PHISHING thresholds (`0.45`/`0.85`) do not match production metadata (`0.1314096`/`0.6961575`). The production threshold values were not changed in this analysis. Candidate threshold performance is also not a validated operating point: internal FPR is 9.05%, and benchmark FPR is 5.67%, well above the 0.5% target.

## Three controlled next experiments

Each experiment should be run in an isolated `experiments/auto_ml/` candidate directory, preserve the existing artifacts, log input hashes/configuration, and change one major factor at a time. Keep benchmark v1 as regression-only; never choose features, calibration, or thresholds against it. Any new lockbox should be constructed from genuinely observed URLs with provenance and with source/domain groups reserved before training.

1. **Broaden legitimate source/domain coverage and reduce sampling skew.**  
   **Hypothesis:** the legitimate test errors are partly a consequence of narrow per-class domain coverage and source-specific URL distributions; increasing legitimate-domain representation and capping dominant phishing domains will reduce held-out legitimate FPR without a material phishing-recall loss.  
   **Change:** rerun the same model/configuration with only the row-selection/domain-cap policy changed. Keep equal class totals and cohort quotas; sample/reweight by registered domain so a few domains cannot dominate. Record per-class source/domain counts and all split overlaps.  
   **Independent evaluation:** reserve unseen legitimate source/domain groups and phishing registered domains before selection; evaluate once on a new domain-disjoint lockbox plus a structure-rich legitimate set. Report FPR, recall, precision, and errors by cohort/source/domain. Hypothesis is supported only if lockbox FPR improves while phishing recall does not materially regress; report uncertainty for small groups.

2. **Isolate structural-feature reliance.**  
   **Hypothesis:** reducing dependence on correlated URL-shape signals (especially hostname length/trusted-TLD signals, and separately query/length/digit signals) can lower false positives on authentic query, encoded, and long URLs; the current evidence does not justify a combined feature change.  
   **Change:** run sequential feature-group ablations against the unchanged selected baseline: first remove `HostnameLength` and `IsTrustedTLD`; in a separate candidate remove query/count/encoding and length/digit features. Keep data, split, estimator, class weights, calibration, and thresholds fixed. Do not add trusted-domain exceptions or allowlists.  
   **Independent evaluation:** compare candidates on the same new unseen-domain structure-rich lockbox and phishing-domain lockbox; retain v1 only as a regression check. Report per-cohort FP/FN numerators and denominators, overall FPR/recall, PR-AUC, and counterfactual-pair consistency. Reject any improvement that comes from suppressing normal path/query evidence at the expense of phishing recall.

3. **Validate calibration and operating thresholds independently.**  
   **Hypothesis:** a calibration/threshold procedure matched to a separately reserved domain-disjoint calibration population will produce more stable probabilities and a better FPR/recall trade-off than inheriting production metadata or using config defaults. Calibration alone cannot repair poor ranking.  
   **Change:** keep the best model and its features fixed; compare the existing sigmoid calibrator with one alternative calibration method on calibration-only domains. Choose any operating point using calibration/validation data only, with explicit SAFE/SUSPICIOUS/PHISHING counts. Do not use the final lockbox for selection.  
   **Independent evaluation:** evaluate the frozen calibrator and thresholds once on new unseen domains, report reliability bins, Brier score, PR-AUC/ROC-AUC, FPR and recall with counts, and confidence intervals. The target remains legitimate FPR ≤0.5% and representative phishing recall ≥98%; if the calibration sample cannot represent deployment prevalence, mark probability calibration UNVERIFIED.

## Remaining gaps

The current internal split does not represent natural class prevalence, has much lower legitimate than phishing domain diversity, and has sparse or absent fragment, pagination, and API examples. The fixed benchmark has only eight legitimate domains and contains curated counterfactuals; it is too small and reused for tuning to serve as a new independent generalization claim. A larger, separately sourced and domain-disjoint lockbox is required. No root cause beyond measured associations and the stated hypotheses is established.
