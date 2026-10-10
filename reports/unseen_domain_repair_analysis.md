# Unseen-domain repair: audit outcome

## Decision

**No model training was started.** The audit could not establish an unused, source- and registered-domain-disjoint validation set and lockbox. Reusing prior validation/test data would leak model-selection information; treating the latest PhishTank CSV as independent without comparing all registered domains against prior datasets would be an unsupported claim.

The detailed audit is in [`data_quality_audit.md`](./data_quality_audit.md) and [`data_quality_audit.json`](./data_quality_audit.json). The isolated run directory contains the new single-download feed snapshot and its hashed manifest.

## Baseline, clearly distinguished from a new result

The latest completed repair remains the validation-selected character 3–5-gram TF-IDF plus numeric-feature logistic model. Its threshold was 0.481771 (SAFE threshold 0.45). On the already-reported internal test:

| Metric | Prior result |
|---|---:|
| Legitimate FPR | 162/1,039 = 15.59% (Wilson 95% CI 13.51–17.92%) |
| Phishing FNR | 32/1,039 = 3.08% |
| Phishing recall | 1,007/1,039 = 96.92% (Wilson 95% CI 95.68–97.81%) |
| Precision | 86.14% |
| Brier / PR-AUC / ROC-AUC | 0.0658 / 0.9760 / 0.9795 |
| 10-bin expected calibration error | 0.0599 |

The test included 24 legitimate domains and 793 phishing domains, but it has prior exposure and is a repeatability/regression result. Benchmark v1 is also regression-only: 51/600 legitimate false positives (8.50%) and 381/392 phishing recall (97.19%). No new candidate exists and no metric from this run is being presented as an independent estimate.

## What the audit found

1. **Legacy legitimate rows are unevenly verified.** The 138,030-row dataset has 201 registered domains, zero invalid URLs or normalized duplicates, and 37 target/source-page registered-domain mismatches. Only 2,090 rows explicitly claim individual target HTTP 200 verification; 80,017 explicitly say the target was not separately fetched, and 55,923 have other or ambiguous verification metadata. Four source groups account for 56.7% of rows, and content paths account for 92.3%.
2. **The strongest fresh legitimate set is already spent.** The previous collection has 425 deduplicated URLs across 33 domains: 424 same-domain HTTP 200 and one HTTP 202, with 51 rows whose recorded final URL differs from the original link but remains on the same registered domain. It was used in the previous accuracy-repair experiment and has only 2 search, 9 multiple-parameter, 8 encoded, 1 pagination, and 2 login/account observations.
3. **Phishing labels need temporal qualifications.** The legacy active-feed text has no row timestamps or verification metadata. The older PhishTank snapshot has 69,139 rows marked verified/online, but 33,207 had verification times over one year before capture. These are feed assertions at a point in time, not independent proof of current malicious behavior.
4. **A fresh feed file alone is not a lockbox.** One current official PhishTank snapshot was downloaded, with 69,100 verified/online rows and timestamps through 2026-10-09 09:11:30 UTC. It was not normalized/domain-joined against every historical input; therefore no subset was certified unused or scored. No suspicious destination was visited.
5. **There are potential sources but no new observations.** All 17 domains in the base collector catalog are already in prior data or benchmark reservations. A supplemental 56-domain repair allowlist has 22 domains absent from stored prior data/benchmark reservations, but all 22 produced zero rows in its previous collection attempt. They should be retried or replaced; none yielded fresh lockbox rows in this run.

## Tests and protected files

- Backend: 14 passed, 1 failed due to the existing missing `scripts.final_ml_pass` module.
- Extension: 23 passed.
- Production model, feature names, metadata, extractor, service, and config hashes matched the pre-run values.
- No production files were edited; no model was trained, promoted, or deployed.

## Exact next action

Retry the 22 previously zero-yield first-party domains and expand the documented allowlist as needed, collecting observed URLs with a slow request cadence and per-URL provenance (source page, collection time, HTTP status, final URL, content type, normalized URL, registered domain). Preassign disjoint source groups/domains to train, calibration, validation, and lockbox before looking at model scores. Collect at least 600 legitimate lockbox URLs from 20+ new domains, especially real searches, multi-parameter queries, encoded URLs, pagination, fragments, login/account, docs, and APIs. Normalize the refreshed PhishTank data and exclude any registered domain appearing in any prior data or split before reserving a phishing lockbox. Only then begin up to 12 controlled experiments.

The acceptance gates were **not passed**; the new-run FPR and recall are **UNVERIFIED**, not successful. The machine-readable run status is [`unseen_domain_repair_final.json`](./unseen_domain_repair_final.json), and the empty new-run leaderboard is [`unseen_domain_repair_leaderboard.json`](./unseen_domain_repair_leaderboard.json).
