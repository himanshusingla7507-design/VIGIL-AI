# VIGIL-AI data quality audit

**Decision: blocked before training.** The existing experiments do not provide an unused validation set plus a domain-disjoint lockbox for this run. The report records what is verified and what remains uncertain; no new candidate was trained.

## Legitimate data

`legitimate_urls_realworld_v3.csv` contains 138,030 rows, all label 0, with 138,030 unique normalized URLs across 201 registered domains and 210 source names. No URLs failed the project normalizer. The prior pipeline removed 1,330 rows on benchmark-reserved domains, leaving 136,700 eligible rows across 189 domains.

The dataset has real provenance metadata, but it does not uniformly establish a current, individually fetched target:

- 2,090 rows explicitly claim an individual target HTTP 200.
- 80,017 rows explicitly say the target was not separately fetched.
- 55,923 rows have other or ambiguous verification-method metadata; these cannot be treated as individually fetch-verified without further provenance review.
- 37 rows have a target registered domain different from the `source_page` registered domain. These may be genuine outbound references, but need row-level review before strict first-party inclusion.
- The four largest sources (NASA, GOV.UK, The GitHub Blog, RFC Editor) account for 56.7% of rows.
- Content paths are 127,436/138,030 (92.3%). Search (139), multiple parameters (1,378), encoding (343), long queries (236), pagination (593), fragments (516), login/account (141), and tracking (89) are comparatively sparse.

The 425-row first-party collection in `accuracy_repair_20261009` has stronger row-level evidence: 424 same-registered-domain HTTP 200 responses and one HTTP 202, with no cross-registered-domain redirects or normalized duplicates. In 51 rows the recorded final URL differs from the original observed link while remaining on the same registered domain. It has only 33 source domains and very sparse high-value structures (2 search, 9 multiple-parameter, 8 encoded, 1 pagination, and 2 login/account rows). It has already been used in the previous model-selection/evaluation cycle, so it cannot serve as this run's fresh lockbox.

## Phishing data

`data/external/phishing_database_active.txt` has 789,054 lines and no per-row timestamps, verification fields, or online-status metadata. The previous audit retained 751,113 unique normalized rows, removed 79 normalized duplicates, and rejected 674 malformed or unsupported lines. Its label means “listed in this feed,” not “independently confirmed malicious and currently active.”

The prior PhishTank snapshot has 69,139 entries marked `verified=yes` and `online=yes`, but verification times range from 2011 through 2026. At the capture time, 33,207 entries were more than one year past verification. These flags document PhishTank's state at verification time, not current activity.

A current official PhishTank CSV snapshot was downloaded once into the isolated experiment directory. It has 69,100 rows, each marked verified and online, with 69,097 distinct raw URL strings. Its verification timestamps extend through 2026-10-09 09:11:30 UTC. No destination URL was fetched. Its registered-domain overlap with all previous training and evaluation rows has **not** been certified, so it is not used as a lockbox or training input in this run.

## Split integrity and prior evaluations

The previous runner hashes registered domains into train, calibration, validation, and test; the latest report records no registered-domain overlap. Rechecking the legacy legitimate rows found no source-name group crossing the deterministic splits in this particular file, but source-group assignment is not an explicit invariant of that runner.

Those prior validation and test rows have already been used for model selection or reporting. Benchmark v1 is regression-only. The base collector catalog has 17 domains, all already represented in prior legitimate data or the benchmark. A supplemental 56-domain allowlist used by the prior repair collector has 22 domains absent from stored prior data and benchmark reservations, but those 22 all yielded zero rows in that collection attempt. No fresh legitimate lockbox rows have been collected from them. The newer phishing snapshot also cannot be declared domain-disjoint without completing the overlap audit.

## Last prior candidate (not a new result)

The previous validation-selected character n-gram plus numeric-feature candidate used phishing threshold 0.481771. On its previously reported internal test it produced:

| Metric | Result |
|---|---:|
| Legitimate false positives | 162/1,039 (15.59%; Wilson 95% CI 13.51–17.92%) |
| Phishing false negatives | 32/1,039 (3.08%) |
| Phishing recall | 1,007/1,039 (96.92%; Wilson 95% CI 95.68–97.81%) |
| Precision | 86.14% |
| Brier score / PR-AUC / ROC-AUC | 0.0658 / 0.9760 / 0.9795 |
| 10-bin expected calibration error | 0.0599 |

That test has 24 legitimate and 793 phishing registered domains, but is a repeatability/regression result, not an independent estimate for this run. On benchmark v1, also regression-only, FPR was 51/600 (8.50%) and recall was 381/392 (97.19%).

## Required next data work

1. Retry the 22 previously zero-yield first-party domains or add documented reputable sources; individually fetch observed URLs and retain source page, collection time, HTTP status, final URL, content type, registered domain, and verification method.
2. Reserve source groups and registered domains for train, calibration, validation, and lockbox **before** model selection. Aim for at least 600 legitimate lockbox URLs across 20+ new domains, with meaningful counts in dynamic URL structures.
3. Normalize the new PhishTank snapshot and compare every registered domain and normalized URL against all historical inputs and prior splits. Keep only disjoint domains in any prospective lockbox; report submission/verification ages and do not describe feed flags as ground truth.
4. After both classes have enough unused domains and the audit passes, run controlled experiments on the remainder only. Keep benchmark v1 regression-only.

## Validation and production safety

- Backend pipeline tests: 14 passed, 1 failed. The pre-existing failure is `ModuleNotFoundError: No module named 'scripts.final_ml_pass'` in `test_experimental_url_features_share_serving_canonicalization`.
- Extension tests: 23 passed, 0 failed.
- Protected production artifact and code hashes matched before and after the audit and tests.
- No model was trained, selected, promoted, or deployed.

Machine-readable counts, hashes, status assessments, and limitations are in [`data_quality_audit.json`](./data_quality_audit.json).
