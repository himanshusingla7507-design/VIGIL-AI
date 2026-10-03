# VIGIL ML and Backend Evaluation

Evaluation run: 2026-10-04 local time. Training timestamps in `model_metadata.json` are UTC. Metrics marked fresh below were produced by executing the current scripts against the current prepared data; they are not estimates of deployment performance.

## Data Audit

The only training source was `final_dataset_v2.csv`. It contains `url,label` only; upstream provenance and collection dates are absent. No external data was merged, and no external-validation result is available.

| Audit item | Fresh result |
| --- | ---: |
| Raw rows | 235,370 |
| Rows after preparation | 234,432 |
| Benign labels (0) | 134,849 |
| Phishing labels (1) | 99,583 |
| Exact duplicate rows | 14 |
| Feature-equivalent duplicate rows | 937 |
| Duplicate rows removed after conflict handling | 936 |
| Conflicting label groups / rows removed | 1 / 2 |
| Cross-source duplicate groups | 0; only one source was present |
| Unique registered domains | 197,707 |
| Valid collection dates | 0 |

The conflicting group was `education.gouv.fr`: `https://www.education.gouv.fr/` was labeled phishing while the feature-equivalent root URL without `www` or a trailing slash was labeled benign. Both rows were excluded rather than choosing a label. The cleaner detects conflicts before deduplication and retains `source`, `collection_date`, and `source_row` fields.

Domain counts and group splits use `tldextract` 5.3.2 with its bundled Public Suffix List snapshot and private suffixes enabled. No network fetch is made for suffix data.

## External Source Research

| Source | Current finding | Use |
| --- | --- | --- |
| [OpenPhish Community Feed](https://openphish.com/phishing_feeds.html) | Updated every 12 hours, but the [terms](https://openphish.com/terms.html) restrict use to non-commercial purposes and restrict sharing or making its data available to third parties. | A brief availability/schema request was made, but data was not saved or used; written permission would be needed for this project's use. |
| [PhishTank download feed](https://phishtank.org/developer_info.php) | The verified-online CSV endpoint was reachable and documents URL, verification/submission timestamps, online status, and target. Current PhishTank terms point to [Cisco's EULA](https://www.cisco.com/c/en/us/about/legal/cloud-and-software/end_user_license_agreement.html); the official endpoint returned HTTP 403 during this run, so reuse rights could not be verified. | Only a streaming sample was inspected; no full feed was saved or used. |
| [ISCX-URL2016](https://www.unb.ca/cic/datasets/url-2016.html) | Published in 2016 with separate benign, phishing, spam, malware, and defacement classes. The official download requires a form; the download page returned a server error during this run. Its classes cannot safely be collapsed into phishing/benign without filtering. | Not downloaded or used. |
| [URLhaus](https://urlhaus.abuse.ch/about/) | Tracks malware URLs, not a phishing-only label. Current API documentation requires an authentication key and the service has access/use conditions. | Not used as phishing data. |

No compatible, clearly reusable, independent external source was integrated. External validation is therefore `not_run`, not zero-error or assumed successful. This is a genuine acceptance gap.

## Feature Audit

The extractor returns 35 deterministic URL-string features. The model uses 29. URL text is canonicalized without fetching it; lexical length/count/entropy features use a fixed `http://` scheme representation, making them invariant to an HTTP/HTTPS-only change. The separate `IsHTTPS` value remains available in evidence but is not a model input.

| Feature | Type | Meaning / notes |
| --- | --- | --- |
| `URLLength` | integer | Length of the scheme-neutral canonical URL representation. |
| `HostnameLength` | integer | Normalized hostname length; inference available. |
| `PathLength` | integer | Path character count. |
| `QueryLength` | integer | Query character count. |
| `FragmentLength` | integer | Fragment character count. |
| `PathSegmentCount` | integer | Non-empty path segment count. |
| `QueryParameterCount` | integer | Parsed query parameter count. |
| `DotCount` | integer | Dots in normalized hostname. |
| `SubdomainDepth` | integer | Host labels before the final two labels; not a Public Suffix List calculation. |
| `NoOfDigitsInURL` | integer | Digits in the scheme-neutral canonical URL. |
| `DigitRatioInURL` | float, 0-1 | Digit count divided by scheme-neutral URL length. |
| `NoOfLettersInURL` | integer | Letters in the scheme-neutral canonical URL. |
| `LetterRatioInURL` | float, 0-1 | Letter count divided by scheme-neutral URL length. |
| `NoOfEqualsInURL` | integer | Equals signs in the scheme-neutral representation. |
| `NoOfQMarkInURL` | integer | Question marks in the scheme-neutral representation. |
| `NoOfAmpersandInURL` | integer | Ampersands in the scheme-neutral representation. |
| `NoOfAtInURL` | integer | At signs in the scheme-neutral representation. |
| `NoOfHyphenInURL` | integer | Hyphens in the scheme-neutral representation. |
| `NoOfUnderscoreInURL` | integer | Underscores in the scheme-neutral representation. |
| `URLPercentEncodingCount` | integer | Percent signs; malformed escapes are rejected during validation. |
| `HasObfuscation` | binary | Percent encoding or userinfo is present. |
| `HasUserInfo` | binary | URL user/password component is present. |
| `HasPort` | binary | A non-default explicit port is present. |
| `IsDomainIP` | binary | Host is a valid IPv4 or IPv6 literal. |
| `IsShortened` | binary | Host exactly matches the configured shortener list. |
| `HasSuspiciousTLD` | binary | Host matches the configured suspicious-TLD suffix list; list maintenance is a limitation. |
| `HasSuspiciousToken` | binary | Configured lure token occurs in hostname, path, query, or fragment. |
| `IsTrustedTLD` | binary | Host matches the configured common-TLD suffix list; this is not a trust verdict. |
| `URLEntropy` | float | Shannon entropy of the scheme-neutral canonical URL. |
| `DomainLength` | integer | Excluded: exact alias of `HostnameLength`. |
| `NoOfSubDomain` | integer | Excluded: exact alias of `SubdomainDepth`. |
| `HasSuspiciousWord` | binary | Excluded: exact alias of `HasSuspiciousToken`. |
| `HasTrustedBrand` | binary | Excluded: constant-zero placeholder in the extractor. |
| `HasTrustedBrandToken` | binary | Excluded: constant-zero placeholder and exact alias of `HasTrustedBrand`. |
| `IsHTTPS` | binary | Excluded from the model after protocol counterfactuals; retained only for neutral evidence. |

All model inputs are numeric and available at inference. Exact aliases and constant placeholders were excluded. `IsHTTPS` originally had 43% permutation importance in a preceding same-data candidate and changing only the scheme moved legitimate-domain scores from approximately 0.01-0.02 to 0.98-0.99. Scheme-neutral extraction and exclusion removed that counterfactual effect; the resulting metric loss is recorded below rather than hidden.

Permutation importance for the selected model was freshly computed on a 2,000-row validation sample with two repeats. Largest mean decreases were `PathLength` 0.2483, `URLLength` 0.0652, `NoOfDigitsInURL` 0.0559, and `DotCount` 0.0452. These are model-specific validation diagnostics, not causal effects.

## Model Experiments

Candidates were compared on the same validation partitions. Selection score was `0.50*PR-AUC + 0.30*F1 + 0.20*recall - 0.25*FPR - 0.10*Brier`. Candidate and binary final-test metrics use a 0.5 probability cutoff; the separate three-way triage metrics use the selected SAFE/PHISHING thresholds. Values here are freshly executed validation metrics, not final test results.

| Split / candidate | PR-AUC | F1 | Recall | FPR | Brier | Fit seconds | Median one-row ms | Serialized candidate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Random / Logistic Regression | 0.8810 | 0.7914 | 0.7015 | 0.0526 | 0.1246 | 0.65 | 0.45 | 1.5 KB |
| Random / Random Forest | 0.8947 | 0.8075 | 0.7134 | 0.0396 | 0.1135 | 9.30 | 26.51 | 159.1 MB |
| Random / HistGradientBoosting | 0.8978 | 0.8077 | 0.6979 | 0.0224 | 0.1098 | 1.03 | 1.66 | 368 KB |
| Domain / Logistic Regression | 0.9079 | 0.8267 | 0.7499 | 0.0558 | 0.1174 | 0.66 | 0.47 | 1.5 KB |
| Domain / Random Forest | 0.9197 | 0.8394 | 0.7612 | 0.0455 | 0.1067 | 10.79 | 27.73 | 169.6 MB |
| Domain / HistGradientBoosting | 0.9226 | 0.8403 | 0.7449 | 0.0243 | 0.1019 | 1.14 | 1.67 | 368 KB |

HistGradientBoosting was selected on both validation partitions for the best composite score and much lower FPR/size/latency than Random Forest. It does not have the best recall at the 0.5 binary cutoff; selection is a tradeoff, not a claim of universal superiority.

## Fresh Final Evaluation

The final calibrated HistGradientBoosting artifact has 29 input features, model size 1,100,240 bytes, and was trained at the UTC time recorded in `model_metadata.json`. The evaluator recomputes the same deterministic split and checks both the prepared dataset hash and feature-extractor source hash before scoring.

| Evaluation | Rows | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | Brier | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Random untouched test | 46,887 | 0.8609 | 0.9560 | 0.7051 | 0.8116 | 0.8846 | 0.9006 | 0.1084 | 0.0240 | 0.2949 |
| Domain-isolated test | 47,901 | 0.8632 | 0.9519 | 0.7218 | 0.8210 | 0.8875 | 0.9062 | 0.1067 | 0.0280 | 0.2782 |

The random split used seed 42 and had 3,272 overlapping registered domains between train and test, as expected for a random split. The separate domain split used seed 44 and had zero overlapping domains (158,165 train domains; 39,542 test domains). It selected its model family using only group-train domains.

Calibration was measured on the untouched random test (ECE 0.00476, Brier 0.10837) and domain test (ECE 0.00671, Brier 0.10674). The low ECE should be read alongside the Brier score and class distribution; probability is not a guarantee of correctness.

Thresholds were selected on a separate 18,755-row holdout: SAFE 0.13141, PHISHING 0.69616. The selection constraint was at most 2% false-SAFE and at most 1% benign-to-PHISHING on that holdout. Measured false-SAFE / benign-to-PHISHING rates were 2.19% / 1.04% on random test and 3.73% / 1.26% on domain test. The remaining SUSPICIOUS band is deliberately broad because the model is uncertain on many URLs.

Temporal validation was not run because the source contains no dates. External validation was not run because no compatible source with verified reuse terms was integrated. The final shortcut-free result is materially lower than the prior protocol-sensitive candidate; the prior candidate is backed up and not represented as real-world performance.

## Regression and API Results

| Case | Result |
| --- | --- |
| `https://fast.com/`, `https://fast.com`, `https://www.fast.com/` | SAFE; equal probability 0.060029 and risk score 0 |
| Seven named legitimate references other than `fast.com` | SUSPICIOUS, not PHISHING; the validation CSV expected SAFE. Raising SAFE enough to pass them would exceed the chosen false-SAFE budget. |
| Five reserved-domain synthetic phishing examples | All PHISHING; these are regression tests, not prevalence evidence. |
| HTTP versus HTTPS for identical URL text | Identical model probability, label, and risk score; `IsHTTPS` is evidence-only. |
| Live Flask HTTP smoke tests | `/health`, `/model-info`, and `/scan` returned expected JSON; service/API label, probability, and risk score agreed. |
| API error handling | Malformed JSON, empty URL, unsupported scheme, and invalid IPv6 returned 400; overlong URL and oversized body returned 413. |
| CORS | Configured `http://localhost:5173` allowed; untrusted origin returned no allow-origin header. |
| History privacy | Persisted URL fields omit userinfo, query, and fragment; DELETE clears history. |
| Pickle integrity | Model and feature-name hashes are checked before deserialization; modified model bytes were rejected. |

Cold model bundle load was about 809 ms in this run. Median/p95 direct inference were 7.54/11.22 ms across 100 scans in the selected local environment; process RSS was about 178 MB. The model bundle is cached once per process. Model and feature-name SHA-256 values detect mismatched or partially replaced files before pickle deserialization; they are not signed provenance and do not protect against an attacker who can replace both artifact and metadata. Extension `background.js` and `popup.js` still call the same local `/scan` endpoint; that endpoint was exercised over real HTTP, but the extension itself was not launched in a browser during this run.

## Engineering Iterations

| Iteration | Problem and hypothesis | Change and validation | Outcome / next action |
| --- | --- | --- | --- |
| 1 | Raw URL duplicates and dedup-before-conflict-checking could leak or hide label conflicts. | Canonicalized feature-equivalent URLs, checked label conflicts first, retained row/source fields, and ran a synthetic conflict test plus the full source audit. | Removed 936 duplicate rows and both rows in one conflict group; retained 234,432. No external sources were present. |
| 2 | `IsHTTPS` and other scheme-derived counts were a dataset shortcut. | Measured a 0.98+ probability swing on HTTP/HTTPS pairs, then made lexical features scheme-invariant and excluded `IsHTTPS` from model inputs. | Paired scores are now identical; random PR-AUC fell from the earlier protocol-sensitive candidate's 0.9929 to 0.9006. The shortcut-free score is the active model. |
| 3 | The old threshold search optimized a binary objective that ignored its phishing threshold. | Selected a separate SAFE/PHISHING pair on an 18,755-row holdout with explicit false-SAFE and benign-to-PHISHING limits; measured the policy on random and domain tests. | Thresholds are 0.13141/0.69616; holdout false-SAFE/benign-to-PHISHING rates are 1.90%/0.99%. Test rates are reported above. |
| 4 | API input/privacy and model artifact integrity needed end-to-end checks. | Added request limits, structured error responses, history URL redaction, pre-unpickle hash checks, and regression tests; sent real HTTP requests to the Flask app. | API, CORS, consistency, privacy, and tamper checks passed; full suite is 14/14. |
| 5 | A fresh compatible external source was required to establish independent validation. | Checked OpenPhish terms, PhishTank feed/EULA access, ISCX-URL2016 download, and URLhaus scope/auth requirements. | No source met verified access/reuse/label criteria in this run; external integration and validation remain blocked. |

## Reproduction

PowerShell from the repository root:

```powershell
.\.venv\Scripts\python.exe prepare_dataset.py
.\.venv\Scripts\python.exe train_model.py
.\.venv\Scripts\python.exe evaluate_model.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m py_compile api.py service.py phishing_detector.py feature_extractor.py train_model.py prepare_dataset.py evaluate_model.py
.\.venv\Scripts\python.exe api.py
```
