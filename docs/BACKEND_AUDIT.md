# VIGIL ML/backend reliability audit
# VIGIL ML/backend reliability audit

> Historical audit of an earlier runtime/model. Its old label expectations, counts, metrics, thresholds, and limitations are superseded by [ml-evaluation.md](ml-evaluation.md).

> Historical audit of an earlier runtime/model. Its old label expectations, counts, metrics, thresholds, and limitations are superseded by [ml-evaluation.md](ml-evaluation.md).

Audit date: 2026-10-04 (Asia/Calcutta). This report describes the repository as
audited; no synthetic URL was opened or fetched.

## 1. Validation failures and disposition

The initial 13-case run was 11/13. The two failures were:

| URL | Expected | Actual | Model P(phishing) | Risk | Evidence | Threshold |
|---|---|---|---:|---:|---|---|
| `http://secure-bank-login.example.com/update-account` | SUSPICIOUS | PHISHING | 0.998512 | 100 | HTTP, `secure`, `bank`, `login`, `update`, `account`, 3 hyphens | safe 0.45 / phishing 0.85 |
| `http://microsoft-security.example.com/login` | SUSPICIOUS | PHISHING | 0.998512 | 100 | HTTP, `security`, `login`, brand-like subdomain, hyphen | safe 0.45 / phishing 0.85 |

The raw model outputs are already above the phishing threshold; the result is
not caused by the reserved-domain policy. These are synthetic `.example.com`
placeholders whose expected labels understate their explicit lure structure.
The expectation was corrected to PHISHING with that rationale; the classifier
was not weakened and no domain-specific bypass was added. The complete suite
then passes 13/13.

## 2. Legitimate-domain regression

The following variations were evaluated through `service.scan`: fast.com and
www.fast.com, with and without `/`; github.com, google.com, microsoft.com,
python.org, and cloudflare.com, with and without `www`/`/` where applicable.
All returned SAFE. Current probabilities are 0.003954 for fast.com,
0.013584 for github.com, 0.021837 for google.com, 0.011354 for microsoft.com,
0.028633 for python.org, and 0.010780 for cloudflare.com. Canonicalization removes only the presentation difference
between `www.` and a root slash for feature analysis; no trusted-domain score
override is used.

## 3. Current data sources and provenance

The only data actually present and processed by the active training command is
`final_dataset_v2.csv`: 235,370 rows, 134,850 label-0 and 100,520 label-1.
The repository does not retain the upstream publication name, download URL,
collection dates, license, or source-row identifiers, so those fields are
unknown rather than inferred. `merge_dataset.py` references possible filenames
but none of those files are present and the script is not part of active
training. No MURL, PhishTank, CompPhish, or fresh external feed was downloaded
or evaluated. No independent external validation set exists in this run.

The active binary mapping is legitimate/benign/safe -> 0 and
phishing/malicious/fraud/suspicious -> 1. The active source contains only the
two observed numeric classes. Exact duplicates: 0. Case-insensitive raw URL
duplicates: 0. URL-normalized duplicates: 14, with 0 conflicting labels.
Unique registered-domain groups under the repository's conservative last-two-
labels grouping: 157,351. The grouping remains limited for public suffixes
such as `co.uk`.

MURL is technically compatible only after a declared binary policy. Its public
description is multi-class (Benign, Phishing, Defacement, Malware, Legitimate,
Spam, Exploit; 783,705 URLs; CC BY 4.0). VIGIL must not collapse every
non-benign class into “phishing”. `scripts/load_murl.py` accepts a local CSV/ZIP,
records a SHA-256 and class counts, maps only Benign/Legitimate to 0 and
Phishing to 1, and reports/excludes other classes. It was not run because no
MURL artifact is in the repository.

## 4. Feature audit

All 35 features are deterministic URL-string features and are available in both
training and inference through the same `extract_features` function. No target,
label, response, DNS, WHOIS, page-content, or collection-time field is used.

| Feature | Type / range | Availability | Leakage / redundancy review |
|---|---|---|---|
| URLLength | integer >=0 | train + serve | stable; overlaps HostnameLength/PathLength/QueryLength |
| HostnameLength | integer >=0 | train + serve | stable; overlaps DomainLength |
| PathLength | integer >=0 | train + serve | stable; overlaps URLLength |
| QueryLength | integer >=0 | train + serve | stable; overlaps URLLength |
| FragmentLength | integer >=0 | train + serve | stable; overlaps URLLength |
| PathSegmentCount | integer >=0 | train + serve | stable; related to PathLength |
| QueryParameterCount | integer >=0 | train + serve | parser-dependent for malformed query syntax |
| DotCount | integer >=0 | train + serve | overlaps subdomain depth/hostname structure |
| SubdomainDepth | integer >=0 | train + serve | duplicates NoOfSubDomain |
| NoOfSubDomain | integer >=0 | train + serve | exact duplicate of SubdomainDepth |
| NoOfDigitsInURL | integer >=0 | train + serve | stable; related to DigitRatioInURL |
| DigitRatioInURL | float [0,1] | train + serve | deterministic ratio; redundant with digit count/length |
| NoOfLettersInURL | integer >=0 | train + serve | related to LetterRatioInURL/length |
| LetterRatioInURL | float [0,1] | train + serve | deterministic ratio; redundant |
| NoOfEqualsInURL | integer >=0 | train + serve | query syntax proxy; related to query count |
| NoOfQMarkInURL | integer >=0 | train + serve | generally 0/1 after parsing; overlaps query presence |
| NoOfAmpersandInURL | integer >=0 | train + serve | query syntax proxy |
| NoOfAtInURL | integer >=0 | train + serve | stable structural signal |
| NoOfHyphenInURL | integer >=0 | train + serve | lexical shortcut risk; should not be decisive alone |
| NoOfUnderscoreInURL | integer >=0 | train + serve | lexical shortcut risk |
| URLPercentEncodingCount | integer >=0 | train + serve | stable but benign encodings exist |
| HasObfuscation | binary | train + serve | overlaps percent encoding/userinfo |
| HasUserInfo | binary | train + serve | stable structural signal |
| HasPort | binary | train + serve | explicit non-default port only after normalization |
| IsHTTPS | binary | train + serve | dataset shortcut risk; HTTPS is not safety proof |
| IsDomainIP | binary | train + serve | stable; regex fallback is IPv4-specific |
| IsShortened | binary | train + serve | fixed-list shortcut; list can become stale |
| HasSuspiciousTLD | binary | train + serve | fixed-list/dataset shortcut; not proof of phishing |
| HasSuspiciousToken | binary | train + serve | lexical shortcut; brand/word context matters |
| HasSuspiciousWord | binary | train + serve | exact duplicate of HasSuspiciousToken |
| IsTrustedTLD | binary | train + serve | coarse suffix heuristic, not reputation |
| URLEntropy | float >=0 | train + serve | length-sensitive and correlated with URL text features |
| DomainLength | integer >=0 | train + serve | exact/near duplicate of HostnameLength after normalization |
| HasTrustedBrand | constant 0 | train + serve | no leakage, but unusable dead feature; remove in next model version |
| HasTrustedBrandToken | constant 0 | train + serve | no leakage, but unusable dead feature; remove in next model version |

The clearest redundancies are SubdomainDepth/NoOfSubDomain,
HasSuspiciousToken/HasSuspiciousWord, the two trusted-brand constants, and
DomainLength/HostnameLength. They were retained for artifact compatibility in
this model; a future retraining should remove them and compare performance
under grouped validation, not random accuracy alone.

## 5. Evaluation and calibration

Recorded random holdout: 47,074 examples. Accuracy 0.976505, precision
0.987929, recall 0.956675, F1 0.972051, ROC-AUC 0.991623, PR-AUC 0.992575,
FPR 0.008713, FNR 0.043325, confusion matrix `[[26735,235],[871,19233]]`.

Recorded registered-domain-aware holdout: 42,619 examples
(`26842+256+550+14971`). Accuracy 0.981088, precision 0.983188, recall
0.964564, F1 0.973787, ROC-AUC 0.989089, PR-AUC 0.989369, FPR 0.009447,
FNR 0.035436, confusion matrix `[[26842,256],[550,14971]]`. Counts are not
compared directly with the random holdout because the sizes differ.

The active artifact is wrapped in `CalibratedClassifierCV(method="sigmoid")`.
Its recorded Brier scores are 0.019588 (random) and 0.017598 (domain-aware),
but there is no reliability diagram or expected calibration error yet; the API
therefore exposes `probability`, not a user-facing claim of confidence.

Candidate selection compares Logistic Regression, Random Forest, and
HistGradientBoosting using PR-AUC plus F1. Threshold selection is now performed
on a dedicated stratified holdout, separate from model selection and the final
test set, and the active artifact records that split. The selected training
threshold pair is safe 0.45 and phishing 0.50; the service enforces a minimum
0.15 gap, so its effective phishing threshold is 0.60. This policy should be
revisited with an operational false-positive/false-negative cost.

## 6. API, security, and performance checks

`service.py`, `/scan`, `app.py`, and the browser extension use the same
prediction service. `trial/app.py` was corrected to remove manual boosts and
delegate to `service.scan`. URL-only analysis performs no fetch, redirect
following, file download, JavaScript execution, or form submission. API checks
reject non-JSON, missing/non-string/empty URLs, unsupported schemes, invalid
ports, and URLs over 2048 characters. CORS is restricted to
`VIGIL_FRONTEND_ORIGIN` (default localhost:5173).

History persistence now strips query strings and fragments because those fields
can contain tokens or personal data. The live response still contains the
requested URL so the caller can render its result.

The model bundle is cached with `lru_cache(maxsize=1)`, so it loads once per
process. A local warm-process benchmark measured approximately 7.4 ms per
`service.scan` after first load; cold model load was approximately 8.3 ms on the
audit machine. These are machine-dependent and should be re-measured in the
deployment environment. The model is memory-resident and does not fetch
network resources.

## 7. Remaining limitations

The active training source lacks upstream provenance and collection dates; no
independent external validation has been performed; the feature set contains
known redundancies and two dead constants; domain grouping uses a last-two-label
fallback; URL-only inference cannot inspect page content or live reputation;
and the committed artifact must be retrained after the threshold-split fix.
Therefore the backend is audit-ready for integration testing, but should not be
described as production-validated until a provenance-complete external holdout
and a fresh artifact are available.
