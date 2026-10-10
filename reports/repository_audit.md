# VIGIL-AI Repository Audit

**Snapshot:** 2026-10-09  
**Root:** `C:\Users\adity\Desktop\VIGIL-AI-main`  
**Audit mode:** read-only except for the three requested audit outputs. No application code, data, models, configuration, or extension behavior was changed.

## Scope, method, and confidence

The audit inventoried hidden and ignored paths with filesystem metadata, excluding file-by-file enumeration inside dependency and Git-history trees as requested. Text review concentrated on the runtime API/service/feature path, frontend and extension clients, tests, model metadata, evaluation reports, training entry points, and documentation. Large experiment programs were summarized from their headers, imports, top-level symbols, important entry-point sections, and their saved reports; this is a structural audit, not a line-by-line verification of every branch in those multi-thousand-line experiments. `repository_file_inventory.json` records an inspection status per item.

Serialized model/joblib files were not deserialized. The SQLite history was not queried. Large feeds and benchmark datasets were not read row-by-row. The notebook was inspected as JSON/source but not executed. No external URL was opened or fetched. No model training, promotion, backend, frontend build, or Python test command was run.

## Executive summary

- The active implementation is a local Flask API (`api.py`) that delegates all predictions to `service.py`; the React/Vite UI and Manifest V3 extension consume that API. A separate, older Streamlit application (`app.py`) and still older `trial/` clients coexist and should not be mistaken for the main path.
- The serving model is the root `phishing_model.pkl`, metadata version `v2.1.0`, `CalibratedHistGradientBoosting`, with the ordered 29-feature list in `feature_names.pkl`. The root model and feature-list SHA-256 values match `model_metadata.json`. The pickles were not loaded during this audit.
- Production thresholds are `SAFE < 0.13140956380602112`, `SUSPICIOUS` from that value up to (but not including) `0.6961575221255231`, and `PHISHING >= 0.6961575221255231`. `config.py` still has defaults `0.45` and `0.85`; serving metadata currently overrides them.
- The training inputs named by the active metadata (`final_dataset_v2.csv` and `data/processed/clean_dataset.csv`) are absent. The root `dataset_summary.json` says current preparation is blocked for lack of complete real benign cohorts. Thus current training/evaluation is not reproducible from this snapshot.
- The latest saved promotion gate says **DO NOT PROMOTE**. The domain-only candidate is not the production artifact; required `fast.com` and full legitimate triage evidence was incomplete, and its serialized size was about 8.8 times the baseline.
- The root folder has no `.git` directory, so this snapshot's branch, commit, and tracked/modified/untracked state cannot be determined. An embedded `.git` exists only under `data/external/Phishing.Database/`.
- An exact SHA-256 comparison confirms that `data/external/phishing_database_active.txt` and `data/external/Phishing.Database/phishing-links-ACTIVE.txt` are duplicate 66,612,944-byte feed copies. `train_model_backup_before_balancing.py` is also byte-identical to `train_model.py`.
- A strict JSON parse of 115 project JSON files (before the inventory JSON was generated) found two pre-existing non-standard JSON files: `reports/external_validation.json` and `reports/model_comparison.json` contain `NaN` values, which are not valid JSON. The two newly created audit JSON files are validated separately below.
- Freshly run validation in this audit: browser-extension Node tests passed **23/23**. Python tests, frontend tests/build, browser QA, and app startup were not run. Historical test claims are noted separately below.

## Repository state and inventory totals

At the pre-report scan, the filesystem contained 27,045 files and 2,594 directories. Of those files, 26,715 were inside three summarized trees: `.venv/` (16,681 files; 575,348,309 bytes), `frontend/node_modules/` (10,003; 190,150,088 bytes), and `data/external/Phishing.Database/.git/` (31; 1,676,716,444 bytes). The remaining 330 files and 77 directories were inventoried individually. The three requested reports add three regular files under the already-existing `reports/` directory; the final inventory therefore contains 333 individual file entries plus those three summarized tree entries. The inventory JSON also lists ordinary directories.

No other `vendor/` or `history/` directory was found outside those excluded trees. The `vigil_history.sqlite3` file itself is inventoried, but its records were not read. The embedded Phishing.Database checkout is an external source snapshot, not the root project's Git repository.

`repository_file_inventory.json` contains the recursive paths, file/directory type, byte size, inferred purpose, and inspection status, including the audit outputs. The inspection-exclusion list is repeated near the end of this report.

## Architecture and runtime flows

### Main application

```text
React frontend ─┐
                ├─ HTTP JSON ─> api.py (Flask) ─> service.py
Browser extension┘                              ├─ feature_extractor.py
                                                 ├─ model + feature pickle
                                                 ├─ metadata thresholds
                                                 └─ SQLite scan history
```

`api.py` exposes `/`, `/health`, `/model-info`, `/scan`, `/history`, `/history/<id>`, and `DELETE /history`. `/scan` accepts one JSON URL and enforces a 2,048-character URL bound (and a 4,096-byte Flask request-body bound). The API returns the scan result; before history persistence, `_history_result()` removes URL userinfo, query, and fragment. The service does not open the target URL.

`service.scan()` validates and normalizes the URL, calls `extract_features()`, forms a one-row pandas frame in the model feature-list order, calls `predict_proba`, applies metadata thresholds, calculates a normalized 0–100 risk score, and returns structural evidence, features, version, thresholds, and timestamp. The model is loaded lazily and cached. SHA-256 checks are performed when expected hashes are present. `api.py` persists sanitized results in `vigil_history.sqlite3`.

### Frontend

`frontend/src/main.tsx` mounts `App`; `App` checks health and switches among Scan, History, Analysis, and About pages. `services/api.ts` calls the Flask endpoints using `VITE_API_BASE_URL` (default `http://localhost:5000`). Scan input is checked in `utils.ts`; page/components render the result, risk meter, evidence, a selected subset of features, history, and model metadata. The frontend is a presentation/client layer; it does not run inference.

### Browser extension

`extenison/manifest.json` is Manifest V3. It grants `tabs`, `webNavigation`, and `storage`, and only a host permission for `http://127.0.0.1:5000/*`. `background.js` is the coordinator and posts to `/scan`; it caches results per tab/normalized URL for 30 seconds, deduplicates in-flight scans, tracks navigation identity, uses session storage for block-state tokens, and blocks only an explicit `PHISHING` result. `SAFE`, `SUSPICIOUS`, backend errors, malformed responses, and timeouts do not redirect; errors fail open. A local `blocked.html` interstitial uses text nodes/textContent and offers Back or a deliberate one-time bypass. The popup uses the same worker request path. The extension does not contain a model.

### Legacy and prototype applications

Root `app.py` is a separate Streamlit/NeuroGuard UI, not the current React API architecture. It imports `phishing_detector.check_phishing`, renders raw HTML, monitors local processes/system resources, and attempts a request to a hard-coded Render URL when the VIGIL tab renders. The request is not part of the Flask path and was not executed. `trial/app.py` and `trial/popup.js` are older prototypes; the prototype popup uses a hard-coded remote API, its own 45%/75% thresholds and `innerHTML` interpolation. No current manifest references `trial/`.

## Startup, deployment, configuration, and tests

### Entrypoints and reproducible commands

- Local backend: `python api.py` (binds `127.0.0.1`, defaults to port 5000).
- Frontend: from `frontend/`, `npm run dev`; `npm run build` performs `tsc -b && vite build`; `npm test -- --run` runs Vitest.
- Extension: load `extenison/` unpacked in Chromium after starting the API. The documented Node checks/tests are listed in `extenison/README.md`.
- Training/evaluation as documented: `python prepare_dataset.py`, `python train_model.py`, then `python evaluate_model.py`. These expect absent input data; training also writes production artifacts, so none were run.
- Python test command in README/CI: `python -m pytest -q`; CI also compiles selected modules with `python -m py_compile`.
- `Procfile` declares `web: gunicorn api:app`. No container/orchestrator or explicit production bind/auth configuration was found.
- `run_vigil.bat` points at a different user's absolute path and launches backend/frontend terminals. `runme.bat` points at another stale path and writes `shell_test.txt`; neither was run.
- `frontend/qa/browser-qa.mjs` requires a running backend/frontend and Playwright, writes screenshots under `frontend/qa-output/`, and was not run.

### Environment and dependency state

Environment variables observed: `VIGIL_PORT`, `VIGIL_FRONTEND_ORIGIN`, `VITE_API_BASE_URL`. The extension endpoint is hard-coded to `127.0.0.1:5000`. `frontend/.env.example` sets `VITE_API_BASE_URL=http://localhost:5000`; no real `.env` file was inspected or found in the inventory.

The local `.venv` reports Python 3.11.9 and installed versions Flask 3.1.3, Flask-CORS 6.0.5, gunicorn 26.2.0, NumPy 2.4.6, pandas 3.0.6, psutil 7.2.2, pytest 9.1.1, requests 2.34.2, scikit-learn 1.9.1, Streamlit 1.65.0, and tldextract 5.4.0. Training metadata records Python 3.13.15, NumPy 2.5.3, pandas 3.0.6, scikit-learn 1.9.1, and tldextract 5.3.2. The CI workflow targets Python 3.12 and Node 20; the available Node/npm are 24.19.0/11.17.0. This is a runtime/reproducibility mismatch, not evidence that the current model fails to load.

`requirements.txt` is unpinned. `frontend/package.json` uses `latest` for several direct dependencies, although the committed `frontend/package-lock.json` currently resolves React 19.3.0, Vite 8.3.2, TypeScript 7.0.2, Vitest 5.0.3, and Playwright 1.63.0. `npm ci` is the reproducible install path in CI.

### Test evidence

| Evidence | Result | Status |
|---|---:|---|
| `node --test extenison\\extension.test.mjs extenison\\background.runtime.test.mjs` | 23 passed, 0 failed | Run during this audit |
| Python pytest | Not run | No current result |
| Frontend Vitest/build | Not run | No current result |
| Browser QA | Not run | Requires running app/browser and writes screenshots |
| `reports/final_promotion_gate.json` historical test record | Python 15, frontend 3, extension 8; build and syntax checks marked PASS | Reported historical result, not rerun here |

The current `tests/test_pipeline.py` imports `scripts.final_ml_pass` in `test_experimental_url_features_share_serving_canonicalization`, but `scripts/final_ml_pass.py` is absent (and explicitly ignored by `.gitignore`). This is a likely current pytest failure point; no Python test was run to confirm it.

## Production ML audit

The separate structured record is [repository_ml_audit.json](./repository_ml_audit.json). It distinguishes the root serving artifact from experiment outputs.

### Production artifact and schema

| Property | Current artifact evidence |
|---|---|
| Model path/type/version | `phishing_model.pkl`; `CalibratedHistGradientBoosting`; `v2.1.0` |
| Feature list | `feature_names.pkl`; 29 ordered features in `model_metadata.json`; hash matches metadata |
| Model SHA-256 | `5f16e09d5f6fb613d391051b2b5693cf47478356d77cec8c8e52f5b309159ba2` |
| Feature-list SHA-256 | `d02a7c9cd2cb5b73c2bbccc7347c240fed6d77593b8e7d602dbb67f424099da9` |
| Feature-extractor SHA-256 | `826436788ddf02e2dfe76c55cf6e062bab297c3cf1ead4602e4533c446733874`, matching metadata |
| Feature count | 29 |
| Calibration | Metadata identifies a calibrated histogram-gradient-boosting classifier; training report describes calibration. The pickle itself was not deserialized. |

Ordered feature schema:

`URLLength`, `HostnameLength`, `PathLength`, `QueryLength`, `FragmentLength`, `PathSegmentCount`, `QueryParameterCount`, `DotCount`, `SubdomainDepth`, `NoOfDigitsInURL`, `DigitRatioInURL`, `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfAtInURL`, `NoOfHyphenInURL`, `NoOfUnderscoreInURL`, `URLPercentEncodingCount`, `HasObfuscation`, `HasUserInfo`, `HasPort`, `IsDomainIP`, `IsShortened`, `HasSuspiciousTLD`, `HasSuspiciousToken`, `IsTrustedTLD`, `URLEntropy`.

The extractor exposes 35 values, but metadata excludes six: `IsHTTPS` (kept for evidence, excluded after protocol counterfactuals), `DomainLength` (alias of `HostnameLength`), `NoOfSubDomain` (alias of `SubdomainDepth`), `HasSuspiciousWord` (alias of `HasSuspiciousToken`), and `HasTrustedBrand`/`HasTrustedBrandToken` (constant-zero placeholders).

### Dataset, metrics, and evaluation interpretation

Active metadata says 234,432 training rows, class counts 134,849/99,583, 197,707 registered domains, and input `final_dataset_v2.csv` with no upstream provenance or collection dates. It records 936 duplicate removals and two conflicting-label rows removed. The named raw CSV and generated `data/processed/clean_dataset.csv` are not present.

Recorded split metrics at the default `0.5` decision threshold:

| Split | Test rows | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | Domain overlap |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Stratified random | 46,887 | 0.8609 | 0.9560 | 0.7051 | 0.8116 | 0.8846 | 0.0240 | 0.2949 | 3,272 registered domains |
| Registered-domain holdout | 47,901 | 0.8632 | 0.9519 | 0.7218 | 0.8210 | 0.8875 | 0.0280 | 0.2782 | 0 |

The split metrics are stored in metadata; `reports/metrics.json` is not a fresh metric table: it records `blocked_model_dataset_mismatch`, with the candidate dataset hash different from the production dataset hash. `evaluate_model.py` itself refuses to report mixed-dataset metrics. The reported random split is leakage-prone because domains overlap; the domain split is the more relevant generalization check, but neither establishes real-world accuracy.

Training's saved threshold-selection method used a separate 18,755-row partition and constraints of at most 2% false-safe rate and at most 1% benign phishing rate. The resulting serving cutoffs are safe `0.13140956380602112` and phishing `0.6961575221255231`. Random/domain ECEs are recorded as about 0.0048/0.0067. These are dataset-conditioned estimates; no temporal evaluation is available.

The bundled Phishing.Database feed is phishing-only. Historical `reports/external_validation.json` records 154,931 positives and recall 0.9572, but cannot establish false-positive rate or overall accuracy on a population containing negatives. Active `model_metadata.json` says external validation was not run because no compatible independently licensed source was integrated. Treat the old one-class report as limited error analysis, not an independent balanced validation.

### Experiments and promotion

The actual serving path in `service.py` loads only the three root artifacts. `models/experimental/dynamic_candidate/dynamic_candidate.joblib` and AutoML candidate files are experimental; nothing in the serving code points at them. `models/backup/*` holds metadata snapshots, not complete backup bundles. `train_model_backup_before_balancing.py` is byte-identical to current `train_model.py`.

`reports/final_promotion_gate.json` (2026-10-07) says **DO NOT PROMOTE**. It describes a domain-only hostname-character TF-IDF + logistic-regression candidate, but states that no serving artifact was persisted and the candidate fast.com results and complete three-way legitimate-reference triage were missing. It also records 233 false phishing outcomes in the candidate legitimate cohort and an approximately 8.8× model-size increase. A separate 190-row dynamic HGB experiment (`95` benign and `95` phishing rows) fails the saved evaluation gates; it is not a production replacement.

### Bias, failure modes, and known inconsistencies

- Provenance is missing for the production training CSV; collection dates are absent, so drift/temporal performance is unknown.
- Random-split domain overlap is 3,272; the zero-overlap domain split helps, but available reports remain dataset-specific and class prevalence is artificial.
- `PathLength` dominates the current feature-importance table (0.2483), followed by URL length (0.0652), digit count (0.0559), and dot count (0.0452). This is a lexical shortcut/bias concern, not proof of a particular exploit.
- Current stored domain holdout recall at threshold 0.5 is 72.18% (27.82% false-negative rate). The phishing-only external report has 4.28% misses in a different run/report and cannot be reconciled into an overall production estimate.
- `fast.com` is a documented historical false-positive regression. Metadata/README report current canonical variants SAFE at probability 0.060029, but the latest candidate gate could not certify equivalent candidate behavior.
- Root `dataset_summary.json` says the replacement dataset was not generated and reports only 95 retained real benign URL rows with missing required structures; curated benchmark rows are excluded as not real observations. This conflicts with old merged-source and experiment reports.
- `data/processed/dataset_summary.json` describes an earlier 854,870-row PhiUSIIL + phishing-feed workflow; active model metadata instead claims a 234,432-row local `final_dataset_v2.csv`. Neither named training CSV is present.
- `docs/MODEL_REPORT.md` explicitly warns it is historical, yet includes superseded thresholds/metrics. `config.py` defaults (`0.45`/`0.85`) also differ from the active metadata thresholds. `service.py` currently trusts valid metadata values, so these defaults are fallback values rather than the live policy.
- No locally retained evaluation data can reproduce the active model's training, threshold selection, or split metrics. The artifacts are hash-consistent with metadata, but the absence of a signed metadata source means hashes are integrity checks against accidental/tampered artifact mismatch, not an authenticity chain.

## File-by-file audit

The inventory JSON is exhaustive for paths/types/sizes/purpose/status. The following tables cover project-owned source, configuration, tests, and documentation by file. `Content review` distinguishes direct implementation review from signature/entry-point review.

### Backend, inference, and root utilities

| File | Purpose, inputs/outputs, dependencies, and use | State / findings |
|---|---|---|
| [api.py](../api.py) | Flask app; validates JSON and URL requests, exposes health/model/history endpoints, sanitizes and persists history; calls `service.scan`/`model_info`, SQLite, Flask-CORS. Clients are the React service and extension worker. | Active; implementation reviewed. No API auth; CORS is not authorization. Public deployment through Gunicorn would need an explicit trusted-network/auth boundary. |
| [service.py](../service.py) | Single inference path: artifact loading/hash check, thresholds, evidence, classification, risk score, response object; consumes `feature_extractor.py`, `config.py`, pandas, root model artifacts. Used by API, wrapper, tests, Streamlit UI. | Active; implementation reviewed. Hash verification is conditional on a nonempty expected digest; metadata is not signed. Pickle deserialization assumes trusted local artifacts. |
| [feature_extractor.py](../feature_extractor.py) | URL normalization, IDN/IP/domain handling, entropy, feature extraction; used by service and preparation/training/evaluation/scripts/tests. | Active; implementation reviewed. 35 computed values, 29 production fields; rules are lexical and not page/reputation signals. |
| [config.py](../config.py) | Model-version/type defaults, fallback thresholds, static suspicious domains/TLDs/tokens; imported by inference/training. | Active configuration; defaults do not match current metadata thresholds. `TRUSTED_DOMAINS` is not the serving decision path; no trusted-domain bypass is used. |
| [phishing_detector.py](../phishing_detector.py) | Compatibility facade `predict_url`, `check_phishing`; forwards to service. Used by legacy Streamlit UI, tests, validation script. | Compatibility/legacy; `check_phishing` converts all exceptions to an `ERROR` dict including raw exception text. The Flask API bypasses it. |
| [app.py](../app.py) | Streamlit dashboard with local system monitor and VIGIL scan tab; calls `phishing_detector`, psutil, Streamlit. | Legacy alternate UI; selected sections reviewed. Hard-coded external Render request and broad exception suppression; not the documented React/API startup. |
| [prepare_dataset.py](../prepare_dataset.py) | Canonicalizes `url`/label records, normalizes, deduplicates/conflict audits, writes prepared dataset and summary; used by training and `data_audit.py`. | Active training prerequisite; major paths reviewed. Requires absent root `final_dataset_v2.csv`; do not run without explicitly reviewing its writes. |
| [train_model.py](../train_model.py) | Trains/compares Logistic Regression, Random Forest, HGB; uses domain-disjoint partitions, calibration, threshold selection, metrics and writes root model/features/metadata/importance with backup. | Active trainer but not run; major sections/entry point reviewed. Mutates production artifacts if executed; data input absent. |
| [evaluate_model.py](../evaluate_model.py) | Loads production bundle, checks dataset and feature-extractor hashes, makes holdout metrics or writes a blocked mismatch report. | Active evaluation script; implementation reviewed. Requires absent clean CSV; can overwrite `reports/metrics.json`. |
| [data_audit.py](../data_audit.py) | Calls `prepare_records` on root `final_dataset_v2.csv` and writes root `dataset_audit_report.json`. | Utility, not runtime; data absent. |
| [collect_legitimate_urls.py](../collect_legitimate_urls.py) | Requests external sitemap/feed/Hacker News/GitHub/Wiki/Wayback/Common Crawl sources, validates/deduplicates URLs and writes collection results. | Data-acquisition utility; function/signature survey. Has outbound network behavior; not executed. Reports and provenance should be checked before training from its results. |
| [large_legitimate_regression.py](../large_legitimate_regression.py) | Builds URL-structure references, evaluates production/experimental predictions and regression cohorts; imports service and dynamic-recovery experiment. | Experiment/regression utility; declarations and report evidence reviewed, not run. |
| [validation_check.py](../validation_check.py) | Prints predictions for a fixed benign/suspicious URL sample through `phishing_detector.predict_url`. | Manual smoke-check utility; not executed. |
| [fix_dataset.py](../fix_dataset.py) | Legacy CSV conversion from `dataset_phishing.csv` status to URL/label output. | Stale one-off; expected input absent, hard-coded filenames. |
| [merge_dataset.py](../merge_dataset.py) | Legacy concatenation of several differently named CSV sources and label normalization. | Stale one-off; broad bare `except`, hard-coded paths, and empty input list can fail at concat. Not the active `prepare_dataset.py` pipeline. |

### Training experiments, scripts, and backups

| File(s) | Purpose and relationships | State / evidence |
|---|---|---|
| [train_balanced_experiment.py](../train_balanced_experiment.py) | Experimental balanced training/evaluation; consumes historical datasets and writes candidate reports/artifacts. | Experimental; signatures/entry-point overview and reports reviewed only. Not imported by serving path. |
| [train_dynamic_augmentation_experiment.py](../train_dynamic_augmentation_experiment.py) | Dynamic benign augmentation, domain split, calibration, candidate comparison and regression suite. | Experimental; signatures and associated reports reviewed. Candidate not promoted. |
| [train_dynamic_hardening_experiment.py](../train_dynamic_hardening_experiment.py) | Large experiment for dynamic strata, weighted sampling, domain split, calibration, feature/source analyses. | Experimental; multi-thousand-line body not exhaustively inspected. Reports mark promotion gates/limitations; do not equate with production. |
| [train_dynamic_recovery_experiment.py](../train_dynamic_recovery_experiment.py) | Recovery/augmentation candidate experiments and cohort evaluation. | Experimental; signatures and reports reviewed, not run. |
| [train_model.py.backup_dynamic](../train_model.py.backup_dynamic) | Earlier training implementation backup. | Backup/legacy; not a serving import. |
| [train_model_backup_before_balancing.py](../train_model_backup_before_balancing.py) | Backup copy of trainer. | Exact byte-for-byte duplicate of `train_model.py` (SHA-256 verified). |
| [scripts/analyze_dynamic_training_bias.py](../scripts/analyze_dynamic_training_bias.py), [scripts/analyze_experiment_failure.py](../scripts/analyze_experiment_failure.py) | Analyze source/cohort overlap and experiment failure reports. | Offline analysis scripts; structural review only; use saved reports as evidence. |
| [scripts/baseline_dynamic_urls.py](../scripts/baseline_dynamic_urls.py), [scripts/build_dynamic_benign_cohort.py](../scripts/build_dynamic_benign_cohort.py) | Prepare dynamic-URL baseline/cohort outputs for experiments. | Experimental data prep, not runtime; no output regenerated. |
| [scripts/collect_benign_dynamic_urls.py](../scripts/collect_benign_dynamic_urls.py) | Collect real benign dynamic URLs from configured external sources. | Network-capable data collector; not run; keep provenance and license data with any resulting rows. |
| [scripts/dynamic_counterfactual_analysis.py](../scripts/dynamic_counterfactual_analysis.py), [scripts/dynamic_url_false_positive_analysis.py](../scripts/dynamic_url_false_positive_analysis.py) | Counterfactual feature and benign false-positive investigations. | Offline analyses; saved reports show the candidate remains unpromoted. |
| [scripts/evaluate_dynamic_candidate.py](../scripts/evaluate_dynamic_candidate.py), [scripts/record_candidate_evaluation.py](../scripts/record_candidate_evaluation.py) | Apply candidate gates and persist candidate-evaluation reports. | Experiment-only; not part of inference. |
| [scripts/external_phishing_error_analysis.py](../scripts/external_phishing_error_analysis.py), [scripts/verify_phishing_feed.py](../scripts/verify_phishing_feed.py) | Analyze misses in a phishing-only feed and verify feed records. | Offline report tools; one-class feed cannot measure FPR. |
| [scripts/load_murl.py](../scripts/load_murl.py) | Load/normalize MURL dataset inputs for experiment processing. | Data utility; data requirements and output provenance need verification before use. |
| [scripts/run_auto_ml_experiment.py](../scripts/run_auto_ml_experiment.py), [scripts/run_domain_model_experiment.py](../scripts/run_domain_model_experiment.py) | Run candidate-model sweeps and domain-character model experiments. | Experimental only; persisted candidate leaderboard/gate reports; not invoked by service. |
| [scripts/train_benign_dynamic_url_experiment.py](../scripts/train_benign_dynamic_url_experiment.py), [scripts/train_dynamic_candidate.py](../scripts/train_dynamic_candidate.py) | Fit dynamic-benign and 29-feature HGB candidates. | Experimental; saved 190-row candidate evaluation fails gates; no production replacement. |
| [scripts/validation_report.py](../scripts/validation_report.py) | Emit a human-readable validation/regression report. | Offline reporting script; not run. |
| [experiments/auto_ml/data_bootstrap_001/collect_verified_legitimate.py](../experiments/auto_ml/data_bootstrap_001/collect_verified_legitimate.py), [experiments/auto_ml/data_bootstrap_002/collect_verified_legitimate.py](../experiments/auto_ml/data_bootstrap_002/collect_verified_legitimate.py) | Separate collection/bootstrap attempts for verified legitimate examples. | Experimental/network-capable scripts; outputs and source provenance remain experiment artifacts. |

### React frontend

| File(s) | Purpose / usage |
|---|---|
| [frontend/package.json](../frontend/package.json), [frontend/package-lock.json](../frontend/package-lock.json) | Scripts and dependency manifests; lockfile used by `npm ci`; several manifest versions are `latest`. |
| [frontend/vite.config.ts](../frontend/vite.config.ts), [frontend/tsconfig.json](../frontend/tsconfig.json), [frontend/tsconfig.app.json](../frontend/tsconfig.app.json), [frontend/tsconfig.node.json](../frontend/tsconfig.node.json) | Vite/React/Tailwind/Vitest and strict TypeScript project configuration. |
| [frontend/index.html](../frontend/index.html), [frontend/src/main.tsx](../frontend/src/main.tsx) | HTML mount point and React entry point. |
| [frontend/src/App.tsx](../frontend/src/App.tsx) | Health check, page state, Shell and page routing. |
| [frontend/src/services/api.ts](../frontend/src/services/api.ts) | Typed fetch wrappers for scan/history/model/health endpoints. Response types are compile-time only; JSON is cast without runtime schema validation. |
| [frontend/src/types.ts](../frontend/src/types.ts) | API/UI types for verdict, evidence, scan, model, and health. |
| [frontend/src/utils.ts](../frontend/src/utils.ts), [frontend/src/utils.test.ts](../frontend/src/utils.test.ts) | URL validation and formatting helpers; small unit tests. |
| [frontend/src/pages/ScanPage.tsx](../frontend/src/pages/ScanPage.tsx) | Validates and submits user URL; calls API and renders result. |
| [frontend/src/pages/HistoryPage.tsx](../frontend/src/pages/HistoryPage.tsx) | Loads, selects, and clears API history. Clear-history rejection has no local error handling. |
| [frontend/src/pages/AnalysisPage.tsx](../frontend/src/pages/AnalysisPage.tsx) | Summarizes recorded classifications and displays model metadata. |
| [frontend/src/pages/AboutPage.tsx](../frontend/src/pages/AboutPage.tsx) | Describes URL-only scope and limitations. |
| [frontend/src/components/Shell.tsx](../frontend/src/components/Shell.tsx), [frontend/src/components/StatusBadge.tsx](../frontend/src/components/StatusBadge.tsx) | Navigation/service state and label badge. |
| [frontend/src/components/ScanResult.tsx](../frontend/src/components/ScanResult.tsx), [frontend/src/components/RiskMeter.tsx](../frontend/src/components/RiskMeter.tsx) | Result summary, copy, score display, technical disclosure. |
| [frontend/src/components/EvidenceList.tsx](../frontend/src/components/EvidenceList.tsx), [frontend/src/components/FeatureGrid.tsx](../frontend/src/components/FeatureGrid.tsx) | Evidence presentation and allowlisted display of selected model features. |
| [frontend/src/styles.css](../frontend/src/styles.css), [frontend/src/test-setup.ts](../frontend/src/test-setup.ts), [frontend/src/vite-env.d.ts](../frontend/src/vite-env.d.ts) | Styling, Vitest setup, and Vite environment typing. |
| [frontend/qa/browser-qa.mjs](../frontend/qa/browser-qa.mjs) | Playwright end-to-end/responsive-flow test; requires live API/UI and writes screenshots. |

### Browser extension and prototypes

| File(s) | Purpose / usage |
|---|---|
| [extenison/manifest.json](../extenison/manifest.json) | MV3 manifest, permissions, worker and popup. Typographical directory name is reflected in docs/tests. |
| [extenison/background.js](../extenison/background.js) | API-backed navigation scanner, cache, badge, block interstitial and one-time bypass; active worker. |
| [extenison/popup.js](../extenison/popup.js), [extenison/popup.html](../extenison/popup.html), [extenison/popup.css](../extenison/popup.css) | Current-tab scan UI and styling. |
| [extenison/blocked.js](../extenison/blocked.js), [extenison/blocked.html](../extenison/blocked.html), [extenison/blocked.css](../extenison/blocked.css) | Local blocked page; uses textContent and worker storage state rather than embedding/opening the target page. |
| [extenison/extension.test.mjs](../extenison/extension.test.mjs), [extenison/background.runtime.test.mjs](../extenison/background.runtime.test.mjs) | Manifest/surface checks and mocked worker behavior tests; executed together in this audit. |
| [trial/app.py](../trial/app.py), [trial/popup.js](../trial/popup.js) | Older duplicate Streamlit/popup experiment; no current entry-point wiring. `trial/app.py` defines `scan_url` twice, so the later definition shadows the earlier one. Popup's unescaped `innerHTML` interpolation of URL/result data is an XSS risk if this obsolete prototype is used. |

### Documentation and data/report artifacts

The root [README.md](../README.md) describes install, run, API, training, tests, metrics, security, and limitations. It is mostly aligned with the API architecture but assumes missing training CSVs and reports historical metrics as the latest. `docs/API.md` documents API contracts; `docs/ARCHITECTURE.md` describes intended Flask/service/model flow. `extenison/README.md` documents extension flow/security; `frontend/README.md` documents Vite commands.

The remaining documentation is evidence with differing dates and status, not a single source of truth:

| File | Purpose / audit note |
|---|---|
| `docs/BACKEND_AUDIT.md` | Prior backend/model reliability audit; historical results. |
| `docs/BENIGN_DYNAMIC_URL_TRAINING.md` | Benign dynamic URL experiment and candidate comparisons; not promoted. |
| `docs/DATASET_REPORT.md`, `docs/DATA_AUDIT.md` | Data preparation/source and historical audit evidence; compare with current blocked root summary. |
| `docs/DOMAIN_MODEL_EXPERIMENT.md` | Domain-character candidate experiment. |
| `docs/DYNAMIC_TRAINING_COMPARISON.md`, `docs/DYNAMIC_URL_FALSE_POSITIVE_ANALYSIS.md` | Dynamic training and false-positive analyses; candidate-only. |
| `docs/EXTERNAL_PHISHING_ERROR_ANALYSIS.md` | Errors on phishing-only external feed; cannot support FPR. |
| `docs/FALSE_POSITIVE_ANALYSIS.md` | `fast.com` regression history and canonicalization. |
| `docs/FINAL_ML_PASS.md`, `docs/FINAL_PROMOTION_GATE.md`, `docs/FINAL_TRAINING_COMPARISON.md` | Final ML/generalization, promotion, and candidate comparison records; promotion gate explicitly says do not promote. |
| `docs/FINAL_REPORT.md`, `docs/INSPECTION.md` | Repository maintenance and inspection snapshots; historical status. |
| `docs/ml-evaluation.md` | Current-style v2.1.0 metrics/provenance narrative; metadata supports its stated domain/random metrics, but source data is absent. |
| `docs/MODEL_REPORT.md` | Explicitly marked historical; includes obsolete threshold values, do not cite as current. |
| `docs/project-report.md` | Presentation-style overview/results/architecture; historical and broader than current implementation. |
| `validation_report.md` | Synthetic/reference regression report, not an independent real-world holdout. |
| `test/sample set.md` | Manual sample URL set, not an automated test. |
| `audit_notebook.ipynb` | Small local audit notebook with a code cell; not executed. |
| `docs/ideation-ppt.pdf` | Binary presentation; metadata inventoried, contents not inspected. |

`reports/` contains 38 pre-existing experiment/evaluation outputs before the three audit reports: `auto_ml_leaderboard.json`, `baseline_dynamic_legitimate.json`, `benign_dynamic_url_sources.json`, `benign_dynamic_url_training.json`, `calibration.json`, `dataset_overlap.json`, `dataset_quality.json`, `domain_model_experiment.json`, `dynamic_augmentation_final.json`, `dynamic_augmentation_run.txt`, `dynamic_benign_cohort.json`, `dynamic_candidate_evaluation.json`, `dynamic_candidate_promotion.json`, `dynamic_candidate_training.json`, `dynamic_counterfactual_analysis.json`, `dynamic_experiment_failure_analysis.json`, `dynamic_hardening_final.json`, `dynamic_hardening_run.txt`, `dynamic_recovery_comparison.json`, `dynamic_recovery_final.json`, `dynamic_training_bias_analysis.json`, `dynamic_training_comparison.json`, `dynamic_url_false_positive_analysis.json`, `error_analysis.json`, `external_phishing_error_analysis.json`, `external_validation.json`, `final_ml_validation.json`, `final_promotion_gate.json`, `final_training_comparison.json`, `large_legitimate_regression.json`, `legitimate_dynamic_benchmark.json`, `legitimate_dynamic_benchmark_results.json`, `metrics.json`, `model_comparison.json`, `phishing_feed_verification.json`, `recovered_dynamic_data.json`, `regression.json`, and `residual_fp_correction_run.txt`. The inventory gives individual sizes and parsed/metadata-only status. Their primary roles are collection/source manifests, data-quality and overlap checks, candidate training/comparison, counterfactual/error/cohort analysis, calibration, regression, external feed analysis, and promotion-gate decisions.

Root `model_metadata.json`, `dataset_summary.json`, and `dataset_audit_report.json` are metadata/audit records; `feature_importance.csv` is a 29-row feature-importance table; `legitimate_real_collection.json` is collection data. `data/experiments/legitimate_dynamic_training.csv` is the limited retained real benign sample; `legitimate_dynamic_benchmark.csv` includes curated public-service patterns which the current data summary explicitly excludes from real training. The external phishing feed is mirrored in the embedded `data/external/Phishing.Database` checkout. No dataset/model downloads were performed.

## Security, reliability, and reproducibility findings

1. **Local API trust boundary:** no authentication/rate limiting is present. History is readable/deletable by any client that reaches it. CORS restricts browser origins but does not authenticate callers. The Python dev server binds loopback; the `Procfile` does not document an auth/network boundary for a hosted Gunicorn deployment.
2. **History privacy is partial:** query, fragment, and userinfo are removed before new persistence, but secret-looking path segments can remain. The scan response itself still contains the submitted URL. Existing SQLite history was not inspected, so legacy rows' sanitization is unknown.
3. **Legacy HTML risk:** `trial/popup.js` interpolates URL and response data into `innerHTML`. It is not wired by the current extension manifest. Root `app.py` also uses Streamlit `unsafe_allow_html` for an older UI and contacts an external Render endpoint.
4. **Untrusted model artifacts:** Python pickle/joblib deserialization can execute code. Current hashes match metadata and the files are local, but hashes do not authenticate metadata; only load trusted artifacts.
5. **Fail-open extension behavior:** deliberate UX safety on backend errors means phishing navigation can continue when the service is offline or times out; the popup reports offline separately and does not invent a verdict.
6. **Unpinned environments and absent training inputs** prevent repeatable clean installation/training from the current snapshot. Python versions differ between local venv, training metadata, and CI.
7. **Metric/source contradictions** are detailed in the ML section and JSON audit; the active artifact must be distinguished from old reports and experimental candidates.
8. **Existing JSON syntax defects:** `reports/external_validation.json` and `reports/model_comparison.json` contain bare `NaN` tokens. Strict JSON consumers will reject them; these pre-existing files were not modified.

## Content excluded from inspection

| Path/scope | Reason and treatment |
|---|---|
| `.venv/` | Dependency implementation; 16,681 files / 575,348,309 bytes, summarized only. Relevant installed package versions were read from dist-info metadata. |
| `frontend/node_modules/` | Dependency implementation; 10,003 files / 190,150,088 bytes, summarized only. Versions were read from the lockfile, not individual package source. |
| `data/external/Phishing.Database/.git/` | Embedded external repository history; 31 files / 1,676,716,444 bytes, summarized only. Root project `.git` is absent. |
| `phishing_model.pkl`, `feature_names.pkl`, `models/experimental/**/*.joblib` | Serialized artifacts not deserialized; production hashes and metadata were checked. |
| `vigil_history.sqlite3` | Potentially sensitive local scan records; metadata/size only. |
| External feed/adblock data under `data/external/` | Large dataset rows not read; paths/sizes and saved aggregate reports reviewed. The duplicated 66,612,944-byte feed copies were streaming-hash compared. |
| `data/experiments/*.csv`, `legitimate_real_collection.json`, and large report JSONs (notably `reports/large_legitimate_regression.json`) | Dataset/experiment contents not copied into the audit; sizes and JSON structure/summary fields reviewed. |
| `docs/ideation-ppt.pdf`, extension PNG icons | Binary presentation/image contents not inspected. |
| Python `.pyc` files under `__pycache__/` | Generated bytecode; inventoried, not decompiled. |
| `reports/*.txt` experiment logs and feed text rows | File metadata only except report summaries already represented in structured JSON/docs; no external data retrieved. |
| `frontend/src/styles.css`, extension CSS files | Layout/style source not reviewed property-by-property; inventory status records the limited inspection. |

## Open questions / unresolved evidence

- What exact source, collection date, license, and label policy produced `final_dataset_v2.csv`? The file is absent and metadata says those fields were unavailable.
- Which of the competing data snapshots (`854,870`-row merged workflow, `234,432`-row metadata source, or blocked 95-row benign preparation state) is intended to be canonical for future evaluation?
- Can the current production model be loaded under the installed Python 3.11.9 environment, and are its full serialized dependencies compatible? This was intentionally not tested.
- Are the historical external-feed metrics independently reproducible and suitable for any claim? Saved artifacts conflict: metadata says external validation was not run, while older reports contain phishing-only measurements.
- Is the loopback-only API intended to remain local-only, or is Gunicorn deployed on a network? No deployment boundary/auth evidence is present.
- Which old Streamlit/trial clients, collection scripts, and experimental reports are still intended to be supported?
- What are the actual current repository branch/commit and working-tree changes? No root Git metadata exists.
