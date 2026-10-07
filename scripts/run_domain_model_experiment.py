"""Targeted URL-only domain morphology experiment; never writes production artifacts."""
from __future__ import annotations

import json
import os
import pickle
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from feature_extractor import extract_features, get_registered_domain, normalize_url  # noqa: E402
from service import load_model_bundle  # noqa: E402
from train_model import calibration_metrics, threshold_search  # noqa: E402

DATASET = os.path.join(ROOT, "data", "processed", "clean_dataset.csv")
EXTERNAL = os.path.join(ROOT, "data", "processed", "external_validation.csv")
OUT = os.path.join(ROOT, "reports", "domain_model_experiment.json")
DOC = os.path.join(ROOT, "docs", "DOMAIN_MODEL_EXPERIMENT.md")


def metrics(y, p, threshold=0.5):
    y, p = np.asarray(y, dtype=int), np.asarray(p, dtype=float)
    pred = p >= threshold
    tn = int(((y == 0) & ~pred).sum()); fp = int(((y == 0) & pred).sum())
    fn = int(((y == 1) & ~pred).sum()); tp = int(((y == 1) & pred).sum())
    roc = float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None
    fpr = float(fp / max(fp + tn, 1)) if (y == 0).any() else None
    return {"pr_auc": float(average_precision_score(y, p)), "roc_auc": roc, "precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)), "f1": float(f1_score(y, pred, zero_division=0)), "fpr": fpr, "fnr": float(fn / max(fn + tp, 1)), "brier": float(brier_score_loss(y, p)), "ece": calibration_metrics(y, p)["expected_calibration_error"], "confusion_matrix": [[tn, fp], [fn, tp]]}


def latency_ms(fn, repeats=15):
    values = []
    for _ in range(repeats):
        start = time.perf_counter(); fn(); values.append((time.perf_counter() - start) * 1000)
    return float(np.median(values))


def calibrator_fit(raw, y):
    model = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000)
    model.fit(np.asarray(raw).reshape(-1, 1), y)
    return model


def domain_features(values):
    rows = []
    for value in values:
        parsed = urlsplit(value); host = (parsed.hostname or "").lower().strip("."); registered = get_registered_domain(value)
        chars = host or registered; n = max(len(chars), 1); counts = {c: chars.count(c) for c in set(chars)}
        ent = -sum((count / n) * np.log2(count / n) for count in counts.values())
        vowels = sum(c in "aeiou" for c in chars); repeated = max((chars.count(c) for c in set(chars)), default=0) / n
        rows.append([len(registered), len(host), ent, sum(c.isdigit() for c in chars) / n, chars.count("-") / n, repeated, len(set(chars)) / n, vowels / n, (len(chars) - vowels) / n, max(len(host.split(".")) - 2, 0), int("xn--" in host), int(any(ord(c) > 127 for c in value)), int(bool(re.search(r"(.)\1\1", chars))), int(any(not c.isalnum() and c not in ".-" for c in chars))])
    return np.asarray(rows, dtype=float)


def cohorts(frame, p, threshold):
    parsed = frame["url"].map(urlsplit); host = parsed.map(lambda x: x.hostname or ""); path = parsed.map(lambda x: x.path or ""); query = parsed.map(lambda x: x.query or "")
    masks = {"pathless": path.isin(["", "/"]), "short": frame["url"].str.len() <= 60, "https": parsed.map(lambda x: x.scheme.lower() == "https"), "no_suspicious_token": frame["url"].map(lambda x: not bool(extract_features(x)["HasSuspiciousToken"])), "no_suspicious_tld": frame["url"].map(lambda x: not bool(extract_features(x)["HasSuspiciousTLD"])), "no_digits": frame["url"].str.count(r"\d").eq(0), "no_ip": frame["url"].map(lambda x: not bool(extract_features(x)["IsDomainIP"])), "ordinary_looking_domain": frame["url"].map(lambda x: not bool(extract_features(x)["HasSuspiciousToken"] or extract_features(x)["HasSuspiciousTLD"] or extract_features(x)["IsDomainIP"]))}
    y = frame["label"].to_numpy(); output = {}
    for name, mask in masks.items():
        mask = np.asarray(mask, dtype=bool); positives = y == 1; selected = mask & positives; missed = selected & (p < threshold); output[name] = {"samples": int(selected.sum()), "detected": int((selected & (p >= threshold)).sum()), "recall": float(1 - missed.sum() / max(selected.sum(), 1)), "fnr": float(missed.sum() / max(selected.sum(), 1))}
    return output


def main():
    started = time.perf_counter()
    df = pd.read_csv(DATASET); external = pd.read_csv(EXTERNAL)
    df["hostname"] = df["url"].map(lambda x: (urlsplit(x).hostname or "").lower())
    df["registered_domain"] = df["url"].map(get_registered_domain)
    y = df["label"].astype(int).to_numpy(); groups = df["registered_domain"].to_numpy()
    baseline, feature_names, metadata = load_model_bundle()
    X_url = pd.DataFrame(df["url"].map(extract_features).tolist())[feature_names]
    X_ext = pd.DataFrame(external["url"].map(extract_features).tolist())[feature_names]

    # Four group-disjoint partitions: fit 60%, calibration 10%, threshold 10%, test 20%.
    first = GroupShuffleSplit(n_splits=1, test_size=.2, random_state=44)
    fitcal_idx, test_idx = next(first.split(df, y, groups))
    second = GroupShuffleSplit(n_splits=1, test_size=.5, random_state=45)
    fit_idx, threshold_idx = next(second.split(df.iloc[fitcal_idx], y[fitcal_idx], groups[fitcal_idx]))
    fit_idx, threshold_idx = fitcal_idx[fit_idx], fitcal_idx[threshold_idx]
    third = GroupShuffleSplit(n_splits=1, test_size=(.1 / .7), random_state=46)
    train_idx, cal_idx = next(third.split(df.iloc[fit_idx], y[fit_idx], groups[fit_idx]))
    train_idx, cal_idx = fit_idx[train_idx], fit_idx[cal_idx]
    split = {"train_rows": int(len(train_idx)), "calibration_rows": int(len(cal_idx)), "threshold_rows": int(len(threshold_idx)), "test_rows": int(len(test_idx)), "overlapping_domains": int(len(set(groups[train_idx]) & set(groups[test_idx]))), "strategy": "registered-domain GroupShuffleSplit"}

    variant_results = {}; chosen = None
    for ngram in [(3, 5), (3, 6), (2, 6)]:
        t0 = time.perf_counter(); vec = TfidfVectorizer(analyzer="char", ngram_range=ngram, min_df=2, max_features=250000, sublinear_tf=True, dtype=np.float32)
        tr = vec.fit_transform(df["hostname"].iloc[train_idx]); cal = vec.transform(df["hostname"].iloc[cal_idx]); te = vec.transform(df["hostname"].iloc[test_idx])
        raw_model = LogisticRegression(C=2.0, class_weight="balanced", solver="liblinear", max_iter=1000)
        raw_model.fit(tr, y[train_idx]); cal_raw = raw_model.predict_proba(cal)[:, 1]; calibrator = calibrator_fit(cal_raw, y[cal_idx]); cal_p = calibrator.predict_proba(cal_raw.reshape(-1, 1))[:, 1]
        test_raw = raw_model.predict_proba(te)[:, 1]; test_p = calibrator.predict_proba(test_raw.reshape(-1, 1))[:, 1]
        threshold_pair = threshold_search(y[threshold_idx], calibrator.predict_proba(raw_model.predict_proba(vec.transform(df["hostname"].iloc[threshold_idx]))[:, 1].reshape(-1, 1))[:, 1])
        result = {"ngram_range": list(ngram), "calibration_metrics": metrics(y[cal_idx], cal_p), "domain_test_metrics": metrics(y[test_idx], test_p, threshold_pair[1]), "thresholds": {"safe": threshold_pair[0], "phishing": threshold_pair[1]}, "training_seconds": time.perf_counter() - t0, "model_size_bytes": len(pickle.dumps((vec, raw_model, calibrator), protocol=pickle.HIGHEST_PROTOCOL)), "inference_latency_ms": latency_ms(lambda: calibrator.predict_proba(raw_model.predict_proba(te[:1])[:, 1].reshape(-1, 1))), "artifacts": (vec, raw_model, calibrator)}
        variant_results["-".join(map(str, ngram))] = result
        if chosen is None or result["calibration_metrics"]["pr_auc"] > chosen[1]["calibration_metrics"]["pr_auc"]:
            chosen = (ngram, result)
    ngram, selected = chosen; vec, raw_model, calibrator = selected.pop("artifacts")
    threshold_pair = (selected["thresholds"]["safe"], selected["thresholds"]["phishing"])
    domain_test_p = calibrator.predict_proba(raw_model.predict_proba(vec.transform(df["hostname"].iloc[test_idx]))[:, 1].reshape(-1, 1))[:, 1]
    baseline_test_p = baseline.predict_proba(X_url.iloc[test_idx])[:, 1]
    baseline_cal_p = baseline.predict_proba(X_url.iloc[cal_idx])[:, 1]
    baseline_thresholds = metadata["thresholds"]
    ensemble_cal_raw = .7 * baseline_cal_p + .3 * calibrator.predict_proba(raw_model.predict_proba(vec.transform(df["hostname"].iloc[cal_idx]))[:, 1].reshape(-1, 1))[:, 1]
    ensemble_calibrator = calibrator_fit(ensemble_cal_raw, y[cal_idx]); ensemble_threshold_scores = ensemble_calibrator.predict_proba((.7 * baseline.predict_proba(X_url.iloc[threshold_idx])[:, 1] + .3 * calibrator.predict_proba(raw_model.predict_proba(vec.transform(df["hostname"].iloc[threshold_idx]))[:, 1].reshape(-1, 1))[:, 1]).reshape(-1, 1))[:, 1]
    ensemble_thresholds = threshold_search(y[threshold_idx], ensemble_threshold_scores)
    ensemble_test_raw = .7 * baseline_test_p + .3 * domain_test_p; ensemble_test_p = ensemble_calibrator.predict_proba(ensemble_test_raw.reshape(-1, 1))[:, 1]

    model_outputs = {"current_model": (baseline_test_p, baseline_thresholds), "domain_only_model": (domain_test_p, {"safe": threshold_pair[0], "phishing": threshold_pair[1]}), "ensemble": (ensemble_test_p, {"safe": ensemble_thresholds[0], "phishing": ensemble_thresholds[1]})}
    models_report = {}
    latency_fns = {"current_model": lambda: baseline.predict_proba(X_url.iloc[test_idx].iloc[[0]]), "domain_only_model": lambda: calibrator.predict_proba(raw_model.predict_proba(vec.transform(df["hostname"].iloc[test_idx].iloc[:1]))[:, 1].reshape(-1, 1)), "ensemble": lambda: ensemble_calibrator.predict_proba((.7 * baseline.predict_proba(X_url.iloc[test_idx].iloc[[0]])[:, 1] + .3 * calibrator.predict_proba(raw_model.predict_proba(vec.transform(df["hostname"].iloc[test_idx].iloc[:1]))[:, 1].reshape(-1, 1))[:, 1]).reshape(-1, 1))}
    for name, (p, th) in model_outputs.items():
        models_report[name] = {"domain_aware": metrics(y[test_idx], p, th["phishing"]), "calibration": calibration_metrics(y[test_idx], p), "thresholds": th, "latency_ms": latency_ms(latency_fns[name]), "model_size_bytes": int(metadata["artifacts"]["model_size_bytes"] if name == "current_model" else len(pickle.dumps((vec, raw_model, calibrator), protocol=pickle.HIGHEST_PROTOCOL))), "hard_case_recall": cohorts(df.iloc[test_idx].copy(), p, th["phishing"])}

    # Random-split comparison for the same selected domain model and ensemble.
    random_split = StratifiedShuffleSplit(n_splits=1, test_size=.2, random_state=42); random_train, random_test = next(random_split.split(df, y)); random_domain = calibrator.predict_proba(raw_model.predict_proba(vec.transform(df["hostname"].iloc[random_test]))[:, 1].reshape(-1, 1))[:, 1]; random_base = baseline.predict_proba(X_url.iloc[random_test])[:, 1]; random_ensemble = ensemble_calibrator.predict_proba((.7 * random_base + .3 * random_domain).reshape(-1, 1))[:, 1]
    random_report = {"current_model": metrics(y[random_test], random_base, baseline_thresholds["phishing"]), "domain_only_model": metrics(y[random_test], random_domain, threshold_pair[1]), "ensemble": metrics(y[random_test], random_ensemble, ensemble_thresholds[1])}

    ext_hostname = external["url"].map(lambda x: (urlsplit(x).hostname or "").lower())
    ext_raw = raw_model.predict_proba(vec.transform(ext_hostname))[:, 1]
    ext_domain = calibrator.predict_proba(ext_raw.reshape(-1, 1))[:, 1]
    ext_base = baseline.predict_proba(X_ext)[:, 1]; ext_ensemble = ensemble_calibrator.predict_proba((.7 * ext_base + .3 * ext_domain).reshape(-1, 1))[:, 1]
    external_report = {}
    for name, p, th in (("current_model", ext_base, baseline_thresholds["phishing"]), ("domain_only_model", ext_domain, threshold_pair[1]), ("ensemble", ext_ensemble, ensemble_thresholds[1])):
        ext_m = metrics(np.ones(len(p), dtype=int), p, th); ext_m["roc_auc"] = None; ext_m["fpr"] = None; external_report[name] = ext_m

    numeric_model = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000)); t0 = time.perf_counter(); numeric_model.fit(domain_features(df["url"].iloc[train_idx]), y[train_idx]); numeric_cal_raw = numeric_model.predict_proba(domain_features(df["url"].iloc[cal_idx]))[:, 1]; numeric_cal = calibrator_fit(numeric_cal_raw, y[cal_idx]); numeric_test_p = numeric_cal.predict_proba(numeric_model.predict_proba(domain_features(df["url"].iloc[test_idx]))[:, 1].reshape(-1, 1))[:, 1]; numeric_threshold_scores = numeric_cal.predict_proba(numeric_model.predict_proba(domain_features(df["url"].iloc[threshold_idx]))[:, 1].reshape(-1, 1))[:, 1]; numeric_th = threshold_search(y[threshold_idx], numeric_threshold_scores)
    numeric_report = {"domain_features": ["registered_domain_length", "hostname_length", "character_entropy", "digit_ratio", "hyphen_ratio", "repeated_character_score", "character_diversity", "vowel_ratio", "consonant_ratio", "subdomain_depth", "punycode_indicator", "unicode_indicator", "repeated_character_indicator", "special_character_indicator"], "domain_aware": metrics(y[test_idx], numeric_test_p, numeric_th[1]), "thresholds": {"safe": numeric_th[0], "phishing": numeric_th[1]}, "training_seconds": time.perf_counter() - t0, "model_size_bytes": len(pickle.dumps(numeric_model, protocol=pickle.HIGHEST_PROTOCOL))}

    result = {"status": "freshly_measured_read_only_experiment", "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "holdout_policy": {"external_rows": int(len(external)), "used_for_training": False, "used_for_calibration": False, "used_for_thresholds": False}, "production_model": {"model_type": metadata["model_type"], "thresholds": metadata["thresholds"], "model_size_bytes": metadata["artifacts"]["model_size_bytes"]}, "domain_split": split, "character_model_variants": {k: {key: value for key, value in v.items() if key != "artifacts"} for k, v in variant_results.items()}, "selected_ngram_range": list(ngram), "numeric_domain_feature_model": numeric_report, "models": models_report, "random_split": random_report, "external_validation": external_report, "promotion_gate": {"approved": False, "decision": "REJECT_UNTIL_REVIEW", "reason": "This research artifact does not modify production; promotion requires domain-aware improvement, safe FPR, calibration, practical latency, fast.com regression, and tests."}, "runtime_seconds": time.perf_counter() - started}
    with open(OUT, "w", encoding="utf-8") as stream: json.dump(result, stream, indent=2, allow_nan=False)
    with open(DOC, "w", encoding="utf-8") as stream:
        stream.write("# Domain Model Experiment\n\nFreshly measured URL-only experiment. The Phishing.Database holdout was not used for training, calibration, or threshold selection. Production artifacts were not modified.\n\n")
        stream.write(f"Selected character n-gram range: `{ngram}`. Ensemble weight: 70% current model + 30% calibrated domain model.\n\n")
        stream.write("| Model | Random PR-AUC | Domain PR-AUC | External PR-AUC | Domain recall | Domain FNR | Domain FPR | Brier | ECE |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for name in models_report:
            r, d, e = random_report[name], models_report[name]["domain_aware"], external_report[name]
            stream.write(f"| {name} | {r['pr_auc']:.4f} | {d['pr_auc']:.4f} | {e['pr_auc']:.4f} | {d['recall']:.4f} | {d['fnr']:.4f} | {d['fpr']:.4f} | {d['brier']:.4f} | {d['ece']:.4f} |\n")
        stream.write("\nExternal FPR is undefined because the holdout contains phishing URLs only. The candidate was not promoted.\n")
    print(json.dumps({"selected_ngram_range": list(ngram), "models": models_report, "random_split": random_report, "external_validation": external_report, "numeric_domain_feature_model": numeric_report}, indent=2))


if __name__ == "__main__": main()
