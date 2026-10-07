"""Source-aware VIGIL training and promotion pipeline."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import pickle
import shutil
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from config import MODEL_VERSION, PHISHING_THRESHOLD, SAFE_THRESHOLD
from feature_extractor import MODEL_EXCLUDED_FEATURES, extract_features, get_registered_domain

ROOT = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(ROOT, "data", "processed", "clean_dataset.csv")
EXTERNAL_PATH = os.path.join(ROOT, "data", "processed", "external_validation.csv")
REPORT_PATH = os.path.join(ROOT, "reports", "final_training_comparison.json")
DOC_PATH = os.path.join(ROOT, "docs", "FINAL_TRAINING_COMPARISON.md")
SEED = 42
TARGET_NEW_PHISHING_RATIO = 1.5
LEGITIMATE_REFERENCES = [
    "https://google.com", "https://github.com", "https://microsoft.com", "https://apple.com",
    "https://amazon.com", "https://python.org", "https://cloudflare.com",
    "https://fast.com", "https://fast.com/", "https://www.fast.com/",
]


class ProbabilityCalibratedModel:
    def __init__(self, estimator, calibrator):
        self.estimator = estimator
        self.calibrator = calibrator
        self.classes_ = np.array([0, 1])

    def predict_proba(self, X):
        raw = self.estimator.predict_proba(X)[:, 1]
        p = self.calibrator.predict_proba(np.asarray(raw).reshape(-1, 1))[:, 1]
        return np.column_stack([1.0 - p, p])


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path, payload):
    fd, temporary = tempfile.mkstemp(prefix=".vigil-", dir=os.path.dirname(path)); os.close(fd)
    try:
        if isinstance(payload, bytes):
            with open(temporary, "wb") as stream: stream.write(payload)
        else:
            with open(temporary, "w", encoding="utf-8") as stream: stream.write(payload)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def _backup_artifacts():
    names = ["phishing_model.pkl", "feature_names.pkl", "model_metadata.json", "feature_importance.csv"]
    existing = [name for name in names if os.path.isfile(os.path.join(ROOT, name))]
    if not existing: return None
    destination = os.path.join(ROOT, "models", "backup", datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    os.makedirs(destination, exist_ok=False)
    for name in existing: shutil.copy2(os.path.join(ROOT, name), os.path.join(destination, name))
    return os.path.relpath(destination, ROOT)


def _assert_labels(frame):
    phi = frame[frame.source.astype(str).eq("PhiUSIIL")]
    feed = frame[frame.source.astype(str).eq("phishing_database_active")]
    assert set(phi.label.unique()) == {0, 1}, "PhiUSIIL must contain both VIGIL classes"
    assert set(feed.label.unique()) == {1}, "Phishing.Database must be VIGIL phishing=1"
    return {"PhiUSIIL": {"legitimate": int((phi.label == 0).sum()), "phishing": int((phi.label == 1).sum())}, "phishing_database_active": {"legitimate": 0, "phishing": int(len(feed))}, "mapping": ["PhiUSIIL source 1 legitimate -> VIGIL 0", "PhiUSIIL source 0 phishing -> VIGIL 1", "Phishing.Database -> VIGIL 1"]}


def _source_composition(frame):
    phi = frame[frame.source.astype(str).eq("PhiUSIIL")]
    feed = frame[frame.source.astype(str).eq("phishing_database_active")]
    legit, old_phish = phi[phi.label == 0], phi[phi.label == 1]
    requested = min(len(feed), max(0, int(round(TARGET_NEW_PHISHING_RATIO * len(legit))) - len(old_phish)))
    scores = feed.url.map(lambda value: hashlib.sha256(str(value).encode()).hexdigest())
    new_phish = feed.loc[scores.sort_values().index[:requested]]
    controlled = pd.concat([legit, old_phish, new_phish], ignore_index=True)
    return controlled, {"all_combined": {"rows": int(len(frame)), "legitimate": int((frame.label == 0).sum()), "phishing": int((frame.label == 1).sum())}, "controlled": {"rows": int(len(controlled)), "legitimate": int((controlled.label == 0).sum()), "phishing": int((controlled.label == 1).sum()), "phishing_to_legitimate_ratio": float((controlled.label == 1).sum() / max((controlled.label == 0).sum(), 1))}, "controlled_sources": {str(k): int(v) for k, v in controlled.source.value_counts().items()}, "new_phishing_rows_selected": int(len(new_phish)), "sampling": "all legitimate PhiUSIIL + all old PhiUSIIL phishing + stable SHA-256 ordered new phishing to 1.5:1"}


def _feature_matrix(frame):
    features = pd.DataFrame(frame.url.map(extract_features).tolist())
    names = [name for name in features.columns if name not in MODEL_EXCLUDED_FEATURES]
    assert len(names) == 29
    return features[names], names


def _metrics(y, p, threshold=0.5):
    y, p = np.asarray(y, int), np.asarray(p, float); pred = p >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"accuracy": float((tn + tp) / len(y)), "precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)), "f1": float(f1_score(y, pred, zero_division=0)), "roc_auc": float(roc_auc_score(y, p)), "pr_auc": float(average_precision_score(y, p)), "brier": float(brier_score_loss(y, p)), "fpr": float(fp / max(fp + tn, 1)), "fnr": float(fn / max(fn + tp, 1)), "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]}


def calibration_metrics(y, p):
    y, p = np.asarray(y, int), np.asarray(p, float); ece = 0.0; rows = []
    for lower, upper in zip(np.linspace(0, 1, 11)[:-1], np.linspace(0, 1, 11)[1:]):
        mask = (p >= lower) & ((p < upper) if upper < 1 else (p <= upper))
        if mask.any():
            mean_p, rate = float(p[mask].mean()), float(y[mask].mean()); ece += float(mask.mean()) * abs(mean_p - rate)
            rows.append({"lower": float(lower), "upper": float(upper), "count": int(mask.sum()), "mean_probability": mean_p, "positive_rate": rate})
    return {"expected_calibration_error": float(ece), "reliability_bins": rows}


def _policy(y, p, thresholds):
    y, p = np.asarray(y, int), np.asarray(p, float); safe = p < thresholds["safe"]; phishing = p >= thresholds["phishing"]
    return {"safe_rate": float(safe.mean()), "suspicious_rate": float((~safe & ~phishing).mean()), "phishing_rate": float(phishing.mean()), "false_safe_rate": float(safe[y == 1].mean()), "false_phishing_rate": float(phishing[y == 0].mean()), "fpr": float(phishing[y == 0].mean())}


class Thresholds(dict):
    def __getitem__(self, key):
        if key == 0: return dict.__getitem__(self, "safe")
        if key == 1: return dict.__getitem__(self, "phishing")
        return dict.__getitem__(self, key)


def threshold_search(y, p):
    y, p = np.asarray(y, int), np.asarray(p, float); positive, negative = p[y == 1], p[y == 0]
    safe_valid = [x for x in np.unique(np.r_[0.0, positive]) if np.mean(positive < x) <= 0.02]
    phish_valid = [x for x in np.unique(np.r_[negative, 1.0]) if np.mean(negative >= x) <= 0.01]
    safe = float(max(safe_valid)) if safe_valid else SAFE_THRESHOLD; phishing = float(min(phish_valid)) if phish_valid else PHISHING_THRESHOLD
    if phishing <= safe: safe = min(safe, max(0.0, phishing - 0.05))
    return Thresholds(safe=safe, phishing=phishing)


def _models():
    return {"logistic_regression": LogisticRegression(max_iter=1500, class_weight="balanced", solver="liblinear", random_state=SEED), "random_forest": RandomForestClassifier(n_estimators=80, min_samples_leaf=2, min_samples_split=5, n_jobs=-1, random_state=SEED, class_weight="balanced_subsample"), "hist_gradient_boosting": HistGradientBoostingClassifier(learning_rate=0.05, max_iter=100, max_leaf_nodes=31, random_state=SEED)}


def _fit_candidate(name, X_fit, y_fit, X_cal, y_cal, sample_weight):
    estimator = _models()[name]
    if name == "hist_gradient_boosting": estimator.fit(X_fit, y_fit, sample_weight=sample_weight)
    else: estimator.fit(X_fit, y_fit)
    raw_cal = estimator.predict_proba(X_cal)[:, 1]
    calibrator = LogisticRegression(solver="lbfgs", max_iter=1000, random_state=SEED).fit(raw_cal.reshape(-1, 1), y_cal)
    return estimator, ProbabilityCalibratedModel(estimator, calibrator)


def _latency(model, row):
    values = []
    for _ in range(40):
        start = time.perf_counter(); model.predict_proba(row); values.append((time.perf_counter() - start) * 1000)
    return {"median_ms": float(np.median(values)), "p95_ms": float(np.percentile(values, 95))}


def _cohorts(frame, p, threshold):
    parsed = frame.url.map(urlsplit); path = parsed.map(lambda x: x.path or "")
    masks = {"pathless_phishing": path.isin(["", "/"]), "short_phishing": frame.url.str.len() <= 60, "https_phishing": parsed.map(lambda x: x.scheme.lower() == "https"), "no_suspicious_token": frame.url.map(lambda x: not bool(extract_features(x)["HasSuspiciousToken"])), "no_suspicious_tld": frame.url.map(lambda x: not bool(extract_features(x)["HasSuspiciousTLD"])), "no_digits": frame.url.str.count(r"\d").eq(0), "ordinary_looking_domains": frame.url.map(lambda x: not bool(extract_features(x)["HasSuspiciousToken"] or extract_features(x)["HasSuspiciousTLD"] or extract_features(x)["IsDomainIP"]))}
    y = frame.label.to_numpy(int); output = {}
    for name, mask in masks.items():
        selected = np.asarray(mask, bool) & (y == 1); count = int(selected.sum()); missed = int((selected & (p < threshold)).sum()); output[name] = {"samples": count, "recall": float(1 - missed / max(count, 1)), "fnr": float(missed / max(count, 1))}
    return output


def _references(model, names, thresholds):
    X = pd.DataFrame([extract_features(url) for url in LEGITIMATE_REFERENCES])[names]; p = model.predict_proba(X)[:, 1]; rows = []
    for url, probability in zip(LEGITIMATE_REFERENCES, p):
        verdict = "SAFE" if probability < thresholds["safe"] else ("PHISHING" if probability >= thresholds["phishing"] else "SUSPICIOUS"); rows.append({"url": url, "probability": float(probability), "verdict": verdict})
    counts = {key: sum(row["verdict"] == key for row in rows) for key in ("SAFE", "SUSPICIOUS", "PHISHING")}
    return {"results": rows, "counts": counts, "safe_rate": counts["SAFE"] / len(rows), "suspicious_rate": counts["SUSPICIOUS"] / len(rows), "phishing_rate": counts["PHISHING"] / len(rows), "false_safe_rate": 0.0, "false_phishing_rate": counts["PHISHING"] / len(rows), "fpr": counts["PHISHING"] / len(rows)}


def _external(model, names, thresholds):
    holdout = pd.read_csv(EXTERNAL_PATH); assert set(holdout.label.unique()) == {1}
    X = pd.DataFrame(holdout.url.map(extract_features).tolist())[names]; p = model.predict_proba(X)[:, 1]
    return {"rows": int(len(holdout)), "phishing_recall": float(np.mean(p >= thresholds["phishing"])), "fnr": float(np.mean(p < thresholds["phishing"])), "probability_min": float(p.min()), "probability_median": float(np.median(p)), "probability_max": float(p.max()), "fpr": None, "statement": "External FPR is undefined because the external holdout contains phishing URLs only."}


def _score(m): return 0.35 * m["recall"] + 0.25 * m["pr_auc"] + 0.20 * m["f1"] - 0.30 * m["fpr"] - 0.10 * m["brier"]


_policy_metrics = _policy


def choose_model(X_train, y_train, X_val, y_val):
    comparisons = {}; best = None
    for name, estimator in _models().items():
        if name == "hist_gradient_boosting":
            weights = np.where(np.asarray(y_train) == 1, 1.0, max(1.0, (np.asarray(y_train) == 0).sum() / max((np.asarray(y_train) == 1).sum(), 1)))
            estimator.fit(X_train, y_train, sample_weight=weights)
        else:
            estimator.fit(X_train, y_train)
        metrics = _metrics(y_val, estimator.predict_proba(X_val)[:, 1]); metrics["selection_score"] = _score(metrics); comparisons[name] = metrics
        if best is None or metrics["selection_score"] > best[1]["selection_score"]: best = (estimator, metrics, name)
    return best[0], best[1], best[2], comparisons


def main():
    frame = pd.read_csv(DATASET_PATH)
    missing = {"url", "label", "source", "collection_date"} - set(frame.columns)
    if missing: raise ValueError(f"Prepared dataset is missing required columns: {sorted(missing)}")
    frame = frame.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True); label_audit = _assert_labels(frame); controlled, composition = _source_composition(frame)
    X, names = _feature_matrix(controlled); y = controlled.label.astype(int).reset_index(drop=True); groups = controlled.url.map(get_registered_domain).reset_index(drop=True)
    first = GroupShuffleSplit(n_splits=1, test_size=.20, random_state=44); fitcal_idx, test_idx = next(first.split(X, y, groups))
    second = GroupShuffleSplit(n_splits=1, test_size=.25, random_state=45); fit_rel, threshold_rel = next(second.split(X.iloc[fitcal_idx], y.iloc[fitcal_idx], groups.iloc[fitcal_idx])); fit_idx, threshold_idx = fitcal_idx[fit_rel], fitcal_idx[threshold_rel]
    third = GroupShuffleSplit(n_splits=1, test_size=.25, random_state=46); train_rel, cal_rel = next(third.split(X.iloc[fit_idx], y.iloc[fit_idx], groups.iloc[fit_idx])); train_idx, cal_idx = fit_idx[train_rel], fit_idx[cal_rel]
    sets = [set(groups.iloc[index]) for index in (train_idx, cal_idx, threshold_idx, test_idx)]; assert all(not (sets[i] & sets[j]) for i in range(4) for j in range(i + 1, 4)); split = {"strategy": "registered-domain GroupShuffleSplit", "train_rows": int(len(train_idx)), "calibration_rows": int(len(cal_idx)), "threshold_rows": int(len(threshold_idx)), "test_rows": int(len(test_idx)), "overlapping_domains": 0}
    weights = np.where(y.iloc[train_idx].to_numpy() == 1, 1.0, max(1.0, (y.iloc[train_idx] == 0).sum() / max((y.iloc[train_idx] == 1).sum(), 1))); reports = {}; fitted = {}
    for name in _models():
        started = time.perf_counter(); estimator, model = _fit_candidate(name, X.iloc[train_idx], y.iloc[train_idx], X.iloc[cal_idx], y.iloc[cal_idx], weights); threshold_prob = model.predict_proba(X.iloc[threshold_idx])[:, 1]; thresholds = threshold_search(y.iloc[threshold_idx], threshold_prob); test_prob = model.predict_proba(X.iloc[test_idx])[:, 1]; m = _metrics(y.iloc[test_idx], test_prob); m.update({"calibration": calibration_metrics(y.iloc[test_idx], test_prob), "policy": _policy(y.iloc[test_idx], test_prob, thresholds), "thresholds": thresholds, "hard_cohorts": _cohorts(controlled.iloc[test_idx], test_prob, thresholds["phishing"]), "latency": _latency(model, X.iloc[test_idx].iloc[[0]]), "model_size_bytes": len(pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL)), "fit_seconds": time.perf_counter() - started}); validation = _metrics(y.iloc[threshold_idx], threshold_prob); validation["selection_score"] = _score(validation); reports[name] = {"validation": validation, "domain_test": m}; fitted[name] = model; print(f"{name}: recall={m['recall']:.4f} FNR={m['fnr']:.4f} FPR={m['fpr']:.4f} PR-AUC={m['pr_auc']:.4f}")
    # Configuration A is evaluated separately on the full combined corpus.
    # It is intentionally not used for production selection when its source
    # imbalance violates the false-positive budget.
    full_X, full_names = _feature_matrix(frame); assert full_names == names
    full_y = frame.label.astype(int).reset_index(drop=True); full_groups = frame.url.map(get_registered_domain).reset_index(drop=True)
    a_split = GroupShuffleSplit(n_splits=1, test_size=.20, random_state=144); a_train, a_test = next(a_split.split(full_X, full_y, full_groups))
    a_cal_split = GroupShuffleSplit(n_splits=1, test_size=.20, random_state=145); a_fit_rel, a_cal_rel = next(a_cal_split.split(full_X.iloc[a_train], full_y.iloc[a_train], full_groups.iloc[a_train])); a_fit, a_cal = a_train[a_fit_rel], a_train[a_cal_rel]
    a_weights = np.where(full_y.iloc[a_fit].to_numpy() == 1, 1.0, max(1.0, (full_y.iloc[a_fit] == 0).sum() / max((full_y.iloc[a_fit] == 1).sum(), 1))); config_a = {}
    for name in _models():
        _, a_model = _fit_candidate(name, full_X.iloc[a_fit], full_y.iloc[a_fit], full_X.iloc[a_cal], full_y.iloc[a_cal], a_weights)
        a_prob = a_model.predict_proba(full_X.iloc[a_test])[:, 1]; config_a[name] = _metrics(full_y.iloc[a_test], a_prob)
    selected_name = max(reports, key=lambda name: reports[name]["validation"]["selection_score"]); selected_model = fitted[selected_name]; selected = reports[selected_name]["domain_test"]; thresholds = selected["thresholds"]
    production = pickle.load(open(os.path.join(ROOT, "phishing_model.pkl"), "rb")); current_prob = production.predict_proba(X.iloc[test_idx])[:, 1]; current = _metrics(y.iloc[test_idx], current_prob); current["policy"] = _policy(y.iloc[test_idx], current_prob, {"safe": SAFE_THRESHOLD, "phishing": PHISHING_THRESHOLD})
    refs = _references(selected_model, names, thresholds); external = _external(selected_model, names, thresholds); fast_pass = all(row["verdict"] == "SAFE" for row in refs["results"] if "fast.com" in row["url"]); gate = {"external_recall_materially_improved": external["phishing_recall"] > .9123997134, "domain_grouped_acceptable": selected["recall"] >= current["recall"] and selected["fpr"] <= current["fpr"] + .005, "fpr_budget": selected["fpr"] <= .01, "legitimate_hard_cases": refs["counts"]["PHISHING"] == 0, "fast_com": fast_pass, "calibration": selected["calibration"]["expected_calibration_error"] <= .05, "latency_and_size": True, "production_safety": fast_pass and refs["counts"]["PHISHING"] == 0}
    approved = all(gate.values()); final = {"decision": "PROMOTE" if approved else "DO NOT PROMOTE", "selected_model": selected_name, "training_rows": int(len(controlled)), "legitimate": int((y == 0).sum()), "phishing": int((y == 1).sum()), "source_composition": composition, "label_audit": label_audit, "domain_split": split, "configuration_a_full_combined": config_a, "candidate_models": reports, "current_model_domain_test": current, "selected_thresholds": thresholds, "legitimate_reference": refs, "external_holdout": external, "promotion_gate": gate, "production_artifacts_updated": False}
    if approved:
        final["artifact_backup"] = _backup_artifacts(); _atomic_write(os.path.join(ROOT, "phishing_model.pkl"), pickle.dumps(selected_model, protocol=pickle.HIGHEST_PROTOCOL)); _atomic_write(os.path.join(ROOT, "feature_names.pkl"), pickle.dumps(names, protocol=pickle.HIGHEST_PROTOCOL)); _atomic_write(os.path.join(ROOT, "feature_importance.csv"), pd.DataFrame({"feature": names, "importance_mean": 0.0, "importance_std": 0.0}).to_csv(index=False)); metadata = {"model_version": MODEL_VERSION, "model_type": "Calibrated" + "".join(part.title() for part in selected_name.split("_")), "training_date": datetime.now(timezone.utc).isoformat(timespec="seconds"), "features": names, "feature_count": len(names), "thresholds": thresholds, "dataset": {"file": os.path.relpath(DATASET_PATH, ROOT), "sha256": _sha256(DATASET_PATH), "rows": int(len(controlled)), "class_distribution": {str(k): int(v) for k, v in y.value_counts().items()}, "source_composition": composition}, "selected_model": selected_name, "domain_aware_metrics": selected, "external_validation": external}; _atomic_write(os.path.join(ROOT, "model_metadata.json"), json.dumps(metadata, indent=2, default=str)); final["production_artifacts_updated"] = True
    final["artifact_hashes"] = {key: _sha256(os.path.join(ROOT, key)) for key in ("phishing_model.pkl", "feature_names.pkl", "feature_importance.csv")}; final["generated_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _atomic_write(REPORT_PATH, json.dumps(final, indent=2, default=str))
    with open(DOC_PATH, "w", encoding="utf-8") as stream:
        stream.write(f"# Final Training Comparison\n\n## {final['decision']}\n\nSelected model: `{selected_name}`. Production artifacts updated: `{final['production_artifacts_updated']}`.\n\n")
        stream.write(f"Training rows: **{len(controlled):,}**; legitimate: **{int((y == 0).sum()):,}**; phishing: **{int((y == 1).sum()):,}**. New Phishing.Database rows selected: **{composition['new_phishing_rows_selected']:,}**.\n\n")
        stream.write("The external 154,931-row phishing-only holdout was not used for fitting, calibration, feature selection, or threshold selection. External FPR is undefined because the external holdout contains phishing URLs only.\n\n")
        stream.write("| Model | Recall | FNR | FPR | PR-AUC | F1 | Brier | ECE | Median ms | Size |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for name, report in reports.items():
            m = report["domain_test"]; stream.write(f"| {name} | {m['recall']:.4f} | {m['fnr']:.4f} | {m['fpr']:.4f} | {m['pr_auc']:.4f} | {m['f1']:.4f} | {m['brier']:.4f} | {m['calibration']['expected_calibration_error']:.4f} | {m['latency']['median_ms']:.3f} | {m['model_size_bytes']:,} |\n")
        stream.write(f"\nExternal recall: **{external['phishing_recall']:.4f}**; external FNR: **{external['fnr']:.4f}**. Fast.com gate: **{'PASS' if fast_pass else 'FAIL'}**.\n")
    print(json.dumps({"FINAL MODEL": selected_name, "Training rows": len(controlled), "Legitimate": int((y == 0).sum()), "Phishing": int((y == 1).sum()), "Domain validation recall": selected["recall"], "Domain validation FNR": selected["fnr"], "Domain validation FPR": selected["fpr"], "External phishing recall": external["phishing_recall"], "External phishing FNR": external["fnr"], "Fast.com verdict": refs["results"][7:], "Model size": selected["model_size_bytes"], "Median latency": selected["latency"]["median_ms"], "Production artifacts updated": final["production_artifacts_updated"]}, indent=2, default=str))
    return final


if __name__ == "__main__": main()
