import hashlib
import importlib.metadata
import json
import os
import pickle
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit

from config import MODEL_VERSION, PHISHING_THRESHOLD, SAFE_THRESHOLD
from feature_extractor import MODEL_EXCLUDED_FEATURES, extract_features, get_registered_domain

ROOT = os.path.dirname(os.path.abspath(__file__))


def compute_binary_metrics(y_true, y_prob):
    y_pred = (y_prob >= 0.5).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_true, y_prob)
    pr_auc = average_precision_score(y_true, y_prob)
    brier = brier_score_loss(y_true, y_prob)
    fpr = fp / max(fp + tn, 1)
    fnr = fn / max(fn + tp, 1)
    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "brier_score": float(brier),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "confusion_matrix": cm.tolist(),
    }


def choose_model(X_train, y_train, X_val, y_val):
    candidates = {
        "logistic_regression": LogisticRegression(max_iter=4000, class_weight="balanced", solver="liblinear"),
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=2,
            min_samples_split=5,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced_subsample",
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            learning_rate=0.05,
            max_depth=None,
            max_leaf_nodes=31,
            random_state=42,
        ),
    }

    best_name = None
    best_model = None
    best_score = -1.0
    best_metrics = {}
    comparisons = {}

    for name, estimator in candidates.items():
        fit_started = time.perf_counter()
        estimator.fit(X_train, y_train)
        fit_seconds = time.perf_counter() - fit_started
        proba = estimator.predict_proba(X_val)[:, 1]
        metrics = compute_binary_metrics(y_val, proba)
        score = (
            0.50 * metrics["pr_auc"]
            + 0.30 * metrics["f1"]
            + 0.20 * metrics["recall"]
            - 0.25 * metrics["fpr"]
            - 0.10 * metrics["brier_score"]
        )
        sample = X_val.iloc[[0]]
        latencies = []
        for _ in range(30):
            started = time.perf_counter()
            estimator.predict_proba(sample)
            latencies.append((time.perf_counter() - started) * 1000)
        comparisons[name] = {
            **metrics,
            "selection_score": float(score),
            "fit_seconds": float(fit_seconds),
            "median_single_row_latency_ms": float(np.median(latencies)),
            "model_size_bytes": len(pickle.dumps(estimator, protocol=pickle.HIGHEST_PROTOCOL)),
            "hyperparameters": estimator.get_params(deep=False),
        }
        print(f"{name}: PR-AUC={metrics['pr_auc']:.4f}, F1={metrics['f1']:.4f}, FPR={metrics['fpr']:.4f}, score={score:.4f}")
        if score > best_score:
            best_name, best_model, best_score, best_metrics = name, estimator, score, metrics

    print(f"Selected model: {best_name}")
    return best_model, best_metrics, best_name, comparisons


def calibration_metrics(y_true, y_prob, bin_count=10):
    y_true = np.asarray(y_true, dtype=int)
    y_prob = np.asarray(y_prob, dtype=float)
    bins = np.linspace(0.0, 1.0, bin_count + 1)
    rows = []
    ece = 0.0
    for lower, upper in zip(bins[:-1], bins[1:]):
        mask = (y_prob >= lower) & ((y_prob < upper) if upper < 1 else (y_prob <= upper))
        if not mask.any():
            continue
        predicted = float(y_prob[mask].mean())
        observed = float(y_true[mask].mean())
        ece += float(mask.mean()) * abs(predicted - observed)
        rows.append({"lower": float(lower), "upper": float(upper), "count": int(mask.sum()), "mean_probability": predicted, "positive_rate": observed})
    return {"expected_calibration_error": float(ece), "reliability_bins": rows}


def threshold_search(
    y_true,
    y_prob,
    safe_threshold=SAFE_THRESHOLD,
    phishing_threshold=PHISHING_THRESHOLD,
    max_false_safe_rate=0.02,
    max_phishing_false_positive_rate=0.01,
):
    y_true = np.asarray(y_true, dtype=int)
    y_prob = np.asarray(y_prob, dtype=float)
    negative_scores = y_prob[y_true == 0]
    positive_scores = y_prob[y_true == 1]
    if not len(negative_scores) or not len(positive_scores):
        return float(safe_threshold), float(phishing_threshold)

    safe_candidates = np.unique(np.r_[0.0, positive_scores])
    safe_valid = [threshold for threshold in safe_candidates if np.mean(positive_scores < threshold) <= max_false_safe_rate]
    safe = float(max(safe_valid)) if safe_valid else float(safe_threshold)

    phishing_candidates = np.unique(np.r_[negative_scores, 1.0])
    phishing_valid = [threshold for threshold in phishing_candidates if np.mean(negative_scores >= threshold) <= max_phishing_false_positive_rate]
    phishing = float(min(phishing_valid)) if phishing_valid else float(phishing_threshold)
    if phishing <= safe:
        safe = max(0.0, phishing - 0.05)
    return safe, phishing


def _policy_metrics(y_true, y_prob, thresholds):
    y_true = np.asarray(y_true, dtype=int)
    y_prob = np.asarray(y_prob, dtype=float)
    safe = y_prob < thresholds["safe"]
    phishing = y_prob >= thresholds["phishing"]
    benign = y_true == 0
    malicious = y_true == 1
    return {
        "safe_rate": float(safe.mean()),
        "suspicious_rate": float((~safe & ~phishing).mean()),
        "phishing_rate": float(phishing.mean()),
        "phishing_false_positive_rate": float(phishing[benign].mean()),
        "phishing_false_negative_rate": float((~phishing[malicious]).mean()),
        "false_safe_rate": float(safe[malicious].mean()),
    }


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _backup_artifacts(output_dir):
    names = ["phishing_model.pkl", "feature_names.pkl", "model_metadata.json", "feature_importance.csv"]
    existing = [name for name in names if os.path.isfile(os.path.join(output_dir, name))]
    if not existing:
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_dir = os.path.join(ROOT, "models", "backup", stamp)
    os.makedirs(backup_dir, exist_ok=False)
    for name in existing:
        shutil.copy2(os.path.join(output_dir, name), os.path.join(backup_dir, name))
    return backup_dir


def _atomic_write(path, payload):
    fd, temporary = tempfile.mkstemp(prefix=".vigil-", dir=os.path.dirname(path))
    os.close(fd)
    try:
        mode = "wb" if isinstance(payload, bytes) else "w"
        options = {} if mode == "wb" else {"encoding": "utf-8"}
        with open(temporary, mode, **options) as stream:
            stream.write(payload)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _temporal_evaluation(df, X, y):
    dates = pd.to_datetime(df.get("collection_date"), errors="coerce", utc=True)
    dates = dates.dropna()
    unique_dates = dates.sort_values().unique()
    if len(unique_dates) < 2:
        return {"status": "not_run", "reason": "No usable collection dates are present."}

    cutoff = unique_dates[max(1, int(len(unique_dates) * 0.8))]
    valid = pd.to_datetime(df["collection_date"], errors="coerce", utc=True).notna()
    dated = pd.to_datetime(df["collection_date"], errors="coerce", utc=True)
    train_idx = np.flatnonzero((valid & (dated < cutoff)).to_numpy())
    test_idx = np.flatnonzero((valid & (dated >= cutoff)).to_numpy())
    if not len(train_idx) or len(np.unique(y.iloc[train_idx])) < 2 or len(np.unique(y.iloc[test_idx])) < 2:
        return {"status": "not_run", "reason": "The chronological holdout does not contain both classes in train and test."}

    selector = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=47)
    fit_rel, val_rel = next(selector.split(X.iloc[train_idx], y.iloc[train_idx]))
    fit_idx, val_idx = train_idx[fit_rel], train_idx[val_rel]
    model, validation_metrics, name, comparisons = choose_model(X.iloc[fit_idx], y.iloc[fit_idx], X.iloc[val_idx], y.iloc[val_idx])
    calibrated = CalibratedClassifierCV(estimator=clone(model), method="sigmoid", cv=3)
    calibrated.fit(X.iloc[train_idx], y.iloc[train_idx])
    probabilities = calibrated.predict_proba(X.iloc[test_idx])[:, 1]
    return {
        "status": "executed",
        "cutoff_utc": pd.Timestamp(cutoff).isoformat(),
        "train_rows": int(len(train_idx)),
        "test_rows": int(len(test_idx)),
        "model_name": name,
        "validation_metrics": validation_metrics,
        "candidate_comparisons": comparisons,
        "metrics": compute_binary_metrics(y.iloc[test_idx], probabilities),
        "calibration": calibration_metrics(y.iloc[test_idx], probabilities),
    }


def main():
    output_dir = ROOT
    dataset_path = os.path.join(ROOT, "data", "processed", "clean_dataset.csv")
    if not os.path.isfile(dataset_path):
        raise FileNotFoundError("Run prepare_dataset.py before training.")

    model_path = os.path.join(output_dir, "phishing_model.pkl")
    feature_path = os.path.join(output_dir, "feature_names.pkl")
    metadata_path = os.path.join(output_dir, "model_metadata.json")
    importance_path = os.path.join(output_dir, "feature_importance.csv")
    cleaned_df = pd.read_csv(dataset_path)
    if not {"url", "label", "source", "collection_date"}.issubset(cleaned_df.columns):
        raise ValueError("Prepared dataset is missing required provenance columns.")

    features = pd.DataFrame(cleaned_df["url"].map(extract_features).tolist()).drop(columns=MODEL_EXCLUDED_FEATURES)
    feature_names = features.columns.tolist()
    X = features.loc[:, feature_names]
    y = cleaned_df["label"].astype(int).reset_index(drop=True)
    cleaned_df = cleaned_df.reset_index(drop=True)
    groups = cleaned_df["url"].map(get_registered_domain)

    random_split = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(random_split.split(X, y))
    threshold_split = StratifiedShuffleSplit(n_splits=1, test_size=0.1, random_state=45)
    model_rel, threshold_rel = next(threshold_split.split(X.iloc[train_idx], y.iloc[train_idx]))
    model_idx, threshold_idx = train_idx[model_rel], train_idx[threshold_rel]
    selector = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=43)
    fit_rel, val_rel = next(selector.split(X.iloc[model_idx], y.iloc[model_idx]))
    fit_idx, val_idx = model_idx[fit_rel], model_idx[val_rel]

    base_model, validation_metrics, selected_name, candidate_comparisons = choose_model(
        X.iloc[fit_idx], y.iloc[fit_idx], X.iloc[val_idx], y.iloc[val_idx]
    )
    calibrated_model = CalibratedClassifierCV(estimator=clone(base_model), method="sigmoid", cv=3)
    calibrated_model.fit(X.iloc[model_idx], y.iloc[model_idx])
    test_prob = calibrated_model.predict_proba(X.iloc[test_idx])[:, 1]
    random_metrics = compute_binary_metrics(y.iloc[test_idx], test_prob)
    random_calibration = calibration_metrics(y.iloc[test_idx], test_prob)

    threshold_prob = calibrated_model.predict_proba(X.iloc[threshold_idx])[:, 1]
    threshold_pair = threshold_search(y.iloc[threshold_idx], threshold_prob)
    thresholds = {"safe": threshold_pair[0], "phishing": threshold_pair[1]}
    threshold_metrics = _policy_metrics(y.iloc[threshold_idx], threshold_prob, thresholds)

    group_split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=44)
    group_train_idx, group_test_idx = next(group_split.split(X, y, groups))
    group_selector = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=46)
    group_fit_rel, group_val_rel = next(
        group_selector.split(X.iloc[group_train_idx], y.iloc[group_train_idx], groups.iloc[group_train_idx])
    )
    group_fit_idx, group_val_idx = group_train_idx[group_fit_rel], group_train_idx[group_val_rel]
    group_model, group_validation_metrics, group_model_name, group_comparisons = choose_model(
        X.iloc[group_fit_idx], y.iloc[group_fit_idx], X.iloc[group_val_idx], y.iloc[group_val_idx]
    )
    group_calibrator = CalibratedClassifierCV(estimator=clone(group_model), method="sigmoid", cv=3)
    group_calibrator.fit(X.iloc[group_train_idx], y.iloc[group_train_idx])
    group_prob = group_calibrator.predict_proba(X.iloc[group_test_idx])[:, 1]
    group_metrics = compute_binary_metrics(y.iloc[group_test_idx], group_prob)
    group_calibration = calibration_metrics(y.iloc[group_test_idx], group_prob)
    group_overlap = set(groups.iloc[group_train_idx]) & set(groups.iloc[group_test_idx])

    temporal_metrics = _temporal_evaluation(cleaned_df, X, y)
    importance_rows = min(2000, len(X.iloc[val_idx]))
    importance = permutation_importance(
        base_model,
        X.iloc[val_idx[:importance_rows]],
        y.iloc[val_idx[:importance_rows]],
        scoring="average_precision",
        n_repeats=2,
        random_state=42,
        n_jobs=-1,
    )
    importance_df = pd.DataFrame({
        "feature": feature_names,
        "importance_mean": importance.importances_mean,
        "importance_std": importance.importances_std,
    }).sort_values("importance_mean", ascending=False)

    backup_dir = _backup_artifacts(output_dir)
    model_payload = pickle.dumps(calibrated_model, protocol=pickle.HIGHEST_PROTOCOL)
    feature_payload = pickle.dumps(feature_names, protocol=pickle.HIGHEST_PROTOCOL)
    summary_path = os.path.join(ROOT, "data", "processed", "dataset_summary.json")
    with open(summary_path, encoding="utf-8") as stream:
        dataset_report = json.load(stream)
    dataset_report.pop("output_file", None)
    training_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    source_distribution = {
        str(key): int(value) for key, value in cleaned_df["source"].fillna("unknown").value_counts().items()
    }
    source_names = sorted(cleaned_df["source"].fillna("unknown").astype(str).unique().tolist())
    source_overlap = int(
        cleaned_df.assign(_feature_key=cleaned_df["url"].map(lambda value: value.lower()))
        .groupby("_feature_key")["source"].nunique().gt(1).sum()
    )
    random_train_domains = set(groups.iloc[train_idx])
    random_test_domains = set(groups.iloc[test_idx])
    metadata = {
        "model_version": MODEL_VERSION,
        "model_type": "Calibrated" + "".join(part.title() for part in selected_name.split("_")),
        "training_date": training_timestamp,
        "dataset": {
            "file": os.path.relpath(dataset_path, ROOT),
            "sha256": _sha256(dataset_path),
            "rows": int(len(cleaned_df)),
            "class_distribution": {str(key): int(value) for key, value in y.value_counts().sort_index().items()},
            "source_distribution": source_distribution,
            "sources": source_names,
            "source_provenance": dataset_report.get("source_provenance"),
            "collection_dates_available": int(pd.to_datetime(cleaned_df["collection_date"], errors="coerce", utc=True).notna().sum()),
            "cross_source_duplicate_groups": int(dataset_report.get("cross_source_duplicate_groups", source_overlap)),
            "cleaning_report": dataset_report,
        },
        "feature_count": len(feature_names),
        "features": feature_names,
        "excluded_training_features": {
            "IsHTTPS": "Transport-only signal; excluded after protocol counterfactuals showed a large spurious probability shift.",
            "DomainLength": "Exact alias of HostnameLength.",
            "NoOfSubDomain": "Exact alias of SubdomainDepth.",
            "HasSuspiciousWord": "Exact alias of HasSuspiciousToken.",
            "HasTrustedBrand": "Constant zero placeholder in the current extractor.",
            "HasTrustedBrandToken": "Constant zero placeholder in the current extractor.",
        },
        "feature_extractor_sha256": _sha256(os.path.join(ROOT, "feature_extractor.py")),
        "selected_model": selected_name,
        "hyperparameters": base_model.get_params(deep=False),
        "model_comparisons": candidate_comparisons,
        "validation_metrics": validation_metrics,
        "random_split": {
            "strategy": "stratified random holdout; test excluded from selection, calibration, and fitting",
            "random_state": 42,
            "train_rows": int(len(train_idx)),
            "model_fit_rows": int(len(model_idx)),
            "threshold_rows": int(len(threshold_idx)),
            "test_rows": int(len(test_idx)),
            "overlapping_registered_domains": int(len(random_train_domains & random_test_domains)),
            "metrics": random_metrics,
            "triage_metrics": _policy_metrics(y.iloc[test_idx], test_prob, thresholds),
            "calibration": random_calibration,
        },
        "domain_aware": {
            "strategy": "registered-domain GroupShuffleSplit; model family selected only within group-train domains",
            "random_state": 44,
            "model_name": group_model_name,
            "train_rows": int(len(group_train_idx)),
            "test_rows": int(len(group_test_idx)),
            "train_domains": int(groups.iloc[group_train_idx].nunique()),
            "test_domains": int(groups.iloc[group_test_idx].nunique()),
            "overlapping_domains": int(len(group_overlap)),
            "validation_metrics": group_validation_metrics,
            "candidate_comparisons": group_comparisons,
            "metrics": group_metrics,
            "triage_metrics": _policy_metrics(y.iloc[group_test_idx], group_prob, thresholds),
            "calibration": group_calibration,
        },
        "temporal": temporal_metrics,
        "external_validation": {
            "status": "not_run",
            "reason": "No compatible external source with a verified reuse license was integrated.",
        },
        "thresholds": thresholds,
        "threshold_selection": {
            "holdout_rows": int(len(threshold_idx)),
            "method": "maximize SAFE coverage with <=2% false-safe rate; maximize PHISHING recall with <=1% benign phishing rate",
            "metrics": threshold_metrics,
        },
        "artifact_backup": os.path.relpath(backup_dir, ROOT) if backup_dir else None,
        "software_versions": {
            "python": sys.version.split()[0],
            "numpy": importlib.metadata.version("numpy"),
            "pandas": importlib.metadata.version("pandas"),
            "scikit_learn": importlib.metadata.version("scikit-learn"),
            "tldextract": importlib.metadata.version("tldextract"),
        },
        "dataset_rows": int(len(cleaned_df)),
        "train_rows": int(len(model_idx)),
        "threshold_rows": int(len(threshold_idx)),
        "test_rows": int(len(test_idx)),
        "random_split_metrics": random_metrics,
        "domain_aware_metrics": group_metrics,
        "report": dataset_report,
    }

    _atomic_write(model_path, model_payload)
    _atomic_write(feature_path, feature_payload)
    _atomic_write(importance_path, importance_df.to_csv(index=False))
    _atomic_write(metadata_path, json.dumps(metadata, indent=2, default=str))
    metadata["artifacts"] = {
        "model_size_bytes": os.path.getsize(model_path),
        "model_sha256": _sha256(model_path),
        "feature_names_sha256": _sha256(feature_path),
        "feature_importance_sha256": _sha256(importance_path),
    }
    _atomic_write(metadata_path, json.dumps(metadata, indent=2, default=str))

    print("Training metadata:")
    print(json.dumps(metadata, indent=2, default=str))
    return metadata


if __name__ == "__main__":
    main()
