from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import PHISHING_THRESHOLD, SAFE_THRESHOLD
from feature_extractor import FEATURE_NAMES, MODEL_EXCLUDED_FEATURES, extract_features
from experiments.auto_ml import run_realworld_experiments as base

REPORT_DIR = ROOT / "reports"
PRODUCTION_PATHS = (
    ROOT / "phishing_model.pkl",
    ROOT / "feature_names.pkl",
    ROOT / "model_metadata.json",
    ROOT / "feature_extractor.py",
    ROOT / "service.py",
    ROOT / "config.py",
)
BASE_CANDIDATE = (
    ROOT
    / "experiments"
    / "auto_ml"
    / "realworld_v3"
    / "candidates"
    / "hist_gradient_regularized_calibrated"
    / "candidate.joblib"
)
URL_FEATURES = [name for name in FEATURE_NAMES if name not in MODEL_EXCLUDED_FEATURES]
STRUCTURE_FEATURES = {
    "PathLength",
    "QueryLength",
    "QueryParameterCount",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "URLPercentEncodingCount",
    "URLEntropy",
}
NOISY_HEURISTIC_FEATURES = {"HasSuspiciousToken", "HasSuspiciousTLD", "IsTrustedTLD"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def percentage(numerator: int, denominator: int) -> dict:
    return {
        "numerator": int(numerator),
        "denominator": int(denominator),
        "percentage": 100.0 * numerator / denominator if denominator else None,
    }


def frame(rows: list[dict], feature_names: list[str], with_urls: bool = False) -> pd.DataFrame:
    data = [
        {name: extract_features(row["url"])[name] for name in feature_names}
        for row in rows
    ]
    result = pd.DataFrame(data, columns=feature_names)
    if with_urls:
        result.insert(0, "url", [row["url"] for row in rows])
    return result


def predict(candidate: dict, rows: list[dict]) -> np.ndarray:
    if candidate.get("kind") == "char_ngram":
        values = frame(rows, candidate["feature_names"])
        numeric = candidate["scaler"].transform(values)
        char_values = candidate["vectorizer"].transform([row["url"] for row in rows])
        matrix = csr_matrix(hstack((char_values, numeric), format="csr"))
        probabilities = candidate["estimator"].predict_proba(matrix)[:, 1]
        if candidate.get("calibrator") is not None:
            probabilities = candidate["calibrator"].predict_proba(
                probabilities.reshape(-1, 1)
            )[:, 1]
    else:
        values = frame(rows, candidate["feature_names"])
        probabilities = base.final_probability(candidate, values)
    return np.clip(np.asarray(probabilities, dtype=float), 0.0, 1.0)


def verdicts(probabilities: np.ndarray, threshold: float) -> np.ndarray:
    return np.where(probabilities >= threshold, "PHISHING", "NOT_PHISHING")


def expected_calibration_error(labels: np.ndarray, probabilities: np.ndarray) -> float | None:
    if len(labels) == 0:
        return None
    edges = np.linspace(0.0, 1.0, 11)
    error = 0.0
    for index, (left, right) in enumerate(zip(edges[:-1], edges[1:])):
        mask = (probabilities >= left) & (
            (probabilities < right) if index < 9 else (probabilities <= right)
        )
        if mask.any():
            error += float(mask.mean()) * abs(
                float(labels[mask].mean()) - float(probabilities[mask].mean())
            )
    return error


def metrics(rows: list[dict], probabilities: np.ndarray, threshold: float) -> dict:
    labels = np.asarray([row["label"] for row in rows], dtype=int)
    predicted = verdicts(probabilities, threshold)
    positive = labels == 1
    negative = labels == 0
    predicted_positive = predicted == "PHISHING"
    tp = int(np.sum(positive & predicted_positive))
    fp = int(np.sum(negative & predicted_positive))
    fn = int(np.sum(positive & ~predicted_positive))
    phishing_n = int(positive.sum())
    legitimate_n = int(negative.sum())
    try:
        from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

        if len(set(labels.tolist())) == 2:
            pr_auc = float(average_precision_score(labels, probabilities))
            roc_auc = float(roc_auc_score(labels, probabilities))
            brier = float(brier_score_loss(labels, probabilities))
        else:
            pr_auc = roc_auc = brier = None
    except ValueError:
        pr_auc = roc_auc = brier = None
    return {
        "rows": len(rows),
        "legitimate_rows": legitimate_n,
        "phishing_rows": phishing_n,
        "legitimate_false_phishing": percentage(fp, legitimate_n),
        "phishing_false_negative": percentage(fn, phishing_n),
        "phishing_recall": percentage(tp, phishing_n),
        "phishing_precision": percentage(tp, int(predicted_positive.sum())),
        "verdict_counts": {
            "SAFE": int(np.sum((probabilities < SAFE_THRESHOLD) & ~predicted_positive)),
            "SUSPICIOUS": int(np.sum((probabilities >= SAFE_THRESHOLD) & ~predicted_positive)),
            "PHISHING": int(predicted_positive.sum()),
        },
        "brier_score": brier,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "expected_calibration_error_10_bins": expected_calibration_error(labels, probabilities),
    }


def select_phishing_threshold(rows: list[dict], probabilities: np.ndarray) -> tuple[float, dict]:
    labels = np.asarray([row["label"] for row in rows], dtype=int)
    thresholds = np.unique(
        np.concatenate(([min(1.0, SAFE_THRESHOLD + 1e-6), 1.0], probabilities))
    )
    thresholds = thresholds[thresholds > SAFE_THRESHOLD]
    candidates = []
    for threshold in thresholds:
        predicted = probabilities >= threshold
        fp = int(np.sum((labels == 0) & predicted))
        tp = int(np.sum((labels == 1) & predicted))
        fpr = fp / max(1, int(np.sum(labels == 0)))
        recall = tp / max(1, int(np.sum(labels == 1)))
        candidates.append((float(threshold), fpr, recall, tp / max(1, int(predicted.sum()))))

    recall_guard = [item for item in candidates if item[2] >= 0.98]
    if recall_guard:
        chosen = min(recall_guard, key=lambda item: (item[1], -item[2], -item[3], -item[0]))
        method = "minimum_validation_FPR_subject_to_validation_recall_at_least_98_percent"
    else:
        maximum_recall = max(item[2] for item in candidates)
        chosen = min(
            (item for item in candidates if math.isclose(item[2], maximum_recall)),
            key=lambda item: (item[1], -item[3], -item[0]),
        )
        method = "98_percent_recall_unattainable_on_validation; maximum_recall_then_minimum_FPR"
    return chosen[0], {
        "selection_method": method,
        "validation_false_positive_rate": 100.0 * chosen[1],
        "validation_phishing_recall": 100.0 * chosen[2],
        "validation_precision": 100.0 * chosen[3],
        "recall_guard_met": chosen[2] >= 0.98,
    }


def fit_calibrator(estimator, calibration_rows: list[dict], feature_names: list[str], kind: str):
    labels = np.asarray([row["label"] for row in calibration_rows], dtype=int)
    weights = base.domain_sample_weights(calibration_rows)
    if kind == "char_ngram":
        feature_frame = frame(calibration_rows, feature_names)
        numeric = estimator["scaler"].transform(feature_frame)
        chars = estimator["vectorizer"].transform([row["url"] for row in calibration_rows])
        matrix = csr_matrix(hstack((chars, numeric), format="csr"))
        scores = estimator["estimator"].predict_proba(matrix)[:, 1]
        candidate = dict(estimator)
    else:
        candidate = estimator
        scores = base.raw_probability(candidate["estimator"], frame(calibration_rows, feature_names))
    calibrator = LogisticRegression(solver="lbfgs", max_iter=2000, random_state=base.SEED)
    calibrator.fit(scores.reshape(-1, 1), labels, sample_weight=weights)
    candidate["calibrator"] = calibrator
    return candidate


def fit_hgb_candidate(
    spec: dict,
    train_rows: list[dict],
    calibration_rows: list[dict],
) -> tuple[dict, dict]:
    feature_names = spec["features"]
    train_frame = frame(train_rows, feature_names)
    labels = np.asarray([row["label"] for row in train_rows], dtype=int)
    weights = base.domain_sample_weights(train_rows) if spec["domain_weighted"] else None
    estimator = HistGradientBoostingClassifier(**spec["params"])
    started = time.perf_counter()
    estimator.fit(train_frame, labels, sample_weight=weights)

    calibration_frame = frame(calibration_rows, feature_names)
    calibration_labels = np.asarray([row["label"] for row in calibration_rows], dtype=int)
    raw_scores = estimator.predict_proba(calibration_frame)[:, 1]
    calibration_weights = (
        base.domain_sample_weights(calibration_rows) if spec["domain_weighted"] else None
    )
    calibrator = LogisticRegression(solver="lbfgs", max_iter=2000, random_state=base.SEED)
    calibrator.fit(
        raw_scores.reshape(-1, 1),
        calibration_labels,
        sample_weight=calibration_weights,
    )
    candidate = {
        "estimator": estimator,
        "calibrator": calibrator,
        "feature_names": feature_names,
        "model_name": spec["name"],
    }
    return candidate, {
        "fit_seconds": time.perf_counter() - started,
        "training_sample_weights": "inverse_registered_domain" if spec["domain_weighted"] else "none",
        "calibration_sample_weights": "inverse_registered_domain" if spec["domain_weighted"] else "none",
    }


def fit_ngram_candidate(train_rows: list[dict], calibration_rows: list[dict]) -> tuple[dict, dict]:
    feature_names = URL_FEATURES
    numeric_train = frame(train_rows, feature_names)
    scaler = StandardScaler(with_mean=False)
    scaled_numeric = scaler.fit_transform(numeric_train)
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        max_features=30000,
        sublinear_tf=True,
        dtype=np.float32,
    )
    chars = vectorizer.fit_transform([row["url"] for row in train_rows])
    matrix = csr_matrix(hstack((chars, scaled_numeric), format="csr"))
    labels = np.asarray([row["label"] for row in train_rows], dtype=int)
    classifier = LogisticRegression(
        C=1.0,
        solver="liblinear",
        max_iter=1500,
        random_state=base.SEED,
    )
    weights = base.domain_sample_weights(train_rows)
    started = time.perf_counter()
    classifier.fit(matrix, labels, sample_weight=weights)
    candidate = {
        "kind": "char_ngram",
        "feature_names": feature_names,
        "vectorizer": vectorizer,
        "scaler": scaler,
        "estimator": classifier,
        "calibrator": None,
        "model_name": "char_ngrams_plus_29_numeric",
    }
    candidate = fit_calibrator(candidate, calibration_rows, feature_names, "char_ngram")
    return candidate, {
        "fit_seconds": time.perf_counter() - started,
        "character_vocabulary_size": len(vectorizer.vocabulary_),
        "ngram_range": [3, 5],
        "max_features": 30000,
        "regularization_C": 1.0,
    }


def feature_groups(rows: list[dict], probabilities: np.ndarray, threshold: float) -> dict:
    labels = np.asarray([row["label"] for row in rows], dtype=int)
    prediction = probabilities >= threshold
    false_positive = (labels == 0) & prediction
    false_negative = (labels == 1) & ~prediction
    result = {}
    for group_type, key_fn in (
        ("url_structure", lambda row: base.get_cohorts(row["url"])),
        ("source", lambda row: [row.get("source_name") or "unknown"]),
        ("registered_domain", lambda row: [row["registered_domain"]]),
    ):
        grouped = defaultdict(lambda: {"rows": 0, "legitimate": 0, "phishing": 0, "false_positives": 0, "false_negatives": 0})
        for index, row in enumerate(rows):
            keys = key_fn(row) or ["unclassified"]
            for key in keys:
                item = grouped[str(key)]
                item["rows"] += 1
                if labels[index] == 0:
                    item["legitimate"] += 1
                    item["false_positives"] += int(false_positive[index])
                else:
                    item["phishing"] += 1
                    item["false_negatives"] += int(false_negative[index])
        result[group_type] = {
            key: {
                **counts,
                "legitimate_fpr": percentage(counts["false_positives"], counts["legitimate"]),
                "phishing_false_negative_rate": percentage(counts["false_negatives"], counts["phishing"]),
            }
            for key, counts in sorted(
                grouped.items(),
                key=lambda item: (
                    -item[1]["false_positives"] - item[1]["false_negatives"],
                    item[0],
                ),
            )
        }

    values = frame(rows, URL_FEATURES)
    comparisons = {}
    for name in URL_FEATURES:
        fp_values = values.loc[false_positive, name]
        correct_values = values.loc[(labels == 0) & ~prediction, name]
        fn_values = values.loc[false_negative, name]
        detected_values = values.loc[(labels == 1) & prediction, name]
        if len(fp_values) or len(fn_values):
            comparisons[name] = {
                "false_positive_mean": float(fp_values.mean()) if len(fp_values) else None,
                "correct_legitimate_mean": float(correct_values.mean()) if len(correct_values) else None,
                "false_negative_mean": float(fn_values.mean()) if len(fn_values) else None,
                "detected_phishing_mean": float(detected_values.mean()) if len(detected_values) else None,
            }
    false_positive_examples = []
    false_negative_examples = []
    for index, row in enumerate(rows):
        if false_positive[index] or false_negative[index]:
            example = {
                "url": row["url"],
                "label": row["label"],
                "probability": float(probabilities[index]),
                "verdict": "PHISHING" if prediction[index] else "NOT_PHISHING",
                "source_name": row.get("source_name"),
                "registered_domain": row["registered_domain"],
                "cohorts": sorted(base.get_cohorts(row["url"])),
                "features": extract_features(row["url"]),
            }
            (false_positive_examples if false_positive[index] else false_negative_examples).append(example)
    false_positive_examples.sort(key=lambda item: item["probability"], reverse=True)
    false_negative_examples.sort(key=lambda item: item["probability"], reverse=True)
    result["feature_error_contrasts"] = comparisons
    result["false_positive_examples"] = false_positive_examples[:100]
    result["false_negative_examples"] = false_negative_examples[:100]
    result["failure_count"] = int(false_positive.sum() + false_negative.sum())
    return result


def production_prediction(rows: list[dict]) -> tuple[np.ndarray, list[str]]:
    import service

    results = [service.scan(row["url"]) for row in rows]
    return np.asarray([item["probability"] for item in results]), [item["label"] for item in results]


def service_metrics(rows: list[dict], probabilities: np.ndarray, labels_out: list[str]) -> dict:
    actual = np.asarray([row["label"] for row in rows], dtype=int)
    predicted = np.asarray(labels_out)
    positive = actual == 1
    negative = actual == 0
    is_phishing = predicted == "PHISHING"
    tp = int(np.sum(positive & is_phishing))
    fp = int(np.sum(negative & is_phishing))
    fn = int(np.sum(positive & ~is_phishing))
    return {
        "legitimate_false_phishing": percentage(fp, int(negative.sum())),
        "phishing_false_negative": percentage(fn, int(positive.sum())),
        "phishing_recall": percentage(tp, int(positive.sum())),
        "phishing_precision": percentage(tp, int(is_phishing.sum())),
        "brier_score": float(np.mean((probabilities - actual) ** 2)) if len(actual) else None,
    }


def validation_rank(record: dict) -> tuple:
    score = record["validation_metrics"]
    fpr = score["legitimate_false_phishing"]["percentage"] or 0.0
    recall = score["phishing_recall"]["percentage"] or 0.0
    return (recall >= 98.0, -fpr, recall, score["phishing_precision"]["percentage"] or 0.0)


def meaningfully_improves(new: dict, old: dict) -> bool:
    new_metrics = new["validation_metrics"]
    old_metrics = old["validation_metrics"]
    nfpr = new_metrics["legitimate_false_phishing"]["percentage"] or 0.0
    ofpr = old_metrics["legitimate_false_phishing"]["percentage"] or 0.0
    nr = new_metrics["phishing_recall"]["percentage"] or 0.0
    oldr = old_metrics["phishing_recall"]["percentage"] or 0.0
    if nr >= 98.0 > oldr:
        return True
    if nr >= 98.0 and oldr >= 98.0:
        return (ofpr - nfpr >= 0.2 and nr >= oldr - 1.0) or (
            nr - oldr >= 1.0 and nfpr <= ofpr + 0.2
        )
    return (nr - oldr >= 1.0 and nfpr <= ofpr + 0.2) or (
        ofpr - nfpr >= 0.2 and nr >= oldr - 1.0
    )


def validation_feature_permutation(candidate: dict, rows: list[dict]) -> dict:
    from sklearn.metrics import average_precision_score

    feature_names = candidate["feature_names"]
    values = frame(rows, feature_names)
    labels = np.asarray([row["label"] for row in rows], dtype=int)
    baseline = predict(candidate, rows)
    baseline_ap = float(average_precision_score(labels, baseline))
    rng = np.random.default_rng(20261009)
    diagnostics = {}
    for name in feature_names:
        drops = []
        for _ in range(5):
            permuted = values.copy()
            permuted[name] = rng.permutation(permuted[name].to_numpy())
            raw = base.raw_probability(candidate["estimator"], permuted)
            calibrator = candidate.get("calibrator")
            scores = (
                calibrator.predict_proba(raw.reshape(-1, 1))[:, 1]
                if calibrator is not None
                else raw
            )
            drops.append(baseline_ap - float(average_precision_score(labels, scores)))
        diagnostics[name] = {
            "mean_average_precision_drop": float(np.mean(drops)),
            "standard_deviation": float(np.std(drops)),
            "permutations": len(drops),
        }
    return {
        "validation_only": True,
        "baseline_average_precision": baseline_ap,
        "interpretation": "Correlated-feature permutation is associational and not causal; no test or benchmark rows are used.",
        "features": diagnostics,
        "largest_mean_drops": sorted(
            diagnostics.items(),
            key=lambda item: item[1]["mean_average_precision_drop"],
            reverse=True,
        )[:12],
    }


def reliability_hashes() -> dict:
    return {path.name: sha256(path) for path in PRODUCTION_PATHS}


def candidate_specs() -> list[dict]:
    return [
        {
            "name": "hgb_baseline_domain_weighted",
            "hypothesis": "Reproducing the regularized production-feature HGB on the validated cohort sample establishes a matched experimental baseline.",
            "change": "No feature or estimator change; calibrated HGB with inverse registered-domain weights.",
            "features": URL_FEATURES,
            "family": "HistGradientBoosting",
            "domain_weighted": True,
            "params": {
                "learning_rate": 0.05,
                "max_iter": 100,
                "max_leaf_nodes": 15,
                "min_samples_leaf": 20,
                "l2_regularization": 1.0,
                "random_state": base.SEED,
                "class_weight": None,
            },
        },
        {
            "name": "hgb_without_dynamic_structure_group",
            "hypothesis": "Correlated path/query punctuation and encoding counts may cause some false positives; removing this complete feature group should reduce validation FPR if the group is over-weighted, but may reduce phishing recall.",
            "change": "Remove PathLength, QueryLength, QueryParameterCount, punctuation-count and percent-encoding features, and URLEntropy only.",
            "features": [name for name in URL_FEATURES if name not in STRUCTURE_FEATURES],
            "family": "HistGradientBoosting",
            "domain_weighted": True,
            "params": {
                "learning_rate": 0.05,
                "max_iter": 100,
                "max_leaf_nodes": 15,
                "min_samples_leaf": 20,
                "l2_regularization": 1.0,
                "random_state": base.SEED,
                "class_weight": None,
            },
        },
        {
            "name": "hgb_without_tld_token_heuristic_group",
            "hypothesis": "Suspicious-token and TLD indicators may be noisy across legitimate sources; removing only these indicator features should improve held-out-source legitimate FPR if these indicators are over-weighted.",
            "change": "Remove HasSuspiciousToken, HasSuspiciousTLD, and IsTrustedTLD only; retain all URL-structure features.",
            "features": [name for name in URL_FEATURES if name not in NOISY_HEURISTIC_FEATURES],
            "family": "HistGradientBoosting",
            "domain_weighted": True,
            "params": {
                "learning_rate": 0.05,
                "max_iter": 100,
                "max_leaf_nodes": 15,
                "min_samples_leaf": 20,
                "l2_regularization": 1.0,
                "random_state": base.SEED,
                "class_weight": None,
            },
        },
        {
            "name": "hgb_without_domain_weights",
            "hypothesis": "Inverse-domain sample weighting may be unstable because legitimate source-domain diversity is far lower; removing only the weights may improve validation generalization or may let dominant domains overwhelm the fit.",
            "change": "Keep features, estimator, samples, calibration, and split fixed; turn off inverse registered-domain weights for fitting and calibration.",
            "features": URL_FEATURES,
            "family": "HistGradientBoosting",
            "domain_weighted": False,
            "params": {
                "learning_rate": 0.05,
                "max_iter": 100,
                "max_leaf_nodes": 15,
                "min_samples_leaf": 20,
                "l2_regularization": 1.0,
                "random_state": base.SEED,
                "class_weight": None,
            },
        },
        {
            "name": "character_ngrams_plus_numeric",
            "hypothesis": "Character n-grams may distinguish lexical URL patterns beyond aggregate 29-feature counts, improving dynamic-legitimate discrimination while retaining phishing recall.",
            "change": "Replace HGB with a regularized character 3-5-gram TF-IDF plus unchanged numeric features and logistic regression; keep rows, split, domain weights, and sigmoid calibration fixed.",
            "features": URL_FEATURES,
            "family": "CharacterTfidfPlusLogisticRegression",
            "domain_weighted": True,
            "params": {"ngram_range": [3, 5], "max_features": 30000, "C": 1.0},
        },
    ]


def train_trial(spec: dict, rows_by_split: dict, trial_dir: Path) -> tuple[dict, dict]:
    train_rows = base.choose_rows(rows_by_split, "train")
    calibration_rows = base.choose_rows(rows_by_split, "calibration")
    validation_rows = base.choose_rows(rows_by_split, "validation")
    for name, rows in (("train", train_rows), ("calibration", calibration_rows), ("validation", validation_rows)):
        if {row["label"] for row in rows} != {0, 1}:
            raise ValueError(f"{name} sample does not contain both labels")

    if spec["family"] == "CharacterTfidfPlusLogisticRegression":
        candidate, model_details = fit_ngram_candidate(train_rows, calibration_rows)
    else:
        candidate, model_details = fit_hgb_candidate(spec, train_rows, calibration_rows)

    validation_probabilities = predict(candidate, validation_rows)
    phishing_threshold, threshold_details = select_phishing_threshold(validation_rows, validation_probabilities)
    validation_metrics = metrics(validation_rows, validation_probabilities, phishing_threshold)
    record = {
        "experiment": spec["name"],
        "hypothesis": spec["hypothesis"],
        "change": spec["change"],
        "family": spec["family"],
        "features": spec["features"],
        "parameters": spec["params"],
        "domain_weighted": spec["domain_weighted"],
        "thresholds": {
            "safe": SAFE_THRESHOLD,
            "phishing": phishing_threshold,
            "phishing_threshold_selection": threshold_details,
        },
        "validation_metrics": validation_metrics,
        "sample_sizes": {
            name: len(rows)
            for name, rows in (
                ("train", train_rows),
                ("calibration", calibration_rows),
                ("validation", validation_rows),
            )
        },
        "sample_domain_counts": {
            name: {
                "legitimate": len({row["registered_domain"] for row in rows if row["label"] == 0}),
                "phishing": len({row["registered_domain"] for row in rows if row["label"] == 1}),
            }
            for name, rows in (
                ("train", train_rows),
                ("calibration", calibration_rows),
                ("validation", validation_rows),
            )
        },
        "sample_source_counts": {
            "train_legitimate": dict(Counter(row["source_name"] for row in train_rows if row["label"] == 0)),
            "calibration_legitimate": dict(Counter(row["source_name"] for row in calibration_rows if row["label"] == 0)),
            "validation_legitimate": dict(Counter(row["source_name"] for row in validation_rows if row["label"] == 0)),
        },
        "fit_details": model_details,
        "validation_failure_analysis": feature_groups(validation_rows, validation_probabilities, phishing_threshold),
        "dataset_manifest": str((trial_dir / "dataset_manifest.json").relative_to(ROOT)),
    }
    trial_dir.mkdir(parents=True, exist_ok=True)
    artifact = trial_dir / "candidate.joblib"
    joblib.dump(candidate, artifact, compress=3)
    record["artifact"] = str(artifact.relative_to(ROOT))
    record["artifact_sha256"] = sha256(artifact)
    record["artifact_size_bytes"] = artifact.stat().st_size
    candidate["thresholds"] = record["thresholds"]
    joblib.dump(candidate, artifact, compress=3)
    record["artifact_sha256"] = sha256(artifact)
    record["artifact_size_bytes"] = artifact.stat().st_size
    write_json(trial_dir / "experiment.json", record)
    write_json(
        trial_dir / "failure_analysis.json",
        record["validation_failure_analysis"],
    )
    return candidate, record


def domain_counts(rows: list[dict]) -> dict:
    return {
        "rows": len(rows),
        "legitimate_rows": sum(row["label"] == 0 for row in rows),
        "phishing_rows": sum(row["label"] == 1 for row in rows),
        "legitimate_registered_domains": len({row["registered_domain"] for row in rows if row["label"] == 0}),
        "phishing_registered_domains": len({row["registered_domain"] for row in rows if row["label"] == 1}),
    }


def sample_manifest(rows: list[dict]) -> dict:
    digest = hashlib.sha256()
    primary = Counter()
    structures = Counter()
    for row in sorted(rows, key=lambda item: (item["registered_domain"], item["url"], item["label"])):
        digest.update(f'{row["url"]}\t{row["label"]}\t{row["registered_domain"]}\n'.encode("utf-8"))
        primary[f'{row["label"]}:{base.primary_cohort(row["url"])}'] += 1
        for cohort in base.get_cohorts(row["url"]):
            structures[f'{row["label"]}:{cohort}'] += 1
    return {
        **domain_counts(rows),
        "normalized_url_label_domain_sha256": digest.hexdigest(),
        "primary_cohort_counts_by_label": dict(sorted(primary.items())),
        "overlapping_structure_counts_by_label": dict(sorted(structures.items())),
        "source_counts": dict(Counter(row.get("source_name", "unknown") for row in rows)),
    }


def regression_tests() -> dict:
    backend_command = [sys.executable, "-m", "pytest", "-q", "tests/test_pipeline.py"]
    try:
        backend = subprocess.run(
            backend_command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        backend_result = {
            "command": backend_command,
            "status": "PASS" if backend.returncode == 0 else "FAIL",
            "return_code": backend.returncode,
            "output": (backend.stdout + backend.stderr)[-6000:],
        }
    except subprocess.TimeoutExpired as exc:
        backend_result = {
            "command": backend_command,
            "status": "FAIL",
            "error": "backend test command timed out",
            "output": str(exc)[-2000:],
        }

    node = shutil.which("node")
    extension_command = (
        [node, "--test", "extension.test.mjs", "background.runtime.test.mjs"]
        if node
        else None
    )
    if extension_command is None:
        extension_result = {"status": "UNVERIFIED", "error": "Node.js is not available on PATH"}
    else:
        try:
            extension = subprocess.run(
                extension_command,
                cwd=ROOT / "extenison",
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            extension_result = {
                "command": extension_command,
                "status": "PASS" if extension.returncode == 0 else "FAIL",
                "return_code": extension.returncode,
                "output": (extension.stdout + extension.stderr)[-6000:],
            }
        except subprocess.TimeoutExpired as exc:
            extension_result = {
                "command": extension_command,
                "status": "FAIL",
                "error": "extension test command timed out",
                "output": str(exc)[-2000:],
            }
    return {"backend": backend_result, "extension": extension_result}


def evaluate_candidate(candidate: dict, rows: list[dict]) -> dict:
    probabilities = predict(candidate, rows)
    threshold = float(candidate["thresholds"]["phishing"])
    prod_probabilities, prod_labels = production_prediction(rows)
    return {
        "candidate": metrics(rows, probabilities, threshold),
        "production_service_native": service_metrics(rows, prod_probabilities, prod_labels),
        "candidate_failure_analysis": feature_groups(rows, probabilities, threshold),
        "production_probabilities_sha_note": "Production uses metadata thresholds through service.scan; candidate uses its validation-selected phishing cutoff.",
        "candidate_probabilities": probabilities,
        "production_probabilities": prod_probabilities,
        "production_labels": prod_labels,
    }


def run(max_experiments: int) -> dict:
    if max_experiments < 1 or max_experiments > 15:
        raise ValueError("max_experiments must be between 1 and 15")
    for path in (*PRODUCTION_PATHS, BASE_CANDIDATE):
        if not path.is_file():
            raise FileNotFoundError(f"required file not found: {path}")

    initial_hashes = reliability_hashes()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = ROOT / "experiments" / "auto_ml" / f"false_positive_repair_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)

    benchmark_domains, _, fixed = base.load_benchmark_reservations()
    rows_by_split, data_manifest = base.load_inputs(benchmark_domains)
    data_manifest["created_utc"] = datetime.now(timezone.utc).isoformat()
    data_manifest["benchmark_use_policy"] = "fixed v1 evaluated only after validation-based candidate selection; never used for thresholding, training, or selection"
    data_manifest["split_note"] = "Reuses the existing deterministic registered-domain split; prior reports evaluated this split, so results are not a newly sourced independent lockbox."
    write_json(run_dir / "dataset_manifest.json", data_manifest)

    split_domains = {
        split: {
            row["registered_domain"]
            for label in (0, 1)
            for cohort_rows in rows_by_split[split][label].values()
            for row in cohort_rows
        }
        for split in base.SPLITS
    }
    overlap = {
        f"{left}_{right}": sorted(split_domains[left] & split_domains[right])
        for i, left in enumerate(base.SPLITS)
        for right in base.SPLITS[i + 1 :]
        if split_domains[left] & split_domains[right]
    }
    if overlap:
        raise RuntimeError(f"registered-domain overlap in split: {list(overlap)}")

    validation_rows = base.choose_rows(rows_by_split, "validation")
    test_rows = base.choose_rows(rows_by_split, "test")
    validation_production_probabilities, validation_production_labels = production_prediction(
        validation_rows
    )
    import service

    validation_production_threshold = float(
        service.model_info().get("thresholds", {}).get("phishing", PHISHING_THRESHOLD)
    )
    validation_production_metrics = service_metrics(
        validation_rows,
        validation_production_probabilities,
        validation_production_labels,
    )
    validation_production_failure_analysis = feature_groups(
        validation_rows,
        validation_production_probabilities,
        validation_production_threshold,
    )
    domain_disjoint_test_rows = (
        base.external_rows(
            base.read_csv_rows(base.BENCHMARK_DIR / "legitimate_domain_disjoint.csv"),
            0,
            "fixed benchmark legitimate",
        )
        + base.external_rows(
            base.read_csv_rows(base.BENCHMARK_DIR / "phishing_domain_disjoint.csv"),
            1,
            "fixed benchmark phishing",
        )
    )
    core_rows = [
        {
            "url": url,
            "label": 0,
            "source_name": "fixed benchmark core legitimate",
            "source_page": "benchmark_v1/fixed_urls.json",
            "category": "core_legitimate_regression",
            "verification_method": "fixed_benchmark_v1",
            "registered_domain": base.get_registered_domain(url),
        }
        for url in fixed["baseline_legitimate_urls"]
    ]
    counterfactual_rows = [
        {
            "url": base.normalize_url(row["url"]),
            "label": 0,
            "source_name": row.get("source_name", "fixed benchmark counterfactual"),
            "source_page": row.get("source_page", "benchmark_v1/fixed_urls.json"),
            "category": "curated_counterfactual_not_observed",
            "verification_method": "derived_from_fixed_legitimate_base_not_realworld_training_data",
            "registered_domain": base.get_registered_domain(row["url"]),
        }
        for row in fixed["counterfactual_legitimate_urls"]
    ]

    trial_specs = candidate_specs()[:max_experiments]
    initial_candidate = joblib.load(BASE_CANDIDATE)
    incumbent = initial_candidate
    incumbent_val_probabilities = predict(incumbent, validation_rows)
    initial_threshold, initial_threshold_details = select_phishing_threshold(validation_rows, incumbent_val_probabilities)
    incumbent["thresholds"] = {
        "safe": SAFE_THRESHOLD,
        "phishing": initial_threshold,
        "phishing_threshold_selection": initial_threshold_details,
    }
    initial_record = {
        "experiment": "existing_realworld_v3_candidate",
        "artifact": str(BASE_CANDIDATE.relative_to(ROOT)),
        "artifact_sha256": sha256(BASE_CANDIDATE),
        "thresholds": incumbent["thresholds"],
        "validation_metrics": metrics(validation_rows, incumbent_val_probabilities, initial_threshold),
        "hypothesis": "Reference candidate; not counted as a new experiment.",
        "change": "None.",
    }
    leaderboard = [initial_record]
    incumbent_record = initial_record
    consecutive_no_improvement = 0
    stop_reason = "experiment_budget_reached"
    experiments = []
    for spec in trial_specs:
        trial_dir = run_dir / "candidates" / spec["name"]
        write_json(
            trial_dir / "dataset_manifest.json",
            {
                "input_sha256": data_manifest["input_sha256"],
                "benchmark_domain_reservations": data_manifest["benchmark_domain_reservation"],
                "split_method": data_manifest["split_method"],
                "registered_domain_split_overlap": overlap,
                "split_rows_and_domains": data_manifest["all_split_rows"],
                "sample_counts": {
                    split: sample_manifest(base.choose_rows(rows_by_split, split))
                    for split in ("train", "calibration", "validation")
                },
            },
        )
        candidate, record = train_trial(spec, rows_by_split, trial_dir)
        record["validation_production_service_native"] = {
            "metrics": validation_production_metrics,
            "failure_analysis": validation_production_failure_analysis,
            "thresholds": service.model_info().get("thresholds", {}),
            "comparison_rows": len(validation_rows),
        }
        write_json(trial_dir / "experiment.json", record)
        record["outcome_vs_incumbent_validation"] = {
            "meaningful_improvement": meaningfully_improves(record, incumbent_record),
            "previous_incumbent": incumbent_record["experiment"],
        }
        experiments.append(record)
        leaderboard.append(record)
        meaningful = record["outcome_vs_incumbent_validation"]["meaningful_improvement"]
        if meaningful and validation_rank(record) > validation_rank(incumbent_record):
            incumbent, incumbent_record = candidate, record
        if meaningful:
            consecutive_no_improvement = 0
        else:
            consecutive_no_improvement += 1
        write_json(run_dir / "leaderboard.json", {"experiments": leaderboard, "selected_on_validation_only": incumbent_record["experiment"]})
        if consecutive_no_improvement >= 3:
            stop_reason = "three_consecutive_experiments_without_meaningful_validation_improvement"
            break
    if (
        stop_reason == "experiment_budget_reached"
        and len(experiments) < max_experiments
        and consecutive_no_improvement < 3
    ):
        stop_reason = (
            "data_limitation_independent_hard_phishing_lockbox_unavailable;"
            " all_predeclared_controlled_hypotheses_completed"
        )

    # Only after candidate selection is frozen are the existing final test and fixed benchmark opened.
    test_candidate_probabilities = predict(incumbent, test_rows)
    test_candidate_metrics = metrics(test_rows, test_candidate_probabilities, float(incumbent["thresholds"]["phishing"]))
    initial_test_probabilities = predict(initial_candidate, test_rows)
    initial_test_metrics = metrics(
        test_rows,
        initial_test_probabilities,
        float(initial_candidate["thresholds"]["phishing"]),
    )
    initial_test_original_cutoff_metrics = metrics(
        test_rows,
        initial_test_probabilities,
        PHISHING_THRESHOLD,
    )
    test_production_probabilities, test_production_labels = production_prediction(test_rows)
    test_production_metrics = service_metrics(test_rows, test_production_probabilities, test_production_labels)

    benchmark_candidate = evaluate_candidate(incumbent, domain_disjoint_test_rows)
    benchmark_candidate_metrics = benchmark_candidate["candidate"]
    initial_benchmark_probabilities = predict(initial_candidate, domain_disjoint_test_rows)
    initial_benchmark_metrics = metrics(
        domain_disjoint_test_rows,
        initial_benchmark_probabilities,
        float(initial_candidate["thresholds"]["phishing"]),
    )
    initial_benchmark_original_cutoff_metrics = metrics(
        domain_disjoint_test_rows,
        initial_benchmark_probabilities,
        PHISHING_THRESHOLD,
    )
    benchmark_candidate.pop("candidate_probabilities")
    benchmark_candidate.pop("production_probabilities")
    benchmark_candidate.pop("production_labels")
    core_candidate_probabilities = predict(incumbent, core_rows)
    core_candidate_metrics = metrics(core_rows, core_candidate_probabilities, float(incumbent["thresholds"]["phishing"]))
    initial_core_probabilities = predict(initial_candidate, core_rows)
    initial_core_metrics = metrics(
        core_rows,
        initial_core_probabilities,
        float(initial_candidate["thresholds"]["phishing"]),
    )
    initial_core_original_cutoff_metrics = metrics(
        core_rows,
        initial_core_probabilities,
        PHISHING_THRESHOLD,
    )
    counterfactual_probabilities = predict(incumbent, counterfactual_rows)
    counterfactual_metrics = metrics(counterfactual_rows, counterfactual_probabilities, float(incumbent["thresholds"]["phishing"]))

    # The calibrated model uses identical numeric features at train and inference.
    # Verify this empirically against service output before interpreting comparisons.
    import service

    parity_rows = (test_rows + domain_disjoint_test_rows)[:50]
    feature_parity = True
    for row in parity_rows:
        if extract_features(row["url"]) != service.scan(row["url"])["features"]:
            feature_parity = False
            break

    latency_rows = test_rows[: min(300, len(test_rows))]
    timings = []
    for row in latency_rows:
        started = time.perf_counter()
        predict(incumbent, [row])
        timings.append((time.perf_counter() - started) * 1000)
    latency = {
        "sample_count": len(timings),
        "median_ms_per_url_including_feature_extraction": statistics.median(timings) if timings else None,
        "p95_ms_per_url_including_feature_extraction": float(np.percentile(timings, 95)) if timings else None,
    }

    final_candidate_path = run_dir / "best_validation_candidate.joblib"
    joblib.dump(incumbent, final_candidate_path, compress=3)
    final_candidate_hash = sha256(final_candidate_path)
    final_candidate_size = final_candidate_path.stat().st_size
    reloaded_candidate = joblib.load(final_candidate_path)
    candidate_integrity = (
        final_candidate_hash == sha256(final_candidate_path)
        and reloaded_candidate["model_name"] == incumbent["model_name"]
        and np.allclose(
            predict(reloaded_candidate, test_rows[: min(10, len(test_rows))]),
            test_candidate_probabilities[: min(10, len(test_rows))],
            rtol=0,
            atol=1e-12,
        )
    )
    final_hashes = reliability_hashes()
    hashes_unchanged = initial_hashes == final_hashes
    test_results = regression_tests()
    production_threshold = float(
        service.model_info().get("thresholds", {}).get("phishing", PHISHING_THRESHOLD)
    )
    final_internal_failure_analysis = feature_groups(
        test_rows,
        test_candidate_probabilities,
        float(incumbent["thresholds"]["phishing"]),
    )
    production_internal_failure_analysis = feature_groups(
        test_rows,
        test_production_probabilities,
        production_threshold,
    )
    hard_cohort_comparison = {}
    for cohort in ("content_path", "query", "multiple_parameters", "encoding", "login_account", "long_query"):
        candidate_group = final_internal_failure_analysis["url_structure"].get(cohort, {})
        production_group = production_internal_failure_analysis["url_structure"].get(cohort, {})
        candidate_n = candidate_group.get("phishing", 0)
        production_n = production_group.get("phishing", 0)
        candidate_recall = (
            100.0 * (candidate_n - candidate_group.get("false_negatives", 0)) / candidate_n
            if candidate_n else None
        )
        production_recall = (
            100.0 * (production_n - production_group.get("false_negatives", 0)) / production_n
            if production_n else None
        )
        hard_cohort_comparison[cohort] = {
            "phishing_denominator": candidate_n,
            "candidate_recall_percentage": candidate_recall,
            "production_recall_percentage": production_recall,
            "delta_percentage_points": (
                candidate_recall - production_recall
                if candidate_recall is not None and production_recall is not None
                else None
            ),
        }
    meaningful_hard_cohorts = [
        value for value in hard_cohort_comparison.values()
        if value["phishing_denominator"] >= 20 and value["delta_percentage_points"] is not None
    ]
    major_hard_cohort_regression = any(
        value["delta_percentage_points"] < -5.0 for value in meaningful_hard_cohorts
    )
    dynamic_cohorts = {
        cohort: final_internal_failure_analysis["url_structure"].get(cohort, {})
        for cohort in ("query", "multiple_parameters", "encoding")
    }
    systematic_structure_fp = any(
        item.get("legitimate", 0) >= 20
        and (item.get("legitimate_fpr", {}).get("percentage") or 0.0) > 5.0
        for item in dynamic_cohorts.values()
    )

    gates = {
        "core_legitimate_zero_phishing_verdicts": {
            "phishing_verdicts": core_candidate_metrics["legitimate_false_phishing"]["numerator"],
            "denominator": core_candidate_metrics["legitimate_rows"],
            "status": "PASS" if core_candidate_metrics["legitimate_false_phishing"]["numerator"] == 0 else "FAIL",
        },
        "benchmark_legitimate_fpr_at_most_0_5_percent": {
            **benchmark_candidate_metrics["legitimate_false_phishing"],
            "status": "PASS" if (benchmark_candidate_metrics["legitimate_false_phishing"]["percentage"] or 0) <= 0.5 else "FAIL",
        },
        "representative_domain_disjoint_phishing_recall_at_least_98_percent": {
            **test_candidate_metrics["phishing_recall"],
            "status": "PASS" if (test_candidate_metrics["phishing_recall"]["percentage"] or 0) >= 98 else "FAIL",
        },
        "independent_hard_phishing_benchmark_recall_at_least_97_percent": {
            **benchmark_candidate_metrics["phishing_recall"],
            "status": "UNVERIFIED",
            "reason": "benchmark_v1 was repeatedly evaluated by prior work and is not an independently sourced hard-phishing lockbox",
        },
        "feature_extraction_matches_service": {"status": "PASS" if feature_parity else "FAIL", "rows_checked": len(parity_rows)},
        "registered_domain_split_leakage": {"status": "PASS" if not overlap else "FAIL", "overlap_pairs": overlap},
        "domain_duplicate_and_label_conflict_leakage": {
            "status": "PASS"
            if not overlap and data_manifest["exact_url_label_conflicts"] == 0
            else "FAIL",
            "exact_normalized_url_label_conflicts": data_manifest["exact_url_label_conflicts"],
            "normalized_duplicate_rows_removed": data_manifest["duplicate_normalized_url_removal"],
            "reason": "URL deduplication and conflict resolution occur before domain splitting; domain-disjoint splits prevent exact URL cross-split leakage.",
        },
        "no_major_hard_phishing_cohort_regression": {
            "status": "FAIL" if major_hard_cohort_regression else "PASS",
            "maximum_allowed_recall_regression_percentage_points": 5.0,
            "cohorts": hard_cohort_comparison,
        },
        "no_systematic_query_multi_parameter_encoding_false_positive_signal": {
            "status": "FAIL" if systematic_structure_fp else "PASS",
            "cohorts": dynamic_cohorts,
            "interpretation": "High cohort FPR is a measured association; it does not prove these URL structures alone caused the predictions.",
        },
        "production_artifact_hashes_unchanged": {"status": "PASS" if hashes_unchanged else "FAIL"},
        "backend_tests": {"status": test_results["backend"]["status"]},
        "extension_tests": {"status": test_results["extension"]["status"]},
        "candidate_calibration_latency_integrity": {
            "status": "PASS" if candidate_integrity and latency["sample_count"] else "FAIL",
            "brier_score": test_candidate_metrics["brier_score"],
            "expected_calibration_error_10_bins": test_candidate_metrics["expected_calibration_error_10_bins"],
            "latency": latency,
            "artifact_sha256": final_candidate_hash,
            "artifact_size_bytes": final_candidate_size,
        },
    }
    gates["overall_candidate_eligible_for_promotion"] = (
        "PASS"
        if all(
            gate["status"] == "PASS"
            for name, gate in gates.items()
            if name != "independent_hard_phishing_benchmark_recall_at_least_97_percent"
        )
        and gates["independent_hard_phishing_benchmark_recall_at_least_97_percent"]["status"] == "PASS"
        else "FAIL"
    )

    final = {
        "run_id": run_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "experiment_budget": max_experiments,
        "experiments_completed": len(experiments),
        "stop_reason": stop_reason,
        "benchmark_selection_policy": "No benchmark or final-test result was used for training, threshold choice, or candidate selection.",
        "selected_candidate": {
            "name": incumbent_record["experiment"],
            "artifact": str(final_candidate_path.relative_to(ROOT)),
            "sha256": final_candidate_hash,
            "size_bytes": final_candidate_size,
            "thresholds": incumbent["thresholds"],
            "configuration": incumbent_record,
        },
        "initial_reference": initial_record,
        "final_internal_domain_disjoint_test": {
            "data_status": "Previously reported once in realworld_v3; untouched within this repair run, but not a newly sourced independent lockbox.",
            "initial_v3_candidate": {
                "validation_selected_threshold": initial_test_metrics,
                "original_config_threshold_0_85": initial_test_original_cutoff_metrics,
            },
            "candidate": test_candidate_metrics,
            "production_service_native": test_production_metrics,
            "candidate_failure_analysis": final_internal_failure_analysis,
            "production_failure_analysis": production_internal_failure_analysis,
        },
        "fixed_benchmark_v1": {
            "status": "regression_only; prior repeated evaluation means independent hard-phishing acceptance is UNVERIFIED",
            "registered_domain_disjoint_test": {
                "counts": domain_counts(domain_disjoint_test_rows),
                "initial_v3_candidate": {
                    "validation_selected_threshold": initial_benchmark_metrics,
                    "original_config_threshold_0_85": initial_benchmark_original_cutoff_metrics,
                },
                "candidate": benchmark_candidate_metrics,
                "production_service_native": benchmark_candidate["production_service_native"],
                "candidate_failure_analysis": benchmark_candidate["candidate_failure_analysis"],
                "curated_counterfactuals": counterfactual_metrics,
            },
            "core_legitimate_regression": {
                "initial_v3_candidate": {
                    "validation_selected_threshold": initial_core_metrics,
                    "original_config_threshold_0_85": initial_core_original_cutoff_metrics,
                },
                "candidate": core_candidate_metrics,
            },
        },
        "data_manifest": data_manifest,
        "registered_domain_split_overlap": overlap,
        "feature_parity": {"identical_to_service": feature_parity, "rows_checked": len(parity_rows)},
        "validation_feature_permutation": validation_feature_permutation(
            initial_candidate, validation_rows
        ),
        "production_hashes": {"before": initial_hashes, "after": final_hashes, "unchanged": hashes_unchanged},
        "quality_checks": {
            "domain_disjoint_internal_test_counts": domain_counts(test_rows),
            "fixed_benchmark_counts": domain_counts(domain_disjoint_test_rows),
            "feature_extraction_parity": feature_parity,
            "candidate_latency": latency,
            "candidate_artifact_integrity": {
                "sha256": final_candidate_hash,
                "sha256_verified_and_reload_prediction_stable": candidate_integrity,
                "size_bytes": final_candidate_size,
            },
        },
        "acceptance_gates": gates,
        "remaining_limitations": [
            "No newly sourced independent hard-phishing benchmark was available in the repository; benchmark v1 is regression-only.",
            "The internal split is registered-domain-disjoint but has been reported in the prior experiment; treat the new result as a repeatability check, not a new independent generalization claim.",
            "Legitimate input coverage spans far fewer registered domains than the phishing feed; validation source/domain breadth limits recall/FPR conclusions.",
        ],
        "backend_and_extension_tests": {
            **test_results,
        },
    }
    write_json(run_dir / "final_evaluation.json", final)
    write_json(REPORT_DIR / "false_positive_repair_final.json", final)
    write_json(REPORT_DIR / "false_positive_repair_leaderboard.json", {
        "run_id": run_id,
        "selected_on_validation_only": incumbent_record["experiment"],
        "experiments": leaderboard,
        "stop_reason": stop_reason,
    })
    write_json(REPORT_DIR / "false_positive_repair_failure_analysis.json", final["final_internal_domain_disjoint_test"]["candidate_failure_analysis"])
    return final


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded VIGIL-AI false-positive repair experiments.")
    parser.add_argument(
        "--max-experiments",
        type=int,
        default=int(os.environ.get("VIGIL_FP_REPAIR_MAX_EXPERIMENTS", "15")),
        help="Maximum number of new controlled experiments, from 1 to 15.",
    )
    args = parser.parse_args()
    result = run(args.max_experiments)
    print(json.dumps({
        "run_id": result["run_id"],
        "experiments_completed": result["experiments_completed"],
        "stop_reason": result["stop_reason"],
        "selected_candidate": result["selected_candidate"]["name"],
        "acceptance": result["acceptance_gates"]["overall_candidate_eligible_for_promotion"],
    }, indent=2))


if __name__ == "__main__":
    main()
