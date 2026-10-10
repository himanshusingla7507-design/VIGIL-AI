"""Train a balanced, domain-disjoint experimental dynamic URL candidate."""
from __future__ import annotations

import csv
import hashlib
import json
import pickle
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.utils.class_weight import compute_sample_weight

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feature_extractor import (  # noqa: E402
    FEATURE_NAMES,
    MODEL_EXCLUDED_FEATURES,
    extract_features,
    get_registered_domain,
    normalize_url,
)
from service import _thresholds_from_metadata  # noqa: E402

SEED = 42
TEST_FRACTION = 0.20
CALIBRATION_FRACTION_OF_REMAINDER = 0.25
LEGITIMATE_PATH = ROOT / "data" / "experiments" / "legitimate_dynamic_training.csv"
PHISHING_PATH = ROOT / "data" / "external" / "phishing_database_active.txt"
FEATURE_NAMES_PATH = ROOT / "feature_names.pkl"
METADATA_PATH = ROOT / "model_metadata.json"
BASELINE_PATH = ROOT / "reports" / "baseline_dynamic_legitimate.json"
CANDIDATE_DIR = ROOT / "models" / "experimental" / "dynamic_candidate"
ARTIFACT_PATH = CANDIDATE_DIR / "dynamic_candidate.joblib"
REPORT_PATH = ROOT / "reports" / "dynamic_candidate_training.json"


def load_feature_names() -> list[str]:
    with FEATURE_NAMES_PATH.open("rb") as feature_file:
        names = list(pickle.load(feature_file))
    expected = [
        name for name in FEATURE_NAMES if name not in MODEL_EXCLUDED_FEATURES
    ]
    if len(names) != 29 or len(set(names)) != 29 or names != expected:
        raise ValueError("The saved production feature schema is not the expected 29-feature schema.")
    return names


def load_legitimate_rows() -> tuple[list[dict], int]:
    if not LEGITIMATE_PATH.is_file():
        raise FileNotFoundError(f"Legitimate dynamic cohort not found: {LEGITIMATE_PATH}")
    unique = {}
    duplicate_count = 0
    with LEGITIMATE_PATH.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        required = {"url", "label", "source"}
        if not required.issubset(reader.fieldnames or ()):
            raise ValueError(f"Cohort CSV requires columns: {sorted(required)}")
        for row in reader:
            if row["label"].strip() != "0":
                raise ValueError("Legitimate dynamic cohort must contain only label 0.")
            normalized = normalize_url(row["url"])
            if normalized in unique:
                duplicate_count += 1
                continue
            domain = get_registered_domain(normalized)
            if not domain:
                raise ValueError(f"Could not determine registered domain for {row['url']!r}")
            unique[normalized] = {
                "url": row["url"],
                "label": 0,
                "source": row["source"],
                "domain": domain,
            }
    return list(unique.values()), duplicate_count


def load_phishing_rows(legitimate_domains: set[str], target_count: int) -> tuple[list[dict], dict]:
    if not PHISHING_PATH.is_file():
        raise FileNotFoundError(f"Local phishing source not found: {PHISHING_PATH}")

    by_domain = {}
    seen_urls = set()
    duplicate_urls = 0
    invalid_urls = 0
    feed_rows = 0
    with PHISHING_PATH.open(encoding="utf-8", errors="replace") as feed_file:
        for line in feed_file:
            feed_rows += 1
            raw_url = line.strip()
            if not raw_url:
                continue
            try:
                normalized = normalize_url(raw_url)
                domain = get_registered_domain(normalized)
            except (TypeError, ValueError):
                invalid_urls += 1
                continue
            if normalized in seen_urls:
                duplicate_urls += 1
                continue
            seen_urls.add(normalized)
            if not domain or domain in legitimate_domains or domain in by_domain:
                continue
            by_domain[domain] = {
                "url": raw_url,
                "label": 1,
                "source": "phishing_database_active",
                "domain": domain,
            }

    if len(by_domain) < target_count:
        raise ValueError(
            f"Only {len(by_domain)} domain-disjoint phishing examples are available; "
            f"{target_count} are required for a balanced cohort."
        )

    selected_domains = sorted(
        by_domain,
        key=lambda domain: hashlib.sha256(
            f"{SEED}:{domain}:{by_domain[domain]['url']}".encode("utf-8")
        ).digest(),
    )[:target_count]
    selected = [by_domain[domain] for domain in selected_domains]
    feed_summary = {
        "path": str(PHISHING_PATH.relative_to(ROOT)),
        "rows_read": feed_rows,
        "invalid_rows_skipped": invalid_urls,
        "duplicate_normalized_urls_skipped": duplicate_urls,
        "unique_domain_candidates_outside_legitimate_domains": len(by_domain),
        "selected_rows": len(selected),
        "selection": "Deterministic SHA-256 ordering, one URL per registered domain, excluding all legitimate cohort domains.",
    }
    return selected, feed_summary


def make_features(rows: list[dict], feature_names: list[str]) -> pd.DataFrame:
    extracted = [extract_features(row["url"]) for row in rows]
    return pd.DataFrame(extracted, columns=FEATURE_NAMES)[feature_names]


def domain_disjoint_splits(X, y: np.ndarray, groups: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    outer_split = GroupShuffleSplit(n_splits=1, test_size=TEST_FRACTION)
    for seed_offset in range(100):
        outer_split.random_state = 44 + seed_offset
        fitcal_idx, test_idx = next(outer_split.split(X, y, groups))
        calibration_split = GroupShuffleSplit(
            n_splits=1,
            test_size=CALIBRATION_FRACTION_OF_REMAINDER,
            random_state=145 + seed_offset,
        )
        train_rel, calibration_rel = next(
            calibration_split.split(
                X.iloc[fitcal_idx], y[fitcal_idx], groups[fitcal_idx]
            )
        )
        train_idx = fitcal_idx[train_rel]
        calibration_idx = fitcal_idx[calibration_rel]
        partitions = (train_idx, calibration_idx, test_idx)
        if all(set(y[index]) == {0, 1} for index in partitions):
            domain_sets = [set(groups[index]) for index in partitions]
            if not any(
                domain_sets[left] & domain_sets[right]
                for left in range(3)
                for right in range(left + 1, 3)
            ):
                return partitions
    raise ValueError("Could not produce domain-disjoint train/calibration/test sets with both labels.")


def calibrated_probabilities(estimator, calibrator, X: pd.DataFrame) -> np.ndarray:
    raw = estimator.predict_proba(X)[:, list(estimator.classes_).index(1)]
    return calibrator.predict_proba(raw.reshape(-1, 1))[:, 1]


def classification_metrics(y_true: np.ndarray, probability: np.ndarray) -> dict:
    predicted = (probability >= 0.5).astype(int)
    return {
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probability)),
        "pr_auc": float(average_precision_score(y_true, probability)),
        "brier_score": float(brier_score_loss(y_true, probability)),
    }


def baseline_evaluation(estimator, calibrator, feature_names: list[str], thresholds: dict) -> dict:
    with BASELINE_PATH.open(encoding="utf-8") as baseline_file:
        baseline = json.load(baseline_file)
    urls = [row["url"] for row in baseline["results"]]
    rows = [{"url": url} for url in urls]
    probabilities = calibrated_probabilities(
        estimator, calibrator, make_features(rows, feature_names)
    )
    labels = []
    for probability in probabilities:
        if probability >= thresholds["phishing"]:
            labels.append("PHISHING")
        elif probability >= thresholds["safe"]:
            labels.append("SUSPICIOUS")
        else:
            labels.append("SAFE")
    return {
        "total": len(urls),
        "SAFE": labels.count("SAFE"),
        "SUSPICIOUS": labels.count("SUSPICIOUS"),
        "PHISHING": labels.count("PHISHING"),
        "maximum_legitimate_probability": float(probabilities.max()),
        "results": [
            {"url": url, "probability": float(probability), "label": label}
            for url, probability, label in zip(urls, probabilities, labels)
        ],
        "thresholds_from_unchanged_production_metadata": thresholds,
    }


def main() -> None:
    feature_names = load_feature_names()
    legitimate_rows, legitimate_duplicates = load_legitimate_rows()
    legitimate_domains = {row["domain"] for row in legitimate_rows}
    phishing_rows, feed_summary = load_phishing_rows(
        legitimate_domains, len(legitimate_rows)
    )
    rows = legitimate_rows + phishing_rows
    if len(rows) != 2 * len(legitimate_rows):
        raise RuntimeError("Experimental dataset is not balanced 1:1.")

    X = make_features(rows, feature_names)
    y = np.asarray([row["label"] for row in rows], dtype=int)
    groups = np.asarray([row["domain"] for row in rows], dtype=str)
    train_idx, calibration_idx, test_idx = domain_disjoint_splits(X, y, groups)

    estimator = HistGradientBoostingClassifier(
        learning_rate=0.05,
        max_iter=100,
        max_leaf_nodes=31,
        random_state=SEED,
    )
    train_weights = compute_sample_weight("balanced", y[train_idx])
    estimator.fit(X.iloc[train_idx], y[train_idx], sample_weight=train_weights)

    calibration_raw = estimator.predict_proba(X.iloc[calibration_idx])[:, 1]
    calibrator = LogisticRegression(
        solver="lbfgs",
        max_iter=1000,
        random_state=SEED,
    )
    calibrator.fit(calibration_raw.reshape(-1, 1), y[calibration_idx])

    test_probabilities = calibrated_probabilities(
        estimator, calibrator, X.iloc[test_idx]
    )
    metrics = classification_metrics(y[test_idx], test_probabilities)

    with METADATA_PATH.open(encoding="utf-8") as metadata_file:
        production_metadata = json.load(metadata_file)
    thresholds = _thresholds_from_metadata(production_metadata)
    baseline_metrics = baseline_evaluation(
        estimator, calibrator, feature_names, thresholds
    )

    split_indices = {
        "train": train_idx,
        "calibration": calibration_idx,
        "test": test_idx,
    }
    split_summary = {}
    for name, indices in split_indices.items():
        split_summary[name] = {
            "rows": int(len(indices)),
            "legitimate": int((y[indices] == 0).sum()),
            "phishing": int((y[indices] == 1).sum()),
            "unique_registered_domains": int(len(set(groups[indices]))),
        }
    split_domain_sets = {
        name: set(groups[indices]) for name, indices in split_indices.items()
    }
    split_overlaps = {
        f"{first}|{second}": len(split_domain_sets[first] & split_domain_sets[second])
        for first, second in (("train", "calibration"), ("train", "test"), ("calibration", "test"))
    }

    CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "estimator": estimator,
            "calibrator": calibrator,
            "feature_names": feature_names,
            "seed": SEED,
            "production_thresholds_for_reference_only": thresholds,
        },
        ARTIFACT_PATH,
    )

    unique_domains = set(groups)
    report = {
        "experiment": "dynamic_candidate",
        "production_artifacts_modified": False,
        "dataset": {
            "dataset_size": int(len(rows)),
            "legitimate_count": int((y == 0).sum()),
            "phishing_count": int((y == 1).sum()),
            "class_ratio_phishing_to_legitimate": float((y == 1).sum() / (y == 0).sum()),
            "unique_registered_domains": int(len(unique_domains)),
            "features": feature_names,
            "feature_count": len(feature_names),
            "legitimate_source": {
                "path": str(LEGITIMATE_PATH.relative_to(ROOT)),
                "selected_rows": len(legitimate_rows),
                "duplicate_normalized_urls_removed": legitimate_duplicates,
                "unique_registered_domains": len(legitimate_domains),
            },
            "phishing_source": feed_summary,
            "class_balance_policy": "1:1; select one phishing URL per registered domain outside all legitimate cohort domains.",
        },
        "split": {
            "method": "GroupShuffleSplit by registered domain; test 20%, then calibration 25% of the remaining rows.",
            "seed": 44,
            "counts": split_summary,
            "train_count": split_summary["train"]["rows"],
            "calibration_count": split_summary["calibration"]["rows"],
            "test_count": split_summary["test"]["rows"],
            "registered_domain_overlaps": split_overlaps,
        },
        "model": {
            "estimator": "HistGradientBoostingClassifier",
            "parameters": {
                "learning_rate": 0.05,
                "max_iter": 100,
                "max_leaf_nodes": 31,
                "random_state": SEED,
            },
            "calibration": {
                "method": "LogisticRegression over raw HGB probabilities on a domain-disjoint calibration partition.",
                "solver": "lbfgs",
                "max_iter": 1000,
                "random_state": SEED,
            },
            "metric_decision_threshold": 0.5,
        },
        "test_metrics": metrics,
        "baseline_legitimate_urls": baseline_metrics,
        "candidate_artifact": str(ARTIFACT_PATH.relative_to(ROOT)),
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_PATH.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)
        report_file.write("\n")

    print(f"Dataset: {report['dataset']['dataset_size']} rows; {report['dataset']['legitimate_count']} legitimate; {report['dataset']['phishing_count']} phishing")
    print(f"Domains: {report['dataset']['unique_registered_domains']}; train/calibration/test: {report['split']['train_count']}/{report['split']['calibration_count']}/{report['split']['test_count']}")
    print("Test metrics:", json.dumps(metrics, sort_keys=True))
    print(
        "Baseline legitimate URLs: "
        f"SAFE={baseline_metrics['SAFE']} "
        f"SUSPICIOUS={baseline_metrics['SUSPICIOUS']} "
        f"PHISHING={baseline_metrics['PHISHING']} "
        f"max_probability={baseline_metrics['maximum_legitimate_probability']:.6f}"
    )
    print(f"Candidate artifact: {ARTIFACT_PATH.relative_to(ROOT)}")
    print(f"Training report: {REPORT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()