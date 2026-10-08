#!/usr/bin/env python3
"""Train and evaluate VIGIL candidates with high-confidence legitimate URLs.

Run from any working directory with the repository's Python dependencies
installed:

    python train_dynamic_augmentation_experiment.py

Training inputs are read-only. Candidate artifacts are written only to
models/experiments/dynamic_augmentation/, and the final report is written to
reports/dynamic_augmentation_final.json.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import pickle
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feature_extractor import (  # noqa: E402
    FEATURE_NAMES,
    MODEL_EXCLUDED_FEATURES,
    extract_features,
    get_registered_domain,
    normalize_url,
)

DATASET_PATH = ROOT / "data" / "processed" / "clean_dataset.csv"
EXISTING_DYNAMIC_PATH = (
    ROOT / "data" / "external" / "benign_dynamic" / "legitimate_dynamic_urls.csv"
)
NEW_LEGITIMATE_PATH = ROOT / "data" / "external" / "legitimate_real_clean.csv"
EXTERNAL_VALIDATION_PATH = ROOT / "data" / "processed" / "external_validation.csv"
PRODUCTION_MODEL_PATH = ROOT / "phishing_model.pkl"
PRODUCTION_FEATURES_PATH = ROOT / "feature_names.pkl"
PRODUCTION_IMPORTANCE_PATH = ROOT / "feature_importance.csv"
EXPERIMENT_DIR = ROOT / "models" / "experiments" / "dynamic_augmentation"
REPORT_PATH = ROOT / "reports" / "dynamic_augmentation_final.json"
REGRESSION_SUITE_PATH = ROOT / "tests" / "test_pipeline.py"

SEED = 42
PHISHING_LABEL = 1
LEGITIMATE_LABEL = 0
MAX_DOMAIN_FPR = 0.02
MIN_EXTERNAL_RECALL = 0.9124
MAX_ECE = 0.05
MAX_MODEL_BYTES = 25 * 1024 * 1024
MAX_MEDIAN_LATENCY_MS = 50.0
SPLIT_FRACTIONS = {
    "train": 0.45,
    "calibration": 0.15,
    "threshold": 0.20,
    "test": 0.20,
}
FEATURE_COLUMNS = [
    name for name in FEATURE_NAMES if name not in MODEL_EXCLUDED_FEATURES
]
if len(FEATURE_COLUMNS) != 29:
    raise RuntimeError(
        f"Expected VIGIL's 29 production features, found {len(FEATURE_COLUMNS)}."
    )

GOOGLE_SEARCH_URLS = [
    "https://google.com/search?q=test",
    "https://www.google.com/search?q=cybersecurity",
]
YOUTUBE_QUERY_URLS = [
    "https://www.youtube.com/?feature=ytca",
    "https://www.youtube.com/results?search_query=music",
]
FAST_COM_URLS = [
    "https://fast.com",
    "https://fast.com/",
    "https://www.fast.com/",
]


def log(message: str) -> None:
    print(message, flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def production_hashes() -> dict[str, str]:
    paths = {
        "phishing_model.pkl": PRODUCTION_MODEL_PATH,
        "feature_names.pkl": PRODUCTION_FEATURES_PATH,
        "feature_importance.csv": PRODUCTION_IMPORTANCE_PATH,
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "Cannot verify production artifact safety; missing: " + ", ".join(missing)
        )
    return {name: sha256_file(path) for name, path in paths.items()}


def json_safe(value):
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, (np.bool_, bool)):
        return bool(value)
    if isinstance(value, Path):
        return str(value)
    return value


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".vigil-dynamic-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_csv_urls(path: Path, description: str, require_labels: bool = False) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"{description} not found: {path}")
    header = pd.read_csv(path, nrows=0)
    if "url" not in header.columns:
        raise ValueError(f"{description} must contain a 'url' column.")
    columns = ["url"]
    if require_labels:
        missing = {"label", "source"} - set(header.columns)
        if missing:
            raise ValueError(
                f"{description} missing required columns: {sorted(missing)}"
            )
        columns.extend(["label", "source"])
    elif "label" in header.columns:
        columns.append("label")
    frame = pd.read_csv(
        path,
        usecols=columns,
        dtype={"url": "string", "source": "string"},
    )
    frame = frame.dropna(subset=["url"]).copy()
    frame["url"] = frame["url"].astype(str)
    return frame


def parse_label(value) -> int:
    if isinstance(value, (int, np.integer)):
        number = int(value)
        if number in (LEGITIMATE_LABEL, PHISHING_LABEL):
            return number
    text = str(value).strip().lower()
    if text in {"0", "legitimate", "benign", "safe"}:
        return LEGITIMATE_LABEL
    if text in {"1", "phishing", "phish", "malicious"}:
        return PHISHING_LABEL
    raise ValueError(f"Unsupported clean_dataset label: {value!r}")


def registered_domain(url: str) -> str:
    domain = get_registered_domain(url)
    if not domain:
        raise ValueError(f"Could not determine registered domain for {url!r}")
    return domain.lower()


def load_and_combine_corpus() -> tuple[pd.DataFrame, dict]:
    base = read_csv_urls(DATASET_PATH, "clean_dataset.csv", require_labels=True)
    base["label"] = base["label"].map(parse_label).astype(int)
    base["source"] = base["source"].astype(str).str.strip()
    if base["source"].eq("").any():
        raise ValueError("clean_dataset.csv contains empty source values.")
    base["normalized_url"] = base["url"].map(normalize_url)
    base["source_group"] = "original"

    seen_urls = set(base["normalized_url"])
    rows = base.to_dict("records")
    added_counts = {}
    duplicate_counts = {}
    inputs = [
        (NEW_LEGITIMATE_PATH, "new_high_confidence"),
        (EXISTING_DYNAMIC_PATH, "existing_dynamic"),
    ]
    for path, source in inputs:
        additions = read_csv_urls(path, path.name)
        added = 0
        duplicates = 0
        for url in additions["url"]:
            normalized = normalize_url(url)
            if normalized in seen_urls:
                duplicates += 1
                continue
            seen_urls.add(normalized)
            rows.append(
                {
                    "url": str(url),
                    "label": LEGITIMATE_LABEL,
                    "source": source,
                    "normalized_url": normalized,
                    "source_group": source,
                }
            )
            added += 1
        added_counts[source] = added
        duplicate_counts[source] = duplicates
        log(
            f"{path.name}: {len(additions):,} loaded, {added:,} added, "
            f"{duplicates:,} duplicate normalized URLs."
        )

    corpus = pd.DataFrame.from_records(rows)
    corpus["registered_domain"] = corpus["normalized_url"].map(registered_domain)
    counts = {
        "rows_by_source": {
            str(key): int(value)
            for key, value in corpus["source"].value_counts().items()
        },
        "rows_by_label": {
            str(key): int(value)
            for key, value in corpus["label"].value_counts().items()
        },
        "augmentation_rows_added": added_counts,
        "duplicate_normalized_urls_skipped": duplicate_counts,
        "original_rows_retained": int(len(base)),
        "combined_rows": int(len(corpus)),
        "unique_normalized_urls": int(corpus["normalized_url"].nunique()),
    }
    if set(corpus["label"].unique()) != {LEGITIMATE_LABEL, PHISHING_LABEL}:
        raise ValueError("The combined training corpus must contain both classes.")
    return corpus, counts


def grouped_split(domains: pd.Series) -> np.ndarray:
    """Assign rows to the requested proportions without splitting a domain."""
    groups = domains.to_numpy()
    all_positions = np.arange(len(groups))
    split_ids = np.full(len(groups), -1, dtype=np.int8)

    first = GroupShuffleSplit(n_splits=1, test_size=0.55, random_state=SEED)
    train_pos, remainder_pos = next(
        first.split(all_positions, groups=groups)
    )
    split_ids[train_pos] = 0

    remaining_groups = groups[remainder_pos]
    calibration_share = SPLIT_FRACTIONS["calibration"] / 0.55
    second = GroupShuffleSplit(
        n_splits=1, test_size=calibration_share, random_state=SEED + 1
    )
    calibration_local, final_local = next(
        second.split(remainder_pos, groups=remaining_groups)
    )
    calibration_pos = remainder_pos[calibration_local]
    final_pos = remainder_pos[final_local]
    split_ids[calibration_pos] = 1

    final_groups = groups[final_pos]
    threshold_share = SPLIT_FRACTIONS["threshold"] / 0.40
    third = GroupShuffleSplit(
        n_splits=1, test_size=threshold_share, random_state=SEED + 2
    )
    threshold_local, test_local = next(
        third.split(final_pos, groups=final_groups)
    )
    split_ids[final_pos[threshold_local]] = 2
    split_ids[final_pos[test_local]] = 3

    if np.any(split_ids < 0):
        raise RuntimeError("Grouped splitting left rows without a split.")
    domain_sets = [
        set(domains.iloc[np.flatnonzero(split_ids == index)])
        for index in range(4)
    ]
    for left in range(4):
        for right in range(left + 1, 4):
            overlap = domain_sets[left] & domain_sets[right]
            if overlap:
                raise RuntimeError(
                    f"Registered domains leaked across splits: {sorted(overlap)[:5]}"
                )
    return split_ids


def split_summary(corpus: pd.DataFrame, split_ids: np.ndarray) -> dict:
    names = ["train", "calibration", "threshold", "test"]
    summary = {}
    for split_id, name in enumerate(names):
        part = corpus.iloc[np.flatnonzero(split_ids == split_id)]
        summary[name] = {
            "rows": int(len(part)),
            "fraction_of_rows": float(len(part) / len(corpus)),
            "registered_domains": int(part["registered_domain"].nunique()),
            "labels": {
                str(key): int(value) for key, value in part["label"].value_counts().items()
            },
            "sources": {
                str(key): int(value) for key, value in part["source"].value_counts().items()
            },
        }
    return summary


def extract_feature_matrix(urls: pd.Series | list[str], label: str) -> pd.DataFrame:
    records = []
    for index, url in enumerate(urls):
        try:
            features = extract_features(str(url))
            records.append([features[name] for name in FEATURE_COLUMNS])
        except Exception as exc:
            raise RuntimeError(
                f"Feature extraction failed for {label} row {index}: {url!r}"
            ) from exc
        if (index + 1) % 50_000 == 0:
            log(f"  extracted {index + 1:,} / {len(urls):,} {label} URLs")
    matrix = pd.DataFrame.from_records(records, columns=FEATURE_COLUMNS).astype(float)
    if len(matrix) != len(urls):
        raise RuntimeError(f"Feature row count mismatch for {label}.")
    return matrix


def build_estimators() -> dict:
    return {
        "logistic_regression": Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight=None,
                        random_state=SEED,
                        solver="lbfgs",
                    ),
                ),
            ]
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            learning_rate=0.08,
            max_iter=400,
            max_leaf_nodes=63,
            min_samples_leaf=30,
            l2_regularization=1.0,
            early_stopping=False,
            random_state=SEED,
        ),
    }


def source_aware_weights(train: pd.DataFrame) -> tuple[np.ndarray, dict]:
    """Cap each augmented source's total training weight at half the phishing weight."""
    phishing_rows = int(train["label"].eq(PHISHING_LABEL).sum())
    if not phishing_rows:
        raise ValueError("Training split contains no phishing examples.")
    weights = np.ones(len(train), dtype=float)
    report = {}
    for source in ("new_high_confidence", "existing_dynamic"):
        positions = np.flatnonzero(train["source_group"].eq(source).to_numpy())
        count = len(positions)
        if count:
            per_row_weight = min(1.0, (0.5 * phishing_rows) / count)
            weights[positions] = per_row_weight
        else:
            per_row_weight = 0.0
        report[source] = {
            "training_rows": int(count),
            "per_row_weight": float(per_row_weight),
            "effective_weight": float(weights[positions].sum()),
            "maximum_effective_weight": float(0.5 * phishing_rows),
        }
    report["phishing_training_rows"] = phishing_rows
    report["phishing_effective_weight"] = float(
        weights[train["label"].eq(PHISHING_LABEL).to_numpy()].sum()
    )
    report["combined_augmentation_effective_weight"] = float(
        sum(report[source]["effective_weight"] for source in (
            "new_high_confidence", "existing_dynamic"
        ))
    )
    return weights, report


def raw_positive_probability(estimator, matrix: pd.DataFrame) -> np.ndarray:
    classes = list(estimator.classes_)
    positive_index = classes.index(PHISHING_LABEL)
    return estimator.predict_proba(matrix)[:, positive_index].astype(float)


def fit_calibrator(raw: np.ndarray, labels: np.ndarray) -> LogisticRegression:
    if len(np.unique(labels)) != 2:
        raise ValueError("Calibration split must contain both classes.")
    calibrator = LogisticRegression(
        max_iter=2000, random_state=SEED, solver="lbfgs"
    )
    calibrator.fit(raw.reshape(-1, 1), labels)
    return calibrator


def calibrated_probability(
    estimator, calibrator: LogisticRegression, matrix: pd.DataFrame
) -> np.ndarray:
    raw = raw_positive_probability(estimator, matrix)
    return calibrator.predict_proba(raw.reshape(-1, 1))[:, 1]


def expected_calibration_error(labels: np.ndarray, probabilities: np.ndarray) -> float:
    edges = np.linspace(0.0, 1.0, 11)
    error = 0.0
    for index in range(len(edges) - 1):
        if index == len(edges) - 2:
            mask = (probabilities >= edges[index]) & (probabilities <= edges[index + 1])
        else:
            mask = (probabilities >= edges[index]) & (probabilities < edges[index + 1])
        if mask.any():
            error += float(mask.mean()) * abs(
                float(probabilities[mask].mean()) - float(labels[mask].mean())
            )
    return float(error)


def domain_false_positive_rate(
    labels: np.ndarray, probabilities: np.ndarray, domains: pd.Series, threshold: float
) -> tuple[float, float]:
    legitimate = labels == LEGITIMATE_LABEL
    if not legitimate.any():
        return 0.0, 0.0
    url_fpr = float(np.mean(probabilities[legitimate] >= threshold))
    frame = pd.DataFrame(
        {
            "domain": domains.to_numpy()[legitimate],
            "positive": probabilities[legitimate] >= threshold,
        }
    )
    domain_fpr = float(frame.groupby("domain", sort=False)["positive"].max().mean())
    return url_fpr, domain_fpr


def select_threshold(
    labels: np.ndarray, probabilities: np.ndarray, domains: pd.Series
) -> dict:
    legitimate = labels == LEGITIMATE_LABEL
    phishing = labels == PHISHING_LABEL
    if not legitimate.any() or not phishing.any():
        raise ValueError("Threshold split must contain both classes.")
    per_domain_max = (
        pd.DataFrame(
            {
                "domain": domains.to_numpy()[legitimate],
                "probability": probabilities[legitimate],
            }
        )
        .groupby("domain", sort=False)["probability"]
        .max()
        .to_numpy()
    )
    candidates = np.unique(
        np.concatenate(
            [
                probabilities[phishing],
                per_domain_max,
                np.array([np.nextafter(1.0, 2.0)]),
            ]
        )
    )
    best = None
    for threshold in candidates:
        domain_fpr = float(np.mean(per_domain_max >= threshold))
        if domain_fpr > MAX_DOMAIN_FPR:
            continue
        recall = float(np.mean(probabilities[phishing] >= threshold))
        url_fpr = float(np.mean(probabilities[legitimate] >= threshold))
        candidate = (recall, threshold, -url_fpr, float(threshold), domain_fpr, url_fpr)
        if best is None or candidate[:3] > best[:3]:
            best = candidate
    if best is None:
        raise RuntimeError("No threshold satisfies the 2% domain FPR constraint.")
    return {
        "phishing_threshold": best[3],
        "threshold_split_phishing_recall": best[0],
        "threshold_split_domain_fpr": best[4],
        "threshold_split_url_fpr": best[5],
        "domain_fpr_limit": MAX_DOMAIN_FPR,
        "selection_rule": "maximum phishing recall with registered-domain FPR <= 2%",
    }


def cohort_metrics(
    labels: np.ndarray, probabilities: np.ndarray, threshold: float
) -> dict:
    predicted = probabilities >= threshold
    tp = int(np.sum((labels == PHISHING_LABEL) & predicted))
    fn = int(np.sum((labels == PHISHING_LABEL) & ~predicted))
    fp = int(np.sum((labels == LEGITIMATE_LABEL) & predicted))
    tn = int(np.sum((labels == LEGITIMATE_LABEL) & ~predicted))
    phishing_count = tp + fn
    legitimate_count = fp + tn
    return {
        "rows": int(len(labels)),
        "phishing_recall": float(tp / phishing_count) if phishing_count else None,
        "fnr": float(fn / phishing_count) if phishing_count else None,
        "url_fpr": float(fp / legitimate_count) if legitimate_count else None,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
    }


def full_metrics(
    labels: np.ndarray,
    probabilities: np.ndarray,
    domains: pd.Series,
    threshold: float,
) -> dict:
    result = cohort_metrics(labels, probabilities, threshold)
    url_fpr, domain_fpr = domain_false_positive_rate(
        labels, probabilities, domains, threshold
    )
    result["domain_fpr"] = domain_fpr
    result["url_fpr"] = url_fpr
    result["ece"] = expected_calibration_error(labels, probabilities)
    if len(np.unique(labels)) == 2:
        result["pr_auc"] = float(average_precision_score(labels, probabilities))
        result["roc_auc"] = float(roc_auc_score(labels, probabilities))
    else:
        result["pr_auc"] = None
        result["roc_auc"] = None
    return result


def phishing_cohorts(
    urls: pd.Series,
    features: pd.DataFrame,
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> dict:
    parsed = [urlsplit(normalize_url(url)) for url in urls]
    path_depth = np.array(
        [len([part for part in item.path.split("/") if part]) for item in parsed]
    )
    url_length = features["URLLength"].to_numpy()
    masks = {
        "pathless": path_depth == 0,
        "short": url_length <= 75,
        "no_suspicious_tld": features["HasSuspiciousTLD"].to_numpy() == 0,
        "no_suspicious_tokens": features["HasSuspiciousToken"].to_numpy() == 0,
        "query": np.array([bool(item.query) for item in parsed]),
        "long": url_length > 120,
        "ip_host": features["IsDomainIP"].to_numpy() > 0,
        "encoded": features["URLPercentEncodingCount"].to_numpy() > 0,
        "deep_path": path_depth >= 4,
    }
    result = {}
    for name, mask in masks.items():
        mask &= labels == PHISHING_LABEL
        result[name] = cohort_metrics(labels[mask], probabilities[mask], threshold)
    return result


def dynamic_benign_metrics(
    urls: pd.Series, probabilities: np.ndarray, threshold: float
) -> dict:
    parsed = [urlsplit(normalize_url(url)) for url in urls]
    features = extract_feature_matrix(urls, "dynamic-benign holdout")
    tracking_names = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "gclid", "dclid", "fbclid", "msclkid", "yclid", "mc_cid", "mc_eid",
        "ref", "ref_src",
    }
    query_parameters = [
        set(parse_qs(item.query, keep_blank_values=True)) for item in parsed
    ]
    masks = {
        "overall": np.ones(len(urls), dtype=bool),
        "query": np.array([bool(item.query) for item in parsed]),
        "multi_path": np.array(
            [sum(bool(part) for part in item.path.split("/")) >= 2 for item in parsed]
        ),
        "fragment": np.array([bool(item.fragment) for item in parsed]),
        "long_gt_120": features["URLLength"].to_numpy() > 120,
        "gt_200": features["URLLength"].to_numpy() > 200,
        "encoded": features["URLPercentEncodingCount"].to_numpy() > 0,
        "tracking": np.array(
            [bool({name.lower() for name in names} & tracking_names) for names in query_parameters]
        ),
    }
    result = {}
    predicted = probabilities >= threshold
    for name, mask in masks.items():
        result[name] = {
            "rows": int(mask.sum()),
            "fpr": float(predicted[mask].mean()) if mask.any() else None,
        }
    return result


def save_candidate(name: str, estimator, calibrator, threshold: dict) -> dict:
    model_path = EXPERIMENT_DIR / f"{name}_estimator.pkl"
    calibrator_path = EXPERIMENT_DIR / f"{name}_calibrator.pkl"
    features_path = EXPERIMENT_DIR / f"{name}_feature_names.pkl"
    threshold_path = EXPERIMENT_DIR / f"{name}_threshold.json"
    items = {
        model_path: pickle.dumps(estimator, protocol=pickle.HIGHEST_PROTOCOL),
        calibrator_path: pickle.dumps(calibrator, protocol=pickle.HIGHEST_PROTOCOL),
        features_path: pickle.dumps(FEATURE_COLUMNS, protocol=pickle.HIGHEST_PROTOCOL),
        threshold_path: json.dumps(json_safe(threshold), indent=2).encode("utf-8"),
    }
    for path, payload in items.items():
        if EXPERIMENT_DIR.resolve() not in path.resolve().parents:
            raise RuntimeError(f"Refusing to write candidate outside experiment dir: {path}")
        atomic_write(path, payload)
    size = sum(len(payload) for path, payload in items.items() if path != threshold_path)
    return {
        "artifact_paths": {path.name: str(path.relative_to(ROOT)) for path in items},
        "model_size_bytes": int(size),
        "model_size_mib": float(size / (1024 * 1024)),
    }


def measure_latency(estimator, calibrator, sample: pd.DataFrame) -> float:
    row = sample.iloc[[0]]
    if calibrator is None:
        raw_positive_probability(estimator, row)
    else:
        calibrated_probability(estimator, calibrator, row)
    durations = []
    for _ in range(101):
        started = time.perf_counter()
        if calibrator is None:
            raw_positive_probability(estimator, row)
        else:
            calibrated_probability(estimator, calibrator, row)
        durations.append((time.perf_counter() - started) * 1000.0)
    return float(np.median(durations))


def run_regression_suite() -> dict:
    if not REGRESSION_SUITE_PATH.is_file():
        raise FileNotFoundError(f"Existing regression suite not found: {REGRESSION_SUITE_PATH}")
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "command": "python -m pytest -q",
        "returncode": int(completed.returncode),
        "passed": completed.returncode == 0,
        "stdout_tail": completed.stdout[-12000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def reference_regression(
    estimator,
    calibrator,
    threshold: float,
    production_model,
    production_features: list[str],
    production_threshold: float,
) -> dict:
    urls = GOOGLE_SEARCH_URLS + YOUTUBE_QUERY_URLS + FAST_COM_URLS
    matrix = extract_feature_matrix(urls, "regression references")
    candidate_scores = calibrated_probability(estimator, calibrator, matrix)
    production_matrix = matrix.reindex(columns=production_features)
    production_scores = raw_positive_probability(production_model, production_matrix)
    result = {}
    for start, end, category in (
        (0, len(GOOGLE_SEARCH_URLS), "google_search"),
        (
            len(GOOGLE_SEARCH_URLS),
            len(GOOGLE_SEARCH_URLS) + len(YOUTUBE_QUERY_URLS),
            "youtube_query",
        ),
        (
            len(GOOGLE_SEARCH_URLS) + len(YOUTUBE_QUERY_URLS),
            len(urls),
            "fast_com",
        ),
    ):
        result[category] = {
            "urls": urls[start:end],
            "candidate": [
                {
                    "probability": float(candidate_scores[index]),
                    "phishing": bool(candidate_scores[index] >= threshold),
                }
                for index in range(start, end)
            ],
            "production": [
                {
                    "probability": float(production_scores[index]),
                    "phishing": bool(production_scores[index] >= production_threshold),
                }
                for index in range(start, end)
            ],
        }
    return result


def load_external_validation() -> pd.DataFrame:
    frame = read_csv_urls(EXTERNAL_VALIDATION_PATH, "external_validation.csv")
    if "label" in frame.columns:
        labels = frame["label"].map(parse_label).astype(int)
        if not labels.eq(PHISHING_LABEL).all():
            raise ValueError("external_validation.csv must be phishing-only.")
        frame["label"] = labels
    else:
        frame["label"] = PHISHING_LABEL
    frame["normalized_url"] = frame["url"].map(normalize_url)
    frame["registered_domain"] = frame["normalized_url"].map(registered_domain)
    return frame


def production_threshold(metadata: dict) -> float:
    thresholds = metadata.get("thresholds", {})
    value = thresholds.get("phishing", 0.85)
    threshold = float(value)
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError(f"Invalid production phishing threshold: {value!r}")
    return threshold


def evaluate_production_model(
    production_model,
    production_features: list[str],
    matrix: pd.DataFrame,
    labels: np.ndarray,
    domains: pd.Series,
    threshold: float,
) -> dict:
    scores = raw_positive_probability(
        production_model, matrix.reindex(columns=production_features)
    )
    return full_metrics(labels, scores, domains, threshold), scores


def print_comparison(rows: list[dict]) -> None:
    columns = [
        ("MODEL", "model"),
        ("DOMAIN RECALL", "domain_recall"),
        ("DOMAIN FPR", "domain_fpr"),
        ("EXTERNAL RECALL", "external_recall"),
        ("DYNAMIC BENIGN FPR", "dynamic_benign_fpr"),
        ("LONG URL FPR", "long_url_fpr"),
        ("QUERY FPR", "query_fpr"),
        ("FRAGMENT FPR", "fragment_fpr"),
        ("ECE", "ece"),
        ("MODEL SIZE", "model_size"),
        ("MEDIAN LATENCY", "median_latency"),
    ]
    widths = [max(16, len(title)) for title, _ in columns]
    print("\n" + " | ".join(title.ljust(width) for (title, _), width in zip(columns, widths)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        values = []
        for _, key in columns:
            value = row.get(key)
            if key == "model":
                text = str(value)
            elif value is None:
                text = "N/A"
            elif key in {"model_size"}:
                text = f"{value:.2f} MiB"
            elif key in {"median_latency"}:
                text = f"{value:.3f} ms"
            else:
                text = f"{value:.4f}"
            values.append(text)
        print(" | ".join(value.ljust(width) for value, width in zip(values, widths)))


def main() -> dict:
    hashes_before = production_hashes()
    EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)

    corpus, corpus_report = load_and_combine_corpus()
    split_ids = grouped_split(corpus["registered_domain"])
    splits_report = split_summary(corpus, split_ids)
    positions = {
        name: np.flatnonzero(split_ids == index)
        for index, name in enumerate(("train", "calibration", "threshold", "test"))
    }
    train = corpus.iloc[positions["train"]].reset_index(drop=True)
    calibration = corpus.iloc[positions["calibration"]].reset_index(drop=True)
    threshold_frame = corpus.iloc[positions["threshold"]].reset_index(drop=True)
    test = corpus.iloc[positions["test"]].reset_index(drop=True)

    log("Extracting training features...")
    X_train = extract_feature_matrix(train["url"], "train")
    X_calibration = extract_feature_matrix(calibration["url"], "calibration")
    X_threshold = extract_feature_matrix(threshold_frame["url"], "threshold")
    weights, weights_report = source_aware_weights(train)
    estimators = build_estimators()
    candidates = {}

    for name, estimator in estimators.items():
        log(f"Fitting {name}...")
        y_train = train["label"].to_numpy(dtype=int)
        if name == "logistic_regression":
            estimator.fit(
                X_train,
                y_train,
                classifier__sample_weight=weights,
            )
        else:
            estimator.fit(X_train, y_train, sample_weight=weights)

        calibration_raw = raw_positive_probability(estimator, X_calibration)
        calibrator = fit_calibrator(
            calibration_raw, calibration["label"].to_numpy(dtype=int)
        )
        threshold_scores = calibrator.predict_proba(
            raw_positive_probability(estimator, X_threshold).reshape(-1, 1)
        )[:, 1]
        threshold = select_threshold(
            threshold_frame["label"].to_numpy(dtype=int),
            threshold_scores,
            threshold_frame["registered_domain"],
        )
        artifacts = save_candidate(name, estimator, calibrator, threshold)
        candidates[name] = {
            "estimator": estimator,
            "calibrator": calibrator,
            "threshold": threshold,
            "artifacts": artifacts,
            "threshold_scores": threshold_scores,
        }
        log(
            f"  selected threshold={threshold['phishing_threshold']:.6f}; "
            f"threshold phishing recall="
            f"{threshold['threshold_split_phishing_recall']:.4f}; "
            f"domain FPR={threshold['threshold_split_domain_fpr']:.4f}"
        )

    # Freeze model and threshold selection using only the threshold split.
    selected_name = max(
        candidates,
        key=lambda name: (
            candidates[name]["threshold"]["threshold_split_phishing_recall"],
            -candidates[name]["threshold"]["threshold_split_domain_fpr"],
            name == "hist_gradient_boosting",
        ),
    )
    selected = candidates[selected_name]

    # The external holdout is loaded only after estimators, calibrators,
    # thresholds, candidate files, and model selection are frozen.
    log("Candidate and threshold decisions frozen; opening external validation.")
    external = load_external_validation()
    X_external = extract_feature_matrix(external["url"], "external validation")
    external_labels = external["label"].to_numpy(dtype=int)
    selected_external_scores = calibrated_probability(
        selected["estimator"], selected["calibrator"], X_external
    )
    selected_external = cohort_metrics(
        external_labels,
        selected_external_scores,
        selected["threshold"]["phishing_threshold"],
    )
    production_model, production_features, metadata = __import__(
        "service"
    ).load_model_bundle()
    production_features = list(production_features)
    if production_features != FEATURE_COLUMNS:
        raise RuntimeError(
            "Production feature order differs from the 29-feature experiment pipeline."
        )
    prod_threshold = production_threshold(metadata)
    production_external, production_external_scores = evaluate_production_model(
        production_model,
        production_features,
        X_external,
        external_labels,
        external["registered_domain"],
        prod_threshold,
    )
    selected_external["recall"] = selected_external["phishing_recall"]
    selected_external["rows"] = int(len(external))
    selected_external["production_recall"] = production_external["phishing_recall"]
    selected_external["production_rows"] = int(len(external))

    log("Evaluating the domain-disjoint test split...")
    X_test = extract_feature_matrix(test["url"], "test")
    test_labels = test["label"].to_numpy(dtype=int)
    test_domains = test["registered_domain"]
    test_results = {}
    for name, candidate in candidates.items():
        scores = calibrated_probability(
            candidate["estimator"], candidate["calibrator"], X_test
        )
        threshold = candidate["threshold"]["phishing_threshold"]
        test_results[name] = full_metrics(test_labels, scores, test_domains, threshold)
        test_results[name]["phishing_cohorts"] = phishing_cohorts(
            test["url"], X_test, test_labels, scores, threshold
        )
        candidate["test_scores"] = scores
    selected_test = test_results[selected_name]

    dynamic_mask = (
        test["source_group"].isin(("new_high_confidence", "existing_dynamic")).to_numpy()
        & test["label"].eq(LEGITIMATE_LABEL).to_numpy()
    )
    if not dynamic_mask.any():
        raise RuntimeError("No dynamic legitimate URLs landed in the domain test holdout.")
    dynamic_urls = test.loc[dynamic_mask, "url"].reset_index(drop=True)
    dynamic_domains = set(test.loc[dynamic_mask, "registered_domain"])
    for name in ("train", "calibration", "threshold"):
        split_domains = set(
            corpus.loc[split_ids == ("train", "calibration", "threshold", "test").index(name),
                       "registered_domain"]
        )
        if dynamic_domains & split_domains:
            raise RuntimeError(f"Dynamic holdout domains leaked into {name} split.")
    selected_dynamic_scores = selected["test_scores"][dynamic_mask]
    selected_dynamic = dynamic_benign_metrics(
        dynamic_urls,
        selected_dynamic_scores,
        selected["threshold"]["phishing_threshold"],
    )

    # Compare production on the exact same test and dynamic-benign URLs.
    production_test, production_test_scores = evaluate_production_model(
        production_model,
        production_features,
        X_test,
        test_labels,
        test_domains,
        prod_threshold,
    )
    production_dynamic = dynamic_benign_metrics(
        dynamic_urls,
        production_test_scores[dynamic_mask],
        prod_threshold,
    )

    regression = reference_regression(
        selected["estimator"],
        selected["calibrator"],
        selected["threshold"]["phishing_threshold"],
        production_model,
        production_features,
        prod_threshold,
    )
    regression_suite = run_regression_suite()

    for candidate in candidates.values():
        candidate["median_latency_ms"] = measure_latency(
            candidate["estimator"], candidate["calibrator"], X_test
        )
    selected_latency = selected["median_latency_ms"]
    production_latency = measure_latency(
        production_model, None, X_test.reindex(columns=production_features)
    )

    # Production-model latency uses its direct predict_proba path.
    # The candidate model size includes its serialized estimator and calibrator.
    candidate_summary = {
        "model": selected_name,
        "domain_recall": selected_test["phishing_recall"],
        "domain_fpr": selected_test["domain_fpr"],
        "external_recall": selected_external["phishing_recall"],
        "dynamic_benign_fpr": selected_dynamic["overall"]["fpr"],
        "long_url_fpr": selected_dynamic["long_gt_120"]["fpr"],
        "query_fpr": selected_dynamic["query"]["fpr"],
        "fragment_fpr": selected_dynamic["fragment"]["fpr"],
        "ece": selected_test["ece"],
        "model_size": selected["artifacts"]["model_size_mib"],
        "median_latency": selected_latency,
    }
    production_summary = {
        "model": "current_production",
        "domain_recall": production_test["phishing_recall"],
        "domain_fpr": production_test["domain_fpr"],
        "external_recall": production_external["phishing_recall"],
        "dynamic_benign_fpr": production_dynamic["overall"]["fpr"],
        "long_url_fpr": production_dynamic["long_gt_120"]["fpr"],
        "query_fpr": production_dynamic["query"]["fpr"],
        "fragment_fpr": production_dynamic["fragment"]["fpr"],
        "ece": production_test["ece"],
        "model_size": sum(
            path.stat().st_size
            for path in (PRODUCTION_MODEL_PATH, PRODUCTION_FEATURES_PATH)
        ) / (1024 * 1024),
        "median_latency": production_latency,
    }

    reference_passed = all(
        not item["phishing"]
        for group in regression.values()
        for item in group["candidate"]
    )
    gates = {
        "external_recall_at_least_91_24_percent": bool(
            selected_external["phishing_recall"] >= MIN_EXTERNAL_RECALL
        ),
        "test_domain_fpr_at_most_2_percent": bool(
            selected_test["domain_fpr"] <= MAX_DOMAIN_FPR
        ),
        "test_ece_at_most_0_05": bool(selected_test["ece"] <= MAX_ECE),
        "dynamic_benign_fpr_improved_vs_production": bool(
            selected_dynamic["overall"]["fpr"] < production_dynamic["overall"]["fpr"]
        ),
        "google_youtube_fast_com_not_phishing": bool(reference_passed),
        "existing_regression_suite_passed": bool(regression_suite["passed"]),
        "model_size_at_most_25_mib": bool(
            selected["artifacts"]["model_size_bytes"] <= MAX_MODEL_BYTES
        ),
        "median_latency_at_most_50_ms": bool(
            selected_latency <= MAX_MEDIAN_LATENCY_MS
        ),
    }

    hashes_after = production_hashes()
    hashes_unchanged = hashes_before == hashes_after
    if not hashes_unchanged:
        raise RuntimeError(
            "Production artifact hash changed during the experiment: "
            f"before={hashes_before}, after={hashes_after}"
        )
    gates["production_hashes_unchanged"] = hashes_unchanged
    decision = "PROMOTE CANDIDATE" if all(gates.values()) else "DO NOT PROMOTE"

    # Strip in-memory estimator objects and large probability vectors before
    # serialization; only candidate artifacts and metrics are persisted.
    candidate_reports = {}
    for name, candidate in candidates.items():
        candidate_reports[name] = {
            "threshold": candidate["threshold"],
            "test": test_results[name],
            "artifacts": candidate["artifacts"],
            "test_median_latency_ms": candidate["median_latency_ms"],
        }
    report = {
        "experiment": "dynamic_augmentation",
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "decision": decision,
        "selected_candidate": selected_name,
        "inputs": {
            "training": str(DATASET_PATH.relative_to(ROOT)),
            "existing_dynamic_legitimate": str(EXISTING_DYNAMIC_PATH.relative_to(ROOT)),
            "new_high_confidence_legitimate": str(NEW_LEGITIMATE_PATH.relative_to(ROOT)),
            "frozen_external_validation": str(EXTERNAL_VALIDATION_PATH.relative_to(ROOT)),
        },
        "corpus": corpus_report,
        "domain_grouped_splits": splits_report,
        "source_aware_training_weights": weights_report,
        "models": candidate_reports,
        "selected_candidate_domain_test": selected_test,
        "selected_candidate_dynamic_benign_holdout": {
            "rows": int(dynamic_mask.sum()),
            "registered_domains": int(len(dynamic_domains)),
            "domain_disjoint_from_training_calibration_and_threshold": True,
            "metrics": selected_dynamic,
        },
        "production_dynamic_benign_holdout": production_dynamic,
        "external_validation": {
            "rows": int(len(external)),
            "phishing_rows": int(external_labels.sum()),
            "candidate": selected_external,
            "production": production_external,
            "tuning_performed": False,
        },
        "regression_references": regression,
        "existing_regression_suite": regression_suite,
        "comparison": {
            "candidate": candidate_summary,
            "production": production_summary,
        },
        "promotion_gates": gates,
        "production_artifact_hashes": {
            "before": hashes_before,
            "after": hashes_after,
            "identical": hashes_unchanged,
        },
        "safety": {
            "input_data_modified": False,
            "production_artifacts_modified": False,
            "candidate_artifacts_directory": str(EXPERIMENT_DIR.relative_to(ROOT)),
            "domain_exceptions_created": False,
        },
    }
    atomic_write(
        REPORT_PATH,
        json.dumps(json_safe(report), indent=2, allow_nan=False).encode("utf-8"),
    )
    print_comparison([candidate_summary, production_summary])
    log(f"\nFINAL DECISION: {decision}")
    log(f"Report: {REPORT_PATH}")
    return json_safe(report)


if __name__ == "__main__":
    main()

