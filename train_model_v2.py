"""Train an isolated, domain-split experimental VIGIL phishing classifier."""
from __future__ import annotations

import hashlib
import json
import pickle
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
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
from sklearn.model_selection import GroupShuffleSplit

from config import MODEL_VERSION
from feature_extractor import extract_features, get_registered_domain, normalize_url
from service import _thresholds_from_metadata, load_model_bundle

ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "processed" / "clean_dataset.csv"
PRODUCTION_FEATURES_PATH = ROOT / "feature_names.pkl"
PRODUCTION_METADATA_PATH = ROOT / "model_metadata.json"
EXPERIMENT_DIR = (
    ROOT / "models" / "experimental" / "train_model_v2"
    / "repair_source_balanced_natural_calibration"
)
REPORT_PATH = ROOT / "reports" / "train_model_v2_repair_v2.json"
OPTIONAL_LEGITIMATE_PATHS = {
    "legitimate_dynamic_training": ROOT / "data" / "experiments" / "legitimate_dynamic_training.csv",
    "legitimate_dynamic_benchmark": ROOT / "data" / "experiments" / "legitimate_dynamic_benchmark.csv",
    "legitimate_training_v3": ROOT / "data" / "experiments" / "legitimate_training_v3.csv",
    "external_benign_dynamic": ROOT / "data" / "external" / "benign_dynamic" / "legitimate_dynamic_urls.csv",
}
PROTECTED_PATHS = (
    ROOT / "phishing_model.pkl",
    PRODUCTION_FEATURES_PATH,
    PRODUCTION_METADATA_PATH,
    ROOT / "feature_extractor.py",
    ROOT / "service.py",
    ROOT / "config.py",
)
SEED = 44
MODEL_THRESHOLD = 0.5
REQUIRED_DATA_COLUMNS = {"url", "label", "source", "collection_date"}
LABELS = {0, 1}
REGRESSION_DATASETS = {
    "legitimate_dynamic_training",
    "legitimate_dynamic_benchmark",
    "legitimate_training_v3",
    "external_benign_dynamic",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def protected_hashes() -> dict[str, str]:
    missing = [str(path) for path in PROTECTED_PATHS if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Required production files are missing: {missing}")
    return {path.name: sha256_file(path) for path in PROTECTED_PATHS}


def production_feature_contract() -> tuple[list[str], dict, dict[str, float]]:
    model, feature_names, metadata = load_model_bundle()
    if not feature_names or len(feature_names) != len(set(feature_names)):
        raise ValueError("Production feature_names.pkl is empty or has duplicates.")
    if metadata.get("features") != feature_names:
        raise ValueError("Production metadata feature order differs from feature_names.pkl.")
    if metadata.get("feature_count") != len(feature_names):
        raise ValueError("Production metadata feature_count does not match feature_names.pkl.")
    model_features = getattr(model, "n_features_in_", None)
    if model_features != len(feature_names):
        raise ValueError(
            f"Production estimator expects {model_features} features; "
            f"feature_names.pkl contains {len(feature_names)}."
        )
    sample = extract_features("https://example.org/path?q=one")
    missing = [name for name in feature_names if name not in sample]
    if missing:
        raise ValueError(f"Production feature extractor lacks model features: {missing}")
    return feature_names, metadata, _thresholds_from_metadata(metadata)


def validate_labels(frame: pd.DataFrame, source: str) -> dict[str, int]:
    if "label" not in frame.columns:
        raise ValueError(f"{source}: required 'label' column is missing.")
    if frame["label"].isna().any():
        raise ValueError(f"{source}: null labels are not allowed.")
    try:
        numeric = pd.to_numeric(frame["label"], errors="raise")
    except (TypeError, ValueError) as error:
        raise ValueError(f"{source}: labels must be numeric 0/1.") from error
    if not np.all(np.equal(numeric.to_numpy(), np.floor(numeric.to_numpy()))):
        raise ValueError(f"{source}: labels must be integer 0/1.")
    labels = set(numeric.astype(int).unique())
    if not labels.issubset(LABELS):
        raise ValueError(f"{source}: unsupported labels {sorted(labels - LABELS)}.")
    frame["label"] = numeric.astype(int)
    return {str(label): int(count) for label, count in frame["label"].value_counts().sort_index().items()}


def normalize_and_validate_urls(frame: pd.DataFrame, source: str) -> tuple[pd.DataFrame, dict]:
    if "url" not in frame.columns:
        raise ValueError(f"{source}: required 'url' column is missing.")
    if frame["url"].isna().any():
        raise ValueError(f"{source}: contains {int(frame['url'].isna().sum())} null URLs.")
    normalized = []
    invalid = []
    for index, value in frame["url"].items():
        try:
            normalized.append(normalize_url(value))
        except (TypeError, ValueError) as error:
            invalid.append({"row": int(index), "error": str(error)})
            normalized.append("")
    if invalid:
        raise ValueError(
            f"{source}: {len(invalid)} URLs failed project normalization; "
            f"first failures: {invalid[:5]}"
        )
    result = frame.copy()
    result["normalized_url"] = normalized
    result["registered_domain"] = result["normalized_url"].map(get_registered_domain)
    duplicate_mask = result["normalized_url"].duplicated(keep=False)
    conflicting = (
        result.loc[duplicate_mask]
        .groupby("normalized_url", sort=False)["label"]
        .nunique()
    )
    if not conflicting.empty and (conflicting > 1).any():
        examples = conflicting[conflicting > 1].index[:5].tolist()
        raise ValueError(f"{source}: conflicting labels for normalized URL(s): {examples}")
    duplicates_removed = int(result["normalized_url"].duplicated().sum())
    result = result.drop_duplicates("normalized_url", keep="first").reset_index(drop=True)
    return result, {
        "rows_before": int(len(frame)),
        "rows_after": int(len(result)),
        "invalid_urls": 0,
        "normalized_duplicate_rows_removed": duplicates_removed,
        "registered_domains": int(result["registered_domain"].nunique()),
    }


def load_primary_dataset() -> tuple[pd.DataFrame, dict]:
    if not DATASET_PATH.is_file():
        raise FileNotFoundError(f"Required training dataset not found: {DATASET_PATH}")
    frame = pd.read_csv(DATASET_PATH)
    missing = sorted(REQUIRED_DATA_COLUMNS - set(frame.columns))
    if missing:
        raise ValueError(f"{DATASET_PATH.name}: required columns missing: {missing}")
    label_counts_before_deduplication = validate_labels(frame, DATASET_PATH.name)
    expected_sources = {"PhiUSIIL", "phishing_database_active"}
    actual_sources = set(frame["source"].dropna().astype(str))
    if frame["source"].isna().any() or actual_sources != expected_sources:
        raise ValueError(
            f"{DATASET_PATH.name}: source values do not match the audited dataset; "
            f"expected both {sorted(expected_sources)}, found {sorted(actual_sources)}."
        )
    source_labels = {
        str(source): set(group["label"].unique())
        for source, group in frame.groupby("source", dropna=False)
    }
    if source_labels.get("phishing_database_active") != {1}:
        raise ValueError("phishing_database_active must contain only VIGIL label 1.")
    if source_labels.get("PhiUSIIL") != {0, 1}:
        raise ValueError("PhiUSIIL must contain both audited VIGIL labels 0 and 1.")
    original_rows = len(frame)
    frame, url_audit = normalize_and_validate_urls(frame, DATASET_PATH.name)
    source_counts = {
        str(source): {
            str(label): int(count)
            for label, count in group["label"].value_counts().sort_index().items()
        }
        for source, group in frame.groupby("source", dropna=False)
    }
    domain_label_counts = frame.groupby("registered_domain")["label"].nunique()
    date_missing = int(frame["collection_date"].isna().sum())
    return frame, {
        "path": str(DATASET_PATH.relative_to(ROOT)),
        "sha256": sha256_file(DATASET_PATH),
        "rows_before_deduplication": original_rows,
        **url_audit,
        "label_counts_before_deduplication": label_counts_before_deduplication,
        "label_counts_after_deduplication": {
            str(key): int(value)
            for key, value in frame["label"].value_counts().sort_index().items()
        },
        "source_label_counts_after_deduplication": source_counts,
        "missing_collection_date_rows": date_missing,
        "collection_date_note": (
            "All dates are missing; the dataset summary confirms dates were not supplied "
            "by either source."
            if date_missing == len(frame)
            else f"{date_missing} rows have no collection date."
        ),
        "domains_with_both_labels": int((domain_label_counts > 1).sum()),
        "domains_with_single_label": int((domain_label_counts == 1).sum()),
        "domain_label_conflicts": (
            "Retained and reported. All rows for a registered domain are assigned to "
            "exactly one split; the conflict may reflect distinct benign and malicious "
            "URLs on the same domain or source-label noise."
        ),
    }


def inspect_optional_datasets() -> tuple[dict[str, dict], dict[str, pd.DataFrame]]:
    audits: dict[str, dict] = {}
    datasets: dict[str, pd.DataFrame] = {}
    for name, path in OPTIONAL_LEGITIMATE_PATHS.items():
        if not path.is_file():
            audits[name] = {"path": str(path.relative_to(ROOT)), "status": "MISSING_OPTIONAL"}
            continue
        frame = pd.read_csv(path)
        if not {"url", "label"}.issubset(frame.columns):
            audits[name] = {
                "path": str(path.relative_to(ROOT)),
                "status": "INVALID_SCHEMA",
                "columns": list(frame.columns),
                "required_columns": ["url", "label"],
            }
            continue
        if frame["label"].isna().any():
            audits[name] = {
                "path": str(path.relative_to(ROOT)),
                "status": "INVALID_LABELS",
                "reason": "null labels are present",
                "required_labels": [0],
            }
            continue
        try:
            labels = validate_labels(frame, name)
        except ValueError as error:
            audits[name] = {
                "path": str(path.relative_to(ROOT)),
                "status": "INVALID_LABELS",
                "reason": str(error),
                "required_labels": [0],
            }
            continue
        if set(frame["label"].unique()) != {0}:
            audits[name] = {
                "path": str(path.relative_to(ROOT)),
                "status": "INVALID_LABELS",
                "label_counts": labels,
                "required_labels": [0],
            }
            continue
        try:
            checked, url_audit = normalize_and_validate_urls(frame, name)
        except ValueError as error:
            audits[name] = {
                "path": str(path.relative_to(ROOT)),
                "status": "INVALID_URL_DATA",
                "reason": str(error),
                "label_counts": labels,
            }
            continue
        audits[name] = {
            "path": str(path.relative_to(ROOT)),
            "sha256": sha256_file(path),
            "status": "VALID_LEGITIMATE_REGRESSION_ONLY",
            "label_counts": labels,
            **url_audit,
            "used_for_training": False,
            "prior_use": {
                "legitimate_dynamic_training": "Previously used in an earlier candidate experiment.",
                "legitimate_dynamic_benchmark": "Previously used as benchmark/regression data; not an untouched test.",
                "legitimate_training_v3": "Previously used/reviewed in earlier training-data experiments.",
                "external_benign_dynamic": "No recorded evidence of prior use in this workspace.",
            }.get(name, "No recorded evidence of prior use in this workspace."),
        }
        if name in REGRESSION_DATASETS:
            datasets[name] = checked
    return audits, datasets


def combine_training_data(
    primary: pd.DataFrame,
    dynamic_datasets: dict[str, pd.DataFrame],
) -> tuple[pd.DataFrame, dict]:
    base = primary.copy()
    base["source_group"] = base["source"].astype(str)
    base["dataset_memberships"] = "clean_dataset"
    dynamic_frames = []
    dataset_rows = {}
    for name, dataset in dynamic_datasets.items():
        dynamic = dataset[
            ["url", "normalized_url", "registered_domain", "label"]
        ].copy()
        if set(dynamic["label"].unique()) != {0}:
            raise ValueError(f"{name}: legitimate augmentation contains nonzero labels.")
        dynamic["source"] = name
        dynamic["source_group"] = "verified_legitimate_dynamic"
        dynamic["dataset_memberships"] = name
        dynamic_frames.append(dynamic)
        dataset_rows[name] = len(dynamic)
    if not dynamic_frames:
        raise ValueError("No validated legitimate dynamic datasets are available for augmentation.")
    dynamic_rows = pd.concat(dynamic_frames, ignore_index=True)
    cross_dataset_conflicts = (
        dynamic_rows.groupby("normalized_url", sort=False)["label"].nunique()
    )
    if (cross_dataset_conflicts > 1).any():
        raise ValueError(
            "Conflicting labels in legitimate dynamic datasets after normalization."
        )
    dynamic_duplicates = int(dynamic_rows["normalized_url"].duplicated().sum())
    dynamic_unique = (
        dynamic_rows.groupby("normalized_url", sort=False)
        .agg(
            url=("url", "first"),
            registered_domain=("registered_domain", "first"),
            label=("label", "first"),
            source=("source", "first"),
            source_group=("source_group", "first"),
            dataset_memberships=(
                "dataset_memberships",
                lambda values: "|".join(sorted(set(values))),
            ),
        )
        .reset_index()
    )
    combined = pd.concat([base, dynamic_unique], ignore_index=True, sort=False)
    conflict_groups = (
        combined.groupby("normalized_url", sort=False)["label"].nunique()
    )
    if (conflict_groups > 1).any():
        raise ValueError(
            "A validated legitimate dynamic URL conflicts with the primary dataset label."
        )
    duplicate_rows = int(combined["normalized_url"].duplicated().sum())
    combined["_is_dynamic"] = combined["source_group"].eq(
        "verified_legitimate_dynamic"
    )
    combined = combined.sort_values(
        ["_is_dynamic"], ascending=False, kind="stable"
    )
    combined = (
        combined.groupby("normalized_url", sort=False)
        .agg(
            url=("url", "first"),
            registered_domain=("registered_domain", "first"),
            label=("label", "first"),
            source=("source", "first"),
            source_group=("source_group", "first"),
            dataset_memberships=(
                "dataset_memberships",
                lambda values: "|".join(
                    sorted(
                        {
                            membership
                            for value in values
                            for membership in str(value).split("|")
                        }
                    )
                ),
            ),
        )
        .reset_index()
    )
    if set(combined["label"].unique()) != LABELS:
        raise ValueError("Combined training data must preserve both labels.")
    return combined, {
        "primary_rows": len(primary),
        "dynamic_rows_before_deduplication": int(len(dynamic_rows)),
        "dynamic_rows_after_deduplication": int(len(dynamic_unique)),
        "dynamic_duplicate_rows_removed": dynamic_duplicates,
        "dynamic_rows_by_dataset": dataset_rows,
        "combined_same_label_duplicate_rows_removed": duplicate_rows,
        "combined_rows": len(combined),
        "combined_label_counts": {
            str(k): int(v) for k, v in combined["label"].value_counts().sort_index().items()
        },
        "combined_registered_domains": int(combined["registered_domain"].nunique()),
    }


def source_class_balanced_weights(labels: np.ndarray, sources: np.ndarray) -> np.ndarray:
    y = np.asarray(labels, dtype=int)
    source_values = np.asarray(sources, dtype=str)
    if set(np.unique(y)) != LABELS:
        raise ValueError("Source/class weighting requires both labels.")
    weights = np.zeros(len(y), dtype=np.float64)
    for label in (0, 1):
        mask = y == label
        source_groups, counts = np.unique(source_values[mask], return_counts=True)
        if not len(source_groups):
            raise ValueError(f"Class {label} is absent from the training partition.")
        count_by_source = dict(zip(source_groups, counts))
        for source in source_groups:
            group_mask = mask & (source_values == source)
            weights[group_mask] = 1.0 / (len(source_groups) * count_by_source[source])
    return weights


def url_cohorts(url: str) -> list[str]:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    keys = {key.lower() for key, _ in pairs}
    path_segments = {part.lower() for part in parsed.path.split("/") if part}
    cohorts = []
    if not path_segments and not pairs and not parsed.fragment:
        cohorts.append("homepage")
    if path_segments:
        cohorts.append("content_path")
    if pairs:
        cohorts.append("query")
    if keys & {"q", "query", "search", "search_query", "keyword", "keywords", "term", "k", "s"} or path_segments & {"search", "results", "find"}:
        cohorts.append("search")
    if len(pairs) > 1:
        cohorts.append("multiple_query_parameters")
        cohorts.append("query_heavy")
    if "%" in url:
        cohorts.append("encoded")
    if parsed.fragment:
        cohorts.append("fragment")
    return cohorts


def structure_audit(frame: pd.DataFrame, matrix: np.ndarray, feature_names: list[str]) -> dict:
    selected_features = (
        "URLLength",
        "HostnameLength",
        "PathLength",
        "QueryLength",
        "QueryParameterCount",
        "URLPercentEncodingCount",
        "HasSuspiciousTLD",
        "HasSuspiciousToken",
        "IsDomainIP",
        "IsTrustedTLD",
        "URLEntropy",
    )
    values = pd.DataFrame(matrix, columns=feature_names)
    cohort_rows = frame["normalized_url"].map(url_cohorts)
    result = {"by_source_and_label": {}, "by_label": {}, "cohort_counts_by_label": {}}
    for source, label, indices in _source_label_groups(frame):
        group = values.iloc[indices]
        group_urls = frame.iloc[indices]["normalized_url"]
        result["by_source_and_label"][f"{source}::label_{label}"] = {
            "rows": len(indices),
            "registered_domains": int(frame.iloc[indices]["registered_domain"].nunique()),
            "feature_median": {
                name: float(group[name].median()) for name in selected_features
            },
            "structure_rates": _structure_rates(group_urls),
        }
    labels = frame["label"].to_numpy(dtype=int)
    for label in (0, 1):
        indices = np.flatnonzero(labels == label)
        group = values.iloc[indices]
        result["by_label"][str(label)] = {
            "rows": len(indices),
            "feature_median": {
                name: float(group[name].median()) for name in selected_features
            },
            "structure_rates": _structure_rates(frame.iloc[indices]["normalized_url"]),
        }
    for cohort in (
        "homepage",
        "content_path",
        "search",
        "query",
        "multiple_query_parameters",
        "query_heavy",
        "encoded",
        "fragment",
    ):
        counts = Counter()
        for label, tags in zip(labels, cohort_rows):
            if cohort in tags:
                counts[str(label)] += 1
        result["cohort_counts_by_label"][cohort] = {
            str(label): int(counts[str(label)]) for label in (0, 1)
        }
    return result


def _source_label_groups(frame: pd.DataFrame):
    for (source, label), group in frame.groupby(["source_group", "label"]):
        yield str(source), int(label), group.index.to_numpy()


def _structure_rates(urls: pd.Series) -> dict[str, float]:
    tags = urls.map(url_cohorts)
    count = max(len(tags), 1)
    names = (
        "homepage",
        "content_path",
        "search",
        "query",
        "multiple_query_parameters",
        "query_heavy",
        "encoded",
        "fragment",
    )
    return {
        name: float(tags.map(lambda row: name in row).sum() / count)
        for name in names
    }


def error_cohort_metrics(
    frame: pd.DataFrame,
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> dict:
    y = np.asarray(labels, dtype=int)
    predicted = np.asarray(probabilities) >= threshold
    tags = frame["normalized_url"].map(url_cohorts)
    cohorts = (
        "homepage",
        "content_path",
        "search",
        "query",
        "multiple_query_parameters",
        "query_heavy",
        "encoded",
        "fragment",
    )
    output = {}
    for cohort in cohorts:
        mask = tags.map(lambda row: cohort in row).to_numpy()
        selected = mask & (y == 0)
        denom = int(selected.sum())
        fp = int(np.count_nonzero(selected & predicted))
        phish = mask & (y == 1)
        phish_denom = int(phish.sum())
        fn = int(np.count_nonzero(phish & ~predicted))
        output[cohort] = {
            "legitimate_rows": denom,
            "false_positives": fp,
            "false_positive_rate": fp / denom if denom else None,
            "phishing_rows": phish_denom,
            "false_negatives": fn,
            "false_negative_rate": fn / phish_denom if phish_denom else None,
        }
    return output


def expected_calibration_error(labels: np.ndarray, probabilities: np.ndarray) -> float:
    y = np.asarray(labels, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    error = 0.0
    for lower in np.linspace(0, 0.9, 10):
        upper = lower + 0.1
        mask = (p >= lower) & ((p < upper) if upper < 1 else (p <= upper))
        if mask.any():
            error += float(mask.mean()) * abs(float(y[mask].mean()) - float(p[mask].mean()))
    return error


def make_domain_splits(
    frame: pd.DataFrame,
    seed: int = SEED,
) -> dict[str, np.ndarray]:
    if set(frame["label"].unique()) != LABELS:
        raise ValueError("Domain split input must contain both labels 0 and 1.")
    row_indices = np.arange(len(frame))
    labels = frame["label"].to_numpy(dtype=int)
    domains = frame["registered_domain"].to_numpy()
    try:
        fit_cal_indices, test_indices = next(
            GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed).split(
                row_indices, labels, domains
            )
        )
        fit_relative, calibration_relative = next(
            GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed + 1).split(
                fit_cal_indices,
                labels[fit_cal_indices],
                domains[fit_cal_indices],
            )
        )
    except (StopIteration, ValueError) as error:
        raise ValueError(f"Could not create registered-domain splits: {error}") from error
    splits = {
        "train": fit_cal_indices[fit_relative],
        "calibration": fit_cal_indices[calibration_relative],
        "test": test_indices,
    }
    for name, indices in splits.items():
        if set(labels[indices]) != LABELS:
            raise ValueError(f"{name} split does not contain both classes; refusing to train.")
        if not len(indices):
            raise ValueError(f"{name} split is empty; refusing to train.")
    domains_by_split = {
        name: set(domains[indices].tolist()) for name, indices in splits.items()
    }
    overlaps = {
        f"{left}::{right}": sorted(domains_by_split[left] & domains_by_split[right])
        for left, right in (
            ("train", "calibration"),
            ("train", "test"),
            ("calibration", "test"),
        )
    }
    overlaps = {key: value for key, value in overlaps.items() if value}
    if overlaps:
        raise ValueError(f"Registered-domain leakage detected: {overlaps}")
    return splits


def feature_matrix(urls: pd.Series, feature_names: list[str]) -> np.ndarray:
    matrix = np.empty((len(urls), len(feature_names)), dtype=np.float32)
    for row_index, url in enumerate(urls):
        extracted = extract_features(url)
        try:
            matrix[row_index] = [extracted[name] for name in feature_names]
        except KeyError as error:
            raise ValueError(f"Production feature missing during extraction: {error}") from error
    if not np.isfinite(matrix).all():
        raise ValueError("Feature extraction produced non-finite values.")
    return matrix


def calibrated_probabilities(
    estimator: HistGradientBoostingClassifier,
    calibrator: LogisticRegression,
    features: np.ndarray,
) -> np.ndarray:
    classes = list(estimator.classes_)
    if 1 not in classes:
        raise ValueError("Experimental estimator has no phishing class (label 1).")
    positive_index = classes.index(1)
    raw = estimator.predict_proba(features)[:, positive_index]
    calibrated = calibrator.predict_proba(raw.reshape(-1, 1))[:, 1]
    return np.clip(calibrated, 0.0, 1.0)


def classification_metrics(labels: np.ndarray, probabilities: np.ndarray) -> dict:
    y = np.asarray(labels, dtype=int)
    probability = np.asarray(probabilities, dtype=float)
    predictions = probability >= MODEL_THRESHOLD
    matrix = confusion_matrix(y, predictions, labels=[0, 1])
    return {
        "decision_threshold": MODEL_THRESHOLD,
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(precision_score(y, predictions, zero_division=0)),
        "recall": float(recall_score(y, predictions, zero_division=0)),
        "f1": float(f1_score(y, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, probability)),
        "pr_auc": float(average_precision_score(y, probability)),
        "brier_score": float(brier_score_loss(y, probability)),
        "false_positive_rate": (
            float(matrix[0, 1] / (matrix[0, 0] + matrix[0, 1]))
            if matrix[0, 0] + matrix[0, 1]
            else None
        ),
        "false_negative_rate": (
            float(matrix[1, 0] / (matrix[1, 0] + matrix[1, 1]))
            if matrix[1, 0] + matrix[1, 1]
            else None
        ),
        "confusion_matrix": {
            "labels": ["legitimate_0", "phishing_1"],
            "matrix": matrix.astype(int).tolist(),
            "true_negative": int(matrix[0, 0]),
            "false_positive": int(matrix[0, 1]),
            "false_negative": int(matrix[1, 0]),
            "true_positive": int(matrix[1, 1]),
        },
        "class_counts": {str(k): int(v) for k, v in Counter(y.tolist()).items()},
    }


def verdict_counts(
    probabilities: np.ndarray,
    thresholds: dict[str, float],
) -> dict[str, int]:
    return {
        "SAFE": int(np.count_nonzero(probabilities < thresholds["safe"])),
        "SUSPICIOUS": int(
            np.count_nonzero(
                (probabilities >= thresholds["safe"])
                & (probabilities < thresholds["phishing"])
            )
        ),
        "PHISHING": int(np.count_nonzero(probabilities >= thresholds["phishing"])),
    }


def eval_legitimate_regression(
    datasets: dict[str, pd.DataFrame],
    audits: dict[str, dict],
    feature_names: list[str],
    candidate: dict[str, Any],
    production_thresholds: dict[str, float],
    excluded_eval_domains: set[str],
) -> dict:
    results = {}
    for name, frame in datasets.items():
        domains = set(frame["registered_domain"])
        if domains & excluded_eval_domains:
            raise ValueError(f"Regression set {name} was not reserved from fitting domains.")
        features = feature_matrix(frame["normalized_url"], feature_names)
        probabilities = calibrated_probabilities(
            candidate["estimator"], candidate["calibrator"], features
        )
        counts = verdict_counts(probabilities, production_thresholds)
        rows = [
            {
                "url": row.normalized_url,
                "registered_domain": row.registered_domain,
                "source": str(getattr(row, "source", getattr(row, "source_name", name))),
                "category": str(getattr(row, "category", getattr(row, "cohort", "unknown"))),
                "probability": float(probability),
                "verdict": (
                    "PHISHING"
                    if probability >= production_thresholds["phishing"]
                    else "SUSPICIOUS"
                    if probability >= production_thresholds["safe"]
                    else "SAFE"
                ),
            }
            for row, probability in zip(frame.itertuples(index=False), probabilities)
        ]
        results[name] = {
            "path": str(OPTIONAL_LEGITIMATE_PATHS[name].relative_to(ROOT)),
            "prior_use": audits[name]["prior_use"],
            "used_for_training_in_this_run": False,
            "independent_of_training_domains_in_this_run": True,
            "rows": len(frame),
            "registered_domains": len(domains),
            "false_positive_count": counts["PHISHING"],
            "false_positive_rate": counts["PHISHING"] / len(frame) if len(frame) else None,
            "verdict_counts": counts,
            "domain_overlap_with_train_calibration_test": 0,
            "results": rows,
        }
    return results


def split_summary(frame: pd.DataFrame, splits: dict[str, np.ndarray]) -> dict:
    report = {}
    for name, indices in splits.items():
        subset = frame.iloc[indices]
        report[name] = {
            "rows": len(subset),
            "class_counts": {
                str(k): int(v) for k, v in subset["label"].value_counts().sort_index().items()
            },
            "registered_domains": int(subset["registered_domain"].nunique()),
            "source_counts": {
                str(k): int(v) for k, v in subset["source"].value_counts().items()
            },
        }
    names = list(splits)
    report["registered_domain_overlaps"] = {
        f"{names[left]}::{names[right]}": 0
        for left, right in ((0, 1), (0, 2), (1, 2))
    }
    return report


def write_exclusive(path: Path, payload: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, bytes):
        with path.open("xb") as stream:
            stream.write(payload)
    else:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(payload)


def run_training() -> dict:
    candidate_path = EXPERIMENT_DIR / "candidate_model.pkl"
    features_path = EXPERIMENT_DIR / "feature_names.json"
    manifest_path = EXPERIMENT_DIR / "training_manifest.json"
    output_paths = (candidate_path, features_path, manifest_path, REPORT_PATH)
    existing = [str(path) for path in output_paths if path.exists()]
    if existing:
        raise FileExistsError(
            "Refusing to overwrite prior experimental outputs: "
            + ", ".join(existing)
        )
    initial_hashes = protected_hashes()
    feature_names, production_metadata, production_thresholds = production_feature_contract()
    primary_frame, dataset_audit = load_primary_dataset()
    optional_audit, regression_sets = inspect_optional_datasets()
    working, augmentation_audit = combine_training_data(primary_frame, regression_sets)
    splits = make_domain_splits(working)
    indices = {name: values for name, values in splits.items()}
    split_domains = {
        name: set(working.iloc[values]["registered_domain"])
        for name, values in indices.items()
    }
    all_fit_domains = set().union(*split_domains.values())
    started = time.perf_counter()
    matrix = feature_matrix(working["normalized_url"], feature_names)
    y = working["label"].to_numpy(dtype=int)
    source_groups = working["source_group"].to_numpy(dtype=str)
    train_indices = indices["train"]
    calibration_indices = indices["calibration"]
    test_indices = indices["test"]
    structure_distributions = structure_audit(working, matrix, feature_names)

    estimator = HistGradientBoostingClassifier(
        learning_rate=0.05,
        max_iter=100,
        max_leaf_nodes=31,
        random_state=SEED,
    )
    sample_weights = source_class_balanced_weights(
        y[train_indices], source_groups[train_indices]
    )
    estimator.fit(matrix[train_indices], y[train_indices], sample_weight=sample_weights)

    calibration_raw = estimator.predict_proba(matrix[calibration_indices])[
        :, list(estimator.classes_).index(1)
    ]
    calibrator = LogisticRegression(
        solver="lbfgs",
        max_iter=1000,
        random_state=SEED,
    )
    calibrator.fit(calibration_raw.reshape(-1, 1), y[calibration_indices])
    candidate = {"estimator": estimator, "calibrator": calibrator}
    test_frame = working.iloc[test_indices].reset_index(drop=True)
    test_probabilities = calibrated_probabilities(
        estimator, calibrator, matrix[test_indices]
    )
    test_metrics = classification_metrics(y[test_indices], test_probabilities)
    test_metrics["expected_calibration_error"] = expected_calibration_error(
        y[test_indices], test_probabilities
    )
    test_metrics["production_threshold_cohort_metrics"] = error_cohort_metrics(
        test_frame, y[test_indices], test_probabilities, production_thresholds["phishing"]
    )
    test_metrics["threshold_0_5_cohort_metrics"] = error_cohort_metrics(
        test_frame, y[test_indices], test_probabilities, MODEL_THRESHOLD
    )
    test_metrics["production_threshold_verdict_counts"] = verdict_counts(
        test_probabilities, production_thresholds
    )
    test_predictions_at_production_threshold = (
        test_probabilities >= production_thresholds["phishing"]
    )
    test_metrics["production_phishing_threshold_metrics"] = {
        "threshold": production_thresholds["phishing"],
        "false_positive_count": int(
            np.count_nonzero(
                (y[test_indices] == 0) & test_predictions_at_production_threshold
            )
        ),
        "legitimate_denominator": int(np.count_nonzero(y[test_indices] == 0)),
        "false_positive_rate": float(
            np.mean(test_predictions_at_production_threshold[y[test_indices] == 0])
        ),
        "false_negative_count": int(
            np.count_nonzero(
                (y[test_indices] == 1) & ~test_predictions_at_production_threshold
            )
        ),
        "phishing_denominator": int(np.count_nonzero(y[test_indices] == 1)),
        "recall": float(
            np.mean(test_predictions_at_production_threshold[y[test_indices] == 1])
        ),
    }
    test_metrics["production_thresholds_used_for_verdict_counts"] = production_thresholds

    production_model, _, _ = load_model_bundle()
    production_test_probabilities = production_model.predict_proba(matrix[test_indices])[
        :, list(production_model.classes_).index(1)
    ]
    production_test_metrics = classification_metrics(y[test_indices], production_test_probabilities)
    production_test_metrics["production_phishing_threshold_counts"] = verdict_counts(
        production_test_probabilities, production_thresholds
    )
    production_test_metrics["cohorts"] = error_cohort_metrics(
        test_frame,
        y[test_indices],
        production_test_probabilities,
        production_thresholds["phishing"],
    )
    dynamic_test_mask = test_frame["source_group"].eq(
        "verified_legitimate_dynamic"
    ).to_numpy()
    dynamic_test_frame = test_frame.loc[dynamic_test_mask].reset_index(drop=True)
    dynamic_test_probabilities = test_probabilities[dynamic_test_mask]
    production_dynamic_probabilities = production_test_probabilities[dynamic_test_mask]
    dynamic_regression = {}
    memberships = dynamic_test_frame["dataset_memberships"].astype(str)
    for name, audit in optional_audit.items():
        membership_mask = memberships.map(
            lambda value: name in value.split("|")
        ).to_numpy()
        subset = dynamic_test_frame.loc[membership_mask].reset_index(drop=True)
        candidate_probs = dynamic_test_probabilities[membership_mask]
        production_probs = production_dynamic_probabilities[membership_mask]
        candidate_fp = int(np.count_nonzero(candidate_probs >= MODEL_THRESHOLD))
        production_fp = int(
            np.count_nonzero(production_probs >= production_thresholds["phishing"])
        )
        dynamic_regression[name] = {
            "prior_use": audit.get("prior_use", audit.get("status", "unknown")),
            "used_for_training_in_this_run": True,
            "evaluation_partition": "untouched registered-domain-disjoint test rows only",
            "test_rows": len(subset),
            "test_registered_domains": int(subset["registered_domain"].nunique()),
            "candidate_false_positive_count": candidate_fp,
            "candidate_false_positive_rate": (
                candidate_fp / len(subset) if len(subset) else None
            ),
            "candidate_decision_threshold": MODEL_THRESHOLD,
            "production_false_positive_count": production_fp,
            "production_false_positive_rate": (
                production_fp / len(subset) if len(subset) else None
            ),
            "candidate_cohorts": error_cohort_metrics(
                subset,
                np.zeros(len(subset), dtype=int),
                candidate_probs,
                MODEL_THRESHOLD,
            ),
            "production_cohorts": error_cohort_metrics(
                subset,
                np.zeros(len(subset), dtype=int),
                production_probs,
                production_thresholds["phishing"],
            ),
            "prior_evaluation_use": "These source rows were previously reviewed/used; not independent evidence.",
        }
    if dynamic_test_frame.empty:
        raise ValueError(
            "The domain-disjoint test partition contains no legitimate dynamic examples; "
            "cannot evaluate whether augmentation reduced false positives."
        )

    candidate_bundle = {
        "format": "vigil-experimental-calibrated-classifier-v1",
        "estimator": estimator,
        "calibrator": calibrator,
        "feature_names": feature_names,
        "calibration_method": "logistic regression on estimator probability from domain-disjoint calibration partition",
        "classes": [0, 1],
        "model_version_reference": MODEL_VERSION,
        "production_thresholds_reference_only": production_thresholds,
    }
    serialized_model = pickle.dumps(candidate_bundle, protocol=pickle.HIGHEST_PROTOCOL)
    model_size = len(serialized_model)
    write_exclusive(candidate_path, serialized_model)
    write_exclusive(
        features_path,
        json.dumps(feature_names, indent=2) + "\n",
    )
    write_exclusive(
        manifest_path,
        json.dumps(
            {
                "dataset": dataset_audit,
                "optional_datasets": optional_audit,
                "augmentation": augmentation_audit,
                "features": feature_names,
                "production_feature_metadata_sha256": sha256_file(PRODUCTION_METADATA_PATH),
                "production_feature_pickle_sha256": sha256_file(PRODUCTION_FEATURES_PATH),
                "split_seed": SEED,
                "split": split_summary(working, splits),
                "source_and_url_structure_audit": structure_distributions,
            },
            indent=2,
        )
        + "\n",
    )
    final_hashes = protected_hashes()
    if final_hashes != initial_hashes:
        raise RuntimeError(
            f"Protected production files changed during experimental training: "
            f"{_hash_differences(initial_hashes, final_hashes)}"
        )

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "experiment": "train_model_v2",
        "candidate_status": "EXPERIMENTAL_NOT_PROMOTED",
        "production_ready": False,
        "production_artifacts_modified": False,
        "dataset": dataset_audit,
        "optional_legitimate_datasets": optional_audit,
        "training_policy": {
            "dynamic_datasets_used_for_training": sorted(regression_sets),
            "dynamic_datasets_used_for_regression": sorted(regression_sets),
            "dynamic_data_partitioning": "All normalized rows are combined and deduplicated before registered-domain grouping; dynamic data is evaluated only on rows assigned to the untouched test partition.",
            "dynamic_datasets_were_previously_exposed": True,
            "augmentation": augmentation_audit,
            "sample_weighting": "Equal total weight per source_group within each class; classes have equal total mass.",
            "normalization": "feature_extractor.normalize_url",
            "registered_domain": "feature_extractor.get_registered_domain",
            "labels": "clean_dataset.csv labels accepted as VIGIL: 0 legitimate, 1 phishing; source semantics checked against dataset audit",
        },
        "features": {
            "extractor": "feature_extractor.extract_features",
            "source": "production feature_names.pkl",
            "names": feature_names,
            "count": len(feature_names),
            "exact_production_order": True,
        },
        "model": {
            "estimator": "HistGradientBoostingClassifier",
            "parameters": {
                "learning_rate": 0.05,
                "max_iter": 100,
                "max_leaf_nodes": 31,
                "random_state": SEED,
            },
            "sample_weighting": (
                "Equal total weight per source_group within each class on the training partition; "
                "classes have equal total mass."
            ),
            "calibration": {
                "method": "LogisticRegression over raw estimator probabilities, fit without sample weights to retain calibration-partition prevalence",
                "fit_partition": "registered-domain-disjoint calibration partition only",
                "sample_weighting": "none; natural observed calibration rows",
                "parameters": {"solver": "lbfgs", "max_iter": 1000, "random_state": SEED},
            },
        },
        "split": {
            "method": "GroupShuffleSplit by registered domain; test 20%; calibration 25% of remaining rows",
            "seed": SEED,
            **split_summary(working, splits),
            "registered_domain_overlap_checked_before_augmentation": False,
            "no_registered_domain_crosses_partitions": True,
        },
        "source_and_url_structure_audit": structure_distributions,
        "test_metrics": test_metrics,
        "production_on_identical_test_rows": production_test_metrics,
        "legitimate_dynamic_domain_disjoint_test": dynamic_regression,
        "prior_evaluation_use": {
            "legitimate_dynamic_training": "Previously used in earlier candidate experiments; regression-only here.",
            "legitimate_dynamic_benchmark": "Previously used as benchmark/regression data; now included as training augmentation but each row's evaluation is restricted to test domains.",
            "legitimate_training_v3": "Previously used/reviewed in earlier training-data experiments; included as training augmentation and not independent evidence.",
            "test_partition": (
                "Domain-disjoint from train/calibration within this run, but drawn from "
                "clean_dataset.csv, which was used by prior VIGIL training; not an untouched "
                "external lockbox."
            ),
        },
        "production_thresholds_reference_only": production_thresholds,
        "production_hashes_before": initial_hashes,
        "production_hashes_after": final_hashes,
        "production_hashes_verified_unchanged": True,
        "outputs": {
            "candidate_model": str(candidate_path.relative_to(ROOT)),
            "candidate_model_sha256": hashlib.sha256(serialized_model).hexdigest(),
            "candidate_model_size_bytes": model_size,
            "feature_names": str(features_path.relative_to(ROOT)),
            "training_manifest": str(manifest_path.relative_to(ROOT)),
            "report": str(REPORT_PATH.relative_to(ROOT)),
        },
        "fit_and_evaluation_seconds": time.perf_counter() - started,
        "limitations": [
            "clean_dataset.csv has no source collection dates; recency cannot be assessed.",
            "The clean dataset contains registered domains with both labels; those rows were retained and domain-grouped, not automatically relabeled.",
            "The dynamic datasets were previously used in prior work; test-domain results are useful regression checks but are not an independently sourced benchmark.",
            "The calibration partition comes from a previously used corpus; it is domain-disjoint in this run but is not an independent external lockbox.",
            "The domain-disjoint test partition is drawn from a previously used dataset and is not an untouched external lockbox.",
            "This candidate is experimental and has not been tested through production serving or extension behavior.",
        ],
    }
    write_exclusive(REPORT_PATH, json.dumps(report, indent=2, default=str) + "\n")
    return report


def _hash_differences(before: dict[str, str], after: dict[str, str]) -> dict:
    return {
        name: {"before": before.get(name), "after": after.get(name)}
        for name in sorted(set(before) | set(after))
        if before.get(name) != after.get(name)
    }


def main() -> int:
    try:
        report = run_training()
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError, OSError) as error:
        print(f"train_model_v2 stopped: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "candidate_status": report["candidate_status"],
                "rows": report["dataset"]["rows_after"],
                "test_metrics": report["test_metrics"],
                "regression_sets": {
                    name: {
                        "test_rows": result["test_rows"],
                        "candidate_false_positives": result[
                            "candidate_false_positive_count"
                        ],
                        "production_false_positives": result[
                            "production_false_positive_count"
                        ],
                    }
                    for name, result in report[
                        "legitimate_dynamic_domain_disjoint_test"
                    ].items()
                },
                "production_on_identical_test_rows": report[
                    "production_on_identical_test_rows"
                ],
                "production_artifacts_modified": report["production_artifacts_modified"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
