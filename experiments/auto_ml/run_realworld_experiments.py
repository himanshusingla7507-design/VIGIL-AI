from __future__ import annotations

import csv
import hashlib
import json
import os
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    f1_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import PHISHING_THRESHOLD, SAFE_THRESHOLD
from feature_extractor import (
    FEATURE_NAMES,
    MODEL_EXCLUDED_FEATURES,
    extract_features,
    get_registered_domain,
    normalize_url,
)

LEGIT_PATH = ROOT / "legitimate_urls_realworld_v3.csv"
PHISH_PATH = ROOT / "data" / "external" / "phishing_database_active.txt"
BENCHMARK_DIR = ROOT / "experiments" / "auto_ml" / "benchmark_v1"
RUN_ID = "realworld_v3"
OUTPUT_DIR = ROOT / "experiments" / "auto_ml" / RUN_ID
LEADERBOARD_PATH = ROOT / "reports" / "auto_ml_leaderboard.json"
FINAL_PATH = ROOT / "reports" / "auto_ml_final_evaluation.json"
FAILURE_PATH = ROOT / "reports" / "auto_ml_failure_analysis.json"
SEED = 42
MAX_EXPERIMENTS = int(os.environ.get("VIGIL_AUTO_ML_MAX_EXPERIMENTS", "20"))
if not 1 <= MAX_EXPERIMENTS <= 20:
    raise ValueError("VIGIL_AUTO_ML_MAX_EXPERIMENTS must be between 1 and 20")

FEATURES = [name for name in FEATURE_NAMES if name not in MODEL_EXCLUDED_FEATURES]
COHORTS = (
    "homepage",
    "content_path",
    "search",
    "query",
    "multiple_parameters",
    "encoding",
    "fragment",
    "tracking",
    "pagination",
    "login_account",
    "docs",
    "api_endpoint",
    "long_url",
    "long_query",
)
SPLITS = ("train", "calibration", "validation", "test")
CAPS = {"train": 1400, "calibration": 700, "validation": 700, "test": 900}
PER_DOMAIN_CAPS = {"train": 60, "calibration": 30, "validation": 30, "test": 40}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_rank(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def json_write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def get_cohorts(url: str) -> set[str]:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    keys = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    segments = {segment for segment in path.split("/") if segment}
    result: set[str] = set()

    if not parsed.path.strip("/") and not parsed.query and not parsed.fragment:
        result.add("homepage")
    if parsed.path.strip("/"):
        result.add("content_path")
    if parsed.query:
        result.add("query")
    if len(keys) > 1:
        result.add("multiple_parameters")
    if "%" in url:
        result.add("encoding")
    if parsed.fragment:
        result.add("fragment")
    if (
        "search" in segments
        or "search" in keys
        or "q" in keys
        or "query" in keys
        or "search_query" in keys
    ):
        result.add("search")
    if keys & {"utm_source", "utm_medium", "utm_campaign", "gclid", "fbclid", "ref", "source"}:
        result.add("tracking")
    if keys & {"page", "page_number", "p", "offset", "cursor", "start"} or "page" in segments:
        result.add("pagination")
    if any(token in host or token in path for token in ("login", "signin", "sign-in", "account", "auth")):
        result.add("login_account")
    if any(token in host or token in path for token in ("docs", "documentation", "reference", "manual", "guide")):
        result.add("docs")
    if "api" in host.split(".") or "api" in segments or "openapi" in segments or "swagger" in segments:
        result.add("api_endpoint")
    if len(url) >= 250:
        result.add("long_url")
    if len(parsed.query) >= 100:
        result.add("long_query")
    return result


def primary_cohort(url: str) -> str:
    memberships = get_cohorts(url)
    priority = (
        "homepage",
        "login_account",
        "long_query",
        "tracking",
        "pagination",
        "encoding",
        "fragment",
        "search",
        "multiple_parameters",
        "query",
        "api_endpoint",
        "docs",
        "long_url",
        "content_path",
    )
    return next((name for name in priority if name in memberships), "content_path")


def split_for_domain(domain: str) -> str:
    bucket = int(stable_rank(domain)[:8], 16) % 100
    if bucket < 70:
        return "train"
    if bucket < 80:
        return "calibration"
    if bucket < 90:
        return "validation"
    return "test"


def load_benchmark_reservations() -> tuple[set[str], dict[str, list[dict[str, str]]], dict]:
    benchmark_domains: set[str] = set()
    benchmark_sets: dict[str, list[dict[str, str]]] = {}
    for filename in ("legitimate_domain_disjoint.csv", "phishing_domain_disjoint.csv"):
        rows = read_csv_rows(BENCHMARK_DIR / filename)
        benchmark_sets[filename] = rows
        for row in rows:
            benchmark_domains.add(get_registered_domain(normalize_url(row["url"])))

    fixed = json.loads((BENCHMARK_DIR / "fixed_urls.json").read_text(encoding="utf-8"))
    for url in fixed["baseline_legitimate_urls"]:
        benchmark_domains.add(get_registered_domain(normalize_url(url)))
    for row in fixed["counterfactual_legitimate_urls"]:
        benchmark_domains.add(get_registered_domain(normalize_url(row["url"])))
    return benchmark_domains, benchmark_sets, fixed


def load_inputs(benchmark_domains: set[str]) -> tuple[dict[str, dict], dict]:
    legitimate: dict[str, dict] = {}
    legit_invalid = Counter()
    legit_duplicate_count = 0
    expected_columns = {
        "url",
        "label",
        "source_name",
        "source_page",
        "category",
        "verification_method",
    }
    with LEGIT_PATH.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if set(reader.fieldnames or ()) != expected_columns:
            raise ValueError(f"unexpected legitimate CSV columns: {reader.fieldnames}")
        for row in reader:
            if row["label"].strip() != "0":
                legit_invalid["nonzero_or_invalid_label"] += 1
                continue
            try:
                url = normalize_url(row["url"])
                domain = get_registered_domain(url)
            except (TypeError, ValueError):
                legit_invalid["invalid_url"] += 1
                continue
            if not domain:
                legit_invalid["missing_registered_domain"] += 1
                continue
            if url in legitimate:
                legit_duplicate_count += 1
                continue
            legitimate[url] = {
                "url": url,
                "label": 0,
                "source_name": row["source_name"],
                "source_page": row["source_page"],
                "category": row["category"],
                "verification_method": row["verification_method"],
                "registered_domain": domain,
            }

    phishing: dict[str, dict] = {}
    phish_invalid = Counter()
    phish_duplicate_count = 0
    with PHISH_PATH.open(encoding="utf-8-sig", errors="replace") as stream:
        for line in stream:
            raw_url = line.strip()
            if not raw_url:
                phish_invalid["blank_line"] += 1
                continue
            try:
                url = normalize_url(raw_url)
                domain = get_registered_domain(url)
            except (TypeError, ValueError) as exc:
                phish_invalid[str(exc)] += 1
                continue
            if not domain:
                phish_invalid["missing_registered_domain"] += 1
                continue
            if url in phishing:
                phish_duplicate_count += 1
                continue
            phishing[url] = {
                "url": url,
                "label": 1,
                "source_name": "Phishing.Database active feed",
                "source_page": "data/external/phishing_database_active.txt",
                "category": "phishing_feed",
                "verification_method": "listed_in_active_phishing_feed",
                "registered_domain": domain,
            }

    conflicts = set(legitimate) & set(phishing)
    for url in conflicts:
        del legitimate[url]

    reserved_legitimate = sum(row["registered_domain"] in benchmark_domains for row in legitimate.values())
    reserved_phishing = sum(row["registered_domain"] in benchmark_domains for row in phishing.values())
    legitimate = {
        url: row for url, row in legitimate.items()
        if row["registered_domain"] not in benchmark_domains
    }
    phishing = {
        url: row for url, row in phishing.items()
        if row["registered_domain"] not in benchmark_domains
    }

    rows_by_split: dict[str, dict[int, dict[str, list[dict]]]] = {
        split: {0: defaultdict(list), 1: defaultdict(list)} for split in SPLITS
    }
    for source_rows in (legitimate, phishing):
        for row in source_rows.values():
            split = split_for_domain(row["registered_domain"])
            row["split"] = split
            row["primary_cohort"] = primary_cohort(row["url"])
            rows_by_split[split][row["label"]][row["primary_cohort"]].append(row)

    split_domains = {
        split: {
            row["registered_domain"]
            for label in (0, 1)
            for cohort_rows in rows_by_split[split][label].values()
            for row in cohort_rows
        }
        for split in SPLITS
    }
    split_overlaps = {
        f"{left}_{right}": sorted(split_domains[left] & split_domains[right])
        for index, left in enumerate(SPLITS)
        for right in SPLITS[index + 1 :]
        if split_domains[left] & split_domains[right]
    }
    if split_overlaps:
        raise RuntimeError(f"registered domains cross data splits: {split_overlaps}")

    diagnostics = {
        "input_sha256": {
            "legitimate_csv": sha256_file(LEGIT_PATH),
            "phishing_feed": sha256_file(PHISH_PATH),
            "benchmark_manifest": sha256_file(BENCHMARK_DIR / "manifest.json"),
        },
        "raw_input_rows": {
            "legitimate_csv": sum(1 for _ in LEGIT_PATH.open(encoding="utf-8-sig")) - 1,
            "phishing_feed": sum(1 for _ in PHISH_PATH.open(encoding="utf-8-sig", errors="replace")),
        },
        "valid_unique_before_conflict_resolution": {
            "legitimate": len(legitimate) + len(conflicts) + reserved_legitimate,
            "phishing": len(phishing) + reserved_phishing,
        },
        "invalid_input_counts": {
            "legitimate": dict(legit_invalid),
            "phishing": dict(phish_invalid),
        },
        "duplicate_normalized_url_removal": {
            "legitimate": legit_duplicate_count,
            "phishing": phish_duplicate_count,
        },
        "exact_url_label_conflicts": len(conflicts),
        "conflict_policy": "Phishing-feed label wins for exact normalized URL conflicts; conflicting legitimate rows are excluded.",
        "benchmark_domain_reservation": {
            "registered_domains": len(benchmark_domains),
            "legitimate_rows_excluded": reserved_legitimate,
            "phishing_rows_excluded": reserved_phishing,
            "reason": "Keep every fixed benchmark registered domain out of all candidate data.",
        },
        "retained_candidate_pool": {
            "legitimate": len(legitimate),
            "phishing": len(phishing),
            "legitimate_domains": len({row["registered_domain"] for row in legitimate.values()}),
            "phishing_domains": len({row["registered_domain"] for row in phishing.values()}),
            "source_counts": dict(Counter(row["source_name"] for row in legitimate.values())),
            "legitimate_source_categories": dict(Counter(row["category"] for row in legitimate.values())),
        },
        "all_split_rows": {
            split: {
                "legitimate": sum(len(rows) for rows in rows_by_split[split][0].values()),
                "phishing": sum(len(rows) for rows in rows_by_split[split][1].values()),
                "legitimate_domains": len({
                    row["registered_domain"]
                    for cohort_rows in rows_by_split[split][0].values()
                    for row in cohort_rows
                }),
                "phishing_domains": len({
                    row["registered_domain"]
                    for cohort_rows in rows_by_split[split][1].values()
                    for row in cohort_rows
                }),
            }
            for split in SPLITS
        },
        "split_method": "Stable SHA-256 assignment of registered domains to 70/10/10/10 train/calibration/validation/test buckets.",
        "registered_domain_split_overlap": split_overlaps,
    }
    return rows_by_split, diagnostics


def choose_rows(
    rows_by_split: dict,
    split: str,
    positive_ratio: int = 1,
) -> list[dict]:
    chosen: list[dict] = []
    for cohort in COHORTS:
        by_label: dict[int, list[dict]] = {}
        for label in (0, 1):
            candidates = rows_by_split[split][label].get(cohort, [])
            ordered = sorted(candidates, key=lambda row: stable_rank(row["url"]))
            domain_counts: Counter[str] = Counter()
            kept: list[dict] = []
            for row in ordered:
                if domain_counts[row["registered_domain"]] >= PER_DOMAIN_CAPS[split]:
                    continue
                domain_counts[row["registered_domain"]] += 1
                kept.append(row)
            by_label[label] = kept

        quota = CAPS[split]
        count_zero = min(len(by_label[0]), quota)
        count_one = min(len(by_label[1]), quota * positive_ratio)
        if positive_ratio == 1:
            count_zero = count_one = min(count_zero, count_one)
        chosen.extend(by_label[0][:count_zero])
        chosen.extend(by_label[1][:count_one])
    return chosen


def feature_frame(rows: list[dict], feature_names: list[str]) -> pd.DataFrame:
    values = [extract_features(row["url"]) for row in rows]
    return pd.DataFrame(values, columns=FEATURE_NAMES)[feature_names]


def raw_probability(estimator, frame: pd.DataFrame) -> np.ndarray:
    if isinstance(estimator, tuple):
        scaler, classifier = estimator
        return classifier.predict_proba(scaler.transform(frame))[:, 1]
    return estimator.predict_proba(frame)[:, 1]


def final_probability(candidate: dict, frame: pd.DataFrame) -> np.ndarray:
    probability = raw_probability(candidate["estimator"], frame)
    calibrator = candidate.get("calibrator")
    if calibrator is not None:
        probability = calibrator.predict_proba(probability.reshape(-1, 1))[:, 1]
    return np.clip(probability, 0.0, 1.0)


def verdict(probability: float) -> str:
    if probability >= PHISHING_THRESHOLD:
        return "PHISHING"
    if probability >= SAFE_THRESHOLD:
        return "SUSPICIOUS"
    return "SAFE"


def pct(numerator: int, denominator: int) -> dict:
    return {
        "numerator": int(numerator),
        "denominator": int(denominator),
        "percentage": (100.0 * numerator / denominator) if denominator else None,
    }


def metric_bundle(
    rows: list[dict],
    probabilities: np.ndarray,
    cohorts: list[set[str]] | None = None,
) -> dict:
    labels = np.asarray([row["label"] for row in rows], dtype=int)
    predictions = np.asarray([verdict(float(value)) for value in probabilities])
    phishing_actual = labels == 1
    legitimate_actual = labels == 0
    phishing_predicted = predictions == "PHISHING"
    tp = int(np.sum(phishing_actual & phishing_predicted))
    fp = int(np.sum(legitimate_actual & phishing_predicted))
    fn = int(np.sum(phishing_actual & ~phishing_predicted))
    safe_count = int(np.sum(predictions == "SAFE"))
    suspicious_count = int(np.sum(predictions == "SUSPICIOUS"))
    phishing_count = int(np.sum(phishing_predicted))
    verdict_names = ("SAFE", "SUSPICIOUS", "PHISHING")
    legitimate_verdict_counts = {
        name: int(np.sum(legitimate_actual & (predictions == name)))
        for name in verdict_names
    }
    phishing_verdict_counts = {
        name: int(np.sum(phishing_actual & (predictions == name)))
        for name in verdict_names
    }
    if len(set(labels.tolist())) == 2:
        pr_auc = float(average_precision_score(labels, probabilities))
        roc_auc = float(roc_auc_score(labels, probabilities))
        brier = float(brier_score_loss(labels, probabilities))
    else:
        pr_auc = roc_auc = brier = None
    per_cohort = {}
    if cohorts is not None:
        for cohort in COHORTS:
            indexes = np.asarray([cohort in member for member in cohorts], dtype=bool)
            c_labels = labels[indexes]
            c_predictions = predictions[indexes]
            c_positive = c_labels == 1
            c_negative = c_labels == 0
            c_tp = int(np.sum(c_positive & (c_predictions == "PHISHING")))
            c_fp = int(np.sum(c_negative & (c_predictions == "PHISHING")))
            per_cohort[cohort] = {
                "rows": int(indexes.sum()),
                "legitimate_rows": int(c_negative.sum()),
                "phishing_rows": int(c_positive.sum()),
                "legitimate_fpr": pct(c_fp, int(c_negative.sum())),
                "phishing_recall": pct(c_tp, int(c_positive.sum())),
            }
    return {
        "rows": len(rows),
        "legitimate_rows": int(legitimate_actual.sum()),
        "phishing_rows": int(phishing_actual.sum()),
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "phishing_count": phishing_count,
        "legitimate_verdict_counts": legitimate_verdict_counts,
        "phishing_verdict_counts": phishing_verdict_counts,
        "legitimate_false_phishing": pct(fp, int(legitimate_actual.sum())),
        "phishing_false_negative": pct(fn, int(phishing_actual.sum())),
        "phishing_recall": pct(tp, int(phishing_actual.sum())),
        "phishing_precision": pct(tp, phishing_count),
        "phishing_f1": float(f1_score(labels, predictions == "PHISHING", zero_division=0)),
        "brier_score": brier,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "cohorts": per_cohort,
    }


def model_specs() -> list[dict]:
    base_hgb = {
        "learning_rate": 0.05,
        "max_iter": 100,
        "max_leaf_nodes": 31,
        "min_samples_leaf": 20,
        "l2_regularization": 0.0,
        "random_state": SEED,
    }
    return [
        {
            "name": "hist_gradient_domain_weighted_uncalibrated",
            "family": "HistGradientBoosting",
            "features": FEATURES,
            "params": {**base_hgb, "class_weight": None},
            "calibrate": False,
            "positive_ratio": 1,
            "domain_weighted": True,
        },
        {
            "name": "hist_gradient_balanced_calibrated",
            "family": "HistGradientBoosting",
            "features": FEATURES,
            "params": {**base_hgb, "class_weight": None},
            "calibrate": True,
            "positive_ratio": 1,
            "domain_weighted": True,
        },
        {
            "name": "logistic_regression_balanced_calibrated",
            "family": "LogisticRegression",
            "features": FEATURES,
            "params": {"C": 1.0, "solver": "liblinear", "max_iter": 2500, "random_state": SEED},
            "calibrate": True,
            "positive_ratio": 1,
            "domain_weighted": True,
        },
        {
            "name": "random_forest_balanced_calibrated",
            "family": "RandomForest",
            "features": FEATURES,
            "params": {
                "n_estimators": 250,
                "min_samples_leaf": 2,
                "max_features": "sqrt",
                "n_jobs": -1,
                "random_state": SEED,
            },
            "calibrate": True,
            "positive_ratio": 1,
            "domain_weighted": True,
        },
        {
            "name": "hist_gradient_regularized_calibrated",
            "family": "HistGradientBoosting",
            "features": FEATURES,
            "params": {**base_hgb, "max_leaf_nodes": 15, "l2_regularization": 1.0, "class_weight": None},
            "calibrate": True,
            "positive_ratio": 1,
            "domain_weighted": True,
        },
        {
            "name": "hist_gradient_drop_path_length_calibrated",
            "family": "HistGradientBoosting",
            "features": [name for name in FEATURES if name != "PathLength"],
            "params": {**base_hgb, "class_weight": None},
            "calibrate": True,
            "positive_ratio": 1,
            "domain_weighted": True,
        },
    ]


def make_estimator(spec: dict):
    if spec["family"] == "HistGradientBoosting":
        return HistGradientBoostingClassifier(**spec["params"])
    if spec["family"] == "RandomForest":
        return RandomForestClassifier(**spec["params"])
    if spec["family"] == "LogisticRegression":
        raise ValueError("LogisticRegression is constructed with its feature scaler in fit_candidate")
    raise ValueError(f"unknown model family: {spec['family']}")


def domain_sample_weights(rows: list[dict]) -> np.ndarray:
    domain_counts: Counter[tuple[int, str]] = Counter(
        (row["label"], row["registered_domain"]) for row in rows
    )
    weights = np.asarray([
        1.0 / domain_counts[(row["label"], row["registered_domain"])]
        for row in rows
    ])
    for label in (0, 1):
        mask = np.asarray([row["label"] == label for row in rows])
        total = weights[mask].sum()
        if total == 0:
            raise ValueError(f"no rows for label {label} when computing sample weights")
        weights[mask] *= len(rows) / (2.0 * total)
    return weights


def fit_candidate(spec: dict, rows_by_split: dict) -> tuple[dict, dict]:
    train_rows = choose_rows(rows_by_split, "train", spec["positive_ratio"])
    calibration_rows = choose_rows(rows_by_split, "calibration")
    validation_rows = choose_rows(rows_by_split, "validation")
    for split_name, rows in (
        ("train", train_rows),
        ("calibration", calibration_rows),
        ("validation", validation_rows),
    ):
        if {row["label"] for row in rows} != {0, 1}:
            raise ValueError(f"{split_name} sample does not contain both labels")
    feature_names = spec["features"]
    train_frame = feature_frame(train_rows, feature_names)
    calibration_frame = feature_frame(calibration_rows, feature_names)
    validation_frame = feature_frame(validation_rows, feature_names)
    train_y = np.asarray([row["label"] for row in train_rows], dtype=int)
    calibration_y = np.asarray([row["label"] for row in calibration_rows], dtype=int)
    train_weights = domain_sample_weights(train_rows) if spec["domain_weighted"] else None
    calibration_weights = domain_sample_weights(calibration_rows) if spec["domain_weighted"] else None

    started = time.perf_counter()
    if spec["family"] == "LogisticRegression":
        scaler = StandardScaler()
        classifier = LogisticRegression(**spec["params"])
        scaler.fit(train_frame, sample_weight=train_weights)
        classifier.fit(
            scaler.transform(train_frame),
            train_y,
            sample_weight=train_weights,
        )
        estimator = (scaler, classifier)
    else:
        estimator = make_estimator(spec)
        if train_weights is None:
            estimator.fit(train_frame, train_y)
        else:
            estimator.fit(train_frame, train_y, sample_weight=train_weights)
    fit_seconds = time.perf_counter() - started

    calibrator = None
    if spec["calibrate"]:
        calibration_scores = raw_probability(estimator, calibration_frame)
        calibrator = LogisticRegression(solver="lbfgs", max_iter=2000, random_state=SEED)
        calibrator.fit(
            calibration_scores.reshape(-1, 1),
            calibration_y,
            sample_weight=calibration_weights,
        )

    candidate = {
        "estimator": estimator,
        "calibrator": calibrator,
        "feature_names": feature_names,
        "model_name": spec["name"],
    }
    validation_probabilities = final_probability(candidate, validation_frame)
    validation_cohorts = [get_cohorts(row["url"]) for row in validation_rows]
    validation_metrics = metric_bundle(validation_rows, validation_probabilities, validation_cohorts)
    selected_rows = {
        "train": train_rows,
        "calibration": calibration_rows,
        "validation": validation_rows,
    }
    details = {
        "validation_metrics": validation_metrics,
        "fit_seconds": fit_seconds,
        "sample_rows": {split: len(rows) for split, rows in selected_rows.items()},
        "sample_domains": {
            split: {
                "legitimate": len({row["registered_domain"] for row in rows if row["label"] == 0}),
                "phishing": len({row["registered_domain"] for row in rows if row["label"] == 1}),
            }
            for split, rows in selected_rows.items()
        },
        "sample_sources": {
            split: dict(Counter(row["source_name"] for row in rows))
            for split, rows in selected_rows.items()
        },
        "domain_balanced_sample_weights": spec["domain_weighted"],
    }
    return candidate, details


def save_sample_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "url",
        "label",
        "source_name",
        "source_page",
        "category",
        "verification_method",
        "registered_domain",
        "split",
        "primary_cohort",
    ]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row[field] for field in fields} for row in rows)


def timing_metrics(candidate: dict, rows: list[dict]) -> dict:
    timings = []
    for row in rows[:300]:
        started = time.perf_counter()
        feature_values = extract_features(row["url"])
        frame = pd.DataFrame([[feature_values[name] for name in candidate["feature_names"]]], columns=candidate["feature_names"])
        final_probability(candidate, frame)
        timings.append((time.perf_counter() - started) * 1000)
    return {
        "sample_count": len(timings),
        "median_ms_per_url_including_feature_extraction": statistics.median(timings) if timings else None,
        "p95_ms_per_url_including_feature_extraction": float(np.percentile(timings, 95)) if timings else None,
    }


def external_rows(rows: list[dict[str, str]], label: int, source: str) -> list[dict]:
    normalized = []
    for row in rows:
        url = normalize_url(row["url"])
        normalized.append({
            "url": url,
            "label": label,
            "source_name": source,
            "source_page": row.get("source_page", source),
            "category": row.get("category", "benchmark"),
            "verification_method": "fixed_immutable_domain_disjoint_benchmark",
            "registered_domain": get_registered_domain(url),
        })
    return normalized


def evaluate_external(candidate: dict, dataset: list[dict]) -> tuple[dict, np.ndarray]:
    frame = feature_frame(dataset, candidate["feature_names"])
    probabilities = final_probability(candidate, frame)
    metrics = metric_bundle(dataset, probabilities, [get_cohorts(row["url"]) for row in dataset])
    return metrics, probabilities


def production_scores(rows: list[dict]) -> np.ndarray:
    import service

    return np.asarray([float(service.scan(row["url"])["probability"]) for row in rows])


def failure_examples(rows: list[dict], probabilities: np.ndarray, limit: int = 100) -> dict:
    examples = []
    for row, probability in zip(rows, probabilities):
        predicted = verdict(float(probability))
        is_failure = (row["label"] == 0 and predicted == "PHISHING") or (
            row["label"] == 1 and predicted != "PHISHING"
        )
        if is_failure:
            examples.append({
                "url": row["url"],
                "label": row["label"],
                "verdict": predicted,
                "probability": float(probability),
                "source_name": row["source_name"],
                "category": row["category"],
                "registered_domain": row["registered_domain"],
                "cohorts": sorted(get_cohorts(row["url"])),
                "features": extract_features(row["url"]),
            })
    examples.sort(key=lambda row: row["probability"], reverse=True)
    return {"failure_count": len(examples), "examples": examples[:limit]}


def main() -> None:
    for required in (LEGIT_PATH, PHISH_PATH, BENCHMARK_DIR / "manifest.json"):
        if not required.exists():
            raise FileNotFoundError(f"required input not found: {required}")
    manifest = json.loads((BENCHMARK_DIR / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != "v1" or manifest.get("immutable_after_creation") is not True:
        raise ValueError("the fixed benchmark manifest is not the expected immutable v1 benchmark")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    benchmark_domains, benchmark_sets, fixed_urls = load_benchmark_reservations()
    rows_by_split, diagnostics = load_inputs(benchmark_domains)
    specs = model_specs()[:MAX_EXPERIMENTS]
    diagnostics["run"] = {
        "experiment_id": RUN_ID,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "experiment_budget": MAX_EXPERIMENTS,
        "experiments_planned": len(specs),
        "prior_controlled_experiments_this_task": 14,
        "cumulative_controlled_experiments_this_task": 14 + len(specs),
        "thresholds": {
            "safe": SAFE_THRESHOLD,
            "phishing": PHISHING_THRESHOLD,
            "source": "existing config.py; fixed throughout this run",
        },
        "feature_extraction": "feature_extractor.extract_features and existing production_29 feature selection.",
    }

    candidates = []
    for spec in specs:
        print(f"Fitting {spec['name']}...", flush=True)
        candidate, details = fit_candidate(spec, rows_by_split)
        candidate_dir = OUTPUT_DIR / "candidates" / spec["name"]
        candidate_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = candidate_dir / "candidate.joblib"
        joblib.dump(candidate, artifact_path, compress=3)
        details.update({
            "candidate": spec["name"],
            "family": spec["family"],
            "features": spec["features"],
            "parameters": spec["params"],
            "calibration": "separate registered-domain-disjoint calibration split using sigmoid LogisticRegression"
            if spec["calibrate"] else "none",
            "training_sampling": {
                "strategy": "deterministic SHA-256 ordering within primary URL-structure cohort with a per-domain cap",
                "positive_to_negative_max_ratio": spec["positive_ratio"],
                "class_weight": spec["params"].get("class_weight"),
                "inverse_registered_domain_weights": spec["domain_weighted"],
            },
            "artifact": str(artifact_path.relative_to(ROOT)),
            "artifact_size_bytes": artifact_path.stat().st_size,
            "artifact_sha256": sha256_file(artifact_path),
            "dataset_sha256": diagnostics["input_sha256"],
            "overall_split_row_and_domain_counts": diagnostics["all_split_rows"],
            "outcome": "validation_only; not evaluated on untouched test or fixed benchmark",
        })
        json_write(candidate_dir / "experiment.json", details)
        candidates.append((spec, candidate, details))
        print(
            f"  validation recall={details['validation_metrics']['phishing_recall']['percentage']:.3f}% "
            f"legitimate_fpr={details['validation_metrics']['legitimate_false_phishing']['percentage']:.3f}%",
            flush=True,
        )

    # Select by validation only. Fixed thresholds are never optimized in this run.
    # If no candidate reaches the FPR target, minimize that gate's shortfall first.
    candidates.sort(
        key=lambda item: (
            item[2]["validation_metrics"]["legitimate_false_phishing"]["percentage"] is not None
            and item[2]["validation_metrics"]["legitimate_false_phishing"]["percentage"] <= 0.5,
            -max(
                0.0,
                (item[2]["validation_metrics"]["legitimate_false_phishing"]["percentage"] or 0.0) - 0.5,
            ),
            item[2]["validation_metrics"]["phishing_recall"]["percentage"] or 0.0,
            item[2]["validation_metrics"]["phishing_precision"]["percentage"] or 0.0,
            -(item[2]["validation_metrics"]["brier_score"] or 1.0),
        ),
        reverse=True,
    )
    best_spec, best_candidate, best_details = candidates[0]

    split_sample_rows = {split: choose_rows(rows_by_split, split) for split in SPLITS}
    # The internal test is first touched after candidate selection.
    test_rows = split_sample_rows["test"]
    test_frame = feature_frame(test_rows, best_candidate["feature_names"])
    test_probabilities = final_probability(best_candidate, test_frame)
    internal_test_metrics = metric_bundle(test_rows, test_probabilities, [get_cohorts(row["url"]) for row in test_rows])
    latency = timing_metrics(best_candidate, test_rows)

    benchmark_legit = external_rows(
        benchmark_sets["legitimate_domain_disjoint.csv"], 0, "benchmark_v1 legitimate_domain_disjoint.csv"
    )
    benchmark_phish = external_rows(
        benchmark_sets["phishing_domain_disjoint.csv"], 1, "benchmark_v1 phishing_domain_disjoint.csv"
    )
    benchmark_domain_disjoint = benchmark_legit + benchmark_phish
    benchmark_domain_metrics, benchmark_domain_probabilities = evaluate_external(best_candidate, benchmark_domain_disjoint)

    core_rows = [
        {
            "url": normalize_url(url),
            "label": 0,
            "source_name": "benchmark_v1 fixed baseline legitimate URL",
            "source_page": "experiments/auto_ml/benchmark_v1/fixed_urls.json",
            "category": "curated_fixed_regression",
            "verification_method": "fixed_immutable_benchmark; not observed training data",
            "registered_domain": get_registered_domain(normalize_url(url)),
        }
        for url in fixed_urls["baseline_legitimate_urls"]
    ]
    counterfactual_rows = [
        {
            "url": normalize_url(row["url"]),
            "label": 0,
            "source_name": "benchmark_v1 curated legitimate counterfactual",
            "source_page": "experiments/auto_ml/benchmark_v1/fixed_urls.json",
            "category": row["variant_type"],
            "verification_method": "fixed_immutable_benchmark_counterfactual; not observed training data",
            "registered_domain": get_registered_domain(normalize_url(row["url"])),
        }
        for row in fixed_urls["counterfactual_legitimate_urls"]
    ]
    fixed_all = core_rows + counterfactual_rows
    fixed_metrics, _ = evaluate_external(best_candidate, fixed_all)
    core_metrics, _ = evaluate_external(best_candidate, core_rows)
    pair_deltas = []
    for row in fixed_urls["counterfactual_legitimate_urls"]:
        base_url = normalize_url(row["base_url"])
        variant_url = normalize_url(row["url"])
        pair_rows = [
            {**core_rows[0], "url": base_url, "registered_domain": get_registered_domain(base_url)},
            {**core_rows[0], "url": variant_url, "registered_domain": get_registered_domain(variant_url)},
        ]
        _, pair_probabilities = evaluate_external(best_candidate, pair_rows)
        pair_deltas.append({
            "base_url": base_url,
            "variant_type": row["variant_type"],
            "variant_url": variant_url,
            "base_probability": float(pair_probabilities[0]),
            "variant_probability": float(pair_probabilities[1]),
            "probability_delta": float(pair_probabilities[1] - pair_probabilities[0]),
            "base_verdict": verdict(float(pair_probabilities[0])),
            "variant_verdict": verdict(float(pair_probabilities[1])),
        })

    production_domain_scores = production_scores(benchmark_domain_disjoint)
    production_domain_metrics = metric_bundle(
        benchmark_domain_disjoint, production_domain_scores, [get_cohorts(row["url"]) for row in benchmark_domain_disjoint]
    )
    production_fixed_scores = production_scores(fixed_all)
    production_fixed_metrics = metric_bundle(fixed_all, production_fixed_scores, [get_cohorts(row["url"]) for row in fixed_all])

    cohort_gaps = [
        cohort for cohort in COHORTS
        if not internal_test_metrics["cohorts"][cohort]["legitimate_rows"]
        or not internal_test_metrics["cohorts"][cohort]["phishing_rows"]
    ]
    required_structure_cohorts = (
        "content_path",
        "query",
        "multiple_parameters",
        "encoding",
        "fragment",
    )
    hard_cohort_regressions = {}
    for cohort in COHORTS:
        candidate_recall = benchmark_domain_metrics["cohorts"][cohort]["phishing_recall"]["percentage"]
        production_recall = production_domain_metrics["cohorts"][cohort]["phishing_recall"]["percentage"]
        denominator = benchmark_domain_metrics["cohorts"][cohort]["phishing_rows"]
        if denominator >= 10 and candidate_recall is not None and production_recall is not None:
            hard_cohort_regressions[cohort] = {
                "candidate_recall_percentage": candidate_recall,
                "production_recall_percentage": production_recall,
                "delta_percentage_points": candidate_recall - production_recall,
                "denominator": denominator,
            }

    acceptance = {
        "legitimate_benchmark_fpr_at_or_below_0_5_percent": {
            "status": "PASS" if benchmark_domain_metrics["legitimate_false_phishing"]["percentage"] is not None
            and benchmark_domain_metrics["legitimate_false_phishing"]["percentage"] <= 0.5 else "FAIL",
            **benchmark_domain_metrics["legitimate_false_phishing"],
        },
        "zero_phishing_verdicts_on_fixed_core_legitimate_set": {
            "status": "PASS" if core_metrics["phishing_count"] == 0 else "FAIL",
            "phishing_verdicts": core_metrics["phishing_count"],
            "denominator": core_metrics["legitimate_rows"],
        },
        "internal_domain_disjoint_phishing_recall_at_least_98_percent": {
            "status": "PASS" if internal_test_metrics["phishing_recall"]["percentage"] is not None
            and internal_test_metrics["phishing_recall"]["percentage"] >= 98 else "FAIL",
            **internal_test_metrics["phishing_recall"],
        },
        "fixed_domain_disjoint_phishing_recall_at_least_97_percent": {
            "status": "PASS" if benchmark_domain_metrics["phishing_recall"]["percentage"] is not None
            and benchmark_domain_metrics["phishing_recall"]["percentage"] >= 97 else "FAIL",
            **benchmark_domain_metrics["phishing_recall"],
        },
        "no_major_hard_phishing_cohort_regression": {
            "status": "PASS" if hard_cohort_regressions and all(
                item["delta_percentage_points"] >= -5.0 for item in hard_cohort_regressions.values()
            ) else "FAIL" if hard_cohort_regressions else "UNVERIFIED",
            "maximum_allowed_regression_percentage_points": 5.0,
            "cohorts": hard_cohort_regressions,
        },
        "no_systematic_normal_url_structure_false_positive_jumps": {
            "status": "PASS" if all(
                internal_test_metrics["cohorts"][cohort]["legitimate_rows"] > 0
                and internal_test_metrics["cohorts"][cohort]["legitimate_fpr"]["percentage"] is not None
                and internal_test_metrics["cohorts"][cohort]["legitimate_fpr"]["percentage"] <= 0.5
                for cohort in required_structure_cohorts
            ) and all(item["variant_verdict"] != "PHISHING" for item in pair_deltas) else "FAIL",
            "basis": "domain-disjoint test cohorts plus all fixed legitimate counterfactual pairs; sparse cohorts are reported separately",
        },
        "backend_and_extension_tests": {"status": "NOT_RUN_BY_TRAINING_RUNNER"},
        "overall_candidate_gate": "PENDING_REGRESSION_TESTS",
    }

    if any(cohort in cohort_gaps for cohort in required_structure_cohorts):
        acceptance["no_systematic_normal_url_structure_false_positive_jumps"]["status"] = "UNVERIFIED"
    if all(item["status"] in ("PASS",) for item in acceptance.values() if isinstance(item, dict) and "status" in item):
        acceptance["overall_candidate_gate"] = "PASS"
    elif any(item["status"] == "FAIL" for item in acceptance.values() if isinstance(item, dict) and "status" in item):
        acceptance["overall_candidate_gate"] = "FAIL"

    all_selected = []
    for split in SPLITS:
        all_selected.extend(split_sample_rows[split])
    save_sample_csv(OUTPUT_DIR / "sampled_dataset.csv", all_selected)
    test_failures = failure_examples(test_rows, test_probabilities)
    benchmark_failures = failure_examples(
        benchmark_domain_disjoint, benchmark_domain_probabilities
    )

    final_report = {
        "experiment_id": RUN_ID,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": diagnostics,
        "experiment_count": len(candidates),
        "candidate_selection": {
            "method": "Validation-only ranking: satisfy fixed 0.5% FPR target where possible; if no candidate qualifies, minimize FPR shortfall, then maximize phishing recall, precision, and Brier score.",
            "selected_candidate": best_spec["name"],
            "thresholds_not_tuned": True,
            "final_test_used_for_selection": False,
            "fixed_benchmark_used_for_selection": False,
        },
        "selected_candidate": {
            "name": best_spec["name"],
            "family": best_spec["family"],
            "features": best_spec["features"],
            "parameters": best_spec["params"],
            "calibration": "separate domain-disjoint calibration set" if best_spec["calibrate"] else "none",
            "validation_metrics": best_details["validation_metrics"],
            "internal_domain_disjoint_test_metrics": internal_test_metrics,
            "internal_test_sample_rows": len(test_rows),
            "internal_test_sample_domains": {
                "legitimate": len({row["registered_domain"] for row in test_rows if row["label"] == 0}),
                "phishing": len({row["registered_domain"] for row in test_rows if row["label"] == 1}),
            },
            "internal_test_inference_latency": latency,
            "artifact": str((OUTPUT_DIR / "candidates" / best_spec["name"] / "candidate.joblib").relative_to(ROOT)),
        },
        "fixed_benchmark": {
            "manifest_version": manifest["version"],
            "benchmark_domains_reserved_from_candidate_data": len(benchmark_domains),
            "domain_disjoint_registered_domains": {
                "legitimate": len({row["registered_domain"] for row in benchmark_legit}),
                "phishing": len({row["registered_domain"] for row in benchmark_phish}),
                "cross_label_overlap": len(
                    {row["registered_domain"] for row in benchmark_legit}
                    & {row["registered_domain"] for row in benchmark_phish}
                ),
            },
            "domain_disjoint_metrics": benchmark_domain_metrics,
            "fixed_baseline_core_legitimate_metrics": core_metrics,
            "fixed_baseline_core_phishing_verdicts": core_metrics["phishing_count"],
            "all_curated_counterfactuals_including_baseline_metrics": fixed_metrics,
            "counterfactual_data_note": "The fixed counterfactual variants are curated benchmark cases, not observed URLs and were never included in training.",
            "candidate_vs_existing_production": {
                "domain_disjoint_metrics": production_domain_metrics,
                "fixed_urls_metrics": production_fixed_metrics,
            },
            "counterfactual_pairs": {
                "count": len(pair_deltas),
                "median_probability_delta": statistics.median(item["probability_delta"] for item in pair_deltas),
                "positive_probability_delta_count": sum(item["probability_delta"] > 0 for item in pair_deltas),
                "phishing_variant_verdict_count": sum(item["variant_verdict"] == "PHISHING" for item in pair_deltas),
                "by_variant_type": {
                    variant: {
                        "count": sum(item["variant_type"] == variant for item in pair_deltas),
                        "median_probability_delta": statistics.median(
                            item["probability_delta"] for item in pair_deltas if item["variant_type"] == variant
                        ),
                        "phishing_verdict_count": sum(
                            item["variant_type"] == variant and item["variant_verdict"] == "PHISHING"
                            for item in pair_deltas
                        ),
                    }
                    for variant in sorted({item["variant_type"] for item in pair_deltas})
                },
                "pairs": pair_deltas,
            },
        },
        "cohort_gaps": {
            "missing_legitimate_or_phishing_test_class": cohort_gaps,
            "interpretation": "Empty denominators are UNVERIFIED, not a pass.",
        },
        "acceptance_gates": acceptance,
    }
    failure_report = {
        "experiment_id": RUN_ID,
        "selected_candidate": best_spec["name"],
        "internal_test": test_failures,
        "fixed_domain_disjoint_benchmark": benchmark_failures,
        "counterfactual_phishing_verdicts": [
            pair for pair in pair_deltas if pair["variant_verdict"] == "PHISHING"
        ],
        "diagnostics": {
            "selection_validation_metrics": best_details["validation_metrics"],
            "internal_test_metrics": internal_test_metrics,
            "benchmark_metrics": benchmark_domain_metrics,
            "actual_failure_examples_only": True,
            "analysis_note": "Examples are actual URLs from the specified datasets or the immutable benchmark; no URL was constructed for training.",
        },
    }

    if acceptance["overall_candidate_gate"] == "PASS":
        recommended = OUTPUT_DIR / "recommended_candidate.joblib"
        joblib.dump(best_candidate, recommended, compress=3)
        final_report["recommended_candidate"] = {
            "path": str(recommended.relative_to(ROOT)),
            "size_bytes": recommended.stat().st_size,
            "sha256": sha256_file(recommended),
            "promotion_status": "Saved separately; production artifacts remain unchanged; user approval required.",
        }
    else:
        final_report["recommended_candidate"] = None

    leaderboard = {}
    if LEADERBOARD_PATH.exists():
        leaderboard = json.loads(LEADERBOARD_PATH.read_text(encoding="utf-8"))
    historic = leaderboard.get("candidates", [])
    new_entries = []
    for candidate_result in candidates:
        spec, details = candidate_result[0], candidate_result[2]
        val = details["validation_metrics"]
        new_entries.append({
            "experiment": RUN_ID,
            "candidate": spec["name"],
            "gate_pass": False,
            "selection_split": "validation",
            "legitimate_fpr": (
                val["legitimate_false_phishing"]["numerator"]
                / val["legitimate_false_phishing"]["denominator"]
                if val["legitimate_false_phishing"]["denominator"] else None
            ),
            "phishing_recall": (
                val["phishing_recall"]["numerator"] / val["phishing_recall"]["denominator"]
                if val["phishing_recall"]["denominator"] else None
            ),
            "f1": val["phishing_f1"],
            "pr_auc": val["pr_auc"],
            "brier_score": val["brier_score"],
            "model_size_bytes": details["artifact_size_bytes"],
            "artifact": details["artifact"],
        })
    selected_leaderboard_entry = next(
        entry for entry in new_entries if entry["candidate"] == best_spec["name"]
    )
    selected_leaderboard_entry["internal_domain_disjoint_test"] = internal_test_metrics
    selected_leaderboard_entry["fixed_benchmark_domain_disjoint"] = benchmark_domain_metrics
    selected_leaderboard_entry["gate_pass"] = acceptance["overall_candidate_gate"] == "PASS"
    leaderboard["candidates"] = historic + new_entries
    leaderboard["latest_run"] = {
        "experiment": RUN_ID,
        "selected_candidate": best_spec["name"],
        "acceptance_status": acceptance["overall_candidate_gate"],
        "experiments_completed": len(candidates),
    }

    json_write(OUTPUT_DIR / "dataset_composition.json", diagnostics)
    json_write(OUTPUT_DIR / "experiment_report.json", {
        "experiment_id": RUN_ID,
        "experiments": [
            {
                "candidate": candidate_result[0]["name"],
                "family": candidate_result[0]["family"],
                "features": candidate_result[0]["features"],
                "parameters": candidate_result[0]["params"],
                "calibration": candidate_result[2]["calibration"],
                "domain_balanced_sample_weights": candidate_result[0]["domain_weighted"],
                "fit_seconds": candidate_result[2]["fit_seconds"],
                "sample_rows": candidate_result[2]["sample_rows"],
                "sample_domains": candidate_result[2]["sample_domains"],
                "validation_metrics": candidate_result[2]["validation_metrics"],
                "dataset_sha256": candidate_result[2]["dataset_sha256"],
                "overall_split_row_and_domain_counts": candidate_result[2]["overall_split_row_and_domain_counts"],
                "artifact": candidate_result[2]["artifact"],
                "artifact_sha256": candidate_result[2]["artifact_sha256"],
                "outcome": "selected_for_single untouched-test evaluation" if candidate_result[0]["name"] == best_spec["name"] else "validation-only",
            }
            for candidate_result in candidates
        ],
    })
    json_write(LEADERBOARD_PATH, leaderboard)
    json_write(FINAL_PATH, final_report)
    json_write(FAILURE_PATH, failure_report)
    print(json.dumps({
        "experiments": len(candidates),
        "selected": best_spec["name"],
        "test_phishing_recall": internal_test_metrics["phishing_recall"],
        "benchmark_phishing_recall": benchmark_domain_metrics["phishing_recall"],
        "benchmark_legitimate_fpr": benchmark_domain_metrics["legitimate_false_phishing"],
        "acceptance": acceptance["overall_candidate_gate"],
        "reports": [str(LEADERBOARD_PATH), str(FINAL_PATH), str(FAILURE_PATH)],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
