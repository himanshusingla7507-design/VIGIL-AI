"""Run controlled, isolated VIGIL URL-model experiments on local real data."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import pickle
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.inspection import permutation_importance
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
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from scipy.sparse import csr_matrix, hstack
from scipy.sparse import csr_matrix, hstack

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feature_extractor import (  # noqa: E402
    FEATURE_NAMES,
    MODEL_EXCLUDED_FEATURES,
    _analysis_url,
    extract_features,
    get_registered_domain,
    normalize_url,
)
from service import _thresholds_from_metadata, scan  # noqa: E402

SEED = 42
LEGIT_PATH = ROOT / "experiments" / "auto_ml" / "data_bootstrap_002" / "legitimate_urls.csv"
PHISH_PATH = ROOT / "data" / "external" / "phishing_database_active.txt"
BASELINE_PATH = ROOT / "reports" / "baseline_dynamic_legitimate.json"
COUNTERFACTUAL_PATH = ROOT / "reports" / "dynamic_counterfactual_analysis.json"
HARD_COHORT_PATH = ROOT / "reports" / "benign_dynamic_url_training.json"
PRODUCTION_FEATURES_PATH = ROOT / "feature_names.pkl"
METADATA_PATH = ROOT / "model_metadata.json"
EXPERIMENT_ID = "exp003_url_char_ngram_hybrid"
EXPERIMENT_DIR = ROOT / "experiments" / "auto_ml" / EXPERIMENT_ID
BENCHMARK_DIR = ROOT / "experiments" / "auto_ml" / "benchmark_v1"
LEADERBOARD_PATH = ROOT / "reports" / "auto_ml_leaderboard.json"

SEED_PARTITION_RANGES = (("train", 0.60), ("calibration", 0.75), ("validation", 0.90), ("test", 1.0))
DOMAIN_SPLIT_CUTOFFS: tuple[float, float, float] | None = None
POSITIVE_DOMAIN_ASSIGNMENTS: dict[str, str] = {}
MAX_FPR_FOR_THRESHOLD = 0.005
MIN_PHISH_RECALL = 0.98
MIN_DOMAIN_RECALL = 0.97


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def stable_fraction(text: str, seed: int = SEED) -> float:
    digest = hashlib.sha256(f"{seed}:{text}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / (2**64)


def split_for_domain(domain: str) -> str:
    assigned = POSITIVE_DOMAIN_ASSIGNMENTS.get(domain)
    if assigned is not None:
        return assigned
    score = stable_fraction(f"split:{domain}")
    if DOMAIN_SPLIT_CUTOFFS is None:
        raise RuntimeError("Domain split cutoffs must be initialized before assigning rows.")
    train_cutoff, calibration_cutoff, validation_cutoff = DOMAIN_SPLIT_CUTOFFS
    if score < train_cutoff:
        return "train"
    if score < calibration_cutoff:
        return "calibration"
    if score < validation_cutoff:
        return "validation"
    return "test"


def configure_domain_splits(legitimate_domains: set[str], reserved_domains: set[str]) -> dict:
    global DOMAIN_SPLIT_CUTOFFS, POSITIVE_DOMAIN_ASSIGNMENTS
    eligible = legitimate_domains - reserved_domains
    ordered = sorted(eligible, key=lambda domain: stable_fraction(f"split:{domain}"))
    if len(ordered) < 20:
        raise ValueError(f"Only {len(ordered)} legitimate registered domains remain after benchmark reservation.")
    count = len(ordered)
    train_end = max(1, round(count * 0.60))
    calibration_end = max(train_end + 1, round(count * 0.75))
    validation_end = max(calibration_end + 1, round(count * 0.90))
    validation_end = min(validation_end, count - 1)
    calibration_end = min(calibration_end, validation_end - 1)
    train_end = min(train_end, calibration_end - 1)
    ranges = {
        "train": (0, train_end),
        "calibration": (train_end, calibration_end),
        "validation": (calibration_end, validation_end),
        "test": (validation_end, count),
    }
    assignments = {}
    for split, (start, stop) in ranges.items():
        for domain in ordered[start:stop]:
            assignments[domain] = split
    scores = [stable_fraction(f"split:{domain}") for domain in ordered]
    DOMAIN_SPLIT_CUTOFFS = (
        scores[train_end - 1],
        scores[calibration_end - 1],
        scores[validation_end - 1],
    )
    POSITIVE_DOMAIN_ASSIGNMENTS = assignments
    return {
        "eligible_legitimate_domains": count,
        "legitimate_domains_per_split": {split: stop - start for split, (start, stop) in ranges.items()},
        "hash_score_cutoffs": {
            "train_upper_exclusive": DOMAIN_SPLIT_CUTOFFS[0],
            "calibration_upper_exclusive": DOMAIN_SPLIT_CUTOFFS[1],
            "validation_upper_exclusive": DOMAIN_SPLIT_CUTOFFS[2],
        },
        "benchmark_reserved_positive_domains": sorted(legitimate_domains & reserved_domains),
    }


def structures(url: str) -> dict[str, bool | str]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    query = parts.query or ""
    parameters = parse_qsl(query, keep_blank_values=True)
    homepage = path in ("", "/") and not query and not parts.fragment
    if path in ("", "/") and not query:
        primary = "homepage"
    elif path in ("", "/"):
        primary = "query_only"
    elif query:
        primary = "path_plus_query"
    else:
        primary = "path_only"
    return {
        "primary": primary,
        "homepage": homepage,
        "path": path not in ("", "/"),
        "query": bool(query),
        "path_plus_query": path not in ("", "/") and bool(query),
        "multiple_query_params": len(parameters) > 1,
        "pagination": any(key.lower() in {"page", "offset", "start", "cursor", "p"} for key, _ in parameters),
        "encoded": any(char == "%" for char in url),
        "fragment": bool(parts.fragment),
        "tracking": any(key.lower().startswith("utm_") or key.lower() in {"gclid", "fbclid", "yclid", "mc_cid", "mc_eid"} for key, _ in parameters),
        "login_account": any(token in f"{host}{path}".lower() for token in ("login", "log-in", "signin", "sign-in", "account", "register", "signup")),
        "docs": any(token in f"{host}{path}".lower() for token in ("doc", "documentation", "reference", "manual")),
        "api": host.startswith("api.") or "/api/" in path.lower() or path.lower().endswith("/api.php"),
        "long_query": len(query) > 100,
        "long_url": len(url) > 200,
        "search": any(token in f"{path}?{query}".lower() for token in ("search", "query", "find")),
        "registered_domain": get_registered_domain(url),
    }


def load_positive_rows() -> tuple[list[dict], dict]:
    rows_by_key = {}
    raw_count = 0
    with LEGIT_PATH.open(newline="", encoding="utf-8") as source:
        for item in csv.DictReader(source):
            raw_count += 1
            url = normalize_url(item["url"])
            analysis = _analysis_url(url)
            rows_by_key.setdefault(
                analysis,
                {
                    "url": url,
                    "label": 0,
                    "source": item["source"],
                    "provenance": "Individually verified successful same-registered-domain first-party HTTPS link from the local collection manifest.",
                    "domain": get_registered_domain(url),
                    "structures": structures(url),
                },
            )
    if not rows_by_key:
        raise ValueError("No locally retained verified legitimate URL rows are available.")
    return list(rows_by_key.values()), {
        "path": str(LEGIT_PATH.relative_to(ROOT)),
        "input_rows": raw_count,
        "analysis_unique_rows": len(rows_by_key),
        "duplicates_removed": raw_count - len(rows_by_key),
        "registered_domains": len({row["domain"] for row in rows_by_key.values()}),
        "source_counts": dict(Counter(row["source"] for row in rows_by_key.values())),
    }


def read_public_url_reports() -> tuple[list[str], list[dict], list[dict]]:
    baseline = load_json(BASELINE_PATH)
    baseline_urls = [row["url"] for row in baseline["results"]]
    counterfactual_report = load_json(COUNTERFACTUAL_PATH)
    counterfactual_rows = counterfactual_report["results"]
    hard_report = load_json(HARD_COHORT_PATH)
    hard_cohorts = hard_report.get("phishing_regressions", {})
    return baseline_urls, counterfactual_rows, hard_cohorts


def build_reserved_domains(baseline_urls: list[str], counterfactual_rows: list[dict]) -> set[str]:
    domains = {get_registered_domain(url) for url in baseline_urls}
    domains.update(get_registered_domain(row["url"]) for row in counterfactual_rows)
    return domains


def feed_primary(url: str) -> str:
    return str(structures(url)["primary"])


def load_phishing_candidates(
    excluded_domains: set[str],
    legitimate_domains: set[str],
    legitimate_split_quotas: dict[str, Counter],
) -> tuple[dict[str, dict[str, list[dict]]], dict]:
    capacities = {
        (split, category): max(200, quota * 12)
        for split, quotas in legitimate_split_quotas.items()
        for category, quota in quotas.items()
        if quota > 0
    }
    heaps: dict[tuple[str, str], list[tuple[int, int, dict]]] = {key: [] for key in capacities}
    invalid = blank = read_count = 0
    serial = 0
    import heapq

    with PHISH_PATH.open(encoding="utf-8", errors="replace") as source:
        for line in source:
            read_count += 1
            raw = line.strip()
            if not raw:
                blank += 1
                continue
            try:
                url = normalize_url(raw)
                domain = get_registered_domain(url)
                analysis_key = _analysis_url(url)
            except (TypeError, ValueError):
                invalid += 1
                continue
            if not domain or domain in excluded_domains or domain in legitimate_domains:
                continue
            split = split_for_domain(domain)
            primary = feed_primary(url)
            bucket = (split, primary)
            if bucket not in heaps:
                continue
            rank = int.from_bytes(hashlib.sha256(f"{SEED}:{analysis_key}".encode("utf-8")).digest()[:8], "big")
            row = {
                "url": url,
                "label": 1,
                "source": "phishing_database_active",
                "provenance": "Unmodified URL record from data/external/phishing_database_active.txt; phishing label follows source identity.",
                "domain": domain,
                "structures": structures(url),
                "analysis_key": analysis_key,
            }
            heap = heaps[bucket]
            capacity = capacities[bucket]
            entry = (-rank, serial, row)
            serial += 1
            if len(heap) < capacity:
                heapq.heappush(heap, entry)
            elif rank < -heap[0][0]:
                heapq.heapreplace(heap, entry)

    candidate_buckets = {
        split: {
            category: [entry[2] for entry in sorted(heap, key=lambda entry: (-entry[0], entry[1]))]
            for (bucket_split, category), heap in heaps.items()
            if bucket_split == split
        }
        for split in legitimate_split_quotas
    }
    return candidate_buckets, {
        "path": str(PHISH_PATH.relative_to(ROOT)),
        "physical_lines": read_count,
        "blank_lines": blank,
        "invalid_urls": invalid,
        "selection": "One URL per registered domain outside all legitimate and benchmark domains; deterministic SHA-256 ordering within the matching primary structure bucket.",
    }


def assign_legitimate_splits(legitimate_rows: list[dict], reserved_domains: set[str]) -> tuple[dict[str, list[dict]], list[dict], dict[str, Counter]]:
    splits = {name: [] for name, _ in SEED_PARTITION_RANGES}
    benchmark = []
    quotas = {name: Counter() for name, _ in SEED_PARTITION_RANGES}
    for row in legitimate_rows:
        domain = row["domain"]
        if domain in reserved_domains:
            benchmark.append(row)
            continue
        split = split_for_domain(domain)
        splits[split].append(row)
        quotas[split][row["structures"]["primary"]] += 1
    if any(not splits[name] for name, _ in SEED_PARTITION_RANGES):
        raise ValueError("A registered-domain split has no legitimate rows; cannot evaluate safely.")
    return splits, benchmark, quotas


def sample_phishing_rows(candidate_buckets: dict[str, dict[str, list[dict]]], quotas: dict[str, Counter]) -> tuple[dict[str, list[dict]], dict]:
    selected_by_split = {name: [] for name in quotas}
    composition = {}
    for split, primary_counts in quotas.items():
        used_domains = set()
        remaining = dict(primary_counts)
        # Fill the rare primary structures first so common path-only rows do not
        # consume domains that could supply query-only or home-page examples.
        for primary in sorted(primary_counts, key=lambda category: (primary_counts[category], category)):
            candidates = candidate_buckets.get(split, {}).get(primary, [])
            for row in candidates:
                if remaining[primary] <= 0:
                    break
                if row["domain"] in used_domains:
                    continue
                selected_by_split[split].append(row)
                used_domains.add(row["domain"])
                remaining[primary] -= 1
        shortfalls = {category: count for category, count in remaining.items() if count}
        if shortfalls:
            raise ValueError(f"Insufficient domain-distinct feed URLs for {split} primary categories: {shortfalls}")
        composition[split] = {
            "rows": len(selected_by_split[split]),
            "primary_structure_counts": dict(Counter(row["structures"]["primary"] for row in selected_by_split[split])),
            "registered_domains": len(used_domains),
        }
    return selected_by_split, composition


def write_rows(path: Path, rows: list[dict]) -> None:
    fields = ("url", "label", "source", "provenance", "primary_structure", "structures", "registered_domain")
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "url": row["url"],
                "label": row["label"],
                "source": row["source"],
                "provenance": row["provenance"],
                "primary_structure": row["structures"]["primary"],
                "structures": json.dumps(row["structures"], separators=(",", ":")),
                "registered_domain": row["domain"],
            })


def main() -> None:
    baseline_urls, counterfactual_rows, hard_cohorts = read_public_url_reports()
    reserved_domains = build_reserved_domains(baseline_urls, counterfactual_rows)
    legitimate_rows, legitimate_source = load_positive_rows()
    legitimate_domains = {row["domain"] for row in legitimate_rows}
    domain_split_plan = configure_domain_splits(legitimate_domains, reserved_domains)
    legitimate_splits, reserved_legitimate, split_quotas = assign_legitimate_splits(legitimate_rows, reserved_domains)
    feed_candidates, feed_summary = load_phishing_candidates(
        reserved_domains, legitimate_domains, split_quotas
    )
    phishing_splits, phishing_composition = sample_phishing_rows(feed_candidates, split_quotas)

    experiment_rows = {}
    split_domain_sets = {}
    for split in split_quotas:
        records = legitimate_splits[split] + phishing_splits[split]
        urls_seen = set()
        for row in records:
            if row["url"] in urls_seen:
                raise ValueError(f"Duplicate normalized URL in {split}: {row['url']}")
            urls_seen.add(row["url"])
        experiment_rows[split] = records
        split_domain_sets[split] = {row["domain"] for row in records}
    overlap_counts = {
        f"{left}|{right}": len(split_domain_sets[left] & split_domain_sets[right])
        for index, left in enumerate(split_domain_sets)
        for right in list(split_domain_sets)[index + 1:]
    }
    if any(overlap_counts.values()):
        raise ValueError(f"Registered-domain overlap across splits: {overlap_counts}")

    all_real_rows = [row for records in experiment_rows.values() for row in records]
    feature_names = load_feature_names()
    features = pd.DataFrame(
        [extract_features(row["url"]) for row in all_real_rows],
        columns=FEATURE_NAMES,
    )[feature_names]
    if features.shape[1] != 29 or features.isna().any().any():
        raise ValueError("Feature matrix failed the exact 29-feature schema/finite-value check.")

    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    benchmark_legitimate = reserved_legitimate + legitimate_splits["test"]
    for row in benchmark_legitimate:
        row["benchmark_category"] = row["structures"]["primary"]
    benchmark_phishing = phishing_splits["test"]
    write_rows(BENCHMARK_DIR / "legitimate_domain_disjoint.csv", benchmark_legitimate)
    write_rows(BENCHMARK_DIR / "phishing_domain_disjoint.csv", benchmark_phishing)

    fixed_benchmark = {
        "baseline_legitimate_urls": baseline_urls,
        "counterfactual_legitimate_urls": counterfactual_rows,
        "source": "Reports existing before this experiment; URLs are scored only and are not added as training rows.",
    }
    (BENCHMARK_DIR / "fixed_urls.json").write_text(json.dumps(fixed_benchmark, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    TRAINING_CSV = EXPERIMENT_DIR / "dataset.csv"
    EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)
    dataset_rows = []
    for split, records in experiment_rows.items():
        for row in records:
            dataset_rows.append({**row, "split": split})
    write_rows(TRAINING_CSV, dataset_rows)

    report = {
        "experiment": EXPERIMENT_ID,
        "dataset": str(TRAINING_CSV.relative_to(ROOT)),
        "feature_count": len(feature_names),
        "features": feature_names,
        "legitimate_source": legitimate_source,
        "phishing_source": feed_summary,
        "split_method": "Deterministic SHA-256 rank assignment over legitimate registered domains, with exact target-count quantiles; the resulting cutoffs assign phishing-feed registered domains to the same four partitions. Positive and phishing domains are kept in exactly one partition.",
        "domain_split_plan": domain_split_plan,
        "split_rows": {
            split: {
                "total": len(records),
                "legitimate": sum(row["label"] == 0 for row in records),
                "phishing": sum(row["label"] == 1 for row in records),
                "registered_domains": len(split_domain_sets[split]),
                "source_counts": dict(Counter(row["source"] for row in records)),
                "primary_structures": dict(Counter(row["structures"]["primary"] for row in records)),
            }
            for split, records in experiment_rows.items()
        },
        "phishing_structure_quotas": phishing_composition,
        "registered_domain_split_overlaps": overlap_counts,
        "benchmark": {
            "version": "v1",
            "legitimate_urls": len(benchmark_legitimate),
            "phishing_urls": len(benchmark_phishing),
            "baseline_urls": len(baseline_urls),
            "counterfactual_urls": len(counterfactual_rows),
            "counterfactual_rows_are_evaluation_only": True,
            "no_synthetic_training_urls": True,
        },
        "data_coverage": {
            "legitimate_structure_counts": dict(Counter(tag for row in legitimate_rows for tag, value in row["structures"].items() if isinstance(value, bool) and value)),
            "phishing_structure_counts": dict(Counter(tag for rows in phishing_splits.values() for row in rows for tag, value in row["structures"].items() if isinstance(value, bool) and value)),
            "limitations": [
                "The phishing feed has no fragment-bearing URLs in the sampled pool; fragment-bearing verified legitimate URLs are retained only in the domain-held-out benchmark.",
                "API-like and search URL examples are sparse in the phishing feed and therefore remain explicitly measured as cohort metrics.",
            ],
        },
        "production_modified": False,
        "training_performed": False,
    }
    (EXPERIMENT_DIR / "dataset_composition.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (BENCHMARK_DIR / "manifest.json").write_text(json.dumps({
        "version": "v1",
        "legitimate_csv": "legitimate_domain_disjoint.csv",
        "phishing_csv": "phishing_domain_disjoint.csv",
        "fixed_urls": "fixed_urls.json",
        "source_report": str((EXPERIMENT_DIR / "dataset_composition.json").relative_to(ROOT)),
        "immutable_after_creation": True,
    }, indent=2) + "\n", encoding="utf-8")

    immutable_hashes = {}
    for path in (
        BENCHMARK_DIR / "legitimate_domain_disjoint.csv",
        BENCHMARK_DIR / "phishing_domain_disjoint.csv",
        BENCHMARK_DIR / "fixed_urls.json",
    ):
        immutable_hashes[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    report["benchmark"]["sha256"] = immutable_hashes
    (EXPERIMENT_DIR / "dataset_composition.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    run_candidate_experiments(
        experiment_rows=experiment_rows,
        benchmark_legitimate=benchmark_legitimate,
        benchmark_phishing=benchmark_phishing,
        baseline_urls=baseline_urls,
        counterfactual_rows=counterfactual_rows,
        hard_cohorts=hard_cohorts,
        feature_names=feature_names,
        dataset_report=report,
    )

    print(json.dumps({
        "dataset_rows": len(dataset_rows),
        "split_rows": report["split_rows"],
        "legitimate_benchmark_rows": len(benchmark_legitimate),
        "phishing_benchmark_rows": len(benchmark_phishing),
        "domain_overlaps": overlap_counts,
    }, indent=2))


def load_feature_names() -> list[str]:
    with PRODUCTION_FEATURES_PATH.open("rb") as feature_file:
        names = list(pickle.load(feature_file))
    expected = [name for name in FEATURE_NAMES if name not in MODEL_EXCLUDED_FEATURES]
    if len(names) != 29 or names != expected:
        raise ValueError("Saved feature schema does not match the current 29-feature schema.")
    return names


def make_matrix(rows: list[dict], feature_names: list[str]) -> pd.DataFrame:
    values = [extract_features(row["url"]) for row in rows]
    matrix = pd.DataFrame(values, columns=FEATURE_NAMES)[feature_names]
    if matrix.isna().any().any() or not np.isfinite(matrix.to_numpy(dtype=float)).all():
        raise ValueError("Feature matrix contains missing or non-finite values.")
    return matrix


def domain_class_weights(rows: list[dict]) -> np.ndarray:
    labels = np.asarray([row["label"] for row in rows], dtype=int)
    domains = [row["domain"] for row in rows]
    counts = Counter(domains)
    weights = np.asarray([1.0 / counts[domain] for domain in domains], dtype=float)
    for label in (0, 1):
        mask = labels == label
        if not mask.any():
            raise ValueError(f"A training partition lacks label {label}.")
        weights[mask] *= 0.5 / weights[mask].sum()
    return weights


def create_estimator(model_name: str, random_state: int):
    if model_name == "hist_gradient_boosting":
        return HistGradientBoostingClassifier(
            learning_rate=0.05,
            max_iter=100,
            max_leaf_nodes=31,
            random_state=random_state,
        )
    if model_name == "logistic_regression":
        return Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                max_iter=2500,
                solver="liblinear",
                random_state=random_state,
            )),
        ])
    if model_name == "url_char_logistic":
        return LogisticRegression(
            C=2.0,
            max_iter=2000,
            solver="liblinear",
            random_state=random_state,
        )
    if model_name == "url_char_logistic":
        return LogisticRegression(
            C=2.0,
            max_iter=2000,
            solver="liblinear",
            random_state=random_state,
        )
    if model_name == "random_forest":
        return RandomForestClassifier(
            n_estimators=240,
            min_samples_leaf=2,
            max_features="sqrt",
            n_jobs=-1,
            random_state=random_state,
        )
    raise ValueError(f"Unsupported candidate model: {model_name}")


def fit_estimator(estimator, model_name: str, X, y, sample_weight) -> None:
    if model_name == "logistic_regression":
        estimator.fit(X, y, classifier__sample_weight=sample_weight)
    else:
        estimator.fit(X, y, sample_weight=sample_weight)


def make_candidate_matrix(rows, feature_names, model_name, vectorizer=None, numeric_scaler=None, fit_text=False):
    if model_name != "url_char_logistic":
        return make_matrix(rows, feature_names)
    urls = [row["url"] for row in rows]
    numeric = make_matrix(rows, feature_names)
    if fit_text:
        text = vectorizer.fit_transform(urls)
        numeric_values = numeric_scaler.fit_transform(numeric)
    else:
        text = vectorizer.transform(urls)
        numeric_values = numeric_scaler.transform(numeric)
    return hstack((csr_matrix(numeric_values), text), format="csr", dtype=np.float32)


def raw_positive_probability(estimator, X) -> np.ndarray:
    classes = list(estimator.classes_)
    return estimator.predict_proba(X)[:, classes.index(1)]


def fit_calibrator(estimator, X_cal, calibration_rows):
    from sklearn.linear_model import LogisticRegression as PlattCalibrator

    labels = np.asarray([row["label"] for row in calibration_rows], dtype=int)
    weights = domain_class_weights(calibration_rows)
    raw = raw_positive_probability(estimator, X_cal)
    calibrator = PlattCalibrator(solver="lbfgs", max_iter=1000, random_state=SEED)
    calibrator.fit(raw.reshape(-1, 1), labels, sample_weight=weights)
    return calibrator


def calibrated_probability(estimator, calibrator, X) -> np.ndarray:
    raw = raw_positive_probability(estimator, X)
    return calibrator.predict_proba(raw.reshape(-1, 1))[:, 1]


def choose_threshold(y_validation: np.ndarray, probabilities: np.ndarray) -> dict:
    legitimate = probabilities[y_validation == 0]
    phishing = probabilities[y_validation == 1]
    if not len(legitimate) or not len(phishing):
        raise ValueError("Validation partition must contain both classes.")
    max_false_positives = int(math.floor(MAX_FPR_FOR_THRESHOLD * len(legitimate)))
    ordered_legitimate = np.sort(legitimate)[::-1]
    if max_false_positives >= len(ordered_legitimate):
        threshold = 0.0
    elif max_false_positives == 0:
        threshold = float(np.nextafter(ordered_legitimate[0], 1.0))
    else:
        threshold = float(np.nextafter(ordered_legitimate[max_false_positives], 1.0))
    validation_predicted = probabilities >= threshold
    validation_fpr = float(np.mean(validation_predicted[y_validation == 0]))
    validation_recall = float(np.mean(validation_predicted[y_validation == 1]))
    return {
        "phishing_threshold": threshold,
        "selected_on": "domain-disjoint validation partition only",
        "maximum_validation_fpr": MAX_FPR_FOR_THRESHOLD,
        "validation_fpr": validation_fpr,
        "validation_phishing_recall": validation_recall,
        "validation_legitimate_rows": int(len(legitimate)),
        "validation_phishing_rows": int(len(phishing)),
    }


def expected_calibration_error(y_true: np.ndarray, probabilities: np.ndarray, bins: int = 10) -> float:
    boundaries = np.linspace(0.0, 1.0, bins + 1)
    ece = 0.0
    for index in range(bins):
        low, high = boundaries[index], boundaries[index + 1]
        mask = (probabilities >= low) & (
            (probabilities < high) if index < bins - 1 else (probabilities <= high)
        )
        if mask.any():
            ece += float(mask.mean()) * abs(float(probabilities[mask].mean()) - float(y_true[mask].mean()))
    return ece


def metric_summary(rows: list[dict], probabilities: np.ndarray, threshold: float) -> dict:
    labels = np.asarray([row["label"] for row in rows], dtype=int)
    predicted = (probabilities >= threshold).astype(int)
    positives = labels == 1
    negatives = labels == 0
    return {
        "rows": len(rows),
        "legitimate_rows": int(negatives.sum()),
        "phishing_rows": int(positives.sum()),
        "decision_threshold": float(threshold),
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "phishing_recall": float(recall_score(labels, predicted, zero_division=0)),
        "phishing_fnr": float(1.0 - recall_score(labels, predicted, zero_division=0)),
        "f1": float(f1_score(labels, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, probabilities)) if len(set(labels)) > 1 else None,
        "pr_auc": float(average_precision_score(labels, probabilities)) if len(set(labels)) > 1 else None,
        "brier_score": float(brier_score_loss(labels, probabilities)),
        "ece": expected_calibration_error(labels, probabilities),
        "legitimate_fpr": float(np.mean(predicted[negatives])) if negatives.any() else None,
        "confusion": {
            "tn": int(((labels == 0) & (predicted == 0)).sum()),
            "fp": int(((labels == 0) & (predicted == 1)).sum()),
            "fn": int(((labels == 1) & (predicted == 0)).sum()),
            "tp": int(((labels == 1) & (predicted == 1)).sum()),
        },
    }


def label_verdict(probability: float, safe_threshold: float, phishing_threshold: float) -> str:
    if probability >= phishing_threshold:
        return "PHISHING"
    if probability >= safe_threshold:
        return "SUSPICIOUS"
    return "SAFE"


def score_urls(estimator, calibrator, feature_names, urls: list[str], model_name="hist_gradient_boosting", vectorizer=None, numeric_scaler=None) -> np.ndarray:
    rows = [{"url": url} for url in urls]
    matrix = make_candidate_matrix(rows, feature_names, model_name, vectorizer, numeric_scaler)
    return calibrated_probability(estimator, calibrator, matrix)


def legitimate_benchmark(estimator, calibrator, feature_names, threshold, safe_threshold, rows, baseline_urls, counterfactual_rows, model_name="hist_gradient_boosting", vectorizer=None, numeric_scaler=None):
    urls = [row["url"] for row in rows] + baseline_urls + [row["url"] for row in counterfactual_rows]
    probabilities = score_urls(estimator, calibrator, feature_names, urls, model_name, vectorizer, numeric_scaler)
    labels = [label_verdict(float(score), safe_threshold, threshold) for score in probabilities]
    baseline_end = len(rows) + len(baseline_urls)
    baseline_labels = labels[len(rows):baseline_end]
    counter_labels = labels[baseline_end:]
    homepage_scores = {}
    counterfactual_probs = probabilities[baseline_end:]
    for row, score in zip(counterfactual_rows, counterfactual_probs):
        if row["variant_type"] == "homepage":
            homepage_scores[row["base_url"]] = float(score)
    deltas = defaultdict(list)
    for row, score in zip(counterfactual_rows, counterfactual_probs):
        if row["variant_type"] != "homepage" and row["base_url"] in homepage_scores:
            deltas[row["variant_type"]].append(float(score) - homepage_scores[row["base_url"]])
    counter_summary = {}
    for variant, values in deltas.items():
        counter_summary[variant] = {
            "samples": len(values),
            "median_probability_delta": float(np.median(values)),
            "mean_probability_delta": float(np.mean(values)),
            "maximum_probability_delta": float(np.max(values)),
            "positive_delta_count": int(sum(value > 0 for value in values)),
            "systematic_jump": bool(float(np.median(values)) >= 0.20),
        }
    return {
        "combined_legitimate_urls": {
            "count": len(urls),
            "phishing_count": int(labels.count("PHISHING")),
            "fpr": labels.count("PHISHING") / len(labels) if labels else None,
            "safe": labels.count("SAFE"),
            "suspicious": labels.count("SUSPICIOUS"),
            "phishing": labels.count("PHISHING"),
            "average_probability": float(probabilities.mean()) if len(probabilities) else None,
            "maximum_probability": float(probabilities.max()) if len(probabilities) else None,
        },
        "verified_legitimate_domain_test": {
            "count": len(rows),
            "phishing_count": int(sum(label == "PHISHING" for label in labels[: len(rows)])),
            "fpr": float(sum(label == "PHISHING" for label in labels[: len(rows)]) / len(rows)) if rows else None,
        },
        "fixed_baseline": {"count": len(baseline_urls), "verdicts": dict(Counter(baseline_labels))},
        "counterfactuals": {
            "count": len(counterfactual_rows),
            "verdicts": dict(Counter(counter_labels)),
            "per_variant": counter_summary,
        },
        "highest_probability_examples": sorted(
            ({"url": url, "probability": float(score), "verdict": verdict}
             for url, score, verdict in zip(urls, probabilities, labels)),
            key=lambda item: item["probability"], reverse=True,
        )[:25],
    }


def score_hard_cohorts(estimator, calibrator, feature_names, threshold, hard_cohorts, trained_domains, model_name="hist_gradient_boosting", vectorizer=None, numeric_scaler=None):
    outputs = {}
    all_examples = {}
    for category, section in hard_cohorts.items():
        if not isinstance(section, dict):
            continue
        unique = {}
        excluded_training_domain = 0
        for example in section.get("examples", []):
            if not isinstance(example, dict) or example.get("label") != 1 or not example.get("url"):
                continue
            url = normalize_url(example["url"])
            domain = get_registered_domain(url)
            key = _analysis_url(url)
            if domain in trained_domains:
                excluded_training_domain += 1
                continue
            unique.setdefault(key, url)
        urls = list(unique.values())
        if urls:
            probabilities = score_urls(estimator, calibrator, feature_names, urls, model_name, vectorizer, numeric_scaler)
            recall = float(np.mean(probabilities >= threshold))
        else:
            probabilities = np.asarray([], dtype=float)
            recall = None
        outputs[category] = {
            "samples": len(urls),
            "excluded_due_to_training_domain_overlap": excluded_training_domain,
            "candidate_phishing_recall": recall,
        }
        all_examples[category] = [(url, float(probability)) for url, probability in zip(urls, probabilities)]
    return outputs, all_examples


def production_hard_cohort_recall(all_examples: dict, production_thresholds: dict) -> dict:
    output = {}
    for category, examples in all_examples.items():
        if not examples:
            output[category] = {"samples": 0, "production_phishing_recall": None}
            continue
        results = [scan(url) for url, _ in examples]
        output[category] = {
            "samples": len(results),
            "production_phishing_recall": sum(result["probability"] >= production_thresholds["phishing"] for result in results) / len(results),
        }
    return output


def ece_for_probabilities(y: np.ndarray, p: np.ndarray) -> float:
    return expected_calibration_error(y, p)


def candidate_importance(estimator, model_name: str, feature_names: list[str], X_validation, y_validation) -> dict:
    if model_name == "hist_gradient_boosting" and hasattr(estimator, "_predictors"):
        gains = [0.0] * len(feature_names)
        for iteration in estimator._predictors:
            for tree in iteration:
                for node in tree.nodes:
                    feature_index = int(node["feature_idx"])
                    gain = float(node["gain"])
                    if 0 <= feature_index < len(gains) and gain > 0:
                        gains[feature_index] += gain
        total = sum(gains) or 1.0
        importance = sorted(
            ({"feature": feature, "normalized_split_gain": gains[i] / total} for i, feature in enumerate(feature_names)),
            key=lambda row: row["normalized_split_gain"], reverse=True,
        )
    elif hasattr(estimator, "feature_importances_"):
        importance = sorted(
            ({"feature": feature, "importance": float(value)} for feature, value in zip(feature_names, estimator.feature_importances_)),
            key=lambda row: row["importance"], reverse=True,
        )
    elif model_name == "logistic_regression":
        coefficients = estimator.named_steps["classifier"].coef_[0]
        importance = sorted(
            ({"feature": feature, "absolute_coefficient": abs(float(value))} for feature, value in zip(feature_names, coefficients)),
            key=lambda row: row["absolute_coefficient"], reverse=True,
        )
    elif model_name == "url_char_logistic":
        coefficients = estimator.coef_[0]
        importance = sorted(
            ({"feature": feature, "absolute_coefficient": abs(float(value))} for feature, value in zip(feature_names, coefficients)),
            key=lambda row: row["absolute_coefficient"], reverse=True,
        )
    else:
        importance = []
    if model_name == "url_char_logistic":
        return {
            "model_importance_top_10": importance[:10],
            "validation_permutation_importance_top_10": None,
            "permutation_note": "Skipped for the high-dimensional character n-gram feature space; coefficient magnitudes are reported instead.",
        }
    permutation = permutation_importance(
        estimator,
        X_validation,
        y_validation,
        scoring="average_precision",
        n_repeats=3,
        random_state=SEED,
        n_jobs=1,
    )
    permutation_rows = sorted(
        ({"feature": feature, "importance_mean": float(permutation.importances_mean[i]), "importance_std": float(permutation.importances_std[i])} for i, feature in enumerate(feature_names)),
        key=lambda row: row["importance_mean"], reverse=True,
    )
    return {"model_importance_top_10": importance[:10], "validation_permutation_importance_top_10": permutation_rows[:10]}


def evaluate_model(model_name, feature_variant, feature_names, splits, benchmark_legitimate, benchmark_phishing, baseline_urls, counterfactual_rows, hard_cohorts, metadata):
    model_id = f"{model_name}_{feature_variant}"
    model_dir = EXPERIMENT_DIR / "candidates" / model_id
    model_dir.mkdir(parents=True, exist_ok=True)

    train_rows = splits["train"]
    cal_rows = splits["calibration"]
    val_rows = splits["validation"]
    test_rows = splits["test"]
    vectorizer = None
    numeric_scaler = None
    if model_name == "url_char_logistic":
        vectorizer = TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=25_000,
            sublinear_tf=True,
            dtype=np.float32,
        )
        numeric_scaler = StandardScaler()
        matrices = {
            "train": make_candidate_matrix(
                splits["train"], feature_names, model_name,
                vectorizer, numeric_scaler, fit_text=True,
            )
        }
        matrices.update({
            name: make_candidate_matrix(
                rows, feature_names, model_name, vectorizer, numeric_scaler
            )
            for name, rows in splits.items()
            if name != "train"
        })
        model_feature_names = feature_names + [
            f"url_char_ngram:{ngram}" for ngram in vectorizer.get_feature_names_out()
        ]
    else:
        matrices = {name: make_matrix(rows, feature_names) for name, rows in splits.items()}
        model_feature_names = feature_names
    y_train = np.asarray([row["label"] for row in train_rows], dtype=int)
    y_cal = np.asarray([row["label"] for row in cal_rows], dtype=int)
    y_val = np.asarray([row["label"] for row in val_rows], dtype=int)
    y_test = np.asarray([row["label"] for row in test_rows], dtype=int)

    estimator = create_estimator(model_name, SEED)
    train_weights = domain_class_weights(train_rows)
    started = time.perf_counter()
    fit_estimator(estimator, model_name, matrices["train"], y_train, train_weights)
    training_seconds = time.perf_counter() - started
    raw_cal = raw_positive_probability(estimator, matrices["calibration"])
    calibrator = LogisticRegression(solver="lbfgs", max_iter=1000, random_state=SEED)
    calibrator.fit(raw_cal.reshape(-1, 1), y_cal, sample_weight=domain_class_weights(cal_rows))

    val_probability = calibrated_probability(estimator, calibrator, matrices["validation"])
    threshold = choose_threshold(y_val, val_probability)
    test_probability = calibrated_probability(estimator, calibrator, matrices["test"])
    test_metrics = metric_summary(test_rows, test_probability, threshold["phishing_threshold"])
    test_domains = {row["domain"] for row in test_rows}
    train_domains = {row["domain"] for row in train_rows}
    cal_domains = {row["domain"] for row in cal_rows}
    val_domains = {row["domain"] for row in val_rows}
    benchmark_legit_result = legitimate_benchmark(
        estimator,
        calibrator,
        feature_names,
        threshold["phishing_threshold"],
        metadata["thresholds"]["safe"],
        benchmark_legitimate,
        baseline_urls,
        counterfactual_rows,
        model_name,
        vectorizer,
        numeric_scaler,
    )
    hard_results, hard_examples = score_hard_cohorts(
        estimator, calibrator, feature_names, threshold["phishing_threshold"],
        hard_cohorts, train_domains | cal_domains | val_domains,
        model_name, vectorizer, numeric_scaler,
    )
    hard_production = production_hard_cohort_recall(hard_examples, metadata["thresholds"])
    for cohort, result in hard_results.items():
        result["production_phishing_recall_same_nontraining_domains"] = hard_production.get(cohort, {}).get("production_phishing_recall")
        baseline_recall = result["production_phishing_recall_same_nontraining_domains"]
        result["not_major_regression"] = (
            result["candidate_phishing_recall"] is not None
            and baseline_recall is not None
            and result["candidate_phishing_recall"] >= baseline_recall - 0.10
        ) if baseline_recall is not None else None

    phishing_recall = test_metrics["phishing_recall"]
    legitimate_fpr = benchmark_legit_result["combined_legitimate_urls"]["fpr"]
    baseline_phishing = benchmark_legit_result["fixed_baseline"]["verdicts"].get("PHISHING", 0)
    counterfactual_jump = any(
        item["systematic_jump"]
        for item in benchmark_legit_result["counterfactuals"]["per_variant"].values()
    )
    hard_ok = all(item["not_major_regression"] is not False for item in hard_results.values())
    gates = {
        "fixed_and_verified_legitimate_phishing_count_zero": baseline_phishing == 0 and benchmark_legit_result["combined_legitimate_urls"]["phishing"] == 0,
        "legitimate_fpr_le_0_5_percent": legitimate_fpr is not None and legitimate_fpr <= 0.005,
        "phishing_recall_at_least_98_percent": phishing_recall >= MIN_PHISH_RECALL,
        "domain_disjoint_test_recall_at_least_97_percent": phishing_recall >= MIN_DOMAIN_RECALL,
        "no_major_existing_hard_cohort_regression": hard_ok,
        "no_systematic_counterfactual_structure_jump": not counterfactual_jump,
        "same_registered_domain_splits": len(test_domains & train_domains) == 0 and len(test_domains & cal_domains) == 0 and len(test_domains & val_domains) == 0,
        "includes_current_29_numeric_features": len(feature_names) == 29,
    }

    probability_latency_ms = []
    for _ in range(8):
        started = time.perf_counter()
        calibrated_probability(estimator, calibrator, matrices["test"])
        probability_latency_ms.append((time.perf_counter() - started) * 1000 / max(1, len(test_rows)))

    artifact_path = model_dir / "candidate.joblib"
    joblib.dump({
        "estimator": estimator,
        "calibrator": calibrator,
        "feature_names": feature_names,
        "model_feature_names": model_feature_names if model_name == "url_char_logistic" else None,
        "vectorizer": vectorizer,
        "numeric_scaler": numeric_scaler,
        "model_name": model_name,
        "feature_variant": feature_variant,
        "seed": SEED,
        "phishing_threshold": threshold["phishing_threshold"],
    }, artifact_path)

    config = {
        "model_name": model_name,
        "feature_variant": feature_variant,
        "feature_names": feature_names,
        "additional_features": {
            "type": "full URL character TF-IDF n-grams (3,5)" if model_name == "url_char_logistic" else None,
            "max_features": 25_000 if model_name == "url_char_logistic" else None,
            "fitted_on": "training partition only" if model_name == "url_char_logistic" else None,
            "model_input_feature_count": len(model_feature_names),
        },
        "parameters": estimator.get_params(deep=True),
        "weighting": "Inverse per-registered-domain row count, normalized to equal total weight for each class in training/calibration partitions.",
        "calibration": "LogisticRegression on a separate registered-domain-disjoint calibration partition.",
        "threshold_selection": threshold,
        "seed": SEED,
        "training_seconds": training_seconds,
    }
    (model_dir / "configuration.json").write_text(json.dumps(config, indent=2, default=str) + "\n", encoding="utf-8")

    validation_pred = val_probability >= threshold["phishing_threshold"]
    failure_analysis = {
        "false_phishing_benchmark_examples": benchmark_legit_result["highest_probability_examples"][:10],
        "counterfactuals": benchmark_legit_result["counterfactuals"],
        "hard_cohort_results": hard_results,
        "threshold_validation_confusion": {
            "legitimate_false_positives": int(((y_val == 0) & validation_pred).sum()),
            "legitimate_rows": int((y_val == 0).sum()),
            "phishing_false_negatives": int(((y_val == 1) & ~validation_pred).sum()),
            "phishing_rows": int((y_val == 1).sum()),
        },
        "data_limitations": [
            "The active phishing feed contains no fragment-bearing URLs; no fragment phishing labels were invented.",
            "API/search patterns are less common in the phishing feed; per-cohort sample counts are included in dataset composition.",
        ],
    }
    metrics = {
        "experiment": EXPERIMENT_ID,
        "candidate": model_id,
        "candidate_artifact": str(artifact_path.relative_to(ROOT)),
        "feature_count": len(model_feature_names),
        "production_numeric_feature_count": len(feature_names),
        "selected_threshold": threshold,
        "validation_at_selected_threshold": metric_summary(val_rows, val_probability, threshold["phishing_threshold"]),
        "domain_disjoint_test_at_selected_threshold": test_metrics,
        "domain_disjoint_test_at_0_5": metric_summary(test_rows, test_probability, 0.5),
        "legitimate_benchmark": benchmark_legit_result,
        "phishing_benchmark": {
            "rows": len(test_rows),
            "phishing_recall": test_metrics["phishing_recall"],
            "false_negative_rate": test_metrics["phishing_fnr"],
            "features": dict(Counter(tag for row in test_rows for tag, value in row["structures"].items() if isinstance(value, bool) and value)),
        },
        "hard_phishing_cohorts": hard_results,
        "model_size_bytes": artifact_path.stat().st_size,
        "median_inference_latency_ms_per_url": float(np.median(probability_latency_ms)),
        "gates": gates,
        "all_model_gates_pass": all(gates.values()),
    }
    (model_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (model_dir / "failure_analysis.json").write_text(json.dumps(failure_analysis, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    importance = candidate_importance(
        estimator, model_name, model_feature_names, matrices["validation"], y_val
    )
    (model_dir / "validation_feature_importance.json").write_text(
        json.dumps(importance, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    metrics["feature_importance"] = importance
    (model_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return metrics


def run_candidate_experiments(experiment_rows, benchmark_legitimate, benchmark_phishing, baseline_urls, counterfactual_rows, hard_cohorts, feature_names, dataset_report):
    import copy

    with METADATA_PATH.open(encoding="utf-8") as metadata_file:
        metadata = json.load(metadata_file)
    if metadata.get("feature_count") != 29 or len(feature_names) != 29:
        raise ValueError("Production feature schema is not exactly 29 features.")

    model_configs = [
        ("hist_gradient_boosting", "production_29", feature_names),
        ("logistic_regression", "production_29", feature_names),
        ("random_forest", "production_29", feature_names),
        ("hist_gradient_boosting", "drop_PathLength", [name for name in feature_names if name != "PathLength"]),
        ("url_char_logistic", "url_char_3_5_plus_29", feature_names),
    ]
    results = []
    all_split_domains = {
        split: {row["domain"] for row in rows}
        for split, rows in experiment_rows.items()
    }
    print("Domain split row counts:", {split: len(rows) for split, rows in experiment_rows.items()}, flush=True)

    for model_name, feature_variant, selected_features in model_configs:
        try:
            result = evaluate_model(
                model_name,
                feature_variant,
                selected_features,
                experiment_rows,
                benchmark_legitimate,
                benchmark_phishing,
                baseline_urls,
                counterfactual_rows,
                hard_cohorts,
                metadata,
            )
            result["registered_domain_overlaps"] = {
                f"{left}|{right}": len(all_split_domains[left] & all_split_domains[right])
                for i, left in enumerate(all_split_domains)
                for right in list(all_split_domains)[i + 1:]
            }
            results.append(result)
            print(json.dumps({
                "candidate": result["candidate"],
                "test_recall": result["domain_disjoint_test_at_selected_threshold"]["phishing_recall"],
                "test_legitimate_fpr": result["domain_disjoint_test_at_selected_threshold"]["legitimate_fpr"],
                "benchmark_legitimate_fpr": result["legitimate_benchmark"]["combined_legitimate_urls"]["fpr"],
                "gates_passed": [name for name, passed in result["gates"].items() if passed],
            }, sort_keys=True), flush=True)
        except Exception as error:
            results.append({
                "candidate": f"{model_name}_{feature_variant}",
                "error": f"{type(error).__name__}: {error}",
                "all_model_gates_pass": False,
            })
            print(f"Candidate {model_name}_{feature_variant} failed: {type(error).__name__}: {error}", flush=True)

    eligible = [result for result in results if "error" not in result]
    leaderboard_rows = sorted(
        eligible,
        key=lambda result: (
            result["all_model_gates_pass"],
            -result["legitimate_benchmark"]["combined_legitimate_urls"]["fpr"],
            result["domain_disjoint_test_at_selected_threshold"]["phishing_recall"],
            result["domain_disjoint_test_at_selected_threshold"]["f1"],
            result["domain_disjoint_test_at_selected_threshold"]["pr_auc"],
            -result["domain_disjoint_test_at_selected_threshold"]["ece"],
        ),
        reverse=True,
    )
    leaderboard = load_json(LEADERBOARD_PATH) if LEADERBOARD_PATH.exists() else {"candidates": []}
    old_rows = [row for row in leaderboard.get("candidates", []) if row.get("experiment") != EXPERIMENT_ID]
    short_rows = [{
        "experiment": EXPERIMENT_ID,
        "candidate": result["candidate"],
        "gate_pass": result["all_model_gates_pass"],
        "legitimate_fpr": result["legitimate_benchmark"]["combined_legitimate_urls"]["fpr"],
        "phishing_recall": result["domain_disjoint_test_at_selected_threshold"]["phishing_recall"],
        "f1": result["domain_disjoint_test_at_selected_threshold"]["f1"],
        "pr_auc": result["domain_disjoint_test_at_selected_threshold"]["pr_auc"],
        "brier_score": result["domain_disjoint_test_at_selected_threshold"]["brier_score"],
        "model_size_bytes": result["model_size_bytes"],
        "artifact": result["candidate_artifact"],
    } for result in results if "error" not in result]
    leaderboard["candidates"] = sorted(old_rows + short_rows, key=lambda row: (row["gate_pass"], -row["legitimate_fpr"], row["phishing_recall"], row["f1"], row["pr_auc"], -row["brier_score"]), reverse=True)
    LEADERBOARD_PATH.parent.mkdir(parents=True, exist_ok=True)
    LEADERBOARD_PATH.write_text(json.dumps(leaderboard, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    experiment_summary = {
        "experiment": EXPERIMENT_ID,
        "training_or_promotion_performed": True,
        "production_modified": False,
        "dataset_composition": dataset_report,
        "candidates": results,
        "best_candidate": leaderboard_rows[0]["candidate"] if leaderboard_rows else None,
        "best_candidate_passes_all_gates": leaderboard_rows[0]["all_model_gates_pass"] if leaderboard_rows else False,
        "production_artifact_paths_modified": [],
    }
    (EXPERIMENT_DIR / "experiment_report.json").write_text(json.dumps(experiment_summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_feature_names() -> list[str]:
    with PRODUCTION_FEATURES_PATH.open("rb") as feature_file:
        names = list(pickle.load(feature_file))
    expected = [name for name in FEATURE_NAMES if name not in MODEL_EXCLUDED_FEATURES]
    if len(names) != 29 or names != expected:
        raise ValueError("Saved feature schema does not match the current 29-feature schema.")
    return names


if __name__ == "__main__":
    main()