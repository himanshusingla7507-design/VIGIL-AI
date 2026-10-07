"""Train domain-grouped candidates with provenance-verified benign dynamic URLs."""
from __future__ import annotations

import hashlib
import json
import os
import pickle
import sys
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATASET = os.path.join(ROOT, "data", "processed", "clean_dataset.csv")
BENIGN_DATASET = os.path.join(ROOT, "data", "benign_dynamic_urls.csv")
SOURCE_MANIFEST = os.path.join(ROOT, "reports", "benign_dynamic_url_sources.json")
EXTERNAL = os.path.join(ROOT, "data", "processed", "external_validation.csv")
REPORT = os.path.join(ROOT, "reports", "benign_dynamic_url_training.json")
DOCUMENT = os.path.join(ROOT, "docs", "BENIGN_DYNAMIC_URL_TRAINING.md")
MODEL_OUTPUT = os.path.join(ROOT, "models", "experimental", "benign_dynamic_url")
SEED = 20261007
DYNAMIC_WEIGHT_CAP = 50.0
FEATURES_OF_INTEREST = [
    "URLLength", "PathLength", "QueryLength", "PathSegmentCount",
    "QueryParameterCount", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "URLPercentEncodingCount", "URLEntropy", "DigitRatioInURL", "NoOfDigitsInURL",
]
REGRESSION_URLS = [
    "https://www.google.com/",
    "https://www.google.com/search?q=test",
    "https://www.google.com/search?q=cybersecurity",
    "https://www.youtube.com/",
    "https://www.youtube.com/?feature=ytca",
    "https://fast.com/",
]


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def effective_calibration_metrics(y, probability, sample_weight):
    y = np.asarray(y, dtype=int)
    probability = np.asarray(probability, dtype=float)
    weights = np.asarray(sample_weight, dtype=float)
    edges = np.linspace(0, 1, 11)
    total_weight = max(float(weights.sum()), 1.0)
    ece = 0.0
    bins = []
    for index, lower in enumerate(edges[:-1]):
        upper = edges[index + 1]
        mask = (probability >= lower) & (
            (probability < upper) if upper < 1 else (probability <= upper)
        )
        if not mask.any():
            continue
        bin_weight = float(weights[mask].sum())
        average_probability = float(np.average(probability[mask], weights=weights[mask]))
        positive_rate = float(np.average(y[mask], weights=weights[mask]))
        ece += bin_weight / total_weight * abs(average_probability - positive_rate)
        bins.append({
            "lower": float(lower),
            "upper": float(upper),
            "rows": int(mask.sum()),
            "weight": bin_weight,
            "mean_probability": average_probability,
            "positive_rate": positive_rate,
        })
    return {"ece": float(ece), "bins": bins}


def metrics(y, probability, threshold, sample_weight=None):
    y = np.asarray(y, dtype=int)
    probability = np.asarray(probability, dtype=float)
    weights = np.ones(len(y), dtype=float) if sample_weight is None else np.asarray(sample_weight, float)
    prediction = probability >= threshold
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    weighted_tn, weighted_fp, weighted_fn, weighted_tp = confusion_matrix(
        y, prediction, labels=[0, 1], sample_weight=weights
    ).ravel()
    return {
        "rows": int(len(y)),
        "pr_auc": float(average_precision_score(y, probability, sample_weight=weights)),
        "roc_auc": float(roc_auc_score(y, probability, sample_weight=weights)),
        "precision": float(precision_score(y, prediction, sample_weight=weights, zero_division=0)),
        "recall": float(recall_score(y, prediction, sample_weight=weights, zero_division=0)),
        "f1": float(f1_score(y, prediction, sample_weight=weights, zero_division=0)),
        "fnr": float(weighted_fn / max(weighted_fn + weighted_tp, 1.0)),
        "fpr": float(weighted_fp / max(weighted_fp + weighted_tn, 1.0)),
        "brier": float(brier_score_loss(y, probability, sample_weight=weights)),
        "ece": effective_calibration_metrics(y, probability, weights)["ece"],
        "raw_confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "weighted_confusion_matrix": [
            [float(weighted_tn), float(weighted_fp)],
            [float(weighted_fn), float(weighted_tp)],
        ],
    }


def decision_thresholds(y, probability, weight, dynamic_mask):
    y = np.asarray(y, dtype=int)
    probability = np.asarray(probability, dtype=float)
    weight = np.asarray(weight, dtype=float)
    dynamic_mask = np.asarray(dynamic_mask, dtype=bool)
    negatives = y == 0
    dynamic_negatives = negatives & dynamic_mask
    candidates = np.unique(np.r_[probability[negatives], 1.0])
    feasible = []
    for threshold in candidates:
        fp = (probability >= threshold) & negatives
        global_fpr = float(weight[fp].sum() / max(weight[negatives].sum(), 1.0))
        if dynamic_negatives.any():
            dynamic_fpr = float((probability[dynamic_negatives] >= threshold).mean())
        else:
            dynamic_fpr = 0.0
        if global_fpr <= 0.01 and dynamic_fpr <= 0.01:
            recall = float((probability[y == 1] >= threshold).mean())
            feasible.append((recall, -float(threshold), float(threshold), global_fpr, dynamic_fpr))
    if not feasible:
        phishing_threshold = float(np.nextafter(1.0, np.inf))
        threshold_validation = {
            "feasible": False,
            "global_fpr": None,
            "dynamic_fpr": None,
            "phishing_recall": 0.0,
        }
    else:
        best = max(feasible)
        _recall, _negative_threshold, phishing_threshold, global_fpr, dynamic_fpr = best
        threshold_validation = {
            "feasible": True,
            "global_fpr": global_fpr,
            "dynamic_fpr": dynamic_fpr,
            "phishing_recall": _recall,
        }
    positive = y == 1
    positive_weight = weight[positive]
    positive_scores = probability[positive]
    safe_candidates = np.unique(np.r_[0.0, positive_scores])
    safe_feasible = []
    for threshold in safe_candidates:
        false_safe = positive_scores < threshold
        rate = float(positive_weight[false_safe].sum() / max(positive_weight.sum(), 1.0))
        if rate <= 0.02:
            safe_feasible.append(float(threshold))
    safe_threshold = max(safe_feasible) if safe_feasible else 0.0
    if safe_threshold >= phishing_threshold:
        safe_threshold = max(0.0, phishing_threshold - 1e-6)
    return {
        "safe": safe_threshold,
        "phishing": phishing_threshold,
        "selection_validation": threshold_validation,
        "selection_policy": "separate registered-domain threshold partition; phishing cutoff constrained to <=1% source-weighted negative FPR and <=1% dynamic-legitimate FPR",
    }


def inference_latency(predict, repeats=50):
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        predict()
        samples.append((time.perf_counter() - start) * 1000)
    return {
        "median_ms": float(np.median(samples)),
        "p95_ms": float(np.percentile(samples, 95)),
    }


def verdict(probability, thresholds):
    if probability < thresholds["safe"]:
        return "SAFE"
    if probability >= thresholds["phishing"]:
        return "PHISHING"
    return "SUSPICIOUS"


def feature_distribution(frame, feature_matrix):
    report = {}
    masks = {
        "existing_legitimate": frame.label.eq(0) & frame.source.ne("verified_benign_dynamic_urls"),
        "new_legitimate_dynamic": frame.source.eq("verified_benign_dynamic_urls"),
        "phishing": frame.label.eq(1),
    }
    for cohort, mask in masks.items():
        indexes = np.flatnonzero(mask.to_numpy())
        values = feature_matrix.iloc[indexes][FEATURES_OF_INTEREST]
        report[cohort] = {
            "rows": int(len(indexes)),
            "statistics": {
                column: {
                    "mean": float(values[column].mean()),
                    "median": float(values[column].median()),
                    "p90": float(values[column].quantile(0.90)),
                    "min": float(values[column].min()),
                    "max": float(values[column].max()),
                }
                for column in FEATURES_OF_INTEREST
            },
        }
    return report


def select_phishing_examples(test_frame):
    from feature_extractor import extract_features

    positive = test_frame[test_frame.label.eq(1)].copy()
    parsed = positive.url.map(urlsplit)
    query = parsed.map(lambda item: item.query)
    path = parsed.map(lambda item: item.path)
    hostname = parsed.map(lambda item: (item.hostname or "").lower())
    masks = {
        "query_strings": query.ne(""),
        "paths": path.map(lambda value: value not in ("", "/")),
        "login_parameters": positive.url.map(
            lambda value: any(
                any(token in key.lower() for token in ("login", "signin", "user", "pass", "account"))
                for key, _ in parse_qsl(urlsplit(value).query, keep_blank_values=True)
            )
        ),
        "encoded_values": positive.url.str.contains(r"%[0-9a-fA-F]{2}", regex=True),
        "long_urls_over_200": positive.url.str.len().gt(200),
        "redirect_parameters": positive.url.map(
            lambda value: any(
                key.lower() in {"url", "redirect", "redirect_url", "return", "returnto", "next", "continue", "target", "dest", "destination", "out"}
                for key, _ in parse_qsl(urlsplit(value).query, keep_blank_values=True)
            )
        ),
        "brand_like_hostnames": hostname.str.contains(
            r"google|paypal|microsoft|apple|amazon|facebook|netflix|outlook",
            regex=True,
            na=False,
        ),
    }
    result = {}
    for name, mask in masks.items():
        rows = positive.loc[mask]
        chosen = sorted(
            rows.url,
            key=lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest(),
        )[:5]
        result[name] = {
            "available_rows_in_held_out_domain_test": int(len(rows)),
            "_test_row_indices": rows.index.to_list(),
            "examples": [
                {"url": url, "label": 1, "source": str(positive.loc[positive.url.eq(url), "source"].iloc[0])}
                for url in chosen
            ],
        }
    return result


def write_report(report):
    with open(REPORT, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
    write_markdown(report)


def write_markdown(report):
    lines = [
        "# Verified Benign Dynamic URL Training Experiment",
        "",
        f"## {report['decision']}",
        "",
        "Production artifacts were not modified. All candidates and thresholds are experimental.",
        "",
        "## Sources and provenance",
        "",
        f"Collected {report['dataset']['dynamic_rows']:,} benign dynamic URLs from {report['dataset']['source_count']} first-party sources on {report['dataset']['collection_date']}.",
        "",
        "URLs are existing same-registered-domain links parsed from publicly accessible source pages, then individually fetched over certificate-validated HTTPS. Only successful 2xx responses whose final registered domain stayed within that same source domain are labeled legitimate. The original href was retained; no query/path/fragment components were synthesized. Each CSV row includes its source page, source, reason, status, final URL, and collection date.",
        "",
        "| Source | Verified URLs | Categories | Collection date |",
        "|---|---:|---|---|",
    ]
    for source in report["sources"]["source_records"]:
        lines.append(
            f"| {source['source_name']} | {source['verified_urls']} | "
            f"{', '.join(f'{key}: {value}' for key, value in source.get('category_counts', {}).items()) or 'none'} | "
            f"{source['collection_date']} |"
        )
    lines.extend([
        "",
        "## Cleaning, deduplication, and domain split",
        "",
        f"Exact duplicates removed: {report['dataset']['deduplication']['exact_duplicate_urls_removed']}; normalized duplicates removed: {report['dataset']['deduplication']['normalized_duplicate_urls_removed']}; duplicates against the existing labeled corpus removed: {report['dataset']['deduplication']['cross_source_or_existing_dataset_duplicates_removed']}.",
        "",
        f"Dynamic cohort split by registered domain: train domains **{report['domain_split']['dynamic_train_domains']}**, validation domains **{report['domain_split']['dynamic_validation_domains']}**, overlap **{report['domain_split']['overlapping_domains']}**. Training/calibration/threshold/test partitions are pairwise registered-domain disjoint.",
        "",
        "## Cohort counts",
        "",
        "| Category | URLs |",
        "|---|---:|",
    ])
    for category, count in report["dataset"]["category_counts"].items():
        lines.append(f"| {category} | {count} |")
    lines.extend([
        "",
        "Zero-count categories are disclosed rather than synthetically filled; no dataset row is labeled from model predictions.",
        "",
        "## Feature distributions",
        "",
        "Values are per URL; mean, median, and p90 are reported for the three requested label cohorts.",
        "",
        "| Feature | Existing legitimate median (p90) | New dynamic legitimate median (p90) | Phishing median (p90) |",
        "|---|---:|---:|---:|",
    ])
    distributions = report["feature_distributions"]
    for feature in FEATURES_OF_INTEREST:
        existing = distributions["existing_legitimate"]["statistics"][feature]
        dynamic = distributions["new_legitimate_dynamic"]["statistics"][feature]
        phishing = distributions["phishing"]["statistics"][feature]
        lines.append(
            f"| {feature} | {existing['median']:.3f} ({existing['p90']:.3f}) | "
            f"{dynamic['median']:.3f} ({dynamic['p90']:.3f}) | "
            f"{phishing['median']:.3f} ({phishing['p90']:.3f}) |"
        )
    lines.extend([
        "",
        "## Candidate model comparison",
        "",
        "Primary aggregate metrics are reported on a registered-domain held-out test partition with fixed source weights. Dynamic-legitimate metrics use only new benign URLs in held-out registered domains, reported unweighted. Candidate thresholds are selected on a separate registered-domain threshold partition.",
        "",
        "| Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | FNR | FPR | Brier | ECE | Median ms | p95 ms | Size bytes |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for name, result in report["models"].items():
        metric = result["test_metrics"]
        lines.append(
            f"| {name} | {metric['pr_auc']:.6f} | {metric['roc_auc']:.6f} | "
            f"{metric['precision']:.6f} | {metric['recall']:.6f} | {metric['f1']:.6f} | "
            f"{metric['fnr']:.6f} | {metric['fpr']:.6f} | {metric['brier']:.6f} | "
            f"{metric['ece']:.6f} | {result['latency']['median_ms']:.4f} | "
            f"{result['latency']['p95_ms']:.4f} | {result['model_size_bytes']:,} |"
        )
    lines.extend([
        "",
        "### Dynamic-legitimate held-out metrics",
        "",
        "| Model | URLs | FPR | SAFE | SUSPICIOUS | PHISHING |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    for name, result in report["models"].items():
        dynamic = result["dynamic_legitimate_test"]
        lines.append(
            f"| {name} | {dynamic['rows']} | {dynamic['fpr'] if dynamic['fpr'] is not None else 'N/A'} | "
            f"{dynamic['verdict_counts']['SAFE']} | {dynamic['verdict_counts']['SUSPICIOUS']} | "
            f"{dynamic['verdict_counts']['PHISHING']} |"
        )
    lines.extend([
        "",
        "### Existing legitimate homepage behavior",
        "",
        "| Reference/model | URLs | FPR | SAFE | SUSPICIOUS | PHISHING |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    homepage_baseline = report["production_baseline"]["existing_legitimate_homepage_test"]
    lines.append(
        f"| Production | {homepage_baseline['rows']} | {homepage_baseline['fpr']:.6f} | "
        f"{homepage_baseline['verdict_counts']['SAFE']} | "
        f"{homepage_baseline['verdict_counts']['SUSPICIOUS']} | "
        f"{homepage_baseline['verdict_counts']['PHISHING']} |"
    )
    for name, result in report["models"].items():
        homepage = result["existing_legitimate_homepage_test"]
        lines.append(
            f"| {name} | {homepage['rows']} | {homepage['fpr']:.6f} | "
            f"{homepage['verdict_counts']['SAFE']} | "
            f"{homepage['verdict_counts']['SUSPICIOUS']} | "
            f"{homepage['verdict_counts']['PHISHING']} |"
        )
    lines.extend([
        "",
        "## Regression URLs",
        "",
        "| URL | Production probability/verdict | Candidate results |",
        "|---|---|---|",
    ])
    for url, values in report["dynamic_regressions"].items():
        result_text = "; ".join(
            f"{name}: {prediction['probability']:.6f} {prediction['verdict']}"
            for name, prediction in values["candidates"].items()
        )
        lines.append(
            f"| `{url}` | {values['production']['probability']:.6f} {values['production']['verdict']} | "
            f"{result_text} |"
        )
    lines.extend([
        "",
        "## Phishing regression",
        "",
        "Examples below are selected only from already-labeled phishing URLs in held-out domains; they are not synthetic or relabeled. Full per-model predictions are in the JSON report.",
        "",
    ])
    for cohort, result in report["phishing_regressions"].items():
        lines.append(f"### {cohort}: {result['available_rows_in_held_out_domain_test']} held-out rows")
        for name, metric in result.get("model_metrics", {}).items():
            lines.append(
                f"- {name}: recall {metric['recall']:.6f}, FNR {metric['fnr']:.6f}, "
                f"median probability {metric['median_probability']:.6f}"
            )
        for example in result["examples"]:
            lines.append(f"- `{example['url']}`")
        if not result["examples"]:
            lines.append("- No verified held-out example for this cohort.")
        lines.append("")
    lines.extend([
        "## External phishing-only holdout",
        "",
        f"The {report['external_holdout']['rows']:,}-row holdout was checked after training only. External FPR is undefined because the holdout contains phishing URLs only.",
        "",
        "| Model | Recall | FNR | FPR |",
        "|---|---:|---:|---:|",
    ])
    for name, result in report["external_holdout"]["models"].items():
        lines.append(f"| {name} | {result['recall']:.6f} | {result['fnr']:.6f} | undefined |")
    lines.extend([
        "",
        "## Decision",
        "",
        f"**{report['decision']}**",
        "",
        "| Candidate | Overall gate | Test recall | External recall | Dynamic FPR | Homepage FPR |",
        "|---|---|---:|---:|---:|---:|",
    ])
    for name, result in report["models"].items():
        lines.append(
            f"| {name} | {report['promotion_gate']['candidate_gate_passes'][name]} | "
            f"{result['test_metrics']['recall']:.6f} | "
            f"{report['external_holdout']['models'][name]['recall']:.6f} | "
            f"{result['dynamic_legitimate_test']['fpr']:.6f} | "
            f"{result['existing_legitimate_homepage_test']['fpr']:.6f} |"
        )
    lines.extend([
        "",
        "### Existing test suite results",
        "",
        "| Suite | Result |",
        "|---|---|",
    ])
    for suite, status in report["test_results"].items():
        lines.append(f"| {suite} | {status} |")
    lines.extend([
        "",
        "Production promotion is conditional on every gate in the JSON report. This experiment does not promote candidates or alter production model files, feature names, thresholds, frontend, or extension.",
        "",
    ])
    with open(DOCUMENT, "w", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


def main():
    from feature_extractor import (
        FEATURE_NAMES,
        MODEL_EXCLUDED_FEATURES,
        extract_features,
        get_registered_domain,
        normalize_url,
    )
    from service import load_model_bundle

    production_paths = {
        "model": os.path.join(ROOT, "phishing_model.pkl"),
        "feature_names": os.path.join(ROOT, "feature_names.pkl"),
        "feature_importance": os.path.join(ROOT, "feature_importance.csv"),
        "metadata": os.path.join(ROOT, "model_metadata.json"),
    }
    production_hashes_before = {name: sha256(path) for name, path in production_paths.items()}
    external_hash_before = sha256(EXTERNAL)

    existing = pd.read_csv(DATASET, dtype={"url": str, "source": str})
    benign = pd.read_csv(BENIGN_DATASET, dtype={"url": str, "source": str})
    with open(SOURCE_MANIFEST, encoding="utf-8") as stream:
        source_manifest = json.load(stream)
    required_columns = {"url", "label", "source", "provenance", "category"}
    if not required_columns <= set(benign.columns):
        raise ValueError(f"Benign dataset missing columns: {sorted(required_columns - set(benign.columns))}")
    if not benign.label.eq(0).all():
        raise ValueError("Benign dynamic source must use only verified legitimate label 0.")
    if benign.url.duplicated().any():
        raise ValueError("Exact duplicate benign URLs found.")
    normalized_dynamic = benign.url.map(normalize_url)
    if normalized_dynamic.duplicated().any():
        raise ValueError("Normalized duplicate benign URLs found.")
    existing_normalized = set()
    for url in existing.url.dropna():
        try:
            existing_normalized.add(normalize_url(url))
        except ValueError:
            continue
    existing_overlap = sorted(set(normalized_dynamic) & existing_normalized)
    if existing_overlap:
        raise ValueError(f"Benign URLs duplicate existing data after normalization: {len(existing_overlap)}")
    if benign.provenance.isna().any() or benign.source_page_url.isna().any():
        raise ValueError("Every benign row must have explicit source and provenance.")
    if not benign.verification_status.between(200, 299).all():
        raise ValueError("Every benign URL must have a successful individual source verification.")

    existing["source_kind"] = "existing"
    benign = benign.copy()
    benign["source_kind"] = "verified_benign_dynamic_urls"
    benign["url"] = normalized_dynamic
    combined = pd.concat([existing, benign], ignore_index=True, sort=False)
    if combined.url.duplicated().any():
        raise ValueError("Exact cross-source duplicate URL found in combined training data.")
    combined["label"] = combined.label.astype(int)
    if set(combined.label.unique()) != {0, 1}:
        raise ValueError("Combined data must contain both classes.")
    groups = combined.url.map(get_registered_domain).to_numpy()
    labels = combined.label.to_numpy(dtype=int)
    dynamic_mask_all = combined.source_kind.eq("verified_benign_dynamic_urls").to_numpy()
    dynamic_weight = min(
        DYNAMIC_WEIGHT_CAP,
        max(1.0, 0.10 * int(existing.label.eq(0).sum()) / max(len(benign), 1)),
    )
    existing_legitimate = int(existing.label.eq(0).sum())
    existing_phi_phishing = int(
        (existing.source.eq("PhiUSIIL") & existing.label.eq(1)).sum()
    )
    feed = combined.source.eq("phishing_database_active").to_numpy()
    feed_rows = int(feed.sum())
    target_phishing_mass = 1.5 * (existing_legitimate + len(benign) * dynamic_weight)
    feed_weight = max(0.0, target_phishing_mass - existing_phi_phishing) / max(feed_rows, 1)
    sample_weights = np.ones(len(combined), dtype=float)
    sample_weights[feed] = feed_weight
    sample_weights[dynamic_mask_all] = dynamic_weight
    sources = combined.source.astype(str).to_numpy()
    phi_mask = sources == "PhiUSIIL"
    if (combined.loc[phi_mask, "label"].nunique() != 2):
        raise ValueError("PhiUSIIL is expected to preserve both original labels.")

    first = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=44)
    fitcal_idx, test_idx = next(first.split(combined, labels, groups))
    second = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=45)
    traincal_rel, threshold_rel = next(
        second.split(combined.iloc[fitcal_idx], labels[fitcal_idx], groups[fitcal_idx])
    )
    traincal_idx, threshold_idx = fitcal_idx[traincal_rel], fitcal_idx[threshold_rel]
    third = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=46)
    train_rel, calibration_rel = next(
        third.split(combined.iloc[traincal_idx], labels[traincal_idx], groups[traincal_idx])
    )
    train_idx, calibration_idx = traincal_idx[train_rel], traincal_idx[calibration_rel]
    fold_indexes = [train_idx, calibration_idx, threshold_idx, test_idx]
    fold_domains = [set(groups[index]) for index in fold_indexes]
    overlap_rows = []
    for left in range(len(fold_domains)):
        for right in range(left + 1, len(fold_domains)):
            overlap_rows.extend(sorted(fold_domains[left] & fold_domains[right]))
    if overlap_rows:
        raise AssertionError(f"Registered-domain leakage detected: {len(set(overlap_rows))} domains.")
    dynamic_train_domains = set(groups[train_idx][dynamic_mask_all[train_idx]])
    dynamic_validation_idx = np.concatenate([calibration_idx, threshold_idx, test_idx])
    dynamic_validation_domains = set(
        groups[dynamic_validation_idx][dynamic_mask_all[dynamic_validation_idx]]
    )
    dynamic_overlap = dynamic_train_domains & dynamic_validation_domains
    if dynamic_overlap:
        raise AssertionError(f"Dynamic cohort domain leakage: {sorted(dynamic_overlap)}")

    feature_names = [
        name for name in FEATURE_NAMES if name not in MODEL_EXCLUDED_FEATURES
    ]
    production, production_feature_names, metadata = load_model_bundle()
    if feature_names != production_feature_names or len(feature_names) != 29:
        raise AssertionError("Experimental feature order differs from production 29-feature contract.")
    print(f"Extracting production features for {len(combined):,} training rows...", flush=True)
    feature_matrix = pd.DataFrame(
        combined.url.map(extract_features).tolist(), columns=FEATURE_NAMES
    )[feature_names]
    y = labels
    dynamic_mask = dynamic_mask_all
    distribution_cohorts = combined[["label", "source"]].copy()
    distribution_cohorts["source"] = np.where(
        dynamic_mask, "verified_benign_dynamic_urls", combined.source.astype(str)
    )
    feature_distributions = feature_distribution(distribution_cohorts, feature_matrix)

    model_factories = {
        "logistic_regression": lambda: LogisticRegression(
            max_iter=1500, solver="liblinear", random_state=42
        ),
        "random_forest": lambda: RandomForestClassifier(
            n_estimators=80,
            max_depth=24,
            min_samples_leaf=2,
            min_samples_split=5,
            n_jobs=-1,
            random_state=42,
        ),
        "hist_gradient_boosting": lambda: HistGradientBoostingClassifier(
            learning_rate=0.05,
            max_iter=100,
            max_leaf_nodes=31,
            random_state=42,
        ),
    }
    models = {}
    for name, factory in model_factories.items():
        print(f"Training {name}...", flush=True)
        start = time.perf_counter()
        estimator = factory()
        estimator.fit(
            feature_matrix.iloc[train_idx],
            y[train_idx],
            sample_weight=sample_weights[train_idx],
        )
        raw_calibration = estimator.predict_proba(
            feature_matrix.iloc[calibration_idx]
        )[:, 1]
        calibrator = LogisticRegression(
            solver="lbfgs", max_iter=1000, random_state=42
        )
        calibrator.fit(
            raw_calibration.reshape(-1, 1),
            y[calibration_idx],
            sample_weight=sample_weights[calibration_idx],
        )
        models[name] = {
            "estimator": estimator,
            "calibrator": calibrator,
            "fit_seconds": float(time.perf_counter() - start),
        }

    def predict(name, indexes):
        candidate = models[name]
        raw = candidate["estimator"].predict_proba(feature_matrix.iloc[indexes])[:, 1]
        return candidate["calibrator"].predict_proba(raw.reshape(-1, 1))[:, 1]

    model_results = {}
    threshold_cache = {}
    predictions_test = {}
    dynamic_test_mask = dynamic_mask[test_idx]
    test_urls = combined.url.iloc[test_idx].reset_index(drop=True)
    parsed_test_urls = test_urls.map(urlsplit)
    existing_homepage_mask = (
        combined.source_kind.iloc[test_idx].eq("existing").to_numpy()
        & (y[test_idx] == 0)
        & combined.source.iloc[test_idx].eq("PhiUSIIL").to_numpy()
        & parsed_test_urls.map(
            lambda item: item.path in ("", "/") and not item.query and not item.fragment
        ).to_numpy()
    )
    for name, candidate in models.items():
        threshold_probability = predict(name, threshold_idx)
        selected_thresholds = decision_thresholds(
            y[threshold_idx],
            threshold_probability,
            sample_weights[threshold_idx],
            dynamic_mask[threshold_idx],
        )
        threshold_cache[name] = selected_thresholds
        test_probability = predict(name, test_idx)
        predictions_test[name] = test_probability
        model_results[name] = {
            "thresholds_research_only": selected_thresholds,
            "test_metrics": metrics(
                y[test_idx], test_probability, selected_thresholds["phishing"],
                sample_weights[test_idx],
            ),
            "test_metrics_unweighted": metrics(
                y[test_idx], test_probability, selected_thresholds["phishing"]
            ),
            "test_calibration": effective_calibration_metrics(
                y[test_idx], test_probability, sample_weights[test_idx]
            ),
            "dynamic_legitimate_test": {},
            "phishing_regression_test": {},
            "fit_seconds": candidate["fit_seconds"],
        }
        dynamic_positions = np.flatnonzero(dynamic_test_mask)
        dynamic_probability = test_probability[dynamic_positions]
        dynamic_threshold = selected_thresholds["phishing"]
        dynamic_verdicts = [
            verdict(value, selected_thresholds) for value in dynamic_probability
        ]
        dynamic_counts = {
            label: dynamic_verdicts.count(label)
            for label in ("SAFE", "SUSPICIOUS", "PHISHING")
        }
        model_results[name]["dynamic_legitimate_test"] = {
            "rows": int(len(dynamic_positions)),
            "registered_domains": int(len(set(groups[test_idx][dynamic_test_mask]))),
            "fpr": float(np.mean(dynamic_probability >= dynamic_threshold)) if len(dynamic_positions) else None,
            "false_phishing": int(np.sum(dynamic_probability >= dynamic_threshold)),
            "verdict_counts": dynamic_counts,
            "probability_median": float(np.median(dynamic_probability)) if len(dynamic_probability) else None,
            "probability_p90": float(np.percentile(dynamic_probability, 90)) if len(dynamic_probability) else None,
        }
        homepage_probability = test_probability[existing_homepage_mask]
        homepage_verdicts = [
            verdict(value, selected_thresholds) for value in homepage_probability
        ]
        model_results[name]["existing_legitimate_homepage_test"] = {
            "rows": int(len(homepage_probability)),
            "fpr": (
                float(np.mean(homepage_probability >= selected_thresholds["phishing"]))
                if len(homepage_probability) else None
            ),
            "false_phishing": int(np.sum(
                homepage_probability >= selected_thresholds["phishing"]
            )),
            "verdict_counts": {
                label: homepage_verdicts.count(label)
                for label in ("SAFE", "SUSPICIOUS", "PHISHING")
            },
        }

    dynamic_homepages_not_for_training = REGRESSION_URLS
    regressions = {}
    production_thresholds = metadata["thresholds"]
    for url in dynamic_homepages_not_for_training:
        row = pd.DataFrame([extract_features(url)], columns=FEATURE_NAMES)[feature_names]
        production_probability = float(production.predict_proba(row)[0, 1])
        candidates = {}
        for name, candidate in models.items():
            raw = float(candidate["estimator"].predict_proba(row)[0, 1])
            probability = float(candidate["calibrator"].predict_proba([[raw]])[0, 1])
            candidates[name] = {
                "probability": probability,
                "verdict": verdict(probability, threshold_cache[name]),
            }
        regressions[url] = {
            "production": {
                "probability": production_probability,
                "verdict": verdict(production_probability, production_thresholds),
            },
            "candidates": candidates,
            "used_for_training": False,
            "used_for_threshold_selection": False,
        }

    phishing_examples = select_phishing_examples(
        combined.iloc[test_idx].reset_index(drop=True)
    )
    for name, candidate in models.items():
        for cohort_name, cohort in phishing_examples.items():
            cohort_positions = np.asarray(cohort["_test_row_indices"], dtype=int)
            cohort_probability = predictions_test[name][cohort_positions]
            phishing_threshold = threshold_cache[name]["phishing"]
            cohort["model_metrics"] = cohort.get("model_metrics", {})
            cohort["model_metrics"][name] = {
                "rows": int(len(cohort_positions)),
                "recall": float(np.mean(cohort_probability >= phishing_threshold)),
                "fnr": float(np.mean(cohort_probability < phishing_threshold)),
                "median_probability": float(np.median(cohort_probability)),
            }
            for example in cohort["examples"]:
                row = pd.DataFrame(
                    [extract_features(example["url"])], columns=FEATURE_NAMES
                )[feature_names]
                raw = float(candidate["estimator"].predict_proba(row)[0, 1])
                probability = float(candidate["calibrator"].predict_proba([[raw]])[0, 1])
                example.setdefault("model_predictions", {})[name] = {
                    "probability": probability,
                    "verdict": verdict(probability, threshold_cache[name]),
                }
    for cohort in phishing_examples.values():
        del cohort["_test_row_indices"]

    print("Evaluating external phishing-only holdout after training...", flush=True)
    external = pd.read_csv(EXTERNAL, dtype={"url": str, "label": int})
    if len(external) != 154_931 or set(external.label.unique()) != {1}:
        raise ValueError("External holdout must remain the expected 154,931 phishing-only rows.")
    external_features = pd.DataFrame(
        external.url.map(extract_features).tolist(), columns=FEATURE_NAMES
    )[feature_names]
    external_results = {}
    for name, candidate in models.items():
        raw = candidate["estimator"].predict_proba(external_features)[:, 1]
        probability = candidate["calibrator"].predict_proba(raw.reshape(-1, 1))[:, 1]
        threshold = threshold_cache[name]["phishing"]
        recall_value = float(np.mean(probability >= threshold))
        external_results[name] = {
            "rows": int(len(external)),
            "recall": recall_value,
            "fnr": float(1 - recall_value),
            "fpr": None,
            "statement": "External FPR is undefined because this holdout contains phishing URLs only.",
        }

    for name, candidate in models.items():
        row = feature_matrix.iloc[test_idx[[0]]]
        candidate["latency"] = inference_latency(
            lambda: candidate["calibrator"].predict_proba(
                candidate["estimator"].predict_proba(row)[:, 1].reshape(-1, 1)
            )
        )
        bundle = {
            "estimator": candidate["estimator"],
            "calibrator": candidate["calibrator"],
            "feature_names": feature_names,
            "thresholds": threshold_cache[name],
            "source_policy": {
                "dynamic_benign_row_weight": dynamic_weight,
                "phishing_database_row_weight": feed_weight,
            },
        }
        serialized = pickle.dumps(bundle, protocol=pickle.HIGHEST_PROTOCOL)
        candidate["model_size_bytes"] = len(serialized)
        model_results[name]["latency"] = candidate["latency"]
        model_results[name]["model_size_bytes"] = len(serialized)
        model_results[name]["phishing_regression_test"] = {
            cohort: {
                "available_held_out_rows": result["available_rows_in_held_out_domain_test"],
                "examples": result["examples"],
            }
            for cohort, result in phishing_examples.items()
        }
        os.makedirs(MODEL_OUTPUT, exist_ok=True)
        output_path = os.path.join(MODEL_OUTPUT, f"{name}.pkl")
        with open(output_path, "wb") as stream:
            stream.write(serialized)
        model_results[name]["experimental_artifact"] = os.path.relpath(output_path, ROOT)

    print("Calculating baseline and dynamic cohort comparisons...", flush=True)
    production_test_probability = production.predict_proba(
        feature_matrix.iloc[test_idx][production_feature_names]
    )[:, 1]
    production_result = {
        "thresholds": production_thresholds,
        "test_metrics": metrics(
            y[test_idx], production_test_probability, production_thresholds["phishing"],
            sample_weights[test_idx],
        ),
        "dynamic_legitimate_test": {},
    }
    base_dynamic_prob = production_test_probability[dynamic_test_mask]
    base_homepage_probability = production_test_probability[existing_homepage_mask]
    production_result["dynamic_legitimate_test"] = {
        "rows": int(len(base_dynamic_prob)),
        "fpr": float(np.mean(base_dynamic_prob >= production_thresholds["phishing"])) if len(base_dynamic_prob) else None,
        "false_phishing": int(np.sum(base_dynamic_prob >= production_thresholds["phishing"])),
        "verdict_counts": {
            label: sum(
                verdict(value, production_thresholds) == label for value in base_dynamic_prob
            )
            for label in ("SAFE", "SUSPICIOUS", "PHISHING")
        },
    }
    production_result["existing_legitimate_homepage_test"] = {
        "rows": int(len(base_homepage_probability)),
        "fpr": (
            float(np.mean(base_homepage_probability >= production_thresholds["phishing"]))
            if len(base_homepage_probability) else None
        ),
        "false_phishing": int(np.sum(
            base_homepage_probability >= production_thresholds["phishing"]
        )),
        "verdict_counts": {
            label: sum(
                verdict(value, production_thresholds) == label
                for value in base_homepage_probability
            )
            for label in ("SAFE", "SUSPICIOUS", "PHISHING")
        },
    }

    dynamic_full_weights = dynamic_weight
    train_domains = set(groups[train_idx][dynamic_mask[train_idx]])
    validation_domains = set(groups[dynamic_validation_idx][dynamic_mask[dynamic_validation_idx]])
    overall_validation_idx = np.concatenate(
        [calibration_idx, threshold_idx, test_idx]
    )
    overall_train_domains = set(groups[train_idx])
    overall_validation_domains = set(groups[overall_validation_idx])
    category_counts = {
        str(category): int(count)
        for category, count in benign.category.value_counts().items()
    }
    category_counts = {
        category: category_counts.get(category, 0)
        for category in (
            "path_only", "query_only", "path_query", "multiple_query_parameters",
            "long_query", "encoded_query", "fragment", "tracking_parameters",
            "redirect_style", "high_entropy_legitimate", "long_legitimate_url",
        )
    }
    external_hash_after = sha256(EXTERNAL)
    production_hashes_after = {name: sha256(path) for name, path in production_paths.items()}
    gate_by_model = {}
    for name, result in model_results.items():
        homepage_fpr = result["existing_legitimate_homepage_test"]["fpr"]
        production_homepage_fpr = production_result[
            "existing_legitimate_homepage_test"
        ]["fpr"]
        gate_by_model[name] = {
            "observed_dynamic_regressions_not_phishing": all(
                prediction["verdict"] != "PHISHING"
                for entry in regressions.values()
                for candidate_name, prediction in entry["candidates"].items()
                if candidate_name == name
            ),
            "dynamic_legitimate_fpr_within_1_percent": (
                result["dynamic_legitimate_test"]["fpr"] is not None
                and result["dynamic_legitimate_test"]["fpr"] <= 0.01
            ),
            "existing_homepage_behavior_no_regression": (
                homepage_fpr is not None
                and production_homepage_fpr is not None
                and homepage_fpr <= production_homepage_fpr
            ),
            "phishing_recall_remains_strong": result["test_metrics"]["recall"] >= 0.90,
            "phishing_hard_case_recall_remains_strong": all(
                phishing_examples[cohort_name]["available_rows_in_held_out_domain_test"] > 0
                and phishing_examples[cohort_name]["model_metrics"][name]["recall"] >= 0.90
                for cohort_name in (
                    "query_strings", "paths", "login_parameters", "encoded_values",
                    "long_urls_over_200", "redirect_parameters", "brand_like_hostnames",
                )
            ),
            "external_phishing_recall_acceptable": external_results[name]["recall"] >= 0.90,
            "domain_grouped_validation_no_leakage": (
                len(overall_train_domains & overall_validation_domains) == 0
                and len(overlap_rows) == 0
            ),
            "calibration_acceptable": result["test_metrics"]["ece"] <= 0.05,
            "threshold_selection_feasible": result[
                "thresholds_research_only"
            ]["selection_validation"]["feasible"],
        }
    model_gate_passes = {
        name: all(gates.values()) for name, gates in gate_by_model.items()
    }
    test_results = {
        "pytest": "pending",
        "frontend": "pending",
        "frontend_build": "pending",
        "extension": "pending",
        "javascript_syntax": "pending",
    }
    all_existing_tests_pass = all(
        result == "passed" for result in test_results.values()
    )
    decision = (
        "PROMOTE"
        if any(model_gate_passes.values())
        and all_existing_tests_pass
        and production_hashes_before == production_hashes_after
        else "DO NOT PROMOTE"
    )
    report = {
        "decision": decision,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "production_artifacts": {
            "before": production_hashes_before,
            "after": production_hashes_after,
            "unchanged": production_hashes_before == production_hashes_after,
            "thresholds_unchanged": True,
            "production_model_version": metadata["model_version"],
        },
        "dataset": {
            "existing_training_rows": int(len(existing)),
            "existing_legitimate_rows": int(existing.label.eq(0).sum()),
            "existing_phishing_rows": int(existing.label.eq(1).sum()),
            "dynamic_rows": int(len(benign)),
            "source_count": int(benign.source.nunique()),
            "collection_date": source_manifest["collection_date"],
            "category_counts": category_counts,
            "deduplication": source_manifest["deduplication"],
            "normalized_existing_url_duplicates": 0,
            "source_weighting": {
                "all_existing_rows_retained": True,
                "new_benign_rows_retained": True,
                "new_dynamic_benign_row_weight": dynamic_full_weights,
                "dynamic_weight_cap": DYNAMIC_WEIGHT_CAP,
                "dynamic_effective_weight_mass": float(len(benign) * dynamic_full_weights),
                "existing_legitimate_weight_mass": float(existing_legitimate),
                "phishing_database_active_row_weight": float(feed_weight),
                "effective_phishing_to_legitimate_mass_ratio": 1.5,
                "policy": "All existing rows retained. PhiUSIIL weight=1; Phishing.Database source weighted to preserve 1.5:1 aggregate phishing/legitimate mass; verified dynamic negatives receive a capped 10%-of-existing-legitimate effective mass to ensure this specific new cohort participates without dropping any source rows.",
                "source_effective_masses": {
                    "PhiUSIIL": float(len(existing[existing.source.eq("PhiUSIIL")])),
                    "phishing_database_active": float(feed_rows * feed_weight),
                    "verified_benign_dynamic_urls": float(len(benign) * dynamic_full_weights),
                },
            },
        },
        "sources": {
            "source_records": source_manifest["sources"],
            "collection_manifest": os.path.relpath(SOURCE_MANIFEST, ROOT),
            "verification_method": source_manifest["method"],
        },
        "domain_split": {
            "strategy": "Same registered-domain GroupShuffleSplit strategy as the VIGIL trainer (20% test, then separate threshold/calibration groups)",
            "train_rows": int(len(train_idx)),
            "calibration_rows": int(len(calibration_idx)),
            "threshold_rows": int(len(threshold_idx)),
            "test_rows": int(len(test_idx)),
            "train_domains": int(len(overall_train_domains)),
            "validation_domains": int(len(overall_validation_domains)),
            "overlapping_domains": int(len(overall_train_domains & overall_validation_domains)),
            "all_fold_overlapping_domains": int(len(set(overlap_rows))),
            "dynamic_train_rows": int(dynamic_mask[train_idx].sum()),
            "dynamic_validation_rows": int(dynamic_mask[dynamic_validation_idx].sum()),
            "dynamic_train_domains": int(len(train_domains)),
            "dynamic_validation_domains": int(len(validation_domains)),
            "dynamic_overlapping_domains": int(len(train_domains & validation_domains)),
            "dynamic_split_test_rows": int(dynamic_mask[test_idx].sum()),
            "seed": 44,
        },
        "feature_distributions": feature_distributions,
        "models": model_results,
        "production_baseline": production_result,
        "dynamic_regressions": regressions,
        "phishing_regressions": phishing_examples,
        "external_holdout": {
            "rows": int(len(external)),
            "sha256_before": external_hash_before,
            "sha256_after": external_hash_after,
            "unchanged": external_hash_before == external_hash_after,
            "used_for_training": False,
            "used_for_calibration": False,
            "used_for_threshold_selection": False,
            "used_for_feature_selection": False,
            "models": external_results,
            "fpr": None,
            "fpr_statement": "External FPR is undefined because the holdout contains phishing URLs only.",
        },
        "promotion_gate": {
            "by_candidate": gate_by_model,
            "candidate_gate_passes": model_gate_passes,
            "all_existing_tests_pass": all_existing_tests_pass,
            "production_artifacts_unchanged": production_hashes_before == production_hashes_after,
        },
        "test_results": test_results,
        "limitations": [
            "The collected corpus reflects current public first-party link structures and is not an independent benchmark dataset.",
            "Categories with no verified source links remain at zero; no synthetic URLs were used to fill them.",
            "The dynamic cohort is modest and has 16 registered domains. Domain-disjoint metrics have substantial uncertainty and should not be treated as final proof of broad benign dynamic URL coverage.",
        ],
    }
    write_report(report)
    print(json.dumps({
        "decision": report["decision"],
        "dynamic_rows": len(benign),
        "category_counts": category_counts,
        "domain_split": report["domain_split"],
        "models": {
            name: {
                "metrics": item["test_metrics"],
                "dynamic": item["dynamic_legitimate_test"],
                "external_recall": external_results[name]["recall"],
            }
            for name, item in model_results.items()
        },
        "promotion_gate": report["promotion_gate"],
        "report": os.path.relpath(REPORT, ROOT),
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
