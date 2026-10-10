"""Summarize why dynamic-URL experiments trade FPs for phishing recall."""
from __future__ import annotations

import csv
import json
import pickle
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "reports"
EXPERIMENT_DIR = ROOT / "experiments"
MODEL_DIR = ROOT / "models"
OUTPUT_PATH = REPORT_DIR / "dynamic_experiment_failure_analysis.json"

REPORT_PATHS = {
    "dynamic_augmentation": "reports/dynamic_augmentation_final.json",
    "dynamic_training_comparison": "reports/dynamic_training_comparison.json",
    "dynamic_hardening": "reports/dynamic_hardening_final.json",
    "dynamic_recovery_final": "reports/dynamic_recovery_final.json",
    "dynamic_recovery_comparison": "reports/dynamic_recovery_comparison.json",
}

CANDIDATE_CONFIG = {
    "dynamic_augmentation": {"collection": "models", "test_key": "test"},
    "dynamic_training_comparison": {"collection": "candidate_models", "test_key": "domain_test"},
    "dynamic_hardening": {"collection": "candidate_models", "test_key": "domain_test"},
    "dynamic_recovery_final": {"collection": "candidate_models", "test_key": "domain_test"},
    "dynamic_recovery_comparison": {"collection": "candidate_models", "test_key": "domain_test"},
}


def load_json(relative_path: str) -> dict:
    with (ROOT / relative_path).open(encoding="utf-8") as input_file:
        return json.load(input_file)


def value_or_none(mapping: dict | None, *keys):
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            return value
    return None


def normalize_metrics(metrics: dict | None, decision_threshold=None) -> dict:
    metrics = metrics if isinstance(metrics, dict) else {}
    calibration = metrics.get("calibration", {})
    domain_fpr = metrics.get("domain_fpr")
    url_fpr = value_or_none(metrics, "url_fpr", "fpr")
    return {
        "test_decision_threshold": value_or_none(metrics, "threshold") or decision_threshold,
        "accuracy": metrics.get("accuracy"),
        "precision": metrics.get("precision"),
        "phishing_recall": value_or_none(metrics, "phishing_recall", "domain_recall", "recall"),
        "f1": metrics.get("f1"),
        "pr_auc": metrics.get("pr_auc"),
        "brier": value_or_none(metrics, "brier", "brier_score"),
        "ece": value_or_none(metrics, "ece", "expected_calibration_error")
        or value_or_none(calibration, "expected_calibration_error", "ece"),
        "domain_disjoint_fpr": domain_fpr if domain_fpr is not None else url_fpr,
        "domain_disjoint_fpr_kind": (
            "registered_domain_fpr"
            if domain_fpr is not None
            else "url_fpr_on_domain_disjoint_test"
            if url_fpr is not None
            else None
        ),
        "url_fpr": url_fpr,
        "reported_domain_fpr": domain_fpr,
        "fnr": metrics.get("fnr"),
        "rows": value_or_none(metrics, "rows", "samples"),
    }


def selected_threshold(model: dict, experiment: str):
    threshold = model.get("threshold", {})
    if isinstance(threshold, dict) and threshold.get("phishing_threshold") is not None:
        return threshold["phishing_threshold"]
    thresholds = model.get("thresholds", {})
    if isinstance(thresholds, dict) and thresholds.get("phishing") is not None:
        return thresholds["phishing"]
    return None


def external_metrics(report: dict, model_name: str, model: dict, experiment: str) -> dict:
    external = model.get("external_validation") or model.get("external")
    if isinstance(external, dict):
        return {
            "phishing_recall": value_or_none(external, "phishing_recall", "recall"),
            "fnr": external.get("fnr"),
            "rows": value_or_none(external, "rows", "total_phishing_urls"),
            "threshold": external.get("threshold_used"),
            "fpr": external.get("fpr"),
        }

    if experiment == "dynamic_augmentation" and model_name == report.get("selected_candidate"):
        comparison = report.get("comparison", {}).get("candidate", {})
        top_level = report.get("external_validation", {}).get("candidate", {})
        return {
            "phishing_recall": value_or_none(top_level, "phishing_recall", "recall")
            or comparison.get("external_recall"),
            "fnr": top_level.get("fnr"),
            "rows": value_or_none(top_level, "rows", "phishing_rows"),
            "threshold": top_level.get("threshold_used"),
            "fpr": top_level.get("fpr"),
        }

    return {
        "phishing_recall": None,
        "fnr": None,
        "rows": None,
        "threshold": None,
        "fpr": None,
        "availability": "Not reported for this candidate.",
    }


def hard_cohort_metrics(test_metrics: dict) -> dict:
    source = test_metrics.get("hard_cohorts") or test_metrics.get("phishing_cohorts") or {}
    aliases = {
        "pathless_phishing": ("pathless_phishing", "pathless"),
        "short_phishing": ("short_phishing", "short_le60", "short"),
        "no_suspicious_token": ("no_suspicious_token",),
        "no_suspicious_tld": ("no_suspicious_tld",),
        "ordinary_looking_phishing": ("ordinary_looking_domains", "ordinary_looking"),
        "query_bearing_phishing": ("has_query", "query_bearing", "query"),
    }
    output = {}
    for canonical, candidates in aliases.items():
        cohort = next((source[key] for key in candidates if key in source), None)
        if isinstance(cohort, dict):
            output[canonical] = {
                "samples": value_or_none(cohort, "samples", "rows"),
                "phishing_recall": value_or_none(cohort, "phishing_recall", "recall"),
                "fnr": cohort.get("fnr"),
            }
        else:
            output[canonical] = None
    return output


def dynamic_regression(model: dict, report: dict, experiment: str, model_name: str) -> dict:
    holdout = model.get("dynamic_holdout") or model.get("dynamic_benign_holdout")
    if isinstance(holdout, dict):
        structure = holdout.get("structure_breakdown", {})
        query = structure.get("has_query", {}) if isinstance(structure, dict) else {}
        return {
            "sample_count": value_or_none(holdout, "total_urls", "rows", "total"),
            "legitimate_false_phishing_rate": value_or_none(holdout, "phishing_fpr", "false_phishing_rate"),
            "query_bearing_sample_count": query.get("total"),
            "query_bearing_false_phishing_rate": query.get("phishing_fpr"),
            "safe": holdout.get("safe"),
            "suspicious": holdout.get("suspicious"),
            "phishing": holdout.get("phishing"),
            "source": "candidate dynamic_benign_holdout/dynamic_holdout section",
        }

    if experiment == "dynamic_augmentation" and model_name == report.get("selected_candidate"):
        comparison = report.get("comparison", {}).get("candidate", {})
        selection = report.get("selected_candidate_dynamic_benign_holdout", {})
        return {
            "sample_count": selection.get("rows"),
            "legitimate_false_phishing_rate": comparison.get("dynamic_benign_fpr"),
            "query_bearing_sample_count": report.get("production_dynamic_benign_holdout", {}).get("query", {}).get("rows"),
            "query_bearing_false_phishing_rate": comparison.get("query_fpr"),
            "long_url_false_phishing_rate": comparison.get("long_url_fpr"),
            "source": "paired comparison summary; selected candidate only",
        }

    return {
        "sample_count": None,
        "legitimate_false_phishing_rate": None,
        "query_bearing_sample_count": None,
        "query_bearing_false_phishing_rate": None,
        "source": "No comparable legitimate dynamic holdout metric was reported.",
    }


def candidate_rows(reports: dict) -> list[dict]:
    rows = []
    for experiment, report in reports.items():
        config = CANDIDATE_CONFIG[experiment]
        collection = report.get(config["collection"], {})
        if not isinstance(collection, dict):
            continue
        for model_name, model in collection.items():
            if not isinstance(model, dict):
                continue
            test = model.get(config["test_key"], {})
            threshold = selected_threshold(model, experiment)
            normalized = normalize_metrics(test, threshold)
            normalized.update({
                "experiment": experiment,
                "model": model_name,
                "candidate_artifact": artifact_for(experiment, model_name),
                "source_report": REPORT_PATHS[experiment],
                "selected_phishing_threshold": threshold,
                "external_phishing": external_metrics(report, model_name, model, experiment),
                "legitimate_dynamic_regression": dynamic_regression(model, report, experiment, model_name),
                "hard_phishing_cohorts": hard_cohort_metrics(test),
                "threshold_selection": model.get("threshold") or model.get("thresholds"),
                "domain_split": report.get("domain_split") or report.get("domain_grouped_splits"),
            })
            rows.append(normalized)
    return rows


def artifact_for(experiment: str, model_name: str) -> str | None:
    paths = {
        ("dynamic_augmentation", "hist_gradient_boosting"): "experiments/dynamic_augmentation/hist_gradient_boosting_estimator.pkl",
        ("dynamic_augmentation", "logistic_regression"): "experiments/dynamic_augmentation/logistic_regression_estimator.pkl",
        ("dynamic_hardening", "hist_gradient_boosting"): "experiments/dynamic_hardening/candidate_hist_gradient_boosting.pkl",
        ("dynamic_hardening", "logistic_regression"): "experiments/dynamic_hardening/candidate_logistic_regression.pkl",
        ("dynamic_recovery_final", "hist_gradient_boosting"): "experiments/dynamic_recovery/candidate_hist_gradient_boosting.pkl",
        ("dynamic_recovery_final", "logistic_regression"): "experiments/dynamic_recovery/candidate_logistic_regression.pkl",
    }
    return paths.get((experiment, model_name))


def production_rows(reports: dict) -> list[dict]:
    sources = {
        "dynamic_augmentation": reports["dynamic_augmentation"].get("comparison", {}).get("production", {}),
        "dynamic_training_comparison": reports["dynamic_training_comparison"].get("current_production", {}).get("domain_test_metrics", {}),
        "dynamic_hardening": reports["dynamic_hardening"].get("production_comparison", {}).get("domain_test", {}),
        "dynamic_recovery_final": reports["dynamic_recovery_final"].get("production_comparison", {}).get("domain_test", {}),
        "dynamic_recovery_comparison": reports["dynamic_recovery_comparison"].get("production_reference", {}),
    }
    rows = []
    for experiment, metrics in sources.items():
        normalized = normalize_metrics(metrics)
        normalized.update({
            "experiment": experiment,
            "model": "production",
            "source_report": REPORT_PATHS[experiment],
            "thresholds": (
                reports[experiment].get("production_comparison", {}).get("thresholds")
                or reports[experiment].get("current_production", {}).get("thresholds")
                or (reports[experiment].get("model_metadata", {}).get("thresholds"))
            ),
            "external_phishing_recall": value_or_none(metrics, "external_recall", "phishing_recall"),
            "legitimate_dynamic_regression": {
                "false_phishing_rate": value_or_none(metrics, "dynamic_benign_fpr"),
                "query_bearing_false_phishing_rate": metrics.get("query_fpr"),
            },
        })
        rows.append(normalized)
    return rows


def corpus_summary(report: dict) -> dict:
    corpus = report.get("corpus") or report.get("training_corpus") or {}
    if not isinstance(corpus, dict):
        return {}
    rows_by_label = corpus.get("rows_by_label", {})
    legit = corpus.get("legitimate", rows_by_label.get("0"))
    phish = corpus.get("phishing", rows_by_label.get("1"))
    source_counts = corpus.get("rows_by_source") or corpus.get("source_distribution") or {}
    dynamic_rows = corpus.get("dynamic_legitimate_rows")
    if dynamic_rows is None:
        dynamic_rows = sum(
            count for source, count in source_counts.items()
            if "dynamic" in source.lower() or "high_confidence" in source.lower()
        )
    return {
        "rows": corpus.get("combined_rows", corpus.get("final_rows", report.get("training_rows"))),
        "legitimate": legit,
        "phishing": phish,
        "phishing_to_legitimate_ratio": phish / legit if isinstance(phish, (int, float)) and legit else None,
        "dynamic_legitimate_rows": dynamic_rows,
        "dynamic_share_of_legitimate": dynamic_rows / legit if isinstance(dynamic_rows, (int, float)) and legit else None,
        "rows_by_source": source_counts,
        "source_composition": corpus.get("class_composition_by_source"),
        "effective_source_weights": report.get("source_aware_training_weights"),
        "domains_shared_with_external_holdout": corpus.get("domains_shared_with_external_holdout"),
        "rows_in_domains_shared_with_external_holdout": corpus.get("rows_in_domains_shared_with_external_holdout"),
        "domains_with_both_labels": corpus.get("domains_with_both_labels"),
        "rows_in_domains_with_both_labels": corpus.get("rows_in_domains_with_both_labels"),
        "feed_sampling": report.get("phishing_database_stratified_sample"),
        "pool": report.get("pool"),
    }


def tree_gain_importance(estimator, feature_names: list[str]) -> list[dict]:
    totals = [0.0] * len(feature_names)
    predictors = getattr(estimator, "_predictors", [])
    for iteration in predictors:
        for tree in iteration:
            for node in tree.nodes:
                feature_index = int(node["feature_idx"])
                gain = float(node["gain"])
                if 0 <= feature_index < len(totals) and gain > 0:
                    totals[feature_index] += gain
    total_gain = sum(totals)
    if not total_gain:
        return []
    indexed = sorted(enumerate(totals), key=lambda item: item[1], reverse=True)
    return [
        {"rank": rank, "feature": feature_names[index], "normalized_split_gain": value / total_gain}
        for rank, (index, value) in enumerate(indexed[:10], 1)
    ]


def load_candidate_estimator(path: Path):
    artifact = joblib.load(path)
    if isinstance(artifact, dict):
        return artifact["estimator"], list(artifact["feature_names"])
    if path.name == "hist_gradient_boosting_estimator.pkl":
        feature_names_path = path.with_name("hist_gradient_boosting_feature_names.pkl")
        with feature_names_path.open("rb") as names_file:
            return artifact, list(pickle.load(names_file))
    raise ValueError(f"Could not resolve feature names for {path}")


def feature_importance_summary(hardening_report: dict) -> dict:
    production_importance = []
    with (ROOT / "feature_importance.csv").open(newline="", encoding="utf-8") as importance_file:
        for row in csv.DictReader(importance_file):
            production_importance.append({
                "feature": row["feature"],
                "importance_mean": float(row["importance_mean"]),
                "importance_std": float(row["importance_std"]),
            })
    production_importance.sort(key=lambda row: row["importance_mean"], reverse=True)

    with (ROOT / "phishing_model.pkl").open("rb") as model_file:
        production_model = pickle.load(model_file)
    with (ROOT / "feature_names.pkl").open("rb") as names_file:
        production_names = list(pickle.load(names_file))
    production_estimators = [
        item.estimator for item in getattr(production_model, "calibrated_classifiers_", [])
        if hasattr(item, "estimator") and hasattr(item.estimator, "_predictors")
    ]
    production_gain = []
    if production_estimators:
        # Average per-fold gain by normalizing each fitted estimator before averaging.
        fold_rankings = [tree_gain_importance(estimator, production_names) for estimator in production_estimators]
        sums = {}
        for ranking in fold_rankings:
            for item in ranking:
                sums[item["feature"]] = sums.get(item["feature"], 0.0) + item["normalized_split_gain"]
        production_gain = [
            {"rank": rank, "feature": feature, "mean_normalized_split_gain": value / len(fold_rankings)}
            for rank, (feature, value) in enumerate(sorted(sums.items(), key=lambda item: item[1], reverse=True)[:10], 1)
        ]

    best_candidate_path = ROOT / "experiments" / "dynamic_hardening" / "candidate_hist_gradient_boosting.pkl"
    best_estimator, best_names = load_candidate_estimator(best_candidate_path)
    candidate_gain = tree_gain_importance(best_estimator, best_names)
    saved_candidate_importance = hardening_report.get("candidate_models", {}).get("hist_gradient_boosting", {})
    permutation_data = saved_candidate_importance.get("permutation_importance")
    feature_data = saved_candidate_importance.get("feature_importance")
    return {
        "best_candidate_basis": "Highest external phishing recall among the listed candidates with an explicit external result: dynamic_hardening HistGradientBoosting, 0.7801408369.",
        "production": {
            "recorded_feature_importance_csv_top_10": production_importance[:10],
            "recorded_feature_importance_all": production_importance,
            "recorded_csv_method": "The file has importance_mean/std columns; method provenance is not stated. The active train_model.py writer initializes these fields to zero, so these nonzero stored values are reported as recorded importance scores, not asserted to be permutation importance.",
            "hist_gradient_boosting_split_gain_top_10": production_gain,
        },
        "best_candidate": {
            "artifact": str(best_candidate_path.relative_to(ROOT)),
            "feature_count": len(best_names),
            "hist_gradient_boosting_split_gain_top_10": candidate_gain,
            "saved_feature_importance": feature_data,
            "saved_permutation_importance": permutation_data,
            "permutation_importance_available": bool(permutation_data),
            "method_note": "The HGB artifact exposes per-node split gain; this is an internal split-gain ranking, not held-out permutation importance. The report's feature_importance and permutation_importance maps are empty, and no row-level held-out feature matrix is available for a new permutation analysis.",
        },
    }


def main() -> None:
    reports = {key: load_json(path) for key, path in REPORT_PATHS.items()}
    bias = load_json("reports/dynamic_training_bias_analysis.json")
    false_positive = load_json("reports/dynamic_url_false_positive_analysis.json")
    candidate_rows_data = candidate_rows(reports)
    production_rows_data = production_rows(reports)

    augmentation_corpus = corpus_summary(reports["dynamic_augmentation"])
    hardening_corpus = corpus_summary(reports["dynamic_hardening"])
    training_corpus = corpus_summary(reports["dynamic_training_comparison"])
    recovery_corpus = corpus_summary(reports["dynamic_recovery_final"])
    recovery_comparison_corpus = corpus_summary(reports["dynamic_recovery_comparison"])

    old_cohorts = false_positive.get("data", {}).get("verified_labeled_url_cohorts", {})
    legacy_dynamic_cohorts = {
        name: {
            "legitimate": old_cohorts.get(key, {}).get("legitimate"),
            "phishing": old_cohorts.get(key, {}).get("phishing"),
        }
        for name, key in (
            ("path_only", "path_only"),
            ("query_only", "query_only"),
            ("path_plus_query", "path_plus_query"),
            ("multiple_query_parameters", "multiple_query_parameters"),
            ("long_query_over_100_chars", "long_query_over_100_chars"),
        )
    }
    source_structure = (
        reports["dynamic_recovery_final"].get("training_corpus", {}).get("url_structure_by_source_label", {})
    )
    source_structure_rates = {
        source: {
            key: values.get(key)
            for key in ("rows", "has_path_rate", "has_query_rate", "has_fragment_rate")
            if key in values
        }
        for source, values in source_structure.items()
    }

    augmentation_dynamic = reports["dynamic_augmentation"].get("corpus", {})
    aug_labels = augmentation_dynamic.get("rows_by_label", {})
    aug_sources = augmentation_dynamic.get("rows_by_source", {})
    aug_dynamic_rows = aug_sources.get("existing_dynamic", 0) + aug_sources.get("new_high_confidence", 0)
    aug_legit_rows = int(aug_labels.get("0", 0))
    hard_legit = int(hardening_corpus.get("legitimate") or 0)
    hard_dynamic = int(hardening_corpus.get("rows_by_source", {}).get("verified_benign_dynamic", 0))
    recovery_comp_pool = reports["dynamic_recovery_comparison"].get("pool", {})

    split_methods = {
        "dynamic_augmentation": "GroupShuffleSplit by registered domain in scripts/train_dynamic_augmentation_experiment.py.",
        "dynamic_hardening": "Registered-domain grouped split with explicit pairwise set checks in scripts/train_dynamic_hardening_experiment.py.",
        "dynamic_recovery_final": "Registered-domain grouped split with explicit pairwise set checks in scripts/train_dynamic_recovery_experiment.py.",
        "dynamic_recovery_comparison": "Registered-domain grouped split with explicit pairwise set checks in scripts/train_dynamic_recovery_experiment.py.",
        "dynamic_training_comparison": "Domain-grouped split recorded in reports/dynamic_training_comparison.json; explicit overlap counts are not included there.",
    }

    external_domain_overlap = {
        name: {
            "domains_shared_with_external_holdout": corpus.get("domains_shared_with_external_holdout"),
            "rows_in_domains_shared_with_external_holdout": corpus.get("rows_in_domains_shared_with_external_holdout"),
            "source_report": REPORT_PATHS[name],
        }
        for name, corpus in (
            ("dynamic_training_comparison", training_corpus),
            ("dynamic_recovery_comparison", recovery_comparison_corpus),
        )
    }

    hgb_external = [
        row for row in candidate_rows_data
        if row["model"] == "hist_gradient_boosting"
        and row["external_phishing"].get("phishing_recall") is not None
    ]
    best_external = max(hgb_external, key=lambda row: row["external_phishing"]["phishing_recall"])
    baseline_external_recall = 0.9123997134208132

    importance = feature_importance_summary(reports["dynamic_hardening"])
    stored_prod_top = importance["production"]["recorded_feature_importance_csv_top_10"]
    saved_candidate_importance = importance["best_candidate"]
    prod_importance = {
        row["feature"]: row["importance_mean"]
        for row in importance["production"]["recorded_feature_importance_all"]
    }
    candidate_importance = {
        row["feature"]: row["normalized_split_gain"]
        for row in importance["best_candidate"]["hist_gradient_boosting_split_gain_top_10"]
    }
    query_feature_scores = {
        feature: prod_importance.get(feature)
        for feature in ("PathLength", "QueryLength", "QueryParameterCount", "URLPercentEncodingCount", "HasSuspiciousToken")
    }

    root_causes = [
        {
            "rank": 1,
            "cause": "G: combination of source/class skew, source distribution shift, and limited URL-only evidence",
            "assessment": "strongly_supported_combination",
            "evidence": [
                {"report": "reports/dynamic_url_false_positive_analysis.json", "field": "data.verified_labeled_url_cohorts.path_only/query_only/path_plus_query", "value": legacy_dynamic_cohorts, "interpretation": "The legacy production training corpus had zero legitimate rows in the path-only, query-only, and path-plus-query cohorts while those cohorts contained 499,392 phishing rows combined."},
                {"report": "reports/dynamic_augmentation_final.json", "field": "corpus and comparison", "value": {"phishing": int(aug_labels.get("1", 0)), "legitimate": aug_legit_rows, "dynamic_legitimate_added": aug_dynamic_rows, "candidate_external_recall": best_external["external_phishing"]["phishing_recall"], "candidate_dynamic_fpr": reports["dynamic_augmentation"].get("comparison", {}).get("candidate", {}).get("dynamic_benign_fpr")}, "interpretation": "Adding dynamic legitimate examples sharply reduced dynamic false positives but the best measured external recall stayed well below the production reference."},
                {"report": "reports/dynamic_recovery_comparison.json", "field": "pool.removed_exact_holdout_url_overlap and training_corpus", "value": {"active_feed_rows_removed_for_exact_holdout_overlap": recovery_comp_pool.get("removed_exact_holdout_url_overlap", {}).get("phishing_database_active"), "active_feed_rows_retained": recovery_comparison_corpus.get("rows_by_source", {}).get("phishing_database_active"), "legitimate": recovery_comparison_corpus.get("legitimate"), "phishing": recovery_comparison_corpus.get("phishing"), "HGB_external_recall": next((row["external_phishing"]["phishing_recall"] for row in candidate_rows_data if row["experiment"] == "dynamic_recovery_comparison" and row["model"] == "hist_gradient_boosting"), None)}, "interpretation": "The recovery-comparison candidate retained only 10 active-feed phishing rows after exact holdout URL exclusion and showed poor external recall."},
            ],
        },
        {
            "rank": 2,
            "cause": "A: class/source imbalance",
            "assessment": "strongly_supported",
            "evidence": [
                {"report": "reports/dynamic_recovery_comparison.json", "field": "training_corpus", "value": {"legitimate": recovery_comparison_corpus.get("legitimate"), "phishing": recovery_comparison_corpus.get("phishing"), "phishing_to_legitimate_ratio": recovery_comparison_corpus.get("phishing_to_legitimate_ratio"), "source_distribution": recovery_comparison_corpus.get("rows_by_source")}, "interpretation": "That experiment is 301,968 legitimate versus 90,815 phishing rows, with just 10 active-feed rows; its HGB external recall is 0.6069."},
                {"report": "reports/dynamic_augmentation_final.json", "field": "source_aware_training_weights", "value": reports["dynamic_augmentation"].get("source_aware_training_weights"), "interpretation": "Augmentation weighting contributes 97,305 effective legitimate augmentation weight against 310,993 phishing training weight; augmentation did not outweigh the phishing mass, but raw examples and source mix still changed substantially."},
            ],
        },
        {
            "rank": 3,
            "cause": "D: phishing and benign source/structure distribution shift",
            "assessment": "strongly_supported",
            "evidence": [
                {"report": "reports/dynamic_recovery_final.json", "field": "training_corpus.url_structure_by_source_label", "value": source_structure_rates, "interpretation": "Legacy PhiUSIIL legitimate rows have 0% path and query, while active-feed phishing is 74.1% path/18.0% query and verified dynamic benign is 98.8% path/17.8% query. Query rates align after augmentation; source/path composition does not."},
                {"report": "reports/dynamic_hardening_final.json", "field": "candidate_models.hist_gradient_boosting.external_validation", "value": {"external_recall": next((row["external_phishing"]["phishing_recall"] for row in candidate_rows_data if row["experiment"] == "dynamic_hardening" and row["model"] == "hist_gradient_boosting"), None), "production_external_recall": baseline_external_recall}, "interpretation": "The strongest reported candidate external recall remains below the production external recall; training/test improvement does not carry across the external phishing source."},
            ],
        },
        {
            "rank": 4,
            "cause": "C: dynamic benign cohort dominates the legitimate class in several experiment corpora",
            "assessment": "supported_as_a_distribution_change_but_not_as_effective_weight_dominance",
            "evidence": [
                {"report": "reports/dynamic_augmentation_final.json", "field": "corpus.rows_by_source and rows_by_label", "value": {"dynamic_legitimate_rows": aug_dynamic_rows, "legitimate_rows": aug_legit_rows, "dynamic_share_of_legitimate": aug_dynamic_rows / aug_legit_rows if aug_legit_rows else None}, "interpretation": "The two dynamic sources account for about 61.5% of legitimate rows in the augmented corpus."},
                {"report": "reports/dynamic_hardening_final.json", "field": "training_corpus.source_distribution", "value": {"dynamic_legitimate_rows": hard_dynamic, "legitimate_rows": hard_legit, "dynamic_share_of_legitimate": hard_dynamic / hard_legit if hard_legit else None}, "interpretation": "Verified dynamic rows account for about 60.4% of legitimate rows in hardening; effective weighting details differ by experiment."},
            ],
        },
        {
            "rank": 5,
            "cause": "E: 29 URL-only features may be insufficient to separate legitimate dynamic URLs from phishing",
            "assessment": "plausible_contributor_not_proven_as_the_primary_cause",
            "evidence": [
                {"report": "feature_importance.csv", "field": "importance_mean", "value": query_feature_scores, "interpretation": "Recorded production importance is dominated by path/URL length; QueryLength is 0.00172, HasSuspiciousToken is 0.00035, and QueryParameterCount/URLPercentEncodingCount are exactly 0 in the stored file."},
                {"report": "reports/dynamic_hardening_final.json and saved candidate artifact", "field": "HGB split-gain rankings", "value": candidate_importance, "interpretation": "The best externally measured candidate's top gains are hostname length, dot count, URL length, entropy, and hyphens; query-specific features do not rank in its top ten. These are split gains, not permutation importance."},
                {"report": "reports/dynamic_hardening_final.json", "field": "candidate_models.hist_gradient_boosting.feature_importance/permutation_importance", "value": {"feature_importance": saved_candidate_importance.get("saved_feature_importance"), "permutation_importance": saved_candidate_importance.get("saved_permutation_importance")}, "interpretation": "The report's candidate importance maps are empty; no held-out permutation ranking is recorded."},
            ],
        },
        {
            "rank": 6,
            "cause": "F: threshold selection and calibration",
            "assessment": "contributes_to_the_operating_tradeoff_but_does_not_explain_ranking_loss_alone",
            "evidence": [
                {"report": "reports/dynamic_hardening_final.json", "field": "candidate_models.hist_gradient_boosting.thresholds/domain_test/external_validation", "value": {"selected_phishing_threshold": reports["dynamic_hardening"].get("candidate_models", {}).get("hist_gradient_boosting", {}).get("thresholds", {}).get("phishing"), "threshold_split_recall_at_selected_threshold": reports["dynamic_hardening"].get("candidate_models", {}).get("hist_gradient_boosting", {}).get("thresholds", {}).get("threshold_split_recall_at_selected_threshold"), "domain_test_at_0_5_recall": reports["dynamic_hardening"].get("candidate_models", {}).get("hist_gradient_boosting", {}).get("domain_test", {}).get("recall"), "external_recall_at_selected_threshold": reports["dynamic_hardening"].get("candidate_models", {}).get("hist_gradient_boosting", {}).get("external_validation", {}).get("recall")}, "interpretation": "The tuned high threshold reduces false positives but lowers threshold-split recall. However, low external PR-AUC/recall in recovery-comparison also indicates score-ranking/source generalization problems, not only a threshold issue."},
            ],
        },
        {
            "rank": 7,
            "cause": "B: domain leakage",
            "assessment": "not_supported_as_the_primary_internal_split_cause; external_domain_overlap_is_a_validation_caveat",
            "evidence": [
                {"report": "scripts/train_dynamic_augmentation_experiment.py, scripts/train_dynamic_hardening_experiment.py, scripts/train_dynamic_recovery_experiment.py", "field": "registered-domain grouped split implementations", "value": split_methods, "interpretation": "The listed internal evaluation splits are grouped by registered domain; no report evidence shows within-split random URL leakage."},
                {"report": "reports/dynamic_training_comparison.json and reports/dynamic_recovery_comparison.json", "field": "training_corpus.domains_shared_with_external_holdout", "value": external_domain_overlap, "interpretation": "Some training domains are shared with the external holdout, so external recall may be optimistic; this does not explain why recall is lower on those holdouts."},
            ],
        },
    ]

    importance_fields = {
        "PathLength": prod_importance.get("PathLength"),
        "QueryLength": prod_importance.get("QueryLength"),
        "QueryParameterCount": prod_importance.get("QueryParameterCount"),
        "URLPercentEncodingCount": prod_importance.get("URLPercentEncodingCount"),
        "HasSuspiciousToken": prod_importance.get("HasSuspiciousToken"),
    }

    next_experiment = [
        "Keep a 29-feature production-schema baseline and change one factor at a time; run source-weight/dynamic-negative dose ablations instead of simultaneously changing sampling, cohort size, and thresholds.",
        "Retain a minimum, documented phishing sample from every source; assert before fitting that URL deduplication and holdout exclusion do not reduce an expected 620k-row active feed to 10 rows.",
        "Balance source and structural cohorts explicitly: path/query, multiple parameters, encoding, long URLs, pathless, short, no-token, no-suspicious-TLD, and ordinary-looking phishing versus legitimate examples.",
        "Use registered-domain-disjoint train/calibration/threshold/test partitions and make the external holdout domain-disjoint too; report all overlap counts and source composition.",
        "Publish dynamic-benign and query-bearing FPRs beside external phishing recall, PR-AUC, calibration, and hard-cohort recall at the same declared thresholds.",
        "Run feature-importance/permutation analyses on a preserved held-out feature matrix; only then test URL feature additions in a separate ablation, not as an unmeasured simultaneous change.",
    ]
    do_not_change = [
        "Do not replace production artifacts, service behavior, extension behavior, or production thresholds during the experiment.",
        "Do not add domain allowlists, service-specific exceptions, model bypasses, or score-display changes.",
        "Do not remove/relabel phishing rows or tune thresholds on the external holdout/test set to make a candidate pass.",
        "Do not change the feature schema, training source mix, dynamic cohort weight, and threshold policy in one experiment; that would prevent attribution.",
    ]

    report = {
        "analysis": "dynamic_experiment_failure",
        "training_or_promotion_performed": False,
        "overall_conclusion": "A combination is best supported: the legacy label/source correlation made dynamic structure a phishing shortcut; the large, source-distinct benign dynamic cohort corrected that false-positive shortcut but shifted the legitimate class substantially; experiments that under-sampled or nearly removed the active phishing source lost external recall. High tuned thresholds then traded recall for FPR. Domain-only features likely limit discrimination, but the existing evidence does not prove they are the sole cause.",
        "reports_inspected": list(REPORT_PATHS.values()) + [
            "reports/dynamic_training_bias_analysis.json",
            "reports/dynamic_url_false_positive_analysis.json",
            "feature_importance.csv",
            "model_metadata.json",
        ],
        "candidate_artifacts_inspected": [
            "experiments/dynamic_augmentation/hist_gradient_boosting_estimator.pkl",
            "experiments/dynamic_augmentation/logistic_regression_estimator.pkl",
            "experiments/dynamic_hardening/candidate_hist_gradient_boosting.pkl",
            "experiments/dynamic_hardening/candidate_logistic_regression.pkl",
            "experiments/dynamic_recovery/candidate_hist_gradient_boosting.pkl",
            "experiments/dynamic_recovery/candidate_logistic_regression.pkl",
        ],
        "candidate_comparison": candidate_rows_data,
        "production_comparison_by_experiment": production_rows_data,
        "corpus_composition": {
            "dynamic_augmentation": augmentation_corpus,
            "dynamic_training_comparison": training_corpus,
            "dynamic_hardening": hardening_corpus,
            "dynamic_recovery_final": recovery_corpus,
            "dynamic_recovery_comparison": recovery_comparison_corpus,
        },
        "legacy_production_structure_bias": {
            "source_report": "reports/dynamic_url_false_positive_analysis.json",
            "path_query_cohort_counts": legacy_dynamic_cohorts,
            "prior_production_training_structure_by_source_label": source_structure_rates,
            "interpretation": "The report-backed legacy production corpus contained no legitimate path/query examples in the measured path-only, query-only, or path-plus-query cohorts; phishing examples were abundant in each.",
        },
        "external_holdout_domain_overlap": external_domain_overlap,
        "feature_importance": importance,
        "root_cause_ranking": root_causes,
        "production_weaknesses": [
            {
                "finding": "Very high false-phishing rate on legitimate dynamic holdout URLs.",
                "evidence": {"report": "reports/dynamic_augmentation_final.json", "production_dynamic_fpr": reports["dynamic_augmentation"].get("comparison", {}).get("production", {}).get("dynamic_benign_fpr"), "production_query_fpr": reports["dynamic_augmentation"].get("comparison", {}).get("production", {}).get("query_fpr"), "holdout_rows": reports["dynamic_augmentation"].get("production_dynamic_benign_holdout", {}).get("overall", {}).get("rows"), "query_rows": reports["dynamic_augmentation"].get("production_dynamic_benign_holdout", {}).get("query", {}).get("rows")},
            },
            {
                "finding": "Recorded importance is concentrated in URL/path and hostname-shape features; query-specific stored importance is small or zero.",
                "evidence": {"importance_mean_top10": stored_prod_top, "query_related_importance_mean": importance_fields},
            },
        ],
        "candidate_weaknesses": [
            {"finding": "External phishing recall remains below production in every candidate with a measured comparable external holdout.", "candidate_external_recalls": [{"experiment": row["experiment"], "model": row["model"], "recall": row["external_phishing"].get("phishing_recall"), "rows": row["external_phishing"].get("rows")} for row in candidate_rows_data if row["external_phishing"].get("phishing_recall") is not None], "production_reference_recall": baseline_external_recall},
            {"finding": "Hard phishing cohorts remain weak even when overall domain-test F1/PR-AUC improves.", "best_external_candidate": best_external["experiment"] + "/" + best_external["model"], "hard_cohorts": best_external["hard_phishing_cohorts"]},
            {"finding": "Dynamic benign holdouts improve sharply but retain nonzero phishing verdict rates.", "dynamic_holdout_results": [{"experiment": row["experiment"], "model": row["model"], "metrics": row["legitimate_dynamic_regression"]} for row in candidate_rows_data if row["legitimate_dynamic_regression"].get("legitimate_false_phishing_rate") is not None]},
        ],
        "what_to_change_in_next_training_experiment": next_experiment,
        "what_not_to_change": do_not_change,
        "comparability_limitations": [
            "Reports use different corpora, test sizes, and decision thresholds; each candidate row preserves the report's own threshold and split rather than pretending all values are one paired benchmark.",
            "Domain-test FPR is registered-domain FPR where reports provide domain_fpr; otherwise it is URL-level FPR on a domain-disjoint split and is labeled accordingly.",
            "External validation files are phishing-only, so their FPR is undefined.",
            "The recovery-final report explicitly did not use an external holdout; its external recall is null, not inferred.",
            "Candidate permutation-importance outputs are empty. Candidate feature rankings use stored HGB node split gain, which is not permutation importance; the production CSV importance method is not confirmed by current source code.",
        ],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2, ensure_ascii=False)
        output_file.write("\n")

    print(json.dumps({
        "candidate_rows": len(candidate_rows_data),
        "production_reference_rows": len(production_rows_data),
        "best_external_candidate": f"{best_external['experiment']}/{best_external['model']}",
        "best_external_recall": best_external["external_phishing"]["phishing_recall"],
        "recovery_comparison_feed_rows_retained": recovery_comparison_corpus.get("rows_by_source", {}).get("phishing_database_active"),
        "production_dynamic_fpr": reports["dynamic_augmentation"].get("comparison", {}).get("production", {}).get("dynamic_benign_fpr"),
        "candidate_dynamic_fpr": reports["dynamic_augmentation"].get("comparison", {}).get("candidate", {}).get("dynamic_benign_fpr"),
        "report": str(OUTPUT_PATH.relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()