"""Evaluate the experimental dynamic candidate without changing model files."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from feature_extractor import (  # noqa: E402
    FEATURE_NAMES,
    MODEL_EXCLUDED_FEATURES,
    normalize_url,
)
from service import _thresholds_from_metadata  # noqa: E402
from train_dynamic_candidate import (  # noqa: E402
    calibrated_probabilities,
    domain_disjoint_splits,
    load_feature_names,
    load_legitimate_rows,
    load_phishing_rows,
    make_features,
)

CANDIDATE_PATH = ROOT / "models" / "experimental" / "dynamic_candidate" / "dynamic_candidate.joblib"
TRAINING_REPORT_PATH = ROOT / "reports" / "dynamic_candidate_training.json"
BASELINE_PATH = ROOT / "reports" / "baseline_dynamic_legitimate.json"
COUNTERFACTUAL_PATH = ROOT / "reports" / "dynamic_counterfactual_analysis.json"
BIAS_REPORT_PATH = ROOT / "reports" / "dynamic_training_bias_analysis.json"
HARD_COHORT_PATH = ROOT / "reports" / "benign_dynamic_url_training.json"
REFERENCE_PATH = ROOT / "reports" / "final_promotion_gate.json"
METADATA_PATH = ROOT / "model_metadata.json"
OUTPUT_PATH = ROOT / "reports" / "dynamic_candidate_evaluation.json"

STRUCTURAL_VARIANTS = ("path", "query", "multi-query", "encoded", "fragment", "path+query")
STRUCTURE_DELTA_LIMIT = 0.20
MAX_ALLOWED_RELATIVE_RECALL_DROP = 0.20


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as input_file:
        return json.load(input_file)


def score_urls(bundle: dict, urls: list[str]) -> np.ndarray:
    feature_names = bundle["feature_names"]
    rows = [{"url": url} for url in urls]
    features = make_features(rows, feature_names)
    return calibrated_probabilities(bundle["estimator"], bundle["calibrator"], features)


def verdict_counts(probabilities: np.ndarray, thresholds: dict) -> dict[str, int]:
    return {
        "SAFE": int((probabilities < thresholds["safe"]).sum()),
        "SUSPICIOUS": int(
            ((probabilities >= thresholds["safe"]) & (probabilities < thresholds["phishing"])).sum()
        ),
        "PHISHING": int((probabilities >= thresholds["phishing"]).sum()),
    }


def legitimate_summary(urls: list[str], probabilities: np.ndarray, thresholds: dict) -> dict:
    counts = verdict_counts(probabilities, thresholds)
    total = len(urls)
    return {
        "total": total,
        "verdict_counts": counts,
        "false_phishing_count": counts["PHISHING"],
        "false_positive_rate_phishing_label": counts["PHISHING"] / total if total else None,
        "not_safe_rate": (counts["SUSPICIOUS"] + counts["PHISHING"]) / total if total else None,
        "average_probability": float(probabilities.mean()) if total else None,
        "maximum_probability": float(probabilities.max()) if total else None,
        "results": [
            {"url": url, "probability": float(probability)}
            for url, probability in zip(urls, probabilities)
        ],
    }


def classification_metrics(y_true: np.ndarray, probability: np.ndarray, threshold: float) -> dict:
    predicted = (probability >= threshold).astype(int)
    return {
        "decision_threshold": threshold,
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "false_negative_rate": float(1.0 - recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, probability)),
        "roc_auc": float(roc_auc_score(y_true, probability)),
        "brier_score": float(brier_score_loss(y_true, probability)),
        "false_positive_rate": float(
            ((predicted == 1) & (y_true == 0)).sum() / max((y_true == 0).sum(), 1)
        ),
        "confusion_counts": {
            "true_negative": int(((predicted == 0) & (y_true == 0)).sum()),
            "false_positive": int(((predicted == 1) & (y_true == 0)).sum()),
            "false_negative": int(((predicted == 0) & (y_true == 1)).sum()),
            "true_positive": int(((predicted == 1) & (y_true == 1)).sum()),
        },
    }


def evaluate_counterfactuals(bundle: dict, thresholds: dict) -> dict:
    report = load_json(COUNTERFACTUAL_PATH)
    rows = report["results"]
    urls = [row["url"] for row in rows]
    probabilities = score_urls(bundle, urls)
    homepage_scores = {
        row["base_url"]: float(probability)
        for row, probability in zip(rows, probabilities)
        if row["variant_type"] == "homepage"
    }
    per_variant = {}
    detail_rows = []
    for variant_type in STRUCTURAL_VARIANTS:
        selected = [
            (row, float(probability))
            for row, probability in zip(rows, probabilities)
            if row["variant_type"] == variant_type
        ]
        deltas = np.asarray(
            [probability - homepage_scores[row["base_url"]] for row, probability in selected],
            dtype=float,
        )
        probs = np.asarray([probability for _, probability in selected], dtype=float)
        crossings = sum(
            homepage_scores[row["base_url"]] < thresholds["phishing"]
            and probability >= thresholds["phishing"]
            for row, probability in selected
        )
        counts = verdict_counts(probs, thresholds)
        per_variant[variant_type] = {
            "samples": len(selected),
            "probability_increased_vs_homepage": int((deltas > 0).sum()),
            "median_probability_delta": float(np.median(deltas)),
            "mean_probability_delta": float(deltas.mean()),
            "maximum_probability_delta": float(deltas.max()),
            "crossed_into_phishing": int(crossings),
            "verdict_counts": counts,
            "maximum_probability": float(probs.max()),
        }
        for (row, probability), delta in zip(selected, deltas):
            detail_rows.append(
                {
                    "base_url": row["base_url"],
                    "variant_type": variant_type,
                    "url": row["url"],
                    "probability": probability,
                    "homepage_probability": homepage_scores[row["base_url"]],
                    "delta_from_homepage": float(delta),
                }
            )

    systematic_escalation = {
        variant_type: (
            metrics["median_probability_delta"] >= STRUCTURE_DELTA_LIMIT
            or metrics["crossed_into_phishing"] > metrics["samples"] / 2
        )
        for variant_type, metrics in per_variant.items()
    }
    all_counts = verdict_counts(probabilities, thresholds)
    return {
        "total": len(rows),
        "verdict_counts": all_counts,
        "false_positive_rate_phishing_label": (
            all_counts["PHISHING"] / len(rows) if rows else None
        ),
        "not_safe_rate": (
            (all_counts["SUSPICIOUS"] + all_counts["PHISHING"]) / len(rows)
            if rows
            else None
        ),
        "average_probability": float(probabilities.mean()) if len(probabilities) else None,
        "maximum_probability": float(probabilities.max()) if len(probabilities) else None,
        "per_variant": per_variant,
        "systematic_high_risk_escalation": systematic_escalation,
        "systematic_escalation_definition": (
            "A variant fails when its median increase over matched homepages is at least 0.20, "
            "or when more than half of matched domains newly cross the unchanged PHISHING threshold."
        ),
        "results": detail_rows,
    }


def evaluate_hard_cohorts(bundle: dict, thresholds: dict) -> dict:
    report = load_json(HARD_COHORT_PATH)
    cohorts = report.get("phishing_regressions", {})
    per_cohort = {}
    unique_urls = {}
    for cohort_name, cohort in cohorts.items():
        rows_by_normalized = {}
        for example in cohort.get("examples", []):
            if not isinstance(example, dict) or not isinstance(example.get("url"), str):
                continue
            if int(example.get("label", 1)) != 1:
                continue
            url = example["url"]
            normalized = normalize_url(url)
            rows_by_normalized.setdefault(normalized, url)
            unique_urls.setdefault(normalized, url)
        urls = list(rows_by_normalized.values())
        probabilities = score_urls(bundle, urls) if urls else np.asarray([], dtype=float)
        recall = float((probabilities >= thresholds["phishing"]).mean()) if urls else None
        per_cohort[cohort_name] = {
            "samples": len(urls),
            "phishing_recall_at_unchanged_threshold": recall,
            "false_negative_rate": 1.0 - recall if recall is not None else None,
            "probability_minimum": float(probabilities.min()) if urls else None,
            "probability_maximum": float(probabilities.max()) if urls else None,
        }

    all_urls = list(unique_urls.values())
    all_probabilities = score_urls(bundle, all_urls) if all_urls else np.asarray([], dtype=float)
    counts = verdict_counts(all_probabilities, thresholds)
    return {
        "source_report": str(HARD_COHORT_PATH.relative_to(ROOT)),
        "source_section": "phishing_regressions",
        "cohort_sample_counts": per_cohort,
        "unique_phishing_urls": len(all_urls),
        "unique_verdict_counts": counts,
        "unique_phishing_recall": counts["PHISHING"] / len(all_urls) if all_urls else None,
        "unique_false_negative_rate": (
            (counts["SAFE"] + counts["SUSPICIOUS"]) / len(all_urls)
            if all_urls
            else None
        ),
        "results": [
            {"url": url, "probability": float(probability)}
            for url, probability in zip(all_urls, all_probabilities)
        ],
    }


def main() -> None:
    bundle = joblib.load(CANDIDATE_PATH)
    feature_names = load_feature_names()
    expected_features = [
        name for name in FEATURE_NAMES if name not in MODEL_EXCLUDED_FEATURES
    ]
    schema_pass = (
        len(feature_names) == 29
        and feature_names == expected_features
        and bundle.get("feature_names") == expected_features
    )

    stored_thresholds = bundle["production_thresholds_for_reference_only"]
    production_metadata = load_json(METADATA_PATH)
    current_thresholds = _thresholds_from_metadata(production_metadata)
    if stored_thresholds != current_thresholds:
        raise ValueError("Candidate reference thresholds differ from unchanged production metadata.")
    thresholds = stored_thresholds

    baseline_report = load_json(BASELINE_PATH)
    baseline_urls = [row["url"] for row in baseline_report["results"]]
    baseline_probabilities = score_urls(bundle, baseline_urls)
    baseline = legitimate_summary(baseline_urls, baseline_probabilities, thresholds)

    counterfactuals = evaluate_counterfactuals(bundle, thresholds)
    hard_cohorts = evaluate_hard_cohorts(bundle, thresholds)
    bias_report = load_json(BIAS_REPORT_PATH)

    training_report = load_json(TRAINING_REPORT_PATH)
    legitimate_rows, _ = load_legitimate_rows()
    phishing_rows, _ = load_phishing_rows(
        {row["domain"] for row in legitimate_rows}, len(legitimate_rows)
    )
    rows = legitimate_rows + phishing_rows
    X = make_features(rows, feature_names)
    y = np.asarray([row["label"] for row in rows], dtype=int)
    groups = np.asarray([row["domain"] for row in rows], dtype=str)
    train_idx, calibration_idx, test_idx = domain_disjoint_splits(X, y, groups)
    stored_split_counts = training_report["split"]["counts"]
    reproduced_counts = {
        name: len(indices)
        for name, indices in (
            ("train", train_idx),
            ("calibration", calibration_idx),
            ("test", test_idx),
        )
    }
    if reproduced_counts != {
        name: stored_split_counts[name]["rows"] for name in reproduced_counts
    }:
        raise ValueError("Reproduced domain-disjoint split differs from candidate training report.")

    test_probabilities = calibrated_probabilities(
        bundle["estimator"], bundle["calibrator"], X.iloc[test_idx]
    )
    domain_test_metrics = classification_metrics(
        y[test_idx], test_probabilities, thresholds["phishing"]
    )
    test_domain_set = set(groups[test_idx])

    reference_report = load_json(REFERENCE_PATH)
    reference_metrics = reference_report["domain_grouped_validation"]["metrics"]["domain_only"]
    reference_recall = float(reference_metrics["phishing_recall"])
    minimum_recall = reference_recall * (1.0 - MAX_ALLOWED_RELATIVE_RECALL_DROP)
    hard_cohort_floor = minimum_recall

    structural_escalation = any(counterfactuals["systematic_high_risk_escalation"].values())
    low_recall_cohorts = {
        name: result["phishing_recall_at_unchanged_threshold"]
        for name, result in hard_cohorts["cohort_sample_counts"].items()
        if result["phishing_recall_at_unchanged_threshold"] is not None
        and result["phishing_recall_at_unchanged_threshold"] < hard_cohort_floor
    }
    gates = {
        "exact_29_feature_schema": {
            "pass": schema_pass,
            "actual_feature_count": len(feature_names),
            "expected_feature_count": 29,
        },
        "no_phishing_on_fixed_legitimate_baseline": {
            "pass": baseline["verdict_counts"]["PHISHING"] == 0,
            "phishing_count": baseline["verdict_counts"]["PHISHING"],
            "legitimate_false_phishing_rate": baseline["false_positive_rate_phishing_label"],
        },
        "no_systematic_structural_high_risk_escalation": {
            "pass": not structural_escalation,
            "per_variant": counterfactuals["systematic_high_risk_escalation"],
            "criterion": counterfactuals["systematic_escalation_definition"],
        },
        "phishing_recall_not_materially_below_strongest_reference": {
            "pass": domain_test_metrics["recall"] >= minimum_recall,
            "candidate_domain_test_recall": domain_test_metrics["recall"],
            "strongest_validated_reference_recall": reference_recall,
            "maximum_relative_drop": MAX_ALLOWED_RELATIVE_RECALL_DROP,
            "minimum_acceptable_recall": minimum_recall,
            "reference_report": str(REFERENCE_PATH.relative_to(ROOT)),
        },
        "no_major_hard_cohort_regression": {
            "pass": not low_recall_cohorts,
            "minimum_cohort_recall": hard_cohort_floor,
            "low_recall_cohorts": low_recall_cohorts,
            "criterion": "Each sampled phishing hard cohort must recall at least 80% of the strongest validated domain-test phishing recall.",
            "sample_size_caveat": "Five examples per cohort in the source report; this is a regression screen, not a population estimate.",
        },
    }

    failed_gates = [name for name, gate in gates.items() if not gate["pass"]]
    overall_pass = not failed_gates
    output = {
        "evaluation": "experimental_candidate_only",
        "overall_gate": "PASS" if overall_pass else "FAIL",
        "promotable": overall_pass,
        "failed_gates": failed_gates,
        "candidate_artifact": str(CANDIDATE_PATH.relative_to(ROOT)),
        "production_artifacts_modified": False,
        "thresholds": {
            "safe": thresholds["safe"],
            "phishing": thresholds["phishing"],
            "source": "candidate bundle's stored production thresholds, verified against model_metadata.json",
            "changed_for_evaluation": False,
        },
        "feature_schema": {
            "count": len(feature_names),
            "features": feature_names,
            "matches_production_29_features": schema_pass,
        },
        "legitimate_baseline": baseline,
        "counterfactual_legitimate": counterfactuals,
        "phishing_hard_cohorts": hard_cohorts,
        "domain_disjoint_test": {
            "train_rows": reproduced_counts["train"],
            "calibration_rows": reproduced_counts["calibration"],
            "test_rows": reproduced_counts["test"],
            "unique_test_registered_domains": len(test_domain_set),
            "test_labels": {
                "legitimate": int((y[test_idx] == 0).sum()),
                "phishing": int((y[test_idx] == 1).sum()),
            },
            "registered_domain_overlaps": training_report["split"]["registered_domain_overlaps"],
            "metrics_at_unchanged_production_phishing_threshold": domain_test_metrics,
            "training_report_metrics_at_0_5": training_report["test_metrics"],
            "reference_candidate": {
                "name": "domain_only",
                "report": str(REFERENCE_PATH.relative_to(ROOT)),
                "domain_test_phishing_recall": reference_recall,
                "domain_test_pr_auc": reference_metrics.get("pr_auc"),
                "domain_test_f1": reference_metrics.get("f1"),
            },
        },
        "training_bias_evidence": {
            "report": str(BIAS_REPORT_PATH.relative_to(ROOT)),
            "hypothesis_assessment": bias_report.get("hypothesis_assessment"),
        },
        "gate_results": gates,
        "limitations": [
            "The held-out candidate test has only 30 rows; metrics are high-variance.",
            "The labeled hard-cohort report provides five sampled URLs per cohort, not full population data.",
            "The strongest validated reference uses a separate, much larger domain-grouped test set; it is a screening comparator, not a paired statistical comparison.",
            "No phishing-only external holdout CSV is locally available to independently reproduce external recall.",
        ],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as report_file:
        json.dump(output, report_file, indent=2, ensure_ascii=False)
        report_file.write("\n")

    print(f"Gate: {output['overall_gate']}")
    print("Failing metrics:")
    if failed_gates:
        for gate_name in failed_gates:
            print(f"  {gate_name}: {gates[gate_name]}")
    else:
        print("  none")
    print(
        "Baseline legitimate verdicts:",
        baseline["verdict_counts"],
        "FPR=", f"{baseline['false_positive_rate_phishing_label']:.4f}",
    )
    print(
        "Domain test recall:",
        f"{domain_test_metrics['recall']:.4f}",
        "vs strongest reference",
        f"{reference_recall:.4f}",
    )
    print("Report:", OUTPUT_PATH.relative_to(ROOT))


if __name__ == "__main__":
    main()