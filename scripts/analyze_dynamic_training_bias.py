"""Measure URL-structure representation in VIGIL's current training data."""
from __future__ import annotations

import json
import sys
from itertools import combinations_with_replacement
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DATASET_PATH = ROOT / "data" / "processed" / "clean_dataset.csv"
REFERENCE_REPORT_PATH = ROOT / "reports" / "dynamic_url_false_positive_analysis.json"
OUTPUT_PATH = ROOT / "reports" / "dynamic_training_bias_analysis.json"
LABELS = (0, 1)

COHORT_DEFINITIONS = {
    "homepage": "Path is empty or '/', with no query and no fragment.",
    "path_only": "Non-root path and empty query; a fragment may also be present.",
    "query_only": "Empty or root path and non-empty query.",
    "path_plus_query": "Non-root path and non-empty query.",
    "fragment": "Non-empty fragment component.",
    "encoded": "URL contains a percent-encoded byte (% followed by two hex digits).",
    "multiple_query_params": "Query has more than one key/value segment.",
    "long_query": "Raw query string is longer than 100 characters.",
    "long_url": "URL is longer than 200 characters.",
    "tracking_utm_parameters": "Query contains utm_*, gclid, fbclid, yclid, or mc_* parameter.",
    "suspicious_token_present": "Production HasSuspiciousToken feature is 1.",
    "suspicious_token_absent": "Production HasSuspiciousToken feature is 0.",
    "digits_present": "URL contains at least one digit.",
    "digits_absent": "URL contains no digits.",
}

REPORT_COHORT_KEYS = {
    "homepage": "homepage",
    "path_only": "path_only",
    "query_only": "query_only",
    "path_plus_query": "path_plus_query",
    "fragment": "fragment",
    "encoded": "encoded_characters",
    "multiple_query_params": "multiple_query_parameters",
    "long_query": "long_query_over_100_chars",
    "long_url": "long_url_over_200_chars",
}


def percent(count: int | None, total: int) -> float | None:
    if count is None:
        return None
    return round(count * 100 / total, 6) if total else 0.0


def label_counts(frame, mask) -> dict[str, int]:
    return {
        str(label): int((mask & frame["label"].eq(label)).sum())
        for label in LABELS
    }


def analyze_frame(frame) -> dict:
    from feature_extractor import extract_features

    urls = frame["url"].astype(str)
    parts = urls.map(urlsplit)
    paths = parts.map(lambda item: item.path or "")
    queries = parts.map(lambda item: item.query or "")
    fragments = parts.map(lambda item: item.fragment or "")
    parameter_counts = queries.map(
        lambda query: len(parse_qsl(query, keep_blank_values=True))
    )
    tracking = queries.str.lower().str.contains(
        r"(?:^|&)(?:utm_[^=]*|gclid|fbclid|yclid|mc_[^=]*)=",
        regex=True,
        na=False,
    )
    suspicious = urls.map(
        lambda url: bool(extract_features(url)["HasSuspiciousToken"])
    )
    digits = urls.str.contains(r"\d", regex=True, na=False)

    masks = {
        "homepage": paths.isin(("", "/")) & queries.eq("") & fragments.eq(""),
        "path_only": ~paths.isin(("", "/")) & queries.eq(""),
        "query_only": paths.isin(("", "/")) & queries.ne(""),
        "path_plus_query": ~paths.isin(("", "/")) & queries.ne(""),
        "fragment": fragments.ne(""),
        "encoded": urls.str.contains(r"%[0-9a-fA-F]{2}", regex=True, na=False),
        "multiple_query_params": parameter_counts.gt(1),
        "long_query": queries.str.len().gt(100),
        "long_url": urls.str.len().gt(200),
        "tracking_utm_parameters": tracking,
        "suspicious_token_present": suspicious,
        "suspicious_token_absent": ~suspicious,
        "digits_present": digits,
        "digits_absent": ~digits,
    }

    totals = {str(label): int(frame["label"].eq(label).sum()) for label in LABELS}
    cohorts = {}
    for name, mask in masks.items():
        counts = label_counts(frame, mask)
        cohorts[name] = {
            "definition": COHORT_DEFINITIONS[name],
            "counts_by_label": counts,
            "percentage_within_label": {
                label: percent(count, totals[label])
                for label, count in counts.items()
            },
        }

    overlaps = {}
    for first, second in combinations_with_replacement(masks, 2):
        overlaps[f"{first}|{second}"] = label_counts(
            frame, masks[first] & masks[second]
        )

    return {
        "total_rows_by_label": totals,
        "cohorts": cohorts,
        "pairwise_cohort_overlap_counts": overlaps,
        "overlap_status": "computed_from_local_rows",
    }


def analyze_existing_report() -> dict:
    with REFERENCE_REPORT_PATH.open(encoding="utf-8") as report_file:
        reference = json.load(report_file)

    data = reference["data"]
    source_cohorts = data["verified_labeled_url_cohorts"]
    totals = {str(label): int(count) for label, count in data["label_counts"].items()}
    cohorts = {}

    for name in COHORT_DEFINITIONS:
        source_key = REPORT_COHORT_KEYS.get(name)
        source = source_cohorts.get(source_key) if source_key else None
        if source is None:
            counts = {"0": None, "1": None}
        else:
            counts = {
                "0": int(source["legitimate"]),
                "1": int(source["phishing"]),
            }
        cohorts[name] = {
            "definition": COHORT_DEFINITIONS[name],
            "counts_by_label": counts,
            "percentage_within_label": {
                label: percent(count, totals[label])
                for label, count in counts.items()
            },
        }

    exclusive_groups = ("homepage", "path_only", "query_only", "path_plus_query")
    known_disjoint_overlaps = {}
    for first, second in combinations_with_replacement(exclusive_groups, 2):
        if first == second:
            counts = cohorts[first]["counts_by_label"]
        else:
            counts = {"0": 0, "1": 0}
        known_disjoint_overlaps[f"{first}|{second}"] = counts

    redirect_or_tracking = source_cohorts.get("redirect_or_tracking_parameter")
    related_metrics = None
    if redirect_or_tracking:
        related_metrics = {
            "name": "redirect_or_tracking_parameter",
            "counts_by_label": {
                "0": int(redirect_or_tracking["legitimate"]),
                "1": int(redirect_or_tracking["phishing"]),
            },
            "note": "The stored report combines redirect and tracking parameters; it is not an exact tracking/UTM-only count.",
        }

    return {
        "total_rows_by_label": totals,
        "cohorts": cohorts,
        "pairwise_cohort_overlap_counts": None,
        "known_disjoint_overlaps": known_disjoint_overlaps,
        "overlap_status": "row_level_dataset_missing; only structural disjointness and cohort marginals are available",
        "source_report": {
            "path": str(REFERENCE_REPORT_PATH.relative_to(ROOT)),
            "generated_at_utc": reference.get("generated_at_utc"),
            "dataset": data.get("dataset"),
        },
        "unavailable_metrics": [
            "tracking_utm_parameters exact counts",
            "suspicious_token_present and suspicious_token_absent counts",
            "digits_present and digits_absent counts",
            "pairwise overlaps outside the disjoint structural cohorts",
        ],
        "related_report_metric": related_metrics,
    }


def make_hypothesis_assessment(cohorts: dict) -> dict:
    core = ("path_only", "query_only", "path_plus_query")
    legitimate_missing = all(
        cohorts[name]["counts_by_label"]["0"] == 0 for name in core
    )
    phishing_present = all(
        (cohorts[name]["counts_by_label"]["1"] or 0) > 0 for name in core
    )
    if legitimate_missing and phishing_present:
        status = "supports"
        statement = (
            "The stored production-dataset counts show phishing examples in each "
            "path/query cohort and zero legitimate examples in all three."
        )
    else:
        status = "does_not_establish"
        statement = (
            "The available counts do not show zero legitimate examples across all "
            "three core path/query cohorts."
        )
    return {
        "status": status,
        "statement": statement,
        "core_cohorts": list(core),
        "limitation": (
            "The row-level clean_dataset.csv is absent locally. This assessment "
            "uses its prior stored cohort report; null fields were not inferred."
        ),
    }


def main() -> None:
    if DATASET_PATH.is_file():
        from train_dynamic_augmentation_experiment import parse_label, read_csv_urls

        frame = read_csv_urls(
            DATASET_PATH, "clean_dataset.csv", require_labels=True
        )
        frame["label"] = frame["label"].map(parse_label).astype(int)
        analysis = analyze_frame(frame)
        analysis["data_source"] = {
            "mode": "local_dataset",
            "path": str(DATASET_PATH.relative_to(ROOT)),
            "loader": "train_dynamic_augmentation_experiment.read_csv_urls",
        }
    else:
        analysis = analyze_existing_report()
        analysis["data_source"] = {
            "mode": "stored_report_fallback",
            "dataset_path": str(DATASET_PATH.relative_to(ROOT)),
            "dataset_available": False,
            "note": "Counts are limited to exact marginals in the stored production-corpus report.",
        }

    analysis["hypothesis_assessment"] = make_hypothesis_assessment(
        analysis["cohorts"]
    )
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as output_file:
        json.dump(analysis, output_file, indent=2, ensure_ascii=False)
        output_file.write("\n")

    print("Rows by label:", analysis["total_rows_by_label"])
    print("Cohort counts (legitimate / phishing):")
    important = (
        "path_only",
        "query_only",
        "path_plus_query",
        "long_query",
        "multiple_query_params",
        "encoded",
    )
    for name in important:
        counts = analysis["cohorts"][name]["counts_by_label"]
        leg = "unavailable" if counts["0"] is None else f"{counts['0']:,}"
        phish = "unavailable" if counts["1"] is None else f"{counts['1']:,}"
        print(f"  {name}: {leg} / {phish}")

    dynamic_candidates = (
        "path_only",
        "query_only",
        "path_plus_query",
        "long_query",
        "multiple_query_params",
        "encoded",
    )
    known = [
        (analysis["cohorts"][name]["percentage_within_label"]["1"], name)
        for name in dynamic_candidates
        if analysis["cohorts"][name]["percentage_within_label"]["1"] is not None
    ]
    if known:
        phishing_share, strongest = max(known)
        legitimate_share = analysis["cohorts"][strongest]["percentage_within_label"]["0"]
        if legitimate_share is None:
            legit_display = "unavailable"
        else:
            legit_display = f"{legitimate_share:.3f}%"
        print(
            "Strongest measured structural imbalance: "
            f"{strongest} ({legit_display} legitimate vs {phishing_share:.3f}% phishing)"
        )

    print(
        "Hypothesis:",
        analysis["hypothesis_assessment"]["status"],
        "-",
        analysis["hypothesis_assessment"]["statement"],
    )
    if analysis.get("unavailable_metrics"):
        print("Unavailable without row-level CSV:", "; ".join(analysis["unavailable_metrics"]))


if __name__ == "__main__":
    main()