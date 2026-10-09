"""Measure production-score changes across URL shapes for baseline domains."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from service import scan


BASELINE_PATH = ROOT / "reports" / "baseline_dynamic_legitimate.json"
REPORT_PATH = ROOT / "reports" / "dynamic_counterfactual_analysis.json"
VARIANT_TYPES = (
    "homepage",
    "path",
    "query",
    "multi-query",
    "encoded",
    "fragment",
    "path+query",
)


def baseline_origins() -> list[str]:
    with BASELINE_PATH.open(encoding="utf-8") as baseline_file:
        baseline = json.load(baseline_file)

    origins = []
    for item in baseline["results"]:
        parts = urlsplit(item["url"])
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(f"Invalid baseline URL: {item['url']}")
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in origins:
            origins.append(origin)
    return origins


def variants_for(origin: str) -> dict[str, str]:
    homepage = f"{origin}/"
    return {
        "homepage": homepage,
        "path": f"{origin}/search",
        "query": f"{origin}/?q=test",
        "multi-query": f"{origin}/?q=test&page=2",
        "encoded": f"{origin}/?q=cyber%20security",
        "fragment": f"{origin}/#results",
        "path+query": f"{origin}/search?q=test",
    }


def main() -> None:
    results = []
    changes_by_origin = {}

    for origin in baseline_origins():
        variants = variants_for(origin)
        probabilities = {}
        for variant_type in VARIANT_TYPES:
            url = variants[variant_type]
            result = scan(url)
            probabilities[variant_type] = result["probability"]
            results.append(
                {
                    "base_url": variants["homepage"],
                    "variant_type": variant_type,
                    "url": url,
                    "probability": result["probability"],
                    "label": result["label"],
                    "model_version": result["model_version"],
                }
            )
        homepage_probability = probabilities["homepage"]
        changes_by_origin[variants["homepage"]] = {
            variant_type: round(probabilities[variant_type] - homepage_probability, 6)
            for variant_type in VARIANT_TYPES[1:]
        }

    comparison_types = VARIANT_TYPES[1:]
    largest_increase = max(
        (
            (delta, base_url, variant_type)
            for base_url, changes in changes_by_origin.items()
            for variant_type, delta in changes.items()
        ),
        default=(0.0, None, None),
    )
    consistently_increases = {
        variant_type: all(
            changes[variant_type] > 0 for changes in changes_by_origin.values()
        )
        for variant_type in comparison_types
    }
    label_counts = Counter(result["label"] for result in results)
    summary = {
        "total": len(results),
        "label_counts": {
            label: label_counts.get(label, 0)
            for label in ("SAFE", "SUSPICIOUS", "PHISHING")
        },
        "minimum_probability": min(result["probability"] for result in results),
        "maximum_probability": max(result["probability"] for result in results),
        "largest_probability_increase": {
            "increase": largest_increase[0],
            "base_url": largest_increase[1],
            "variant_type": largest_increase[2],
        },
        "consistently_increases_risk": consistently_increases,
    }

    with REPORT_PATH.open("w", encoding="utf-8") as report_file:
        json.dump({"summary": summary, "results": results}, report_file, indent=2)
        report_file.write("\n")

    delta_headers = " ".join(f"{variant_type:>12}" for variant_type in comparison_types)
    print(f"{'base_url':<36} {delta_headers}")
    for base_url, changes in changes_by_origin.items():
        deltas = " ".join(f"{changes[variant_type]:+12.6f}" for variant_type in comparison_types)
        print(f"{base_url:<36} {deltas}")

    increase = summary["largest_probability_increase"]
    if increase["variant_type"] is None or increase["increase"] <= 0:
        print("Largest probability increase: none (no variant exceeds its homepage)")
    else:
        print(
            "Largest probability increase: "
            f"{increase['variant_type']} on {increase['base_url']} "
            f"({increase['increase']:+.6f})"
        )
    print(
        "Consistently increases risk: "
        + ", ".join(
            f"{variant_type}={'yes' if consistently_increases[variant_type] else 'no'}"
            for variant_type in comparison_types
        )
    )
    print(
        f"Probability range: {summary['minimum_probability']:.6f}"
        f" to {summary['maximum_probability']:.6f}"
    )
    print(f"Label counts: {summary['label_counts']}")


if __name__ == "__main__":
    main()