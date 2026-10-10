"""Build a local benign URL cohort from recorded first-party page URLs."""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from feature_extractor import normalize_url

SOURCE_REPORTS = (
    ROOT / "reports" / "benign_dynamic_url_sources.json",
    ROOT / "reports" / "benign_dynamic_url_training.json",
)
SUMMARY_REPORT_PATH = SOURCE_REPORTS[0]
CSV_PATH = ROOT / "data" / "experiments" / "legitimate_dynamic_training.csv"
REPORT_PATH = ROOT / "reports" / "dynamic_benign_cohort.json"

COHORT_NAMES = (
    "homepage",
    "path_only",
    "query_only",
    "path_plus_query",
    "fragment",
    "encoded",
    "multiple_query_params",
    "long_query",
    "long_url",
    "tracking_utm_parameters",
    "search",
    "docs",
    "login_account",
)

AGGREGATE_CATEGORY_MAP = {
    "query_only": "query_only",
    "path_plus_query": "path_query",
    "fragment": "fragment",
    "encoded": "encoded_query",
    "multiple_query_params": "multiple_query_parameters",
    "long_query": "long_query",
    "long_url": "long_legitimate_url",
    "tracking_utm_parameters": "tracking_parameters",
}


def source_records(payload: dict) -> list[dict]:
    sources = payload.get("sources", [])
    if isinstance(sources, dict):
        sources = sources.get("source_records", [])
    return sources if isinstance(sources, list) else []


def read_page_rows(report_path: Path) -> list[dict]:
    with report_path.open(encoding="utf-8") as report_file:
        payload = json.load(report_file)

    rows = []
    for source in source_records(payload):
        source_name = source.get("source_name")
        if not source_name:
            continue
        for page in source.get("first_party_pages_crawled", []):
            url = page.get("url")
            if page.get("status") != 200 or not isinstance(url, str):
                continue
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                continue
            rows.append({"url": url, "source": source_name})
    return rows


def classify_url(url: str) -> list[str]:
    parsed = urlsplit(url)
    path = parsed.path or ""
    query = parsed.query or ""
    is_home = path in ("", "/")
    cohorts = []

    if is_home and not query and not parsed.fragment:
        cohorts.append("homepage")
    if not is_home and not query:
        cohorts.append("path_only")
    if is_home and query:
        cohorts.append("query_only")
    if not is_home and query:
        cohorts.append("path_plus_query")
    if parsed.fragment:
        cohorts.append("fragment")
    if re.search(r"%[0-9a-fA-F]{2}", url):
        cohorts.append("encoded")
    if len(parse_qsl(query, keep_blank_values=True)) > 1:
        cohorts.append("multiple_query_params")
    if len(query) > 100:
        cohorts.append("long_query")
    if len(url) > 200:
        cohorts.append("long_url")
    if re.search(
        r"(?:^|&)(?:utm_[^=]*|gclid|fbclid|yclid|mc_[^=]*)=", query, re.IGNORECASE
    ):
        cohorts.append("tracking_utm_parameters")
    path_and_query = f"{parsed.hostname or ''}{path}?{query}"
    if re.search(r"search|query", path_and_query, re.IGNORECASE):
        cohorts.append("search")
    if re.search(r"(?:^|[./_-])docs?(?:$|[./_-])|documentation", path_and_query, re.IGNORECASE):
        cohorts.append("docs")
    if re.search(r"login|sign.?in|account", path_and_query, re.IGNORECASE):
        cohorts.append("login_account")

    return cohorts


def main() -> None:
    normalized_rows = {}
    input_row_count = 0
    invalid_rows = 0
    for report_path in SOURCE_REPORTS:
        for row in read_page_rows(report_path):
            input_row_count += 1
            try:
                normalized = normalize_url(row["url"])
            except (TypeError, ValueError):
                invalid_rows += 1
                continue
            normalized_rows.setdefault(normalized, row)

    rows = []
    cohort_counts = Counter()
    source_counts = Counter()
    multi_cohort_count = 0
    for row in normalized_rows.values():
        cohorts = classify_url(row["url"])
        cohort_counts.update(cohorts)
        source_counts[row["source"]] += 1
        multi_cohort_count += len(cohorts) > 1
        rows.append(
            {
                "url": row["url"],
                "label": 0,
                "source": row["source"],
                "cohort": json.dumps(cohorts, separators=(",", ":")),
            }
        )

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CSV_PATH.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=("url", "label", "source", "cohort")
        )
        writer.writeheader()
        writer.writerows(rows)

    with SUMMARY_REPORT_PATH.open(encoding="utf-8") as summary_file:
        source_summary = json.load(summary_file)
    aggregate_counts = source_summary.get("category_counts", {})
    missing_cohorts = [
        {
            "cohort": name,
            "row_level_count": int(cohort_counts.get(name, 0)),
            "aggregate_report_count": aggregate_counts.get(
                AGGREGATE_CATEGORY_MAP.get(name, "")
            ),
            "note": (
                "Aggregate count is present in the source report, but the individual "
                "verified URL rows are not preserved in the report."
                if aggregate_counts.get(AGGREGATE_CATEGORY_MAP.get(name, ""), 0)
                else "No row-level URL in the extracted first-party page records."
            ),
        }
        for name in COHORT_NAMES
        if cohort_counts.get(name, 0) == 0
    ]

    dynamic_rows = sum(
        "homepage" not in json.loads(row["cohort"]) for row in rows
    )
    report = {
        "total_unique_urls": len(rows),
        "usable_dynamic_urls_excluding_homepages": dynamic_rows,
        "counts_per_cohort": {
            name: int(cohort_counts.get(name, 0)) for name in COHORT_NAMES
        },
        "counts_per_source": dict(sorted(source_counts.items())),
        "duplicate_count_removed": input_row_count - len(rows),
        "input_row_count": input_row_count,
        "urls_overlapping_multiple_cohorts": int(multi_cohort_count),
        "missing_or_unsupported_requested_cohorts": missing_cohorts,
        "aggregate_report_category_counts_not_used_as_rows": aggregate_counts,
        "provenance": {
            "reports_used_for_rows": [
                str(path.relative_to(ROOT)) for path in SOURCE_REPORTS
            ],
            "row_selection": "Only first_party_pages_crawled entries with HTTP status 200 were used; URLs are already recorded locally and were not opened or fetched.",
            "deduplication": "feature_extractor.normalize_url applied to the full URL; original URL spelling and structure are retained in the CSV.",
            "label_basis": "The reports identify these as successful first-party pages on each source's registered domain; all cohort labels are 0 (legitimate).",
            "other_inspected_reports_excluded": {
                "reports": [
                    "reports/dynamic_augmentation_final.json",
                    "reports/dynamic_hardening_final.json",
                    "reports/dynamic_recovery_comparison.json",
                    "reports/dynamic_recovery_final.json",
                    "reports/dynamic_training_comparison.json",
                ],
                "reason": "Their retained URLs are regression references or phishing examples, not row-level verified benign source URLs.",
            },
            "full_manifest_row_level_limitation": "The benign source reports summarize 435 verified URLs, but do not retain the complete 435 URL rows; this CSV uses only the successful first-party page URLs explicitly present in both reports.",
        },
        "minimum_additional_data_needed": {
            "path_referenced_by_existing_report": "data/benign_dynamic_urls.csv",
            "required_fields": ["url", "source", "cohort/category", "verification status"],
            "reason": "The complete row-level list is needed to recover all reported verified examples and populate currently absent dynamic categories without fabrication.",
        },
        "candidate_retraining_readiness": {
            "ready": False,
            "usable_dynamic_urls": dynamic_rows,
            "reason": "The available rows are a small, path-heavy subset and contain no row-level query-only, multi-query, fragment, long-query, tracking, or login/account examples; this does not cover the reported 435-URL cohort.",
        },
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_PATH.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)
        report_file.write("\n")

    print(f"Unique URLs: {report['total_unique_urls']}")
    print(f"Usable dynamic URLs (excluding homepages): {dynamic_rows}")
    print("Counts per cohort:")
    for name, count in report["counts_per_cohort"].items():
        print(f"  {name}: {count}")
    print(f"Duplicate rows removed: {report['duplicate_count_removed']}")
    print(f"URLs overlapping multiple cohorts: {multi_cohort_count}")
    print(f"Candidate retraining ready: {report['candidate_retraining_readiness']['ready']}")


if __name__ == "__main__":
    main()