from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feature_extractor import get_registered_domain, normalize_url
from experiments.auto_ml import collect_accuracy_repair_data as previous_collector
from experiments.auto_ml.data_quality_contracts import (
    class_balance,
    cohort_counts,
    domain_overlaps,
    missing_cohorts,
    normalized_duplicate_count,
    provenance_errors,
    REQUIRED_COHORTS,
)
from scripts.collect_legitimate_training_v3 import collect_live_source, deduplicate

PREVIOUS_MANIFEST = (
    ROOT / "experiments" / "auto_ml" / "accuracy_repair_20261009"
    / "collection_manifest.json"
)
PHISHING_FEED = ROOT / "data" / "external" / "phishing_database_active.txt"
CSV_ROOTS = (ROOT / "data", ROOT / "experiments" / "auto_ml")
ROOT_DATASETS = (
    ROOT / "legitimate_urls_realworld.csv",
    ROOT / "legitimate_urls_realworld_v2.csv",
    ROOT / "legitimate_urls_realworld_v3.csv",
)
USER_AGENT_POLICY = (
    "Only observed HTTPS first-party URLs individually fetched with a 2xx response "
    "and same registered-domain final URL are retained. No URL is synthesized."
)


def add_url_domain(url: str, urls: set[str], domains: set[str]) -> None:
    try:
        normalized = normalize_url(url)
        urls.add(normalized)
        domains.add(get_registered_domain(normalized))
    except (TypeError, ValueError):
        return


def historical_inventory() -> tuple[set[str], set[str], list[dict], set[str], set[str]]:
    domains: set[str] = set()
    urls: set[str] = set()
    dataset_inventory = []
    csv_paths = set()
    for base in CSV_ROOTS:
        csv_paths.update(path for path in base.rglob("*.csv") if path.is_file())
    csv_paths.update(path for path in ROOT_DATASETS if path.is_file())
    for path in sorted(csv_paths):
        try:
            with path.open(encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                if not reader.fieldnames or "url" not in reader.fieldnames:
                    continue
                file_urls: set[str] = set()
                file_domains: set[str] = set()
                for row in reader:
                    raw = (row.get("url") or "").strip()
                    if not raw:
                        continue
                    add_url_domain(raw, urls, domains)
                    try:
                        normalized = normalize_url(raw)
                        file_urls.add(normalized)
                        try:
                            file_domains.add(get_registered_domain(normalized))
                        except ValueError:
                            pass
                    except ValueError:
                        pass
                dataset_inventory.append(
                    {
                        "path": str(path.relative_to(ROOT)),
                        "unique_normalized_urls": len(file_urls),
                        "registered_domains": len(file_domains),
                    }
                )
        except (OSError, UnicodeError, csv.Error) as error:
            dataset_inventory.append(
                {"path": str(path.relative_to(ROOT)), "read_error": str(error)}
            )

    benchmark = ROOT / "experiments" / "auto_ml" / "benchmark_v1" / "fixed_urls.json"
    if benchmark.exists():
        payload = json.loads(benchmark.read_text(encoding="utf-8"))

        def visit(value):
            if isinstance(value, dict):
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
            elif isinstance(value, str) and value.lower().startswith(("http://", "https://")):
                add_url_domain(value, urls, domains)

        visit(payload)

    historical_dataset_domains = set(domains)
    phishing_domains: set[str] = set()
    phishing_urls: set[str] = set()
    if PHISHING_FEED.exists():
        with PHISHING_FEED.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                value = line.strip()
                if value and not value.startswith(("#", "//")):
                    add_url_domain(value, phishing_urls, phishing_domains)
    domains.update(phishing_domains)
    urls.update(phishing_urls)
    return domains, urls, dataset_inventory, historical_dataset_domains, phishing_domains


def previous_zero_yield_domains() -> dict[str, dict]:
    manifest = json.loads(PREVIOUS_MANIFEST.read_text(encoding="utf-8"))
    return {
        result["registered_domain"]: result
        for result in manifest.get("source_results", [])
        if not result.get("observed_rows")
    }


def write_rows(path: Path, rows: list[dict]) -> None:
    fields = (
        "url", "normalized_url", "label", "source", "collection_method",
        "verification_status", "category", "cohorts", "registered_domain",
        "source_page_url", "verified_final_url", "verified_content_type",
        "collection_date", "provenance",
    )
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def export_readiness_reports(audit_path: Path) -> None:
    report = json.loads(audit_path.read_text(encoding="utf-8"))
    (
        historic_domains,
        historic_urls,
        dataset_inventory,
        historical_dataset_domains,
        phishing_feed_domains,
    ) = historical_inventory()
    source_domains = {
        source["registered_domain"] for source in report.get("source_results", [])
    }
    report["historical_domain_union_count"] = len(historic_domains)
    report["historical_normalized_url_union_count"] = len(historic_urls)
    report["historical_dataset_inventory"] = dataset_inventory
    report["historical_dataset_domain_count"] = len(historical_dataset_domains)
    report["phishing_feed_domain_count"] = len(phishing_feed_domains)
    report["phishing_feed_overlap_with_historical_datasets"] = {
        "overlapping_registered_domains": len(
            phishing_feed_domains & historical_dataset_domains
        ),
        "sample_domains": sorted(phishing_feed_domains & historical_dataset_domains)[:25],
    }
    report["collection"]["missing_classes"] = (
        [0, 1] if not report["collection"]["rows"] else []
    )
    report["collection"]["class_balance_status"] = (
        "UNAVAILABLE_NO_RETAINED_ROWS"
        if not report["collection"]["rows"]
        else "OBSERVED"
    )
    collection_csv = ROOT / report["collection"]["csv"]
    with collection_csv.open(encoding="utf-8", newline="") as stream:
        collected_rows = list(csv.DictReader(stream))
    report["collection"]["missing_url_cohorts"] = missing_cohorts(
        collected_rows
    )
    report["collection"]["required_url_cohorts"] = list(REQUIRED_COHORTS)
    report["collection"]["url_cohort_coverage_status"] = (
        "NO_COHORTS_OBSERVED"
        if not report["collection"]["cohorts"]
        else "PARTIAL"
        if report["collection"]["missing_url_cohorts"]
        else "COMPLETE"
    )
    report["candidate_source_domain_overlap_checks"] = domain_overlaps(
        {
            "historical_data_and_phishing_feed": historic_domains,
            "retried_source_domains": source_domains,
        }
    )
    for source in report.get("source_results", []):
        homepage_errors = [
            error for error in source.get("errors", [])
            if error.startswith("homepage:")
        ]
        error_text = " ".join(homepage_errors)
        match = re.search(r"HTTP Error (\d{3})", error_text)
        source["homepage_http_error_status"] = int(match.group(1)) if match else None
    audit_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (ROOT / "reports").mkdir(parents=True, exist_ok=True)
    json_path = ROOT / "reports" / "zero_yield_retry_readiness.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    collection = report["collection"]
    lines = [
        "# Zero-yield legitimate source retry and lockbox readiness",
        "",
        f"- Decision: **{report['decision']}**",
        f"- Retry run: `{report['created_at_utc']}`; "
        f"{report['source_retry_count']} previously zero-yield sources retried.",
        f"- Retained URLs: {collection['rows']}; unique normalized URLs: "
        f"{collection['unique_normalized_urls']}; registered domains: "
        f"{collection['registered_domains']}.",
        f"- Legitimate class counts: `{json.dumps(collection['classes'], sort_keys=True)}`.",
        f"- Cohort counts: `{json.dumps(collection['cohorts'], sort_keys=True)}`.",
        f"- Required URL cohorts: `{json.dumps(collection['required_url_cohorts'])}`.",
        f"- Missing URL cohorts: `{json.dumps(collection['missing_url_cohorts'])}` "
        f"({collection['url_cohort_coverage_status']}).",
        f"- Historical domain union: {report['historical_domain_union_count']}; "
        f"domain overlaps: `{json.dumps(collection['domain_overlap_checks'])}`.",
        f"- Retried-source domain overlap checks: "
        f"`{json.dumps(report['candidate_source_domain_overlap_checks'])}`.",
        f"- Legacy phishing-feed domains: {report['phishing_feed_domain_count']}; "
        "overlap with historical datasets: "
        f"{report['phishing_feed_overlap_with_historical_datasets']['overlapping_registered_domains']}.",
        f"- Provenance errors: {len(collection['provenance_errors'])}; normalized "
        f"duplicates remaining: {collection['normalized_duplicate_rows_after_deduplication']}.",
        "- Training: **not started**.",
        f"- Two-class lockbox independence: "
        f"**{report['lockbox_assessment']['two_class_lockbox_independence']}**.",
        "",
        "## Source retry outcomes",
        "",
        "| Source | Registered domain | HTTP status | Rows | Result |",
        "|---|---|---:|---:|---|",
    ]
    for source in report.get("source_results", []):
        status = source.get("homepage_status") or source.get("homepage_http_error_status")
        errors = source.get("errors", [])
        result = errors[0] if errors else "verified responses retained"
        lines.append(
            f"| {source['source']} | {source['registered_domain']} | "
            f"{status if status is not None else 'blocked/unknown'} | "
            f"{source['observed_rows']} | {result.replace('|', '/')} |"
        )
    lines.extend(
        [
            "",
            "## Assessment",
            "",
            report["lockbox_assessment"]["reason"],
            "Every candidate source domain was screened against scanned historical URL "
            "CSV datasets, the fixed benchmark URL list, and the legacy phishing feed. "
            "Source collection retained only observed HTTPS URLs with individual 2xx "
            "responses and same-registered-domain final URLs.",
            "",
            f"Machine-readable details: [{json_path.name}](./{json_path.name}).",
            "",
        ]
    )
    (ROOT / "reports" / "zero_yield_retry_readiness.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--report-only":
        export_readiness_reports(Path(sys.argv[2]))
        return
    if len(sys.argv) != 1:
        raise SystemExit("Usage: retry_zero_yield_sources.py [--report-only AUDIT_JSON]")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = ROOT / "experiments" / "auto_ml" / f"zero_yield_retry_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    (
        historic_domains,
        historic_urls,
        dataset_inventory,
        historical_dataset_domains,
        phishing_feed_domains,
    ) = historical_inventory()
    old_zero_yield = previous_zero_yield_domains()
    sources = []
    skipped = []
    for name, homepage in previous_collector.SOURCES:
        domain = get_registered_domain(homepage)
        if domain not in old_zero_yield:
            continue
        if domain in historic_domains:
            skipped.append(
                {"source": name, "registered_domain": domain,
                 "reason": "domain occurs in historical datasets or phishing feed"}
            )
            continue
        sources.append(
            {
                "name": name,
                "url": homepage,
                "why_legitimate": (
                    f"Official public homepage of {name}; only individually observed "
                    "same-domain HTTPS responses are retained."
                ),
            }
        )

    rows = []
    summaries = []
    pause_state = {"last_request": None}
    for source in sources:
        observed, summary = collect_live_source(source, pause_state)
        rows.extend(observed)
        prior = old_zero_yield[get_registered_domain(source["url"])]
        summary["previous_attempt_errors"] = prior.get("errors", [])
        summary["observed_rows"] = len(observed)
        summaries.append(summary)
        print(
            f"{source['name']}: {len(observed)} rows; "
            f"homepage HTTP {summary.get('homepage_status')}; "
            f"errors={len(summary.get('errors', []))}",
            flush=True,
        )

    rows, dedup = deduplicate(rows)
    csv_path = run_dir / "new_legitimate_observations.csv"
    write_rows(csv_path, rows)
    row_domains = {row["registered_domain"] for row in rows}
    domain_checks = domain_overlaps(
        {
            "historical_data_and_phishing_feed": historic_domains,
            "fresh_collection": row_domains,
        }
    )
    errors = provenance_errors(rows)
    duplicate_count = normalized_duplicate_count(rows)
    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "decision": (
            "LEGITIMATE_DATA_COLLECTED_BUT_LOCKBOX_BLOCKED"
            if rows and not errors and not domain_checks and not duplicate_count
            else "BLOCKED_NO_CERTIFIED_LOCKBOX_DATA"
        ),
        "training_started": False,
        "user_agent_policy": USER_AGENT_POLICY,
        "collection_limits": {
            "requests_per_source": 17,
            "minimum_seconds_between_requests": 0.5,
            "https_only": True,
            "same_registered_domain_redirects_only": True,
            "retained_target_status": "2xx",
        },
        "historical_domain_union_count": len(historic_domains),
        "historical_normalized_url_union_count": len(historic_urls),
        "historical_dataset_inventory": dataset_inventory,
        "historical_dataset_domain_count": len(historical_dataset_domains),
        "phishing_feed_domain_count": len(phishing_feed_domains),
        "phishing_feed_overlap_with_historical_datasets": {
            "overlapping_registered_domains": len(
                phishing_feed_domains & historical_dataset_domains
            ),
            "sample_domains": sorted(
                phishing_feed_domains & historical_dataset_domains
            )[:25],
        },
        "phishing_feed": {
            "path": str(PHISHING_FEED.relative_to(ROOT)),
            "label_interpretation": "feed-listed; not proof of current activity",
            "registered_domains": len(phishing_feed_domains),
            "overlap_with_prior_dataset_domains": len(
                phishing_feed_domains & historical_dataset_domains
            ),
        },
        "source_retry_count": len(sources),
        "sources_skipped_for_domain_overlap": skipped,
        "source_results": summaries,
        "collection": {
            "csv": str(csv_path.relative_to(ROOT)),
            "sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
            "rows": len(rows),
            "unique_normalized_urls": len({row["normalized_url"] for row in rows}),
            "registered_domains": len(row_domains),
            "classes": class_balance(rows),
            "missing_classes": [0, 1] if not rows else [],
            "class_balance_status": (
                "UNAVAILABLE_NO_RETAINED_ROWS" if not rows else "OBSERVED"
            ),
            "cohorts": cohort_counts(rows),
            "required_url_cohorts": list(REQUIRED_COHORTS),
            "missing_url_cohorts": missing_cohorts(rows),
            "url_cohort_coverage_status": (
                "NO_COHORTS_OBSERVED"
                if not rows
                else "PARTIAL"
                if missing_cohorts(rows)
                else "COMPLETE"
            ),
            "counts_by_source": dict(sorted(Counter(row["source"] for row in rows).items())),
            "counts_by_registered_domain": dict(
                sorted(Counter(row["registered_domain"] for row in rows).items())
            ),
            "duplicate_rows_removed": dedup,
            "provenance_errors": errors,
            "normalized_duplicate_rows_after_deduplication": duplicate_count,
            "domain_overlap_checks": domain_checks,
        },
        "lockbox_assessment": {
            "independence_of_collected_domains_from_scanned_history": (
                "PROVEN" if rows and not domain_checks else "NOT_PROVEN"
            ),
            "two_class_lockbox_independence": "NOT_PROVEN",
            "reason": (
                "No fresh, independently sourced phishing lockbox rows were reserved. "
                "Prior phishing-feed entries are historical and feed membership alone "
                "does not establish current maliciousness."
            ),
            "required_before_training": [
                "Independently sourced phishing rows with timestamped provenance",
                "Domain-disjoint train/calibration/validation/test/lockbox assignments",
                "Minimum per-class and per-cohort sample counts set before model selection",
            ],
        },
    }
    (run_dir / "readiness_audit.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    export_readiness_reports(run_dir / "readiness_audit.json")
    print(json.dumps({"run_dir": str(run_dir), "audit": report["decision"]}, indent=2))


if __name__ == "__main__":
    main()
