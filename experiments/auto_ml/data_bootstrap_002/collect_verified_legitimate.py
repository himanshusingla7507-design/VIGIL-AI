"""Expand the verified first-party benign cohort using the existing collector."""
from __future__ import annotations

import csv
import json
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from feature_extractor import _analysis_url, normalize_url
from experiments.auto_ml.data_bootstrap_001 import collect_verified_legitimate as bootstrap
import collect_benign_dynamic_urls as collector

EXPERIMENT_DIR = Path(__file__).resolve().parent
OUTPUT_CSV = EXPERIMENT_DIR / "legitimate_urls.csv"
OUTPUT_REPORT = EXPERIMENT_DIR / "collection_report.json"
SEED_CSV = ROOT / "experiments" / "auto_ml" / "data_bootstrap_001" / "legitimate_urls.csv"
PHISH_PATH = ROOT / "data" / "external" / "phishing_database_active.txt"

# Broaden first-party link coverage while retaining the collector's per-domain
# boundary, per-URL HTTPS verification, response-size limit, and fixed source list.
collector.MAX_LINKS_PER_SOURCE = 90
collector.MAX_VERIFICATIONS = 24
SOURCES = collector.SOURCES + bootstrap.ADDITIONAL_SOURCES


def phishing_analysis_identities() -> tuple[set[str], dict]:
    identities = set()
    lines = invalid = blank = 0
    with PHISH_PATH.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            lines += 1
            raw = line.strip()
            if not raw:
                blank += 1
                continue
            try:
                identities.add(_analysis_url(normalize_url(raw)))
            except (TypeError, ValueError):
                invalid += 1
    return identities, {"physical_lines": lines, "blank_lines": blank, "invalid_urls": invalid, "unique_analysis_identities": len(identities)}


def read_seed_rows(phishing_ids: set[str]) -> tuple[dict[str, dict], int]:
    rows = {}
    collisions = 0
    with SEED_CSV.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            normalized = normalize_url(row["url"])
            analysis = _analysis_url(normalized)
            if analysis in phishing_ids:
                collisions += 1
                continue
            rows.setdefault(normalized, {
                "url": normalized,
                "label": 0,
                "source": row["source"],
                "provenance": "Previously individually verified official first-party link retained in bootstrap_001.",
                "category": row.get("category", "previously_verified"),
                "collection_date": row.get("collection_date") or "2026-10-09",
                "source_page_url": None,
                "source_domain": collector.registered_domain(normalized),
                "verification_status": "previously_recorded_2xx_same_registered_domain_https",
                "verified_final_url": normalized,
                "verified_content_type": None,
                "deduplication_key": normalized,
            })
    return rows, collisions


def main() -> None:
    phishing_ids, phishing_stats = phishing_analysis_identities()
    accepted, seed_phishing_collisions = read_seed_rows(phishing_ids)
    source_summaries = []
    duplicate_count = phishing_collisions = 0

    for source in SOURCES:
        try:
            result = bootstrap.collect_source(source)
            discovered = result.pop("rows")
            accepted_from_source = 0
            for row in discovered:
                normalized = normalize_url(row["url"])
                analysis = _analysis_url(normalized)
                if analysis in phishing_ids:
                    phishing_collisions += 1
                    continue
                if normalized in accepted:
                    duplicate_count += 1
                    continue
                accepted[normalized] = {
                    **row,
                    "url": normalized,
                    "label": 0,
                    "deduplication_key": normalized,
                }
                accepted_from_source += 1
            result["accepted_after_global_deduplication"] = accepted_from_source
            source_summaries.append(result)
            print(f"{source['name']}: {accepted_from_source} new verified rows", flush=True)
        except Exception as error:
            source_summaries.append({
                "source_name": source["name"],
                "source_page_url": source["url"],
                "verified_urls": 0,
                "category_counts": {},
                "error": f"{type(error).__name__}: {str(error)[:240]}",
            })
            print(f"{source['name']}: ERROR {type(error).__name__}: {error}", flush=True)
        time.sleep(0.2)

    rows = list(accepted.values())
    fields = (
        "url", "label", "source", "provenance", "category", "collection_date",
        "source_page_url", "source_domain", "verification_status", "verified_final_url",
        "verified_content_type", "deduplication_key",
    )
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    report = {
        "experiment": "auto_ml_data_bootstrap_002",
        "dataset": str(OUTPUT_CSV.relative_to(ROOT)),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_normalized_unique_urls": len(rows),
        "unique_registered_domains": len({row["source_domain"] for row in rows}),
        "counts_by_category": dict(Counter(row["category"] for row in rows)),
        "counts_by_source": dict(Counter(row["source"] for row in rows)),
        "label_counts": dict(Counter(str(row["label"]) for row in rows)),
        "duplicate_urls_removed": duplicate_count,
        "phishing_feed_identity_collisions_removed": seed_phishing_collisions + phishing_collisions,
        "phishing_feed_scan": phishing_stats,
        "sources": source_summaries,
        "method": "Reused the repository's first-party link discovery and individual successful same-domain HTTPS verification. Existing verified rows were retained; only observed source links are included. No URL strings or labels are synthetically generated.",
        "network_scope": "Only the explicit official first-party source homepage list and discovered links on each same registered domain.",
    }
    OUTPUT_REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "total_normalized_unique_urls": len(rows),
        "unique_registered_domains": report["unique_registered_domains"],
        "counts_by_category": report["counts_by_category"],
        "csv": str(OUTPUT_CSV.relative_to(ROOT)),
        "report": str(OUTPUT_REPORT.relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()