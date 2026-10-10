from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feature_extractor import get_registered_domain, normalize_url
from experiments.auto_ml import run_realworld_experiments as base
from scripts.collect_legitimate_training_v3 import (
    REQUEST_PAUSE_SECONDS,
    collect_live_source,
    deduplicate,
)

RUN_DIR = ROOT / "experiments" / "auto_ml" / "accuracy_repair_20261009"
OUTPUT_CSV = RUN_DIR / "new_legitimate_observations.csv"
OUTPUT_JSON = RUN_DIR / "collection_manifest.json"
USER_AGENT_POLICY = (
    "Official first-party homepage and same-registered-domain anchor observations; "
    "each retained URL was individually fetched over HTTPS and had a 2xx response "
    "with the same registered domain. No URL components were synthesized."
)

SOURCES = [
    ("Smithsonian", "https://www.si.edu/"),
    ("CDC", "https://www.cdc.gov/"),
    ("U.S. Food and Drug Administration", "https://www.fda.gov/"),
    ("USA.gov", "https://www.usa.gov/"),
    ("Internal Revenue Service", "https://www.irs.gov/"),
    ("U.S. National Archives", "https://www.archives.gov/"),
    ("National Park Service", "https://www.nps.gov/"),
    ("National Institutes of Health", "https://www.nih.gov/"),
    ("U.S. Geological Survey", "https://www.usgs.gov/"),
    ("NOAA", "https://www.noaa.gov/"),
    ("U.S. Congress", "https://www.congress.gov/"),
    ("The White House", "https://www.whitehouse.gov/"),
    ("U.S. Department of State", "https://www.state.gov/"),
    ("U.S. Department of Education", "https://www.ed.gov/"),
    ("U.S. Department of Energy", "https://www.energy.gov/"),
    ("Princeton University", "https://www.princeton.edu/"),
    ("University of Oxford", "https://www.ox.ac.uk/"),
    ("University of Cambridge", "https://www.cam.ac.uk/"),
    ("California Institute of Technology", "https://www.caltech.edu/"),
    ("University of Michigan", "https://umich.edu/"),
    ("University of Toronto", "https://www.utoronto.ca/"),
    ("ETH Zurich", "https://ethz.ch/"),
    ("EPFL", "https://www.epfl.ch/"),
    ("University of Edinburgh", "https://www.ed.ac.uk/"),
    ("UNICEF", "https://www.unicef.org/"),
    ("UNESCO", "https://www.unesco.org/"),
    ("CERN", "https://home.cern/"),
    ("Khan Academy", "https://www.khanacademy.org/"),
    ("Stack Overflow", "https://stackoverflow.com/"),
    ("Etsy", "https://www.etsy.com/"),
    ("eBay", "https://www.ebay.com/"),
    ("W3Schools", "https://www.w3schools.com/"),
    ("Reuters", "https://www.reuters.com/"),
    ("Associated Press", "https://apnews.com/"),
    ("The Atlantic", "https://www.theatlantic.com/"),
    ("The Conversation", "https://theconversation.com/"),
    ("International Monetary Fund", "https://www.imf.org/"),
    ("OECD", "https://www.oecd.org/"),
    ("UK National Archives", "https://www.nationalarchives.gov.uk/"),
    ("Standard Ebooks", "https://standardebooks.org/"),
    ("New York Public Library", "https://www.nypl.org/"),
    ("MD Anderson Cancer Center", "https://www.mdanderson.org/"),
    ("Encyclopaedia Britannica", "https://www.britannica.com/"),
    ("Best Buy", "https://www.bestbuy.com/"),
    ("The Home Depot", "https://www.homedepot.com/"),
    ("Wayfair", "https://www.wayfair.com/"),
    ("Zalando", "https://www.zalando.com/"),
    ("Linux Foundation", "https://www.linuxfoundation.org/"),
    ("WebKit", "https://webkit.org/"),
    ("npm", "https://www.npmjs.com/"),
    ("freeCodeCamp", "https://www.freecodecamp.org/"),
    ("FastAPI Documentation", "https://fastapi.tiangolo.com/"),
    ("Government of Canada", "https://www.canada.ca/"),
    ("Government of Ireland", "https://www.gov.ie/"),
    ("Parliament of the United Kingdom", "https://www.parliament.uk/"),
    ("Australian Government", "https://www.australia.gov.au/"),
]


def previous_legitimate_domains() -> set[str]:
    paths = (
        ROOT / "legitimate_urls_realworld_v3.csv",
        ROOT / "data" / "experiments" / "legitimate_training_v3.csv",
    )
    domains: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        with path.open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                try:
                    domains.add(get_registered_domain(row["url"]))
                except (KeyError, TypeError, ValueError):
                    continue
    return domains


def write_csv(rows: list[dict]) -> None:
    columns = (
        "url",
        "normalized_url",
        "label",
        "source",
        "collection_method",
        "verification_status",
        "category",
        "cohorts",
        "registered_domain",
        "source_page_url",
        "verified_final_url",
        "verified_content_type",
        "collection_date",
        "provenance",
    )
    with OUTPUT_CSV.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    if OUTPUT_CSV.exists() or OUTPUT_JSON.exists():
        raise FileExistsError("Refusing to overwrite the accuracy-repair collection outputs.")

    existing_domains = previous_legitimate_domains()
    benchmark_domains, _, benchmark_summary = base.load_benchmark_reservations()
    skipped = []
    approved_sources = []
    seen_source_domains = set()
    for name, homepage in SOURCES:
        domain = get_registered_domain(homepage)
        if domain in existing_domains:
            skipped.append({"name": name, "homepage": homepage, "domain": domain,
                            "reason": "registered domain already appears in prior legitimate data"})
        elif domain in benchmark_domains:
            skipped.append({"name": name, "homepage": homepage, "domain": domain,
                            "reason": "registered domain reserved by fixed benchmark"})
        elif domain in seen_source_domains:
            skipped.append({"name": name, "homepage": homepage, "domain": domain,
                            "reason": "duplicate registered domain in proposed sources"})
        else:
            seen_source_domains.add(domain)
            approved_sources.append({
                "name": name,
                "url": homepage,
                "why_legitimate": (
                    f"Official public homepage of {name}; legitimacy is attributed only "
                    "to individually observed same-registered-domain HTTPS URLs."
                ),
            })

    collected: list[dict] = []
    summaries = []
    pause_state = {"last_request": None}
    for source in approved_sources:
        rows, summary = collect_live_source(source, pause_state)
        collected.extend(rows)
        summary["observed_rows"] = len(rows)
        summaries.append(summary)
        print(
            f"{source['name']}: {summary['links_verified']} verified links, "
            f"homepage status {summary['homepage_status']}",
            flush=True,
        )

    rows, duplicates = deduplicate(collected)
    write_csv(rows)
    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": str(OUTPUT_CSV.relative_to(ROOT)),
        "label": 0,
        "provenance_policy": USER_AGENT_POLICY,
        "request_policy": {
            "request_pause_seconds": REQUEST_PAUSE_SECONDS,
            "max_link_verifications_per_source": 16,
            "max_child_pages_per_source": 2,
            "same_registered_domain_https_redirects_only": True,
            "source_domains_seen_in_previous_legitimate_data": len(existing_domains),
            "benchmark_reserved_domains": len(benchmark_domains),
            "benchmark_reservation_source": benchmark_summary,
        },
        "source_allowlist": [
            {
                "name": source["name"],
                "homepage": source["url"],
                "registered_domain": get_registered_domain(source["url"]),
                "provenance_basis": source["why_legitimate"],
            }
            for source in approved_sources
        ],
        "skipped_sources": skipped,
        "source_results": summaries,
        "row_count": len(rows),
        "counts_by_source": dict(Counter(row["source"] for row in rows)),
        "counts_by_registered_domain": dict(Counter(row["registered_domain"] for row in rows)),
        "counts_by_category": dict(Counter(row["category"] for row in rows)),
        "counts_by_cohort": dict(
            Counter(cohort for row in rows for cohort in row["cohorts"].split("|") if cohort)
        ),
        "counts_by_verification_status": dict(Counter(row["verification_status"] for row in rows)),
        "duplicate_removal": duplicates,
        "normalization_function": "feature_extractor.normalize_url",
        "synthetic_urls_created": 0,
        "benchmark_or_counterfactual_rows_included": 0,
    }
    OUTPUT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Saved {len(rows)} distinct verified observations from {len(summaries)} sources.")


if __name__ == "__main__":
    main()
