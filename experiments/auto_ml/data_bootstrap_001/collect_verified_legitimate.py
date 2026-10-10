"""Collect real, first-party benign URL examples into an isolated experiment."""
from __future__ import annotations

import csv
import json
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import collect_benign_dynamic_urls as collector
from feature_extractor import _analysis_url, normalize_url

EXPERIMENT_DIR = Path(__file__).resolve().parent
OUTPUT_CSV = EXPERIMENT_DIR / "legitimate_urls.csv"
OUTPUT_REPORT = EXPERIMENT_DIR / "collection_report.json"
FEED_PATH = ROOT / "data" / "external" / "phishing_database_active.txt"
SEED_CSV = ROOT / "data" / "experiments" / "legitimate_dynamic_training.csv"
SOURCE_MANIFEST = ROOT / "reports" / "benign_dynamic_url_sources.json"

ADDITIONAL_SOURCES = [
    {"name": "NumPy", "url": "https://numpy.org/", "why_legitimate": "Official NumPy project homepage and its first-party documentation/navigation links."},
    {"name": "pandas", "url": "https://pandas.pydata.org/", "why_legitimate": "Official pandas project homepage and its first-party documentation/navigation links."},
    {"name": "scikit-learn", "url": "https://scikit-learn.org/", "why_legitimate": "Official scikit-learn project homepage and its first-party documentation/navigation links."},
    {"name": "PyTorch", "url": "https://pytorch.org/", "why_legitimate": "Official PyTorch project homepage and its first-party documentation/navigation links."},
    {"name": "TensorFlow", "url": "https://www.tensorflow.org/", "why_legitimate": "Official TensorFlow project homepage and its first-party documentation/navigation links."},
    {"name": "Go", "url": "https://go.dev/", "why_legitimate": "Official Go language site and first-party documentation links."},
    {"name": "Rust", "url": "https://www.rust-lang.org/", "why_legitimate": "Official Rust language site and first-party documentation links."},
    {"name": "Kotlin", "url": "https://kotlinlang.org/", "why_legitimate": "Official Kotlin language site and first-party documentation links."},
    {"name": "PHP", "url": "https://www.php.net/", "why_legitimate": "Official PHP project site and first-party documentation links."},
    {"name": "Ruby", "url": "https://www.ruby-lang.org/", "why_legitimate": "Official Ruby language site and first-party documentation links."},
    {"name": "Perl", "url": "https://www.perl.org/", "why_legitimate": "Official Perl project site and first-party documentation links."},
    {"name": "Julia", "url": "https://julialang.org/", "why_legitimate": "Official Julia language site and first-party documentation links."},
    {"name": "SQLite", "url": "https://www.sqlite.org/", "why_legitimate": "Official SQLite project site and first-party documentation links."},
    {"name": "GNU Project", "url": "https://www.gnu.org/", "why_legitimate": "Official GNU Project site and first-party documentation links."},
    {"name": "Linux Kernel", "url": "https://www.kernel.org/", "why_legitimate": "Official Linux kernel site and first-party documentation links."},
    {"name": "OpenAPI Initiative", "url": "https://www.openapis.org/", "why_legitimate": "Official OpenAPI Initiative site and first-party specification links."},
    {"name": "OWASP", "url": "https://owasp.org/", "why_legitimate": "Official OWASP Foundation site and first-party project/documentation links."},
    {"name": "docs.rs", "url": "https://docs.rs/", "why_legitimate": "Official Rust crate documentation service homepage and first-party navigation links."},
    {"name": "Django", "url": "https://www.djangoproject.com/", "why_legitimate": "Official Django project site and first-party documentation links."},
    {"name": "Centers for Disease Control and Prevention", "url": "https://www.cdc.gov/", "why_legitimate": "Official US government public health site and first-party information links."},
    {"name": "US Food and Drug Administration", "url": "https://www.fda.gov/", "why_legitimate": "Official US government FDA site and first-party information links."},
    {"name": "National Institutes of Health", "url": "https://www.nih.gov/", "why_legitimate": "Official US government NIH site and first-party research links."},
    {"name": "National Oceanic and Atmospheric Administration", "url": "https://www.noaa.gov/", "why_legitimate": "Official US government NOAA site and first-party data/information links."},
    {"name": "National Institute of Standards and Technology", "url": "https://www.nist.gov/", "why_legitimate": "Official US government NIST site and first-party standards links."},
    {"name": "Environmental Protection Agency", "url": "https://www.epa.gov/", "why_legitimate": "Official US government EPA site and first-party information links."},
    {"name": "US Geological Survey", "url": "https://www.usgs.gov/", "why_legitimate": "Official US government USGS site and first-party science/data links."},
    {"name": "US Department of Energy", "url": "https://www.energy.gov/", "why_legitimate": "Official US government Department of Energy site and first-party information links."},
    {"name": "USA.gov", "url": "https://www.usa.gov/", "why_legitimate": "Official US government public services portal and first-party service links."},
    {"name": "US National Park Service", "url": "https://www.nps.gov/", "why_legitimate": "Official US government National Park Service site and first-party park pages."},
    {"name": "US Census Bureau", "url": "https://www.census.gov/", "why_legitimate": "Official US government Census Bureau site and first-party data links."},
    {"name": "US Securities and Exchange Commission", "url": "https://www.sec.gov/", "why_legitimate": "Official US government SEC site and first-party filings/information links."},
    {"name": "Federal Reserve", "url": "https://www.federalreserve.gov/", "why_legitimate": "Official US Federal Reserve site and first-party publication links."},
    {"name": "Federal Trade Commission", "url": "https://www.ftc.gov/", "why_legitimate": "Official US government FTC site and first-party consumer information links."},
    {"name": "Consumer Financial Protection Bureau", "url": "https://www.consumerfinance.gov/", "why_legitimate": "Official US government CFPB site and first-party consumer resource links."},
    {"name": "Harvard University", "url": "https://www.harvard.edu/", "why_legitimate": "Official Harvard University site and first-party academic links."},
    {"name": "Princeton University", "url": "https://www.princeton.edu/", "why_legitimate": "Official Princeton University site and first-party academic links."},
    {"name": "California Institute of Technology", "url": "https://www.caltech.edu/", "why_legitimate": "Official Caltech site and first-party academic links."},
    {"name": "Carnegie Mellon University", "url": "https://www.cmu.edu/", "why_legitimate": "Official Carnegie Mellon University site and first-party academic links."},
    {"name": "Cornell University", "url": "https://www.cornell.edu/", "why_legitimate": "Official Cornell University site and first-party academic links."},
    {"name": "University of Oxford", "url": "https://www.ox.ac.uk/", "why_legitimate": "Official University of Oxford site and first-party academic links."},
    {"name": "University of Cambridge", "url": "https://www.cam.ac.uk/", "why_legitimate": "Official University of Cambridge site and first-party academic links."},
    {"name": "University of Toronto", "url": "https://www.utoronto.ca/", "why_legitimate": "Official University of Toronto site and first-party academic links."},
    {"name": "United Nations", "url": "https://www.un.org/", "why_legitimate": "Official United Nations site and first-party publication links."},
    {"name": "World Bank", "url": "https://www.worldbank.org/", "why_legitimate": "Official World Bank site and first-party research/data links."},
    {"name": "UNESCO", "url": "https://www.unesco.org/", "why_legitimate": "Official UNESCO site and first-party publication links."},
    {"name": "BBC", "url": "https://www.bbc.com/", "why_legitimate": "Official BBC site and first-party news links."},
    {"name": "NPR", "url": "https://www.npr.org/", "why_legitimate": "Official NPR site and first-party news links."},
    {"name": "Associated Press", "url": "https://apnews.com/", "why_legitimate": "Official Associated Press site and first-party news links."},
    {"name": "The Guardian", "url": "https://www.theguardian.com/", "why_legitimate": "Official Guardian site and first-party news links."},
]
SOURCES = collector.SOURCES + ADDITIONAL_SOURCES


def load_phishing_identities() -> tuple[set[str], dict]:
    identities = set()
    physical_lines = invalid = blank = 0
    with FEED_PATH.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            physical_lines += 1
            raw = line.strip()
            if not raw:
                blank += 1
                continue
            try:
                identities.add(_analysis_url(normalize_url(raw)))
            except (TypeError, ValueError):
                invalid += 1
    return identities, {
        "path": str(FEED_PATH.relative_to(ROOT)),
        "physical_lines": physical_lines,
        "blank_lines": blank,
        "invalid_urls": invalid,
        "unique_analysis_identities": len(identities),
    }


def load_existing_verified_rows(phishing_identities: set[str]) -> tuple[dict[str, dict], int]:
    rows = {}
    conflicts = 0
    if not SEED_CSV.is_file():
        return rows, conflicts
    with SEED_CSV.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if row.get("label") != "0":
                continue
            try:
                normalized = normalize_url(row["url"])
                analysis_key = _analysis_url(normalized)
            except (KeyError, TypeError, ValueError):
                continue
            if analysis_key in phishing_identities:
                conflicts += 1
                continue
            raw_categories = row.get("cohort", "[]")
            try:
                categories = json.loads(raw_categories)
            except (TypeError, json.JSONDecodeError):
                categories = []
            rows.setdefault(
                normalized,
                {
                    "url": normalized,
                    "label": 0,
                    "source": row.get("source") or "existing_verified_manifest_rows",
                    "provenance": "Previously retained first-party page URL from benign source manifest; not opened in this run.",
                    "category": "|".join(categories) if categories else "uncategorized_existing_verified",
                    "collection_date": "2026-10-07",
                    "source_page_url": None,
                    "source_domain": collector.registered_domain(normalized),
                    "verification_status": "previously_recorded_first_party_page_http_200",
                    "verified_final_url": normalized,
                    "verified_content_type": None,
                    "deduplication_key": normalized,
                },
            )
    return rows, conflicts


def collect_source(source: dict) -> dict:
    homepage = collector.fetch(source["url"])
    if not 200 <= homepage["status"] < 300 or "html" not in homepage["content_type"].lower():
        raise ValueError("official source homepage was not a successful HTML response")
    final_page = collector.urldefrag(homepage["final_url"])[0]
    source_domain = collector.registered_domain(final_page)
    parser = collector.LinkParser()
    parser.feed(homepage["body"].decode("utf-8", "replace"))
    candidates = collector.verification_candidates(source, final_page, parser.links)

    child_urls = []
    for item in candidates:
        parsed = urlsplit(item["url"])
        if not parsed.query and not parsed.fragment and parsed.path not in ("", "/"):
            child_urls.append(item["url"])
    child_urls = list(dict.fromkeys(child_urls))[: collector.MAX_CHILD_PAGES_PER_SOURCE]
    crawled_pages = [{
        "url": final_page,
        "status": int(homepage["status"]),
        "content_type": homepage["content_type"][:120],
    }]
    child_page_errors = []
    expanded = list(candidates)
    for child_url in child_urls:
        try:
            child = collector.fetch(child_url)
            if (
                not 200 <= child["status"] < 300
                or "html" not in child["content_type"].lower()
                or collector.registered_domain(child["final_url"]) != source_domain
            ):
                continue
            child_final = collector.urldefrag(child["final_url"])[0]
            child_parser = collector.LinkParser()
            child_parser.feed(child["body"].decode("utf-8", "replace"))
            expanded.extend(collector.verification_candidates(source, child_final, child_parser.links))
            crawled_pages.append({
                "url": child_final,
                "status": int(child["status"]),
                "content_type": child["content_type"][:120],
            })
            time.sleep(0.1)
        except Exception as error:
            child_page_errors.append({"url": child_url, "error": f"{type(error).__name__}: {str(error)[:180]}"})

    by_url = {item["url"]: item for item in expanded}
    by_category = defaultdict(list)
    for item in by_url.values():
        by_category[collector.classify(item["url"])].append(item)
    selected = []
    for category in sorted(by_category):
        selected.extend(by_category[category][: collector.MAX_VERIFICATIONS])
    selected = selected[: collector.MAX_LINKS_PER_SOURCE]

    verified = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(collector.verify_candidate, item) for item in selected]
        for future in as_completed(futures):
            result = future.result()
            if result:
                verified.append(result)
    verified.sort(key=lambda item: (item["category"], item["url"]))
    return {
        "source_name": source["name"],
        "source_page_url": final_page,
        "source_homepage_status": int(homepage["status"]),
        "source_registered_domain": source_domain,
        "why_legitimate": source["why_legitimate"],
        "collection_method": "Official first-party HTTPS page; only linked same-registered-domain URLs individually verified with 2xx HTTPS responses were retained.",
        "first_party_pages_crawled": crawled_pages,
        "child_page_errors": child_page_errors,
        "candidate_links_checked": len(selected),
        "verified_urls": len(verified),
        "category_counts": dict(Counter(row["category"] for row in verified)),
        "error": None,
        "rows": verified,
    }


def main() -> None:
    phishing_identities, phishing_summary = load_phishing_identities()
    accepted, seed_conflicts = load_existing_verified_rows(phishing_identities)
    source_summaries = []
    duplicate_normalized = cross_phishing_conflicts = 0

    for source in SOURCES:
        try:
            result = collect_source(source)
            discovered = result.pop("rows")
            for row in discovered:
                normalized = normalize_url(row["url"])
                key = _analysis_url(normalized)
                if key in phishing_identities:
                    cross_phishing_conflicts += 1
                    continue
                if normalized in accepted:
                    duplicate_normalized += 1
                    continue
                accepted[normalized] = {
                    **row,
                    "url": normalized,
                    "label": 0,
                    "deduplication_key": normalized,
                }
            source_summaries.append(result)
            print(f"{source['name']}: {result['verified_urls']} verified links checked", flush=True)
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
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
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
        "experiment": "auto_ml_data_bootstrap_001",
        "dataset": str(OUTPUT_CSV.relative_to(ROOT)),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "label_mapping": {"0": "legitimate; existing labeled first-party evidence or individually verified successful first-party HTTPS link"},
        "total_unique_urls": len(rows),
        "counts_by_category": dict(Counter(row["category"] for row in rows)),
        "counts_by_source": dict(Counter(row["source"] for row in rows)),
        "unique_registered_domains": len({row["source_domain"] for row in rows}),
        "deduplication": {
            "full_url_key": "feature_extractor.normalize_url",
            "cross_label_conflict_key": "feature_extractor._analysis_url",
            "duplicate_normalized_legitimate_rows_skipped": duplicate_normalized,
            "phishing_feed_identity_conflicts_skipped": cross_phishing_conflicts + seed_conflicts,
            "phishing_feed": phishing_summary,
        },
        "sources": source_summaries,
        "method": "Uses only first-party links recorded locally plus URLs discovered as existing hyperlinks from official source pages and then individually verified as successful HTTPS responses staying on the same registered domain. No URL components or labels are synthesized.",
        "network_requests": "Only to the 17 explicitly listed official first-party sources and their same-domain links, using the existing repository collector verification rules.",
    }
    with OUTPUT_REPORT.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)
        report_file.write("\n")
    print(json.dumps({
        "total_unique_urls": len(rows),
        "unique_registered_domains": report["unique_registered_domains"],
        "counts_by_category": report["counts_by_category"],
        "csv": str(OUTPUT_CSV.relative_to(ROOT)),
        "report": str(OUTPUT_REPORT.relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()