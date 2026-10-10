"""Recover and collect provenance-verified legitimate URL observations."""
from __future__ import annotations

import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urldefrag, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from feature_extractor import get_registered_domain, normalize_url
from scripts.collect_benign_dynamic_urls import (
    LinkParser,
    SOURCES,
    canonical_url,
    classify,
    verification_candidates,
)

INPUT_CSV = os.path.join(ROOT, "data", "experiments", "legitimate_dynamic_training.csv")
INPUT_MANIFEST = os.path.join(ROOT, "reports", "benign_dynamic_url_sources.json")
OUTPUT_CSV = os.path.join(ROOT, "data", "experiments", "legitimate_training_v3.csv")
OUTPUT_REPORT = os.path.join(ROOT, "reports", "legitimate_training_v3.json")
USER_AGENT = "VIGIL-Legitimate-URL-Research/3.0 (low-rate, first-party link verification)"
MAX_PAGE_BYTES = 1_500_000
MAX_LINK_VERIFICATIONS_PER_SOURCE = 16
MAX_CHILD_PAGES_PER_SOURCE = 2
REQUEST_PAUSE_SECONDS = 0.5
TIMEOUT_SECONDS = 12

DESIRED_COHORTS = (
    "homepage",
    "path",
    "search",
    "query",
    "multiple_parameters",
    "encoded",
    "fragment",
    "pagination",
    "tracking",
    "documentation",
    "login_account",
    "long_url",
)
TRACKING_KEYS = {
    "fbclid", "gclid", "msclkid", "dclid", "yclid", "igshid", "mc_cid",
    "mc_eid", "_ga", "_gl", "ref", "ref_src", "ref_url", "referrer",
    "trk", "trkid", "trackingid", "tracking_id", "spm", "scid", "sc_cid",
    "ocid", "ito", "xtor", "cmpid", "si", "feature", "source", "src",
    "campaign",
}
PAGE_KEYS = {"page", "p", "pg", "paged", "pagenum", "start", "offset", "skip", "cursor", "after"}
SEARCH_KEYS = {"q", "query", "search", "search_query", "searchterm", "keyword", "keywords", "term"}
DOC_SEGMENTS = {"docs", "doc", "documentation", "reference", "manual", "guide", "guides", "tutorial"}
LOGIN_SEGMENTS = {
    "login", "signin", "sign-in", "log-in", "logon", "sso", "oauth", "oauth2",
    "authorize", "auth", "signup", "sign-up", "register", "account", "accounts",
    "myaccount", "my-account", "billing", "dashboard",
}


class ApprovedDomainRedirectHandler(HTTPRedirectHandler):
    def __init__(self, approved_domain: str):
        super().__init__()
        self.approved_domain = approved_domain

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        if (
            urlsplit(new_url).scheme.lower() != "https"
            or get_registered_domain(new_url) != self.approved_domain
        ):
            file_pointer.close()
            raise URLError("redirect outside approved HTTPS registered domain blocked")
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def fetch_observed_url(url: str, approved_domain: str) -> dict:
    if urlsplit(url).scheme.lower() != "https" or get_registered_domain(url) != approved_domain:
        raise ValueError("URL is outside the approved HTTPS registered domain")
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    opener = build_opener(ApprovedDomainRedirectHandler(approved_domain))
    with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
        body = response.read(MAX_PAGE_BYTES + 1)
        return {
            "status": int(response.status),
            "final_url": response.geturl(),
            "content_type": response.headers.get("Content-Type", ""),
            "body": body[:MAX_PAGE_BYTES],
            "truncated": len(body) > MAX_PAGE_BYTES,
        }


def cohorts_for(url: str) -> list[str]:
    parsed = urlsplit(url)
    path_segments = [part.lower() for part in parsed.path.split("/") if part]
    parameters = parse_qsl(parsed.query, keep_blank_values=True)
    keys = {key.lower() for key, _ in parameters}
    cohorts = []
    if not path_segments and not parsed.query and not parsed.fragment:
        cohorts.append("homepage")
    if path_segments:
        cohorts.append("path")
    if parsed.query:
        cohorts.append("query")
    if keys & SEARCH_KEYS or any(part in {"search", "find", "results"} for part in path_segments):
        cohorts.append("search")
    if len(parameters) > 1:
        cohorts.append("multiple_parameters")
    if "%" in url:
        cohorts.append("encoded")
    if parsed.fragment:
        cohorts.append("fragment")
    if keys & PAGE_KEYS or any(part.startswith("page-") for part in path_segments):
        cohorts.append("pagination")
    if any(key.startswith("utm_") for key in keys) or keys & TRACKING_KEYS:
        cohorts.append("tracking")
    hostname = (parsed.hostname or "").lower()
    if set(path_segments) & DOC_SEGMENTS or hostname.startswith(("docs.", "developer.", "developers.")):
        cohorts.append("documentation")
    if set(path_segments) & LOGIN_SEGMENTS or hostname.startswith(("login.", "signin.", "sso.", "auth.")):
        cohorts.append("login_account")
    if len(url) > 200:
        cohorts.append("long_url")
    return cohorts


def category_for(url: str, cohorts: list[str]) -> str:
    detected = classify(url)
    if detected:
        return detected
    for cohort in ("homepage", "documentation", "login_account", "search", "path"):
        if cohort in cohorts:
            return "login_account" if cohort == "login_account" else cohort
    return "other_observed"


def count_mapping(values) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def local_observations() -> tuple[list[dict], dict]:
    with open(INPUT_MANIFEST, encoding="utf-8") as stream:
        manifest = json.load(stream)
    source_records = manifest.get("sources", [])
    historical_pages = {}
    for source_record in source_records:
        for page in source_record.get("first_party_pages_crawled", []):
            try:
                historical_pages[normalize_url(page["url"])] = {
                    "source_page_url": page["url"],
                    "verification_status": f"historical_http_{int(page['status'])}",
                    "source_domain": source_record.get("source_registered_domain")
                    or get_registered_domain(page["url"]),
                    "collection_method": "recovered_local_row_and_first_party_page_manifest",
                    "provenance": source_record.get("why_urls_are_considered_legitimate", ""),
                }
            except (KeyError, TypeError, ValueError):
                continue
    with open(INPUT_CSV, newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or "url" not in reader.fieldnames:
            raise ValueError(f"Input CSV has no url column: {INPUT_CSV}")
        rows = []
        unmatched_historical_rows = 0
        for input_row in reader:
            raw_url = (input_row.get("url") or "").strip()
            if not raw_url:
                continue
            normalized = normalize_url(raw_url)
            page_record = historical_pages.get(normalized)
            if page_record is None:
                unmatched_historical_rows += 1
                page_record = {
                    "source_page_url": "",
                    "verification_status": "historical_status_unmatched",
                    "source_domain": get_registered_domain(normalized),
                    "collection_method": "recovered_local_row_level_csv",
                    "provenance": "Recovered from the existing row-level experimental CSV; no matching page status found in the source manifest.",
                }
            source = (input_row.get("source") or "unknown_local_source").strip()
            cohorts = cohorts_for(normalized)
            rows.append({
                "url": normalized,
                "normalized_url": normalized,
                "label": 0,
                "source": source,
                "collection_method": page_record["collection_method"],
                "verification_status": page_record["verification_status"],
                "category": category_for(normalized, cohorts),
                "cohorts": "|".join(cohorts),
                "registered_domain": get_registered_domain(normalized),
                "source_page_url": page_record["source_page_url"],
                "verified_final_url": page_record["source_page_url"],
                "verified_content_type": "text/html (historical manifest)",
                "collection_date": manifest.get("collection_date", ""),
                "provenance": page_record["provenance"],
            })
    return rows, {
        "input_rows": len(rows),
        "unmatched_historical_rows": unmatched_historical_rows,
        "manifest_reported_verified_rows": manifest.get("rows_after_deduplication"),
    }


def source_provenance(source: dict) -> str:
    return source.get("why_legitimate", "")


def observed_row(url: str, source: dict, source_page_url: str, response: dict, method: str) -> dict:
    normalized = normalize_url(url)
    cohorts = cohorts_for(normalized)
    return {
        "url": normalized,
        "normalized_url": normalized,
        "label": 0,
        "source": source["name"],
        "collection_method": method,
        "verification_status": f"http_{response['status']}_same_registered_domain",
        "category": category_for(normalized, cohorts),
        "cohorts": "|".join(cohorts),
        "registered_domain": get_registered_domain(normalized),
        "source_page_url": source_page_url,
        "verified_final_url": response["final_url"],
        "verified_content_type": response["content_type"][:120],
        "collection_date": datetime.now(timezone.utc).date().isoformat(),
        "provenance": source_provenance(source),
    }


def collect_live_source(source: dict, pause_state: dict) -> tuple[list[dict], dict]:
    approved_domain = get_registered_domain(source["url"])
    summary = {
        "source": source["name"],
        "registered_domain": approved_domain,
        "approved_homepage": source["url"],
        "homepage_status": None,
        "homepage_verified": False,
        "links_checked": 0,
        "links_verified": 0,
        "request_count": 0,
        "errors": [],
        "method": "Extract observed HTTPS same-registered-domain links from the official first-party homepage and up to two linked HTML pages; individually GET each retained URL and require 2xx plus same-registered-domain final URL.",
        "provenance": source_provenance(source),
    }
    rows = []

    def request(url: str) -> dict:
        if pause_state["last_request"] is not None:
            elapsed = time.monotonic() - pause_state["last_request"]
            if elapsed < REQUEST_PAUSE_SECONDS:
                time.sleep(REQUEST_PAUSE_SECONDS - elapsed)
        pause_state["last_request"] = time.monotonic()
        summary["request_count"] += 1
        return fetch_observed_url(url, approved_domain)

    try:
        homepage = request(source["url"])
        summary["homepage_status"] = homepage["status"]
        if (
            not 200 <= homepage["status"] < 300
            or "html" not in homepage["content_type"].lower()
            or get_registered_domain(homepage["final_url"]) != approved_domain
        ):
            raise ValueError("homepage was not a successful same-domain HTML response")
        homepage_url = normalize_url(homepage["final_url"])
        summary["homepage_verified"] = True
        rows.append(observed_row(
            homepage_url, source, homepage_url, homepage, "official_first_party_homepage_get"
        ))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        summary["errors"].append(f"homepage: {type(error).__name__}: {str(error)[:180]}")
        return rows, summary

    parser = LinkParser()
    parser.feed(homepage["body"].decode("utf-8", "replace"))
    first_page_candidates = verification_candidates(
        source,
        homepage_url,
        parser.links,
        limit=MAX_LINK_VERIFICATIONS_PER_SOURCE - 4,
    )
    candidates = list(first_page_candidates)
    checked_urls = set()
    successful_child_pages = 0
    candidates_by_normalized = {item["url"]: item for item in candidates}

    index = 0
    while index < len(candidates) and summary["links_checked"] < MAX_LINK_VERIFICATIONS_PER_SOURCE:
        candidate = candidates[index]
        index += 1
        normalized = normalize_url(candidate["url"])
        if normalized in checked_urls:
            continue
        checked_urls.add(normalized)
        summary["links_checked"] += 1
        try:
            response = request(urldefrag(normalized)[0])
            if (
                not 200 <= response["status"] < 300
                or get_registered_domain(response["final_url"]) != approved_domain
            ):
                continue
            row = observed_row(
                normalized,
                source,
                candidate["source_page_url"],
                response,
                "observed_first_party_anchor_https_get",
            )
            rows.append(row)
            summary["links_verified"] += 1
            parsed = urlsplit(normalized)
            if (
                successful_child_pages < MAX_CHILD_PAGES_PER_SOURCE
                and not parsed.query
                and not parsed.fragment
                and parsed.path not in ("", "/")
                and "html" in response["content_type"].lower()
            ):
                successful_child_pages += 1
                child_parser = LinkParser()
                child_parser.feed(response["body"].decode("utf-8", "replace"))
                nested = verification_candidates(
                    source, normalized, child_parser.links,
                    limit=MAX_LINK_VERIFICATIONS_PER_SOURCE,
                )
                for item in nested:
                    candidates_by_normalized.setdefault(item["url"], item)
                candidates = list(candidates_by_normalized.values())
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
            summary["errors"].append(
                f"link: {type(error).__name__}: {str(error)[:160]}"
            )
    return rows, summary


def deduplicate(rows: list[dict]) -> tuple[list[dict], dict]:
    accepted = []
    exact_seen = set()
    normalized_seen = set()
    exact_duplicates = 0
    normalized_duplicates = 0
    for row in rows:
        raw = row["url"]
        if raw in exact_seen:
            exact_duplicates += 1
            continue
        exact_seen.add(raw)
        normalized = normalize_url(raw)
        if normalized in normalized_seen:
            normalized_duplicates += 1
            continue
        normalized_seen.add(normalized)
        row["url"] = normalized
        row["normalized_url"] = normalized
        row["registered_domain"] = get_registered_domain(normalized)
        row["cohorts"] = "|".join(cohorts_for(normalized))
        accepted.append(row)
    return accepted, {
        "input_observations": len(rows),
        "output_unique_rows": len(accepted),
        "exact_duplicate_rows_removed": exact_duplicates,
        "normalized_duplicate_rows_removed": normalized_duplicates,
        "duplicate_rows_removed_total": exact_duplicates + normalized_duplicates,
        "normalization_function": "feature_extractor.normalize_url",
    }


def main() -> None:
    if os.path.exists(OUTPUT_CSV) or os.path.exists(OUTPUT_REPORT):
        raise FileExistsError(
            "Refusing to overwrite v3 outputs; move or rename the existing v3 files first."
        )
    recovered, recovery_summary = local_observations()
    raw_rows = list(recovered)
    source_summaries = []
    pause_state = {"last_request": None}
    for source in SOURCES:
        live_rows, summary = collect_live_source(source, pause_state)
        raw_rows.extend(live_rows)
        source_summaries.append(summary)
        print(
            f"{source['name']}: {summary['links_verified']} links verified "
            f"of {summary['links_checked']} checked; homepage={summary['homepage_status']}",
            flush=True,
        )

    rows, duplicate_summary = deduplicate(raw_rows)
    source_counts = count_mapping(row["source"] for row in rows)
    domain_counts = count_mapping(row["registered_domain"] for row in rows)
    cohort_counts = Counter()
    for row in rows:
        cohort_counts.update(filter(None, row["cohorts"].split("|")))
    verification_counts = count_mapping(row["verification_status"] for row in rows)
    missing_cohorts = sorted(set(DESIRED_COHORTS) - set(cohort_counts))
    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": os.path.relpath(OUTPUT_CSV, ROOT),
        "label_mapping": {"0": "legitimate observed URL; source and verification provenance are recorded per row"},
        "training_data_policy": "Observed legitimate training rows only. Curated and counterfactual benchmark examples are excluded.",
        "benchmark_examples": {"included_in_training_csv": 0, "separate_benchmark_dataset": None},
        "collection_policy": {
            "approved_source_allowlist": [
                {"source": source["name"], "homepage": source["url"],
                 "registered_domain": get_registered_domain(source["url"])}
                for source in SOURCES
            ],
            "redirect_policy": "HTTPS redirects are followed only when the registered domain stays within that source's approved registered domain.",
            "per_source_link_verification_cap": MAX_LINK_VERIFICATIONS_PER_SOURCE,
            "per_source_child_page_cap": MAX_CHILD_PAGES_PER_SOURCE,
            "request_pause_seconds": REQUEST_PAUSE_SECONDS,
            "page_body_limit_bytes": MAX_PAGE_BYTES,
            "synthetic_urls_created": 0,
        },
        "recovery": recovery_summary,
        "source_provenance": source_summaries,
        "row_counts": {
            "recovered_local_rows_before_deduplication": len(recovered),
            "new_live_verified_rows_before_deduplication": sum(
                item["links_verified"] for item in source_summaries
            ) + sum(item["homepage_verified"] for item in source_summaries),
            "usable_unique_observed_legitimate_urls": len(rows),
        },
        "counts_by_source": source_counts,
        "counts_by_registered_domain": domain_counts,
        "counts_by_cohort": dict(sorted(cohort_counts.items())),
        "counts_by_verification_status": verification_counts,
        "missing_cohorts": missing_cohorts,
        "duplicate_removal": duplicate_summary,
        "cohort_definitions": {
            "homepage": "Observed HTTPS homepage/root URL with no path, query, or fragment.",
            "path": "Observed non-root path.",
            "search": "Observed search/find/results route or search-like query key.",
            "query": "Observed non-empty query string.",
            "multiple_parameters": "Observed URL query with two or more parsed parameters.",
            "encoded": "Observed URL containing percent-encoding.",
            "fragment": "Observed URL containing a fragment.",
            "pagination": "Observed page/offset/cursor-style pagination parameter.",
            "tracking": "Observed known tracking parameter.",
            "documentation": "Observed documentation path or developer/docs host.",
            "login_account": "Observed login, authentication, registration, or account route.",
            "long_url": "Observed URL longer than 200 characters.",
        },
        "data_gaps": {
            "missing_cohorts": missing_cohorts,
            "reported_but_unrecoverable_rows": (
                max(
                    0,
                    int(recovery_summary["manifest_reported_verified_rows"] or 0)
                    - recovery_summary["input_rows"],
                )
            ),
            "historically_unmatched_local_rows": recovery_summary["unmatched_historical_rows"],
            "notes": [
                "The source reports describe 435 verified URLs, but only the local row-level CSV rows were recoverable; aggregate report categories are not treated as row-level data.",
                "No cohort is filled with invented paths, generated query strings, or unverified examples.",
                "A missing cohort means no URL meeting the recorded URL-string rule was present in this collection.",
            ],
        },
    }
    if not rows:
        raise RuntimeError("No observed legitimate URLs were available; refusing to write empty outputs.")

    fields = [
        "url", "normalized_url", "label", "source", "collection_method",
        "verification_status", "category", "cohorts", "registered_domain",
        "source_page_url", "verified_final_url", "verified_content_type",
        "collection_date", "provenance",
    ]
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    with open(OUTPUT_CSV, "x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    with open(OUTPUT_REPORT, "x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(json.dumps({
        "usable_unique_observed_legitimate_urls": len(rows),
        "counts_by_source": source_counts,
        "counts_by_cohort": dict(sorted(cohort_counts.items())),
        "missing_cohorts": missing_cohorts,
        "duplicate_removal": duplicate_summary,
        "csv": os.path.relpath(OUTPUT_CSV, ROOT),
        "report": os.path.relpath(OUTPUT_REPORT, ROOT),
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
