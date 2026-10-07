"""Collect first-party dynamic URLs from verified public institutional pages."""
from __future__ import annotations

import csv
import hashlib
import html.parser
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUTPUT = os.path.join(ROOT, "data", "benign_dynamic_urls.csv")
MANIFEST = os.path.join(ROOT, "reports", "benign_dynamic_url_sources.json")
COLLECTION_DATE = datetime.now(timezone.utc).date().isoformat()
USER_AGENT = "VIGIL-Benign-Dynamic-URL-Research/1.0 (low-rate first-party link verification)"
MAX_PAGE_BYTES = 1_500_000
MAX_LINKS_PER_SOURCE = 36
MAX_VERIFICATIONS = 10
MAX_CHILD_PAGES_PER_SOURCE = 5
SEED = 20261007

SOURCES = [
    {
        "name": "Wikimedia Wikipedia",
        "url": "https://en.wikipedia.org/wiki/Main_Page",
        "why_legitimate": "Wikipedia's official public encyclopedia page and same-registered-domain article/navigation routes.",
    },
    {
        "name": "Mozilla Developer Network",
        "url": "https://developer.mozilla.org/en-US/",
        "why_legitimate": "Mozilla's official developer documentation and same-registered-domain documentation routes.",
    },
    {
        "name": "GitHub",
        "url": "https://github.com/",
        "why_legitimate": "GitHub's official public service homepage and same-registered-domain product/navigation routes.",
    },
    {
        "name": "NASA",
        "url": "https://www.nasa.gov/",
        "why_legitimate": "NASA's official government homepage and same-registered-domain news and information routes.",
    },
    {
        "name": "Library of Congress",
        "url": "https://www.loc.gov/",
        "why_legitimate": "The Library of Congress official government site and same-registered-domain catalog/navigation routes.",
    },
    {
        "name": "World Wide Web Consortium",
        "url": "https://www.w3.org/",
        "why_legitimate": "W3C's official standards organization site and same-registered-domain standards routes.",
    },
    {
        "name": "Internet Engineering Task Force",
        "url": "https://www.ietf.org/",
        "why_legitimate": "IETF's official standards organization site and same-registered-domain publication routes.",
    },
    {
        "name": "arXiv",
        "url": "https://arxiv.org/",
        "why_legitimate": "The arXiv official research preprint repository and same-registered-domain browsing/search routes.",
    },
    {
        "name": "OpenStreetMap",
        "url": "https://www.openstreetmap.org/",
        "why_legitimate": "OpenStreetMap's official public mapping service and same-registered-domain user interface routes.",
    },
    {
        "name": "World Health Organization",
        "url": "https://www.who.int/",
        "why_legitimate": "WHO's official public health organization site and same-registered-domain information routes.",
    },
    {
        "name": "Massachusetts Institute of Technology",
        "url": "https://www.mit.edu/",
        "why_legitimate": "MIT's official university homepage and same-registered-domain academic navigation routes.",
    },
    {
        "name": "Stanford University",
        "url": "https://www.stanford.edu/",
        "why_legitimate": "Stanford's official university homepage and same-registered-domain academic navigation routes.",
    },
    {
        "name": "University of California, Berkeley",
        "url": "https://www.berkeley.edu/",
        "why_legitimate": "UC Berkeley's official university homepage and same-registered-domain academic navigation routes.",
    },
    {
        "name": "GOV.UK",
        "url": "https://www.gov.uk/",
        "why_legitimate": "The UK government's official public services portal and same-registered-domain service routes.",
    },
    {
        "name": "European Space Agency",
        "url": "https://www.esa.int/",
        "why_legitimate": "ESA's official public space agency site and same-registered-domain information routes.",
    },
    {
        "name": "Chrome for Developers",
        "url": "https://developer.chrome.com/",
        "why_legitimate": "Google Chrome's official developer documentation and same-registered-domain documentation routes.",
    },
    {
        "name": "RFC Editor",
        "url": "https://www.rfc-editor.org/",
        "why_legitimate": "The RFC Editor's official standards publication site and same-registered-domain publication routes.",
    },
]

SECRET_KEY_PARTS = ("token", "password", "passwd", "secret", "session", "auth", "credential", "email")


class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.links.append(href.strip())


def registered_domain(url: str) -> str:
    from feature_extractor import get_registered_domain

    return get_registered_domain(url)


def fetch(url: str, timeout: float = 12.0) -> dict:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    with urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_PAGE_BYTES + 1)
        if len(body) > MAX_PAGE_BYTES:
            body = body[:MAX_PAGE_BYTES]
        return {
            "status": int(response.status),
            "final_url": response.geturl(),
            "content_type": response.headers.get("Content-Type", ""),
            "body": body,
        }


def classify(url: str) -> str | None:
    parsed = urlsplit(url)
    path, query, fragment = parsed.path or "", parsed.query or "", parsed.fragment or ""
    pairs = query.split("&") if query else []
    keys = [pair.split("=", 1)[0].lower() for pair in pairs]
    if any(any(secret in key for secret in SECRET_KEY_PARTS) for key in keys):
        return None
    if any(key.startswith("utm_") or key in {"gclid", "fbclid", "yclid"} for key in keys):
        return "tracking_parameters"
    if any(key in {"url", "redirect", "redirect_url", "return", "returnto", "next", "continue", "target", "dest", "destination", "out"} for key in keys):
        return "redirect_style"
    if query and "%" in query:
        return "encoded_query"
    if len(query) > 100:
        return "long_query"
    if len(pairs) > 1:
        return "multiple_query_parameters"
    if fragment:
        return "fragment"
    if path not in ("", "/") and query:
        return "path_query"
    if query:
        return "query_only"
    if path not in ("", "/"):
        if len(url) > 200:
            return "long_legitimate_url"
        path_entropy = _entropy(path)
        if path_entropy >= 4.0:
            return "high_entropy_legitimate"
        return "path_only"
    return None


def _entropy(value: str) -> float:
    from collections import Counter
    import math

    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values()) if value else 0.0


def canonical_url(url: str) -> str:
    from feature_extractor import normalize_url

    return normalize_url(url)


def verification_candidates(
    source: dict,
    source_page: str,
    links: list[str],
    limit: int = MAX_LINKS_PER_SOURCE,
) -> list[dict]:
    root_domain = registered_domain(source_page)
    found = {}
    for href in links:
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absolute = urljoin(source_page, href)
        if classify(absolute) is None:
            continue
        parsed = urlsplit(absolute)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            continue
        try:
            if registered_domain(absolute) != root_domain:
                continue
            canonical = canonical_url(absolute)
        except ValueError:
            continue
        if canonical == canonical_url(source_page):
            continue
        found.setdefault(canonical, {
            "url": canonical,
            "source": source["name"],
            "source_page_url": source_page,
            "source_domain": root_domain,
            "provenance": source["why_legitimate"],
        })

    rng = random.Random(SEED + sum(source_page.encode("utf-8")))
    categorized = defaultdict(list)
    for item in found.values():
        categorized[classify(item["url"])].append(item)
    chosen = []
    categories = list(categorized)
    rng.shuffle(categories)
    for category in categories:
        values = categorized[category]
        rng.shuffle(values)
        chosen.extend(values[:MAX_VERIFICATIONS])
    rng.shuffle(chosen)
    return chosen[:limit]


def verify_candidate(candidate: dict) -> dict | None:
    url = candidate["url"]
    fetch_url, _fragment = urldefrag(url)
    try:
        response = fetch(fetch_url, timeout=10.0)
    except Exception as error:
        candidate["verification_error"] = f"{type(error).__name__}: {str(error)[:180]}"
        return None
    final_domain = registered_domain(response["final_url"])
    if not 200 <= response["status"] < 300 or final_domain != candidate["source_domain"]:
        return None
    candidate.update({
        "verification_status": response["status"],
        "verified_final_url": response["final_url"],
        "verified_content_type": response["content_type"][:120],
        "collection_date": COLLECTION_DATE,
        "label": 0,
        "category": classify(url),
        "deduplication_key": canonical_url(url),
    })
    return candidate


def main():
    from feature_extractor import normalize_url

    discovered = []
    source_results = []
    for source in SOURCES:
        try:
            homepage = fetch(source["url"])
            if not 200 <= homepage["status"] < 300 or "html" not in homepage["content_type"].lower():
                raise ValueError("source homepage was not a successful HTML response")
            final_url = homepage["final_url"]
            page_domain = registered_domain(final_url)
            final_page = urldefrag(final_url)[0]
            parser = LinkParser()
            parser.feed(homepage["body"].decode("utf-8", "replace"))
            candidates = verification_candidates(source, final_page, parser.links)
            child_pages = []
            for item in candidates:
                parsed = urlsplit(item["url"])
                if parsed.query or parsed.fragment or parsed.path in ("", "/"):
                    continue
                child_pages.append(item["url"])
            child_pages = list(dict.fromkeys(child_pages))[:MAX_CHILD_PAGES_PER_SOURCE]
            crawled_pages = [{
                "url": final_page,
                "status": int(homepage["status"]),
                "content_type": homepage["content_type"][:120],
            }]
            child_page_errors = []
            expanded_candidates = list(candidates)
            for child_url in child_pages:
                try:
                    child = fetch(child_url)
                    if (
                        not 200 <= child["status"] < 300
                        or "html" not in child["content_type"].lower()
                        or registered_domain(child["final_url"]) != page_domain
                    ):
                        continue
                    child_final = urldefrag(child["final_url"])[0]
                    child_parser = LinkParser()
                    child_parser.feed(child["body"].decode("utf-8", "replace"))
                    expanded_candidates.extend(
                        verification_candidates(source, child_final, child_parser.links)
                    )
                    crawled_pages.append({
                        "url": child_final,
                        "status": int(child["status"]),
                        "content_type": child["content_type"][:120],
                    })
                except Exception as error:
                    child_page_errors.append({
                        "url": child_url,
                        "error": f"{type(error).__name__}: {str(error)[:180]}",
                    })
                    continue
                time.sleep(0.1)
            deduplicated_candidates = {
                item["url"]: item for item in expanded_candidates
            }
            pool = list(deduplicated_candidates.values())
            by_category = defaultdict(list)
            for item in pool:
                by_category[classify(item["url"])].append(item)
            rng = random.Random(SEED + sum(final_page.encode("utf-8")))
            categories = list(by_category)
            rng.shuffle(categories)
            candidates = []
            for category in categories:
                rng.shuffle(by_category[category])
                candidates.extend(by_category[category][:MAX_VERIFICATIONS])
            rng.shuffle(candidates)
            candidates = candidates[:MAX_LINKS_PER_SOURCE]
            verified = []
            with ThreadPoolExecutor(max_workers=3) as pool:
                futures = [pool.submit(verify_candidate, item) for item in candidates]
                for future in as_completed(futures):
                    item = future.result()
                    if item:
                        verified.append(item)
            verified = sorted(verified, key=lambda item: (item["category"], item["url"]))
            discovered.extend(verified)
            source_results.append({
                "source_name": source["name"],
                "source_page_url": final_page,
                "source_homepage_status": int(homepage["status"]),
                "source_registered_domain": page_domain,
                "collection_method": "Fetch the official first-party homepage and up to five linked same-registered-domain HTML pages over certificate-validated HTTPS; extract existing same-registered-domain anchor href values without synthesizing URL components; individually GET selected hrefs; retain only 2xx responses whose final registered domain remains the source domain.",
                "first_party_pages_crawled": crawled_pages,
                "child_page_errors": child_page_errors,
                "collection_date": COLLECTION_DATE,
                "why_urls_are_considered_legitimate": source["why_legitimate"],
                "candidate_links_checked": len(candidates),
                "verified_urls": len(verified),
                "category_counts": dict(Counter(item["category"] for item in verified)),
                "deduplication_method": "Canonicalized with feature_extractor.normalize_url, then exact and normalized URL deduplication across all sources.",
                "error": None,
            })
            print(
                f"{source['name']}: {len(verified)} verified of {len(candidates)} checked",
                flush=True,
            )
        except Exception as error:
            source_results.append({
                "source_name": source["name"],
                "source_page_url": source["url"],
                "collection_date": COLLECTION_DATE,
                "why_urls_are_considered_legitimate": source["why_legitimate"],
                "verified_urls": 0,
                "category_counts": {},
                "deduplication_method": "Canonicalized with feature_extractor.normalize_url, then exact and normalized URL deduplication across all sources.",
                "error": f"{type(error).__name__}: {str(error)[:240]}",
            })
            print(f"{source['name']}: ERROR {type(error).__name__}: {error}", flush=True)
        time.sleep(0.2)

    previous = pd.read_csv(os.path.join(ROOT, "data", "processed", "clean_dataset.csv"), dtype={"url": str})
    exact_urls = set(previous.url)
    normalized_urls = set()
    previous_domains = set()
    for url in previous.url.dropna():
        try:
            normalized_urls.add(normalize_url(url))
            previous_domains.add(registered_domain(url))
        except ValueError:
            continue

    accepted = []
    rejected_exact = rejected_normalized = rejected_cross_source = 0
    seen_exact, seen_normalized = set(), set()
    source_seen = defaultdict(set)
    for item in discovered:
        raw = item["url"]
        normalized = normalize_url(raw)
        if raw in seen_exact:
            rejected_exact += 1
            continue
        seen_exact.add(raw)
        if normalized in seen_normalized:
            rejected_normalized += 1
            continue
        seen_normalized.add(normalized)
        if normalized in normalized_urls or raw in exact_urls:
            rejected_cross_source += 1
            continue
        source_seen[normalized].add(item["source"])
        accepted.append(item)

    if len(source_seen) != len(accepted):
        raise AssertionError("A normalized URL appeared in multiple provenance sources.")
    if not accepted:
        raise RuntimeError("No provenance-verified dynamic URLs were collected; no dataset was written.")

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    frame = pd.DataFrame(accepted)
    frame["url"] = frame["url"].map(normalize_url)
    frame["label"] = 0
    frame = frame[[
        "url", "label", "source", "provenance", "category", "collection_date",
        "source_page_url", "source_domain", "verification_status",
        "verified_final_url", "verified_content_type", "deduplication_key",
    ]]
    frame.to_csv(OUTPUT, index=False, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")

    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "collection_date": COLLECTION_DATE,
        "dataset": os.path.relpath(OUTPUT, ROOT),
        "label_mapping": {"0": "legitimate; only URLs linked from a named official first-party page and individually verified with a successful same-registered-domain HTTPS GET"},
        "method": "Conservative live collection from official first-party homepages and up to five linked same-registered-domain HTML pages per source. Existing same-domain hrefs were individually fetched over certificate-validated HTTPS; only successful 2xx responses staying on the source registered domain were labeled legitimate. No model predictions, allowlists for classification, or synthetic URLs were used to assign labels.",
        "sources": source_results,
        "source_url_counts": dict(Counter(item["source"] for item in accepted)),
        "category_counts": dict(Counter(item["category"] for item in accepted)),
        "rows_before_deduplication": len(discovered),
        "rows_after_deduplication": len(accepted),
        "deduplication": {
            "exact_duplicate_urls_removed": rejected_exact,
            "normalized_duplicate_urls_removed": rejected_normalized,
            "cross_source_or_existing_dataset_duplicates_removed": rejected_cross_source,
            "method": "Exact URL deduplication, canonical URL deduplication via normalize_url, and cross-source comparison against every URL in clean_dataset.csv.",
        },
        "existing_dataset_registered_domains_overlap": int(
            len({registered_domain(item["url"]) for item in accepted} & previous_domains)
        ),
        "category_definitions": {
            "path_only": "Non-root path with no query or fragment.",
            "query_only": "Query string on the root path.",
            "path_query": "Non-root path and a query string, excluding higher-priority query categories.",
            "multiple_query_parameters": "At least two query key/value segments.",
            "long_query": "Raw query string longer than 100 characters.",
            "encoded_query": "Query contains percent-encoded bytes.",
            "fragment": "URL contains a fragment, excluding higher-priority query categories.",
            "tracking_parameters": "Observed query uses a named utm_* parameter or common ad/click identifier.",
            "redirect_style": "Observed query uses an explicit redirect/return/continue/destination parameter.",
            "high_entropy_legitimate": "Path-only URL whose path Shannon entropy is at least 4.0 bits per character.",
            "long_legitimate_url": "Path-only URL longer than 200 characters.",
        },
    }
    with open(MANIFEST, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=False)
    print(json.dumps({
        "dataset": os.path.relpath(OUTPUT, ROOT),
        "rows": len(frame),
        "sources": manifest["source_url_counts"],
        "categories": manifest["category_counts"],
        "deduplication": manifest["deduplication"],
        "manifest": os.path.relpath(MANIFEST, ROOT),
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
