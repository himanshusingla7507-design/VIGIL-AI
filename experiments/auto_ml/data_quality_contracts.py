from __future__ import annotations

from collections import Counter
from datetime import date
from itertools import combinations
from urllib.parse import urlsplit

from feature_extractor import get_registered_domain, normalize_url

REQUIRED_PROVENANCE_FIELDS = (
    "url",
    "normalized_url",
    "label",
    "source",
    "collection_method",
    "verification_status",
    "registered_domain",
    "source_page_url",
    "verified_final_url",
    "verified_content_type",
    "collection_date",
    "provenance",
)
REQUIRED_COHORTS = (
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


def provenance_errors(rows: list[dict]) -> list[str]:
    errors = []
    for index, row in enumerate(rows):
        missing = [
            field for field in REQUIRED_PROVENANCE_FIELDS
            if row.get(field) is None or row.get(field) == ""
        ]
        if missing:
            errors.append(f"row {index}: missing provenance fields {', '.join(missing)}")
            continue
        try:
            normalized = normalize_url(row["url"])
            row_domain = get_registered_domain(normalized)
            source_domain = get_registered_domain(row["source_page_url"])
            final_domain = get_registered_domain(row["verified_final_url"])
            date.fromisoformat(row["collection_date"])
            status = int(row["verification_status"].split("_")[1])
        except (IndexError, TypeError, ValueError):
            errors.append(f"row {index}: malformed URL, status, or collection date")
            continue
        if row["label"] != 0:
            errors.append(f"row {index}: legitimate collection label is not 0")
        if row["url"] != normalized or row["normalized_url"] != normalized:
            errors.append(f"row {index}: URL is not stored in normalized form")
        if row["registered_domain"] != row_domain:
            errors.append(f"row {index}: registered domain does not match URL")
        if source_domain != row_domain or final_domain != row_domain:
            errors.append(f"row {index}: source or final URL leaves the first-party domain")
        if any(
            urlsplit(url).scheme.lower() != "https"
            for url in (row["url"], row["source_page_url"], row["verified_final_url"])
        ):
            errors.append(f"row {index}: observed URLs must use HTTPS")
        if not 200 <= status < 300:
            errors.append(f"row {index}: target did not return a 2xx status")
        if not row["verification_status"].endswith("_same_registered_domain"):
            errors.append(f"row {index}: verification status is not same-domain")
    return errors


def domain_overlaps(groups: dict[str, set[str]]) -> dict[str, list[str]]:
    overlaps = {}
    for (left_name, left), (right_name, right) in combinations(groups.items(), 2):
        common = sorted(left & right)
        if common:
            overlaps[f"{left_name}::{right_name}"] = common
    return overlaps


def normalized_duplicate_count(rows: list[dict]) -> int:
    normalized_urls = [normalize_url(row["url"]) for row in rows]
    return len(normalized_urls) - len(set(normalized_urls))


def class_balance(rows: list[dict]) -> dict[str, int]:
    return dict(sorted(Counter(str(row["label"]) for row in rows).items()))


def cohort_counts(rows: list[dict]) -> dict[str, int]:
    return dict(
        sorted(
            Counter(
                cohort
                for row in rows
                for cohort in (row.get("cohorts") or "").split("|")
                if cohort
            ).items()
        )
    )


def missing_cohorts(rows: list[dict]) -> list[str]:
    counts = cohort_counts(rows)
    return [cohort for cohort in REQUIRED_COHORTS if not counts.get(cohort)]
