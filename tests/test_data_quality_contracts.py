from experiments.auto_ml.data_quality_contracts import (
    class_balance,
    cohort_counts,
    domain_overlaps,
    missing_cohorts,
    normalized_duplicate_count,
    provenance_errors,
)
from feature_extractor import get_registered_domain, normalize_url


def legitimate_row(url: str) -> dict:
    normalized = normalize_url(url)
    domain = get_registered_domain(normalized)
    return {
        "url": normalized,
        "normalized_url": normalized,
        "label": 0,
        "source": "Example official site",
        "collection_method": "observed_first_party_anchor_https_get",
        "verification_status": "http_200_same_registered_domain",
        "category": "path",
        "cohorts": "path|query|multiple_parameters",
        "registered_domain": domain,
        "source_page_url": f"https://{domain}/",
        "verified_final_url": normalized,
        "verified_content_type": "text/html",
        "collection_date": "2026-10-09",
        "provenance": "Observed link on official first-party page and individually fetched.",
    }


def test_provenance_contract_accepts_individually_verified_first_party_url():
    assert provenance_errors(
        [legitimate_row("https://example.com/search?q=one&page=2")]
    ) == []


def test_provenance_contract_rejects_external_redirect_and_unverified_status():
    row = legitimate_row("https://example.com/path")
    row["verified_final_url"] = "https://other.test/path"
    row["verification_status"] = "http_404_same_registered_domain"
    errors = provenance_errors([row])
    assert any("leaves the first-party domain" in error for error in errors)
    assert any("did not return a 2xx" in error for error in errors)


def test_provenance_contract_rejects_non_https_observations():
    row = legitimate_row("https://example.com/path")
    row["source_page_url"] = "http://example.com/"
    assert any("must use HTTPS" in error for error in provenance_errors([row]))


def test_domain_overlap_and_duplicate_contracts_use_normalized_domains_and_urls():
    groups = {
        "train": {"example.com", "train.test"},
        "lockbox": {"example.com", "lockbox.test"},
    }
    assert domain_overlaps(groups) == {"train::lockbox": ["example.com"]}
    rows = [
        {"url": "https://example.com"},
        {"url": "https://example.com"},
    ]
    assert normalized_duplicate_count(rows) == 1


def test_class_balance_and_structure_counts_are_explicit():
    rows = [
        {"label": 0, "cohorts": "path|query|multiple_parameters"},
        {"label": 1, "cohorts": "path|query"},
    ]
    assert class_balance(rows) == {"0": 1, "1": 1}
    assert cohort_counts(rows) == {
        "multiple_parameters": 1,
        "path": 2,
        "query": 2,
    }
    assert "path" not in missing_cohorts(rows)
    assert "fragment" in missing_cohorts(rows)
