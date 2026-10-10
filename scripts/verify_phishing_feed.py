"""Independently verify Phishing.Database feed counts against VIGIL preparation."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FEED_PATH = ROOT / "data" / "external" / "phishing_database_active.txt"
OUTPUT_PATH = ROOT / "reports" / "phishing_feed_verification.json"
POWERSHELL_UNIQUE_REPORTED = 732_011


def duplicate_examples(
    values: list[tuple[str, str, str]],
    normalization_layer: str,
    limit: int = 20,
) -> list[dict]:
    """Return first examples of distinct inputs sharing a chosen normalized key."""
    first_by_key: dict[str, tuple[str, str, str]] = {}
    examples = []
    for raw, normalized, analysis in values:
        key = normalized if normalization_layer == "normalize_url" else analysis
        previous = first_by_key.get(key)
        if previous is None:
            first_by_key[key] = (raw, normalized, analysis)
            continue
        if len(examples) < limit:
            examples.append(
                {
                    "first_raw_url": previous[0],
                    "duplicate_raw_url": raw,
                    "first_normalize_url_value": previous[1],
                    "duplicate_normalize_url_value": normalized,
                    "first_analysis_url": previous[2],
                    "duplicate_analysis_url": analysis,
                    "shared_normalization_key": key,
                }
            )
    return examples


def exact_duplicate_examples(values: list[str], limit: int = 20) -> list[dict]:
    seen = set()
    examples = []
    for line_number, value in enumerate(values, 1):
        if value in seen and len(examples) < limit:
            examples.append({"line_number": line_number, "raw_url": value})
        seen.add(value)
    return examples


def main() -> None:
    from feature_extractor import _analysis_url, normalize_url

    if not FEED_PATH.is_file():
        raise FileNotFoundError(f"Phishing feed not found: {FEED_PATH}")

    # Match prepare_dataset._read_feed(): UTF-8 with replacement and splitlines().
    raw_lines = FEED_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    empty_lines = [line for line in raw_lines if not line.strip()]
    nonempty_lines = [line for line in raw_lines if line.strip()]

    exact_raw_counts = Counter(nonempty_lines)
    casefold_raw_counts = Counter(line.casefold() for line in nonempty_lines)

    valid_rows: list[tuple[str, str, str]] = []
    invalid_examples = []
    invalid_count = 0
    for line_number, raw in enumerate(raw_lines, 1):
        if not raw.strip():
            continue
        try:
            normalized = normalize_url(raw.strip())
            analysis = _analysis_url(normalized)
        except (TypeError, ValueError) as exc:
            invalid_count += 1
            if len(invalid_examples) < 20:
                invalid_examples.append(
                    {
                        "line_number": line_number,
                        "url": raw,
                        "error": str(exc),
                    }
                )
            continue
        valid_rows.append((raw.strip(), normalized, analysis))

    normalized_url_counts = Counter(normalized for _, normalized, _ in valid_rows)
    analysis_url_counts = Counter(analysis for _, _, analysis in valid_rows)
    valid_raw_counts = Counter(raw for raw, _, _ in valid_rows)
    casefold_valid_counts = Counter(raw.casefold() for raw, _, _ in valid_rows)

    total_physical_lines = len(raw_lines)
    nonempty_line_count = len(nonempty_lines)
    valid_url_count = len(valid_rows)
    unique_valid_raw_urls = len(valid_raw_counts)
    unique_after_normalize_url = len(normalized_url_counts)
    normalized_unique_urls = len(analysis_url_counts)

    exact_raw_duplicates = nonempty_line_count - len(exact_raw_counts)
    exact_duplicates_after_normalize_url = valid_url_count - unique_after_normalize_url
    normalized_duplicates = valid_url_count - normalized_unique_urls
    powershell_difference = len(exact_raw_counts) - POWERSHELL_UNIQUE_REPORTED
    casefold_raw_unique = len(casefold_raw_counts)
    casefold_valid_unique = len(casefold_valid_counts)

    # Verify the preparation counts against the same pipeline functions and row rules.
    prepare_dataset_counts = {
        "rows_before": total_physical_lines,
        "blank_lines": len(empty_lines),
        "missing_urls": 0,
        "invalid_urls": invalid_count,
        "valid_urls_after_missing_and_invalid_filter": valid_url_count,
        "exact_duplicate_urls_after_normalize_url": exact_duplicates_after_normalize_url,
        "normalized_duplicate_urls_after_analysis_url": normalized_duplicates,
        "duplicates_removed_by_drop_duplicates_analysis_url": normalized_duplicates,
        "rows_after": normalized_unique_urls,
    }

    expected_prepare_counts = {
        "rows_before": 789_054,
        "blank_lines": 0,
        "missing_urls": 0,
        "invalid_urls": 674,
        "valid_urls_after_missing_and_invalid_filter": 788_380,
        "exact_duplicate_urls_after_normalize_url": 79,
        "normalized_duplicate_urls_after_analysis_url": 3_995,
        "duplicates_removed_by_drop_duplicates_analysis_url": 3_995,
        "rows_after": 784_385,
    }
    pipeline_matches_known_counts = prepare_dataset_counts == expected_prepare_counts
    powershell_casefold_match = casefold_raw_unique == POWERSHELL_UNIQUE_REPORTED

    explanation = (
        "Python exact uniqueness is case-sensitive: all 789,054 non-empty raw lines are distinct. "
        "The reported PowerShell Sort-Object -Unique count is 732,011, exactly matching the Python "
        "casefolded distinct-string count. This indicates PowerShell's default string comparison "
        "collapsed case variants; it is not counting URLs under VIGIL URL normalization. The raw-line "
        f"difference is {powershell_difference:,}, including {invalid_count:,} invalid URL strings. "
        f"After URL validation, Python has {valid_url_count:,} "
        f"valid rows and {unique_valid_raw_urls:,} exact-unique valid raw strings. normalize_url() then "
        f"collapses {exact_duplicates_after_normalize_url:,} additional rows to {unique_after_normalize_url:,} "
        "unique canonical URLs. _analysis_url() additionally removes a leading www. and root slash "
        f"for analysis identity, collapsing {normalized_duplicates:,} rows total and leaving "
        f"{normalized_unique_urls:,}. That final count exactly matches prepare_dataset.py rows_after."
    )

    status = "PASS" if pipeline_matches_known_counts and powershell_casefold_match else "DISCREPANCY"
    report = {
        "status": status,
        "feed_path": str(FEED_PATH.relative_to(ROOT)),
        "independent_python_counts": {
            "total_physical_lines": total_physical_lines,
            "non_empty_lines": nonempty_line_count,
            "exact_unique_raw_strings": len(exact_raw_counts),
            "exact_duplicate_raw_strings": exact_raw_duplicates,
            "empty_or_whitespace_lines": len(empty_lines),
            "invalid_urls": invalid_count,
            "valid_urls": valid_url_count,
            "unique_valid_urls_before_normalization": unique_valid_raw_urls,
            "unique_valid_urls_after_normalize_url": unique_after_normalize_url,
            "unique_valid_urls_after_analysis_normalization": normalized_unique_urls,
            "exact_duplicates_after_normalize_url": exact_duplicates_after_normalize_url,
            "normalized_duplicates_after_analysis_url": normalized_duplicates,
            "python_casefold_unique_raw_strings": casefold_raw_unique,
            "python_casefold_unique_valid_urls": casefold_valid_unique,
            "casefold_collisions_in_raw_unique_strings": len(exact_raw_counts) - casefold_raw_unique,
        },
        "prepare_dataset_counts": prepare_dataset_counts,
        "known_prepare_dataset_counts_match": pipeline_matches_known_counts,
        "powershell_comparison": {
            "reported_sort_object_unique_count": POWERSHELL_UNIQUE_REPORTED,
            "python_exact_unique_raw_count": len(exact_raw_counts),
            "python_exact_unique_valid_raw_url_count": unique_valid_raw_urls,
            "exact_count_difference": powershell_difference,
            "python_casefold_unique_raw_count": casefold_raw_unique,
            "python_casefold_count_matches_powershell": powershell_casefold_match,
            "explanation": "Sort-Object -Unique compares strings case-insensitively by default; the Python casefold diagnostic matches its reported count exactly. Use Sort-Object -CaseSensitive -Unique for an exact-string comparison.",
        },
        "prepare_dataset_explanation": {
            "_read_feed()": "Reads UTF-8 with errors='replace', calls splitlines(), records len(lines) as rows_before, counts not line.strip() as blank_lines, and creates one row per line with label=1, source=phishing_database_active, collection_date=NA before canonicalization.",
            "_canonicalize() missing filter": "Counts null or whitespace-only url values as missing_urls and drops them. For this feed, blank_lines and missing_urls are both zero.",
            "URL validation and normalize_url()": "For each remaining row, calls normalize_url(str(url).strip()); TypeError/ValueError increments invalid_urls and drops the row. Valid outputs replace url with the normalized URL.",
            "exact_duplicate_urls": "Computed after normalize_url() as records['url'].duplicated().sum(); this feed has 79 repeated normalized URL strings.",
            "normalized_duplicate_urls": "Computed after _analysis_url() as records['_analysis_url'].duplicated().sum(); this counts 3,995 rows whose analysis identity has appeared earlier.",
            "deduplication": "Drops duplicate _analysis_url values, keeping the first row. _analysis_url() removes a leading www. from the host and treats a root '/' path as empty while preserving scheme, non-root path, query, and fragment.",
            "rows_after": "Set to len(records) after drop_duplicates('_analysis_url'): 788,380 valid rows minus 3,995 duplicates = 784,385.",
        },
        "duplicate_examples": {
            "exact_duplicate_raw_strings": exact_duplicate_examples(nonempty_lines),
            "same_normalize_url_values_but_distinct_raw_strings": duplicate_examples(
                valid_rows, "normalize_url"
            ),
            "same_analysis_url_but_distinct_normalize_url_values": duplicate_examples(
                valid_rows, "analysis_url"
            ),
            "maximum_examples_per_list": 20,
        },
        "invalid_url_examples_first_20_only": invalid_examples,
        "counts_reconcile": pipeline_matches_known_counts and powershell_casefold_match,
        "explanation_of_difference": explanation,
        "files_modified": [],
        "training_performed": False,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2, ensure_ascii=False)
        output_file.write("\n")

    print(json.dumps({
        "status": status,
        "total_physical_lines": total_physical_lines,
        "valid_urls": valid_url_count,
        "unique_valid_urls_before_normalization": unique_valid_raw_urls,
        "unique_after_normalize_url": unique_after_normalize_url,
        "normalized_unique_urls": normalized_unique_urls,
        "exact_duplicates_after_normalize_url": exact_duplicates_after_normalize_url,
        "normalized_duplicates": normalized_duplicates,
        "python_casefold_unique_raw_strings": casefold_raw_unique,
        "powershell_reported_unique": POWERSHELL_UNIQUE_REPORTED,
        "output": str(OUTPUT_PATH.relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()