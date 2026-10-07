"""Prepare VIGIL's PhiUSIIL training data and Phishing.Database feed."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

import pandas as pd

from feature_extractor import _analysis_url, get_registered_domain, normalize_url

ROOT = os.path.dirname(os.path.abspath(__file__))
RAW_PATH = os.path.join(ROOT, "data", "raw", "PhiUSIIL_Phishing_URL_Dataset.csv")
FEED_PATH = os.path.join(ROOT, "data", "external", "phishing_database_active.txt")
PROCESSED_DIR = os.path.join(ROOT, "data", "processed")
REPORTS_DIR = os.path.join(ROOT, "reports")
EXTERNAL_HOLDOUT_FRACTION = 0.20


def _empty_report(source: str, rows_before: int) -> dict:
    return {"source": source, "rows_before": int(rows_before), "rows_after": 0,
            "duplicates_removed": 0, "invalid_urls": 0, "missing_urls": 0,
            "exact_duplicate_urls": 0, "normalized_duplicate_urls": 0,
            "label_distribution": {}, "unique_registered_domains": 0}


def _canonicalize(records: pd.DataFrame, report: dict) -> pd.DataFrame:
    records = records.copy()
    missing = records["url"].isna() | records["url"].astype(str).str.strip().eq("")
    report["missing_urls"] = int(missing.sum())
    records = records.loc[~missing].copy()
    canonical, analysis, keep = [], [], []
    for index, value in records["url"].items():
        try:
            value = normalize_url(str(value).strip())
            canonical.append(value)
            analysis.append(_analysis_url(value))
            keep.append(index)
        except (TypeError, ValueError):
            report["invalid_urls"] += 1
    records = records.loc[keep].copy()
    records["url"] = canonical
    records["_analysis_url"] = analysis
    report["exact_duplicate_urls"] = int(records["url"].duplicated().sum())
    report["normalized_duplicate_urls"] = int(records["_analysis_url"].duplicated().sum())
    before = len(records)
    records = records.drop_duplicates("_analysis_url", keep="first").copy()
    report["duplicates_removed"] = int(before - len(records))
    report["rows_after"] = int(len(records))
    report["label_distribution"] = {str(k): int(v) for k, v in records["label"].value_counts().sort_index().items()}
    report["unique_registered_domains"] = int(records["url"].map(get_registered_domain).nunique())
    return records


def _read_phi() -> tuple[pd.DataFrame, dict]:
    frame = pd.read_csv(RAW_PATH, usecols=["URL", "label"], low_memory=False)
    labels = pd.to_numeric(frame["label"], errors="coerce")
    invalid = labels.isna() | ~labels.isin([0, 1])
    report = _empty_report("PhiUSIIL", len(frame))
    report.update({"label_column": "label", "label_semantics_in_source": {"0": "phishing", "1": "legitimate"},
                   "label_mapping_to_vigil": {"source_0": 1, "source_1": 0},
                   "invalid_labels": int(invalid.sum())})
    frame = frame.loc[~invalid, ["URL", "label"]].rename(columns={"URL": "url"})
    # The PhiUSIIL schema uses 1=legitimate and 0=phishing; VIGIL uses the
    # opposite convention, so the conversion is explicit and recorded above.
    frame["label"] = (1 - labels.loc[frame.index]).astype(int)
    frame["source"] = "PhiUSIIL"
    frame["collection_date"] = pd.NA
    return _canonicalize(frame[["url", "label", "source", "collection_date"]], report), report


def _read_feed() -> tuple[pd.DataFrame, dict]:
    with open(FEED_PATH, "r", encoding="utf-8", errors="replace") as stream:
        lines = stream.read().splitlines()
    report = _empty_report("Phishing.Database active", len(lines))
    report["blank_lines"] = int(sum(not line.strip() for line in lines))
    frame = pd.DataFrame({"url": lines, "label": 1, "source": "phishing_database_active", "collection_date": pd.NA})
    return _canonicalize(frame, report), report


def _write_json(path: str, value: dict) -> None:
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, default=str)


def main() -> dict:
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    phi, phi_report = _read_phi()
    feed, feed_report = _read_feed()
    phi_keys, feed_keys = set(phi["_analysis_url"]), set(feed["_analysis_url"])
    overlap_keys = phi_keys & feed_keys
    overlap_rows = feed[feed["_analysis_url"].isin(overlap_keys)].copy()
    feed_unique = feed[~feed["_analysis_url"].isin(phi_keys)].copy()

    def is_holdout(value: str) -> bool:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return int(digest[:8], 16) / 0xFFFFFFFF < EXTERNAL_HOLDOUT_FRACTION

    holdout_mask = feed_unique["_analysis_url"].map(is_holdout)
    external_holdout = feed_unique.loc[holdout_mask].copy()
    feed_training = feed_unique.loc[~holdout_mask].copy()
    training = pd.concat([phi, feed_training], ignore_index=True)

    def finalize(frame: pd.DataFrame) -> pd.DataFrame:
        return frame.drop(columns=["_analysis_url"], errors="ignore")[["url", "label", "source", "collection_date"]]

    finalize(training).to_csv(os.path.join(PROCESSED_DIR, "clean_dataset.csv"), index=False)
    finalize(external_holdout).to_csv(os.path.join(PROCESSED_DIR, "external_validation.csv"), index=False)
    finalize(overlap_rows).to_csv(os.path.join(PROCESSED_DIR, "phishing_database_overlap.csv"), index=False)
    overlap_report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "canonicalization": "feature_extractor.normalize_url + feature_extractor._analysis_url",
        "phiusiil_normalized_unique_urls": len(phi_keys), "feed_normalized_unique_urls": len(feed_keys),
        "cross_source_normalized_overlap_urls": len(overlap_keys),
        "phishing_database_rows_overlapping_phiusiil": int(len(overlap_rows)),
        "phishing_database_unique_rows_after_overlap_removal": int(len(feed_unique)),
        "domain_overlap_count": int(len(set(phi["url"].map(get_registered_domain)) & set(feed["url"].map(get_registered_domain)))),
        "overlap_is_independent_validation": False,
        "notes": "URLs are compared after VIGIL canonicalization; no feed URL was opened or fetched.",
    }
    quality = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {"PhiUSIIL": phi_report, "Phishing.Database active": feed_report},
        "cross_source_overlap_removed_from_feed": int(len(overlap_rows)),
        "feed_rows_reserved_for_external_validation": int(len(external_holdout)),
        "feed_rows_added_to_training": int(len(feed_training)), "final_training_size": int(len(training)),
        "external_validation_size": int(len(external_holdout)),
        "final_training_label_distribution": {str(k): int(v) for k, v in training["label"].value_counts().sort_index().items()},
        "final_training_unique_domains": int(training["url"].map(get_registered_domain).nunique()),
        "external_validation_label_distribution": {str(k): int(v) for k, v in external_holdout["label"].value_counts().sort_index().items()},
        "collection_date_policy": "Null for both sources because no source-supplied retrieval date was provided.",
    }
    _write_json(os.path.join(REPORTS_DIR, "dataset_overlap.json"), overlap_report)
    _write_json(os.path.join(REPORTS_DIR, "dataset_quality.json"), quality)
    _write_json(os.path.join(PROCESSED_DIR, "dataset_summary.json"), quality)
    lines = ["# VIGIL Dataset Preparation Report", "", "This report was generated by `prepare_dataset.py`. URLs were handled as text only; the Phishing.Database feed was not opened, fetched, or browsed.", "", "## Source inspection", "", "| Source | Rows before | Rows after | Invalid URLs | Duplicates removed | Unique registered domains |", "|---|---:|---:|---:|---:|---:|"]
    for item in (phi_report, feed_report):
        lines.append(f"| {item['source']} | {item['rows_before']:,} | {item['rows_after']:,} | {item['invalid_urls']:,} | {item['duplicates_removed']:,} | {item['unique_registered_domains']:,} |")
    lines += ["", "## Label semantics", "", "The repository's PhiUSIIL provenance note (`docs/FINAL_ML_PASS.md`) identifies the source schema as `1 = legitimate`, `0 = phishing`. The preparation step explicitly maps that to VIGIL's `0 = legitimate`, `1 = phishing`; the mapping is recorded in `dataset_quality.json`. Every Phishing.Database row is assigned `1` and marked with source `phishing_database_active`.", "", "## Overlap and role", "", f"After VIGIL canonicalization, {len(overlap_rows):,} Phishing.Database rows overlap PhiUSIIL and are excluded. Of the remaining feed rows, {len(feed_training):,} are added to training and {len(external_holdout):,} are retained as a deterministic external holdout. The holdout is phishing-only, so it cannot estimate false-positive rate.", "", "## Final data", "", f"Training rows: {len(training):,}. External validation rows: {len(external_holdout):,}. Random and registered-domain-aware evaluation splits are performed by the existing training pipeline after this preparation step.", ""]
    with open(os.path.join(ROOT, "docs", "DATASET_REPORT.md"), "w", encoding="utf-8") as stream:
        stream.write("\n".join(lines))
    print(json.dumps(quality, indent=2, default=str))
    return quality


if __name__ == "__main__":
    main()
