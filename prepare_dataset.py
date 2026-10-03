"""Normalize and clean the repository URL dataset into a reproducible training set."""

from __future__ import annotations

import json
import os
from collections import Counter

import pandas as pd

from feature_extractor import _analysis_url, get_registered_domain, normalize_url

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")

LABEL_MAP = {
    "0": 0,
    "1": 1,
    0: 0,
    1: 1,
    "benign": 0,
    "safe": 0,
    "legitimate": 0,
    "phishing": 1,
    "malicious": 1,
    "fraud": 1,
    "suspicious": 1,
}


def normalize_labels(series: pd.Series) -> pd.Series:
    return series.astype(str).str.strip().str.lower().map(LABEL_MAP)


def prepare_records(df: pd.DataFrame, source_name: str) -> tuple[pd.DataFrame, dict]:
    report = {
        "original_rows": int(len(df)),
        "removed_missing_url": 0,
        "removed_missing_label": 0,
        "removed_invalid_label": 0,
        "removed_invalid_url": 0,
        "removed_duplicate_rows": 0,
        "removed_conflicting_label_rows": 0,
        "exact_duplicate_rows": 0,
        "normalized_duplicate_rows": 0,
        "conflicting_label_groups": 0,
        "cross_source_duplicate_groups": 0,
    }
    df.columns = [str(col).strip().lower() for col in df.columns]
    df = df.loc[:, ~df.columns.astype(str).str.startswith("unnamed")]

    url_col = next((c for c in df.columns if "url" in c), None)
    label_col = next((c for c in df.columns if c in {"label", "class", "type", "status", "target"}), None)
    if url_col is None or label_col is None:
        raise ValueError("Dataset must contain a URL column and a label column.")

    source_col = next((c for c in df.columns if c == "source"), None)
    date_col = next((c for c in df.columns if c in {"collection_date", "collected_at", "date"}), None)
    selected = [url_col, label_col] + ([source_col] if source_col else []) + ([date_col] if date_col else [])
    records = df[selected].copy()
    records = records.rename(columns={url_col: "url", label_col: "label"})
    if source_col:
        records = records.rename(columns={source_col: "source"})
    else:
        records["source"] = f"local_file:{source_name}"
    if date_col:
        records = records.rename(columns={date_col: "collection_date"})
    else:
        records["collection_date"] = pd.NA

    missing_url = records["url"].isna() | records["url"].astype(str).str.strip().eq("")
    report["removed_missing_url"] = int(missing_url.sum())
    records = records.loc[~missing_url].copy()
    records["url"] = records["url"].astype(str).str.strip()

    missing_label = records["label"].isna()
    report["removed_missing_label"] = int(missing_label.sum())
    records = records.loc[~missing_label].copy()
    labels = normalize_labels(records["label"])
    valid = labels.notna()
    report["removed_invalid_label"] = int((~valid).sum())
    records = records.loc[valid].copy()
    records["label"] = labels.loc[valid].astype(int)

    normalized_urls = []
    analysis_urls = []
    keep_rows = []
    for index, row in records.iterrows():
        try:
            normalized_url = normalize_url(row["url"])
            analysis_url = _analysis_url(normalized_url)
        except (TypeError, ValueError):
            report["removed_invalid_url"] += 1
            continue
        normalized_urls.append(normalized_url)
        analysis_urls.append(analysis_url)
        keep_rows.append(index)
    records = records.loc[keep_rows].copy()
    records["url"] = normalized_urls
    records["_normalized_url"] = analysis_urls

    report["exact_duplicate_rows"] = int(records["url"].duplicated().sum())
    report["normalized_duplicate_rows"] = int(records["_normalized_url"].duplicated().sum())
    report["cross_source_duplicate_groups"] = int(
        records.groupby("_normalized_url")["source"].nunique().gt(1).sum()
    )

    conflict_groups = records.groupby("_normalized_url")["label"].nunique().loc[lambda s: s > 1]
    conflict_urls = conflict_groups.index
    report["conflicting_label_groups"] = int(len(conflict_groups))
    conflicting = records["_normalized_url"].isin(conflict_urls)
    report["removed_conflicting_label_rows"] = int(conflicting.sum())
    records = records.loc[~conflicting].copy()
    before_deduplication = len(records)
    records = records.drop_duplicates(subset=["_normalized_url"], keep="first").copy()
    report["removed_duplicate_rows"] = before_deduplication - len(records)
    records["source_row"] = records.index.astype(int)
    report["rows_after_cleaning"] = int(len(records))
    report["class_distribution"] = {
        str(label): int(count) for label, count in sorted(Counter(records["label"].tolist()).items())
    }
    report["source_distribution"] = {
        str(source): int(count) for source, count in records["source"].fillna("unknown").value_counts().items()
    }
    report["unique_registered_domains"] = int(records["url"].map(get_registered_domain).nunique())
    records = records.drop(columns=["_normalized_url"])
    return records[["url", "label", "source", "collection_date", "source_row"]], report


def main() -> None:
    dataset_path = os.path.join(ROOT, "final_dataset_v2.csv")
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Expected dataset at {dataset_path}")

    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    df = pd.read_csv(dataset_path)
    records, report = prepare_records(df, os.path.basename(dataset_path))

    output_path = os.path.join(PROCESSED_DIR, "clean_dataset.csv")
    records.to_csv(output_path, index=False)

    report["source_file"] = os.path.basename(dataset_path)
    report["source_provenance"] = "The input CSV has no upstream source or collection-date fields."
    report["output_file"] = output_path
    with open(os.path.join(PROCESSED_DIR, "dataset_summary.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    main()
