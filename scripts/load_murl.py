"""Reproducibly prepare a local MURL download for optional external evaluation.

This script intentionally does not download data. The caller supplies the
Mendeley CSV or ZIP so the downloaded artifact and checksum remain auditable.
Only the binary-compatible classes are retained by default: Benign/Legitimate
-> 0 and Phishing -> 1. Other MURL classes are reported and excluded rather
than silently relabelled as phishing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

import pandas as pd

LABELS = {"benign": 0, "legitimate": 0, "phishing": 1}


def _read(path: Path) -> pd.DataFrame:
    if path.suffix.lower() != ".zip":
        return pd.read_csv(path)
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if n.lower().endswith((".csv", ".tsv"))]
        if not names:
            raise ValueError("MURL archive contains no CSV/TSV file")
        with archive.open(names[0]) as stream:
            return pd.read_csv(stream, sep="\t" if names[0].lower().endswith(".tsv") else ",")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, default=Path("data/external/murl_binary.csv"))
    args = parser.parse_args()
    df = _read(args.input)
    df.columns = [str(c).strip().lower() for c in df.columns]
    url_col = next((c for c in df.columns if "url" in c), None)
    label_col = next((c for c in df.columns if c in {"label", "class", "type", "category", "status"}), None)
    if not url_col or not label_col:
        raise ValueError(f"Could not identify URL/label columns: {list(df.columns)}")
    labels = df[label_col].astype(str).str.strip().str.lower()
    report = {"input": str(args.input), "sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(), "raw_rows": int(len(df)), "raw_classes": labels.value_counts().to_dict()}
    out = pd.DataFrame({"url": df[url_col].astype(str).str.strip(), "label": labels.map(LABELS)})
    out = out.dropna(subset=["url", "label"])
    out = out[out.url.ne("")].drop_duplicates(subset=["url"])
    out["label"] = out["label"].astype(int)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output, index=False)
    report.update({"retained_rows": int(len(out)), "retained_classes": out.label.value_counts().to_dict(), "excluded_rows": int(report["raw_rows"] - len(out)), "output": str(args.output), "mapping": LABELS, "excluded_classes": sorted(set(labels) - set(LABELS))})
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
