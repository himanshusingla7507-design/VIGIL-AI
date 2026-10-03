import json
import os

import pandas as pd

from prepare_dataset import prepare_records

ROOT = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(ROOT, "final_dataset_v2.csv")
OUT = os.path.join(ROOT, "dataset_audit_report.json")


def main() -> dict:
    if not os.path.isfile(DATASET):
        raise FileNotFoundError(f"Expected dataset at {DATASET}")
    frame = pd.read_csv(DATASET)
    _, report = prepare_records(frame, os.path.basename(DATASET))
    report.update(
        {
            "file": os.path.basename(DATASET),
            "rows_total": report["original_rows"],
            "rows_after_valid_label": report["rows_after_cleaning"],
            "duplicate_exact_urls": report["exact_duplicate_rows"],
            "normalized_duplicate_rows": report["normalized_duplicate_rows"],
            "conflicting_label_rows": report["removed_conflicting_label_rows"],
            "source_provenance": "The input CSV has no upstream source or collection-date fields.",
        }
    )
    with open(OUT, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    main()
