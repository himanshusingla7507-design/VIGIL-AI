"""Minimal evaluation script for the VIGIL URL model."""

from __future__ import annotations

import json
import hashlib
import os
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

from feature_extractor import extract_features
from service import load_model_bundle
from train_model import calibration_metrics, compute_binary_metrics

ROOT = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(ROOT, "data", "processed", "clean_dataset.csv")
REPORT_PATH = os.path.join(ROOT, "reports", "metrics.json")


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    if not os.path.exists(DATASET):
        raise FileNotFoundError(f"Dataset not found: {DATASET}. Run prepare_dataset.py first.")

    model, names, metadata = load_model_bundle()
    dataset_hash = _sha256(DATASET)
    if metadata.get("dataset", {}).get("sha256") != dataset_hash:
        report = {
            "evaluation_status": "blocked_model_dataset_mismatch",
            "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "dataset_sha256": dataset_hash,
            "model_dataset_sha256": metadata.get("dataset", {}).get("sha256"),
            "reason": "The rejected candidate dataset is retained for audit, while the production baseline was intentionally restored. No mixed-dataset holdout metrics are reported.",
        }
        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report
    df = pd.read_csv(DATASET)
    features = pd.DataFrame(df["url"].map(extract_features).tolist())
    y = df["label"].astype(int).reset_index(drop=True)
    feature_hash = _sha256(os.path.join(ROOT, "feature_extractor.py"))
    if metadata.get("feature_extractor_sha256") != feature_hash:
        raise RuntimeError("The saved model does not identify this feature extractor; refusing to report holdout metrics.")

    split = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    _, test_idx = next(split.split(features, y))
    X_test = features.iloc[test_idx][names]
    y_test = y.iloc[test_idx].to_numpy()
    probabilities = np.asarray(model.predict_proba(X_test)[:, 1], dtype=float)
    report = {
        "evaluation_status": "freshly_executed_untouched_random_holdout",
        "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset_sha256": dataset_hash,
        "feature_extractor_sha256": feature_hash,
        "split": {"strategy": "StratifiedShuffleSplit", "random_state": 42, "test_rows": int(len(test_idx))},
        "metrics": compute_binary_metrics(y_test, probabilities),
        "calibration": calibration_metrics(y_test, probabilities),
        "model_version": metadata.get("model_version"),
        "model_type": metadata.get("model_type"),
        "thresholds": metadata.get("thresholds"),
    }

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    main()
