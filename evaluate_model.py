"""Evaluate existing VIGIL artifacts without importing training code."""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score,
                             brier_score_loss, confusion_matrix,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedShuffleSplit

from feature_extractor import extract_features
from service import load_model_bundle

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "data/processed/clean_dataset.csv"
REPORT_PATH = ROOT / "reports/metrics.json"
CANDIDATE = ROOT / "models/experimental/train_model_v2/repair_source_balanced_natural_calibration/candidate_model.pkl"
CANDIDATE_FEATURES = CANDIDATE.with_name("feature_names.json")
CANDIDATE_MANIFEST = CANDIDATE.with_name("training_manifest.json")
CANDIDATE_REPORT = ROOT / "reports/train_model_v2_repair_v2.json"
KNOWN_LEGITIMATE = ["https://chatgpt.com/", "https://www.youtube.com/", "https://gemini.google.com/app?hl=en-IN", "https://mail.google.com/mail/u/0/#inbox", "https://www.netflix.com/browse", "https://www.canva.com/templates", "https://www.instagram.com/accounts/onetap/?lsrc=ci"]
KNOWN_PHISHING = ["https://paypal-login.example.com/verify-account", "http://secure-bank-login.example.com/update-account", "https://chatgpt.com.example.com/verify-login"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()


def binary_metrics(y, probability, threshold=0.5):
    prediction = (probability >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    return {"threshold": float(threshold), "accuracy": float(accuracy_score(y, prediction)), "precision": float(precision_score(y, prediction, zero_division=0)), "recall": float(recall_score(y, prediction, zero_division=0)), "roc_auc": float(roc_auc_score(y, probability)), "pr_auc": float(average_precision_score(y, probability)), "brier_score": float(brier_score_loss(y, probability)), "fpr": float(fp / max(tn + fp, 1)), "fnr": float(fn / max(fn + tp, 1)), "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]}


def calibration_metrics(y, probability, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    ece = 0.0
    reliability = []
    for lower, upper in zip(edges[:-1], edges[1:]):
        mask = (probability >= lower) & ((probability < upper) if upper < 1 else (probability <= upper))
        if not mask.any(): continue
        mean_probability = float(probability[mask].mean()); positive_rate = float(y[mask].mean())
        ece += float(mask.mean()) * abs(mean_probability - positive_rate)
        reliability.append({"lower": float(lower), "upper": float(upper), "count": int(mask.sum()), "mean_probability": mean_probability, "positive_rate": positive_rate})
    return {"expected_calibration_error": float(ece), "reliability_bins": reliability}


def prediction(model, frame, feature_names):
    matrix = pd.DataFrame(frame["url"].map(extract_features).tolist())
    missing = [name for name in feature_names if name not in matrix]
    if missing: raise RuntimeError(f"feature contract missing from extractor: {missing}")
    return np.clip(np.asarray(model.predict_proba(matrix[feature_names])[:, 1], dtype=float), 0.0, 1.0)


def score_urls(model, feature_names, urls):
    probabilities = prediction(model, pd.DataFrame({"url": urls}), feature_names)
    return [{"url": url, "probability": float(probability)} for url, probability in zip(urls, probabilities)]


def candidate_audit():
    audit = {"model_path": str(CANDIDATE), "exists": CANDIDATE.exists()}
    if CANDIDATE.exists(): audit.update({"size_bytes": CANDIDATE.stat().st_size, "modified_at": datetime.fromtimestamp(CANDIDATE.stat().st_mtime, timezone.utc).isoformat(), "sha256": sha256(CANDIDATE)})
    else: audit["missing_reason"] = "The report/manifest reference this artifact, but candidate_model.pkl is absent from the workspace."
    if CANDIDATE_FEATURES.exists(): audit.update({"feature_names_sha256": sha256(CANDIDATE_FEATURES), "feature_names": json.loads(CANDIDATE_FEATURES.read_text(encoding="utf-8"))})
    if CANDIDATE_MANIFEST.exists():
        manifest = json.loads(CANDIDATE_MANIFEST.read_text(encoding="utf-8")); audit["manifest_sha256"] = sha256(CANDIDATE_MANIFEST); audit["manifest"] = {k: manifest.get(k) for k in ("dataset", "features", "split", "calibration", "model")}
    if CANDIDATE_REPORT.exists():
        report = json.loads(CANDIDATE_REPORT.read_text(encoding="utf-8")); outputs = report.get("outputs", {})
        audit.update({"report_generated_at_utc": report.get("generated_at_utc"), "report_candidate_status": report.get("candidate_status"), "report_expected_sha256": outputs.get("candidate_model_sha256"), "report_candidate_path": outputs.get("candidate_model"), "report_model": report.get("model"), "report_split": report.get("split")})
    return audit


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--report", default=str(REPORT_PATH)); args = parser.parse_args()
    if not DATASET.exists(): raise FileNotFoundError(f"Dataset not found: {DATASET}")
    dataset = pd.read_csv(DATASET)
    if not {"url", "label"}.issubset(dataset.columns) or set(dataset["label"].unique()) != {0, 1}: raise RuntimeError(f"Dataset is not a two-class labeled URL dataset: {DATASET}")
    split = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42); _, test_idx = next(split.split(dataset["url"], dataset["label"]))
    test = dataset.iloc[test_idx].reset_index(drop=True); y = test["label"].to_numpy(dtype=int)
    production, production_names, metadata = load_model_bundle(); production_probability = prediction(production, test, production_names)
    thresholds = metadata.get("thresholds", {}); threshold = float(thresholds.get("phishing", 0.5)) if isinstance(thresholds, dict) else 0.5
    production_path = ROOT / "phishing_model.pkl"
    result = {"evaluation_status": "completed_existing_artifacts_only", "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "dataset": {"path": str(DATASET), "sha256": sha256(DATASET), "rows": int(len(dataset)), "test_rows": int(len(test)), "split": "StratifiedShuffleSplit random_state=42 test_size=0.2"}, "candidate_audit": candidate_audit(), "production": {"model_path": str(production_path), "model_sha256": sha256(production_path), "feature_names": production_names, "model_version": metadata.get("model_version"), "model_type": metadata.get("model_type"), "metrics": binary_metrics(y, production_probability, threshold), "calibration": calibration_metrics(y, production_probability), "known_legitimate": score_urls(production, production_names, KNOWN_LEGITIMATE), "known_phishing": score_urls(production, production_names, KNOWN_PHISHING)}, "candidate_evaluation": {"status": "not_run_missing_artifact", "path": str(CANDIDATE)}}
    if CANDIDATE.exists():
        with CANDIDATE.open("rb") as stream: candidate = pickle.load(stream)
        candidate_names = json.loads(CANDIDATE_FEATURES.read_text(encoding="utf-8")); candidate_probability = prediction(candidate, test, candidate_names)
        result["candidate_evaluation"] = {"status": "completed", "metrics": binary_metrics(y, candidate_probability), "calibration": calibration_metrics(y, candidate_probability), "known_legitimate": score_urls(candidate, candidate_names, KNOWN_LEGITIMATE), "known_phishing": score_urls(candidate, candidate_names, KNOWN_PHISHING)}
    report_path = Path(args.report); report_path.parent.mkdir(parents=True, exist_ok=True); report_path.write_text(json.dumps(result, indent=2, allow_nan=False), encoding="utf-8"); print(json.dumps(result, indent=2)); return result


if __name__ == "__main__": main()
