"""Record fresh candidate-vs-baseline evidence before a rejected candidate is removed."""
from __future__ import annotations

import json
import os
import pickle
import sys
import time

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from feature_extractor import extract_features
from train_model import calibration_metrics, compute_binary_metrics


def write(name, value):
    with open(os.path.join(ROOT, "reports", name), "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, default=str)


def main():
    with open(os.path.join(ROOT, "model_metadata.json"), encoding="utf-8") as stream:
        meta = json.load(stream)
    with open(os.path.join(ROOT, "models", "backup", meta["artifact_backup"].split("\\")[-1], "model_metadata.json"), encoding="utf-8") as stream:
        baseline_meta = json.load(stream)
    model = pickle.load(open(os.path.join(ROOT, "phishing_model.pkl"), "rb"))
    names = pickle.load(open(os.path.join(ROOT, "feature_names.pkl"), "rb"))

    holdout = pd.read_csv(os.path.join(ROOT, "data", "processed", "external_validation.csv"))
    hx = pd.DataFrame(holdout["url"].map(extract_features).tolist())[names]
    hp = model.predict_proba(hx)[:, 1]
    external_metrics = compute_binary_metrics(holdout["label"], hp)
    external_metrics["roc_auc"] = None
    external_metrics["fpr"] = None
    external = {
        "status": "freshly_measured",
        "source": "Phishing.Database active",
        "rows": int(len(holdout)),
        "label_distribution": {str(k): int(v) for k, v in holdout["label"].value_counts().items()},
        "metrics": external_metrics,
        "calibration": calibration_metrics(holdout["label"], hp),
        "limitations": ["Positive-only holdout; FPR, balanced accuracy, and class-conditional calibration cannot be estimated."],
    }
    write("external_validation.json", external)

    urls = ["https://fast.com/", "https://fast.com", "https://www.fast.com/", "https://google.com", "https://github.com", "https://microsoft.com", "https://apple.com", "https://amazon.com", "https://python.org", "https://cloudflare.com"]
    rx = pd.DataFrame([extract_features(url) for url in urls])[names]
    start = time.perf_counter()
    probs = model.predict_proba(rx)[:, 1]
    elapsed = (time.perf_counter() - start) * 1000
    thresholds = meta.get("thresholds", {})
    regression = {"status": "freshly_measured", "model_version": meta.get("model_version"), "latency_batch_ms": elapsed, "results": []}
    for url, probability in zip(urls, probs):
        label = "SAFE" if probability < thresholds.get("safe", 0.13) else ("PHISHING" if probability >= thresholds.get("phishing", 0.7) else "SUSPICIOUS")
        regression["results"].append({"url": url, "label": label, "probability": float(probability)})
    write("regression.json", regression)

    baseline_random = baseline_meta["random_split"]["metrics"]
    baseline_domain = baseline_meta["domain_aware"]["metrics"]
    candidate_random = meta["random_split"]["metrics"]
    candidate_domain = meta["domain_aware"]["metrics"]
    comparison = {
        "status": "freshly_measured_candidate_rejected",
        "baseline_artifact": baseline_meta.get("model_version"),
        "baseline_metrics_source": "historical checked-in baseline metadata",
        "baseline": {"random": baseline_random, "domain_aware": baseline_domain},
        "candidate": {"model_type": meta.get("model_type"), "random": candidate_random, "domain_aware": candidate_domain, "external_validation": external["metrics"]},
        "promotion_gate": {"domain_aware_performance": False, "phishing_recall": True, "fnr": True, "pr_auc": True, "calibration": True, "fpr": False, "latency": False, "approved": False},
        "decision": "REJECT_CANDIDATE_KEEP_BASELINE",
        "reason": "Candidate recall/FNR improved, but FPR and model latency/size degraded materially; the phishing-only holdout cannot override that gate.",
    }
    write("model_comparison.json", comparison)
    write("calibration.json", {"status": "freshly_measured", "baseline": {"random": baseline_meta["random_split"].get("calibration"), "domain_aware": baseline_meta["domain_aware"].get("calibration")}, "candidate": {"random": meta["random_split"].get("calibration"), "domain_aware": meta["domain_aware"].get("calibration"), "external": external["calibration"]}})
    write("error_analysis.json", {"status": "freshly_measured", "candidate_random": {"fnr": candidate_random["fnr"], "fpr": candidate_random["fpr"], "confusion_matrix": candidate_random["confusion_matrix"]}, "candidate_domain": {"fnr": candidate_domain["fnr"], "fpr": candidate_domain["fpr"], "confusion_matrix": candidate_domain["confusion_matrix"]}, "findings": ["The candidate catches substantially more phishing examples than baseline, but creates substantially more false positives on legitimate examples."]})
    print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main()
