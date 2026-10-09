"""Train the production URL model from the domain-disjoint real-world corpus.

The old model was trained on a corpus where URL paths/queries were almost a
proxy for the phishing label.  This script keeps the serving feature contract,
but uses the checked-in realworld_v3 corpus, whose train/calibration/validation
/test partitions are registered-domain disjoint and contain both classes.
"""
from __future__ import annotations

import hashlib
import json
import os
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, brier_score_loss, confusion_matrix,
                             precision_score, recall_score, roc_auc_score)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DATA = ROOT / "experiments/auto_ml/realworld_v3/sampled_dataset.csv"
MODEL = ROOT / "phishing_model.pkl"
FEATURES = ROOT / "feature_names.pkl"
METADATA = ROOT / "model_metadata.json"
from feature_extractor import extract_features, FEATURE_NAMES, MODEL_EXCLUDED_FEATURES
from production_model import ProbabilityCalibratedModel

FEATURE_LIST = [x for x in FEATURE_NAMES if x not in MODEL_EXCLUDED_FEATURES]

def features(frame):
    return pd.DataFrame([extract_features(u) for u in frame.url], index=frame.index)[FEATURE_LIST]

def metrics(y, p, threshold):
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, p)),
        "brier_score": float(brier_score_loss(y, p)),
        "fpr": float(fp / max(tn + fp, 1)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }

def select_threshold(y, p, max_fpr=0.015):
    candidates = np.unique(np.r_[np.linspace(0.05, 0.999, 2000), p])
    valid = []
    for t in candidates:
        m = metrics(y, p, float(t))
        if m["fpr"] <= max_fpr:
            valid.append((m["recall"], -m["fpr"], float(t)))
    if not valid:
        raise RuntimeError("no threshold satisfies the validation FPR budget")
    return max(valid)[2]

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()

def main():
    data = pd.read_csv(DATA)
    if set(data.label.unique()) != {0, 1} or set(data.split.unique()) != {"train", "calibration", "validation", "test"}:
        raise RuntimeError("realworld_v3 corpus does not satisfy the four-way two-class contract")
    partitions = {name: data[data.split == name].copy() for name in ["train", "calibration", "validation", "test"]}
    X = {k: features(v) for k, v in partitions.items()}
    y = {k: v.label.to_numpy(dtype=int) for k, v in partitions.items()}

    candidates = {}
    for name, removed in [("full_29", []), ("without_dynamic_lengths", ["URLLength", "PathLength", "QueryLength", "FragmentLength"])]:
        names = [x for x in FEATURE_LIST if x not in removed]
        estimator = HistGradientBoostingClassifier(
            learning_rate=0.05, max_iter=180, max_leaf_nodes=31,
            min_samples_leaf=20, l2_regularization=1.0, random_state=42,
            early_stopping=False,
        )
        estimator.fit(X["train"][names], y["train"])
        raw_cal = estimator.predict_proba(X["calibration"][names])[:, 1]
        calibrator = LogisticRegression(C=1.0, max_iter=2000, random_state=42)
        calibrator.fit(raw_cal.reshape(-1, 1), y["calibration"])
        val_raw = estimator.predict_proba(X["validation"][names])[:, 1]
        val_p = calibrator.predict_proba(val_raw.reshape(-1, 1))[:, 1]
        threshold = select_threshold(y["validation"], val_p)
        candidates[name] = (names, estimator, calibrator, threshold, metrics(y["validation"], val_p, threshold))

    # Selection happens only on validation. The test set is untouched until now.
    selected_name = max(candidates, key=lambda k: (candidates[k][4]["recall"], -candidates[k][4]["fpr"]))
    names, estimator, calibrator, threshold, validation_metrics = candidates[selected_name]
    model = ProbabilityCalibratedModel(estimator, calibrator)
    with MODEL.open("wb") as f: pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
    with FEATURES.open("wb") as f: pickle.dump(names, f, protocol=pickle.HIGHEST_PROTOCOL)

    test_raw = estimator.predict_proba(X["test"][names])[:, 1]
    test_p = calibrator.predict_proba(test_raw.reshape(-1, 1))[:, 1]
    safe = 0.25
    metadata = {
        "model_version": "v3.0.0",
        "model_type": "DomainDisjointCalibratedHistGradientBoosting",
        "training_date": pd.Timestamp.now(tz="UTC").isoformat(),
        "dataset": {"file": str(DATA.relative_to(ROOT)), "rows": int(len(data)), "class_distribution": {str(k): int(v) for k, v in data.label.value_counts().sort_index().items()}, "split_contract": "registered-domain-disjoint train/calibration/validation/test with both labels"},
        "feature_count": len(names), "features": names,
        "excluded_training_features": {x: "excluded from candidate variant to remove URL-structure label confounding" for x in FEATURE_LIST if x not in names},
        "thresholds": {"safe": safe, "phishing": threshold, "selection": "validation recall subject to FPR <= 1.5%; test not used"},
        "validation_metrics": validation_metrics,
        "held_out_test_metrics": metrics(y["test"], test_p, threshold),
        "split_rows": {k: int(len(v)) for k, v in partitions.items()},
        "candidate_selected": selected_name,
    }
    metadata["artifacts"] = {"model_sha256": sha(MODEL), "feature_names_sha256": sha(FEATURES)}
    METADATA.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))

if __name__ == "__main__": main()
