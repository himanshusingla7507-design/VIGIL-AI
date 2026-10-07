"""
VIGIL training pipeline
Uses:
    1. Existing PhiUSIIL data
    2. Existing Phishing.Database training data
    3. Verified legitimate dynamic URLs from:
       data/external/benign_dynamic/legitimate_dynamic_urls.csv

The external phishing-only holdout remains untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import shutil
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from config import MODEL_VERSION, PHISHING_THRESHOLD, SAFE_THRESHOLD
from feature_extractor import (
    MODEL_EXCLUDED_FEATURES,
    extract_features,
    get_registered_domain,
)


# ============================================================
# PATHS
# ============================================================

ROOT = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(
    ROOT,
    "data",
    "processed",
    "clean_dataset.csv",
)

EXTERNAL_PATH = os.path.join(
    ROOT,
    "data",
    "processed",
    "external_validation.csv",
)

DYNAMIC_PATH = os.path.join(
    ROOT,
    "data",
    "external",
    "benign_dynamic",
    "legitimate_dynamic_urls.csv",
)

REPORT_PATH = os.path.join(
    ROOT,
    "reports",
    "dynamic_training_comparison.json",
)

DOC_PATH = os.path.join(
    ROOT,
    "docs",
    "DYNAMIC_TRAINING_COMPARISON.md",
)

SEED = 42


# ============================================================
# LEGITIMATE REGRESSION URLS
# ============================================================

LEGITIMATE_REFERENCES = [
    "https://google.com",
    "https://google.com/search?q=test",
    "https://google.com/search?q=cybersecurity",
    "https://www.google.com/",
    "https://www.google.com/search?q=test",
    "https://www.youtube.com/",
    "https://www.youtube.com/?feature=ytca",
    "https://github.com",
    "https://microsoft.com",
    "https://apple.com",
    "https://amazon.com",
    "https://python.org",
    "https://cloudflare.com",
    "https://fast.com",
    "https://fast.com/",
    "https://www.fast.com/",
    "https://example.com/",
]


# ============================================================
# CALIBRATED MODEL
# ============================================================

class ProbabilityCalibratedModel:

    def __init__(self, estimator, calibrator):
        self.estimator = estimator
        self.calibrator = calibrator
        self.classes_ = np.array([0, 1])

    def predict_proba(self, X):
        raw = self.estimator.predict_proba(X)[:, 1]

        calibrated = self.calibrator.predict_proba(
            np.asarray(raw).reshape(-1, 1)
        )[:, 1]

        return np.column_stack(
            [1.0 - calibrated, calibrated]
        )


# ============================================================
# UTILITIES
# ============================================================

def sha256(path):

    digest = hashlib.sha256()

    with open(path, "rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def atomic_write(path, payload):

    os.makedirs(
        os.path.dirname(path),
        exist_ok=True,
    )

    fd, temporary = tempfile.mkstemp(
        prefix=".vigil-",
        dir=os.path.dirname(path),
    )

    os.close(fd)

    try:

        if isinstance(payload, bytes):

            with open(temporary, "wb") as stream:
                stream.write(payload)

        else:

            with open(
                temporary,
                "w",
                encoding="utf-8",
            ) as stream:
                stream.write(payload)

        os.replace(
            temporary,
            path,
        )

    finally:

        if os.path.exists(temporary):
            os.unlink(temporary)


def backup_artifacts():

    names = [
        "phishing_model.pkl",
        "feature_names.pkl",
        "model_metadata.json",
        "feature_importance.csv",
    ]

    existing = [
        name
        for name in names
        if os.path.isfile(
            os.path.join(ROOT, name)
        )
    ]

    if not existing:
        return None

    destination = os.path.join(
        ROOT,
        "models",
        "backup",
        datetime.now(timezone.utc).strftime(
            "%Y%m%d-%H%M%S"
        ),
    )

    os.makedirs(
        destination,
        exist_ok=False,
    )

    for name in existing:

        shutil.copy2(
            os.path.join(ROOT, name),
            os.path.join(destination, name),
        )

    return os.path.relpath(
        destination,
        ROOT,
    )


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url):

    url = str(url).strip()

    if not url:
        return ""

    if "://" not in url:
        url = "http://" + url

    try:

        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return ""

        port = parsed.port

        netloc = hostname

        if port is not None:

            default_port = (
                (scheme == "http" and port == 80)
                or
                (scheme == "https" and port == 443)
            )

            if not default_port:
                netloc = f"{hostname}:{port}"

        path = parsed.path or "/"

        return (
            f"{scheme}://"
            f"{netloc}"
            f"{path}"
            f"{'?' + parsed.query if parsed.query else ''}"
            f"{'#' + parsed.fragment if parsed.fragment else ''}"
        )

    except Exception:

        return ""


# ============================================================
# LOAD DATA
# ============================================================

def load_training_data():

    if not os.path.isfile(DATASET_PATH):
        raise FileNotFoundError(
            f"Training dataset not found: {DATASET_PATH}"
        )

    print("\nLoading existing VIGIL dataset...")

    base = pd.read_csv(
        DATASET_PATH
    )

    required = {
        "url",
        "label",
        "source",
        "collection_date",
    }

    missing = required - set(base.columns)

    if missing:
        raise ValueError(
            f"Missing columns in clean_dataset.csv: {sorted(missing)}"
        )

    base = base.copy()

    print(
        f"Existing VIGIL rows: {len(base):,}"
    )

    # --------------------------------------------------------
    # Load new verified legitimate dynamic URLs
    # --------------------------------------------------------

    if not os.path.isfile(DYNAMIC_PATH):

        raise FileNotFoundError(
            "\nNew legitimate dynamic URL dataset not found:\n"
            f"{DYNAMIC_PATH}\n"
            "Download/create it before training."
        )

    dynamic = pd.read_csv(
        DYNAMIC_PATH
    )

    if "url" not in dynamic.columns:

        raise ValueError(
            "Dynamic dataset must contain a 'url' column."
        )

    dynamic = dynamic[
        ["url"]
    ].copy()

    dynamic["label"] = 0

    dynamic["source"] = (
        "verified_benign_dynamic"
    )

    dynamic["collection_date"] = None

    print(
        f"New legitimate dynamic rows: "
        f"{len(dynamic):,}"
    )

    # --------------------------------------------------------
    # Normalize URLs
    # --------------------------------------------------------

    base["normalized_url"] = (
        base["url"]
        .map(normalize_url)
    )

    dynamic["normalized_url"] = (
        dynamic["url"]
        .map(normalize_url)
    )

    base = base[
        base["normalized_url"].astype(bool)
    ]

    dynamic = dynamic[
        dynamic["normalized_url"].astype(bool)
    ]

    # Remove internal duplicates
    base = base.drop_duplicates(
        subset=["normalized_url"],
        keep="first",
    )

    dynamic = dynamic.drop_duplicates(
        subset=["normalized_url"],
        keep="first",
    )

    # --------------------------------------------------------
    # Remove dynamic URLs that are already in VIGIL
    # --------------------------------------------------------

    existing_urls = set(
        base["normalized_url"]
    )

    dynamic_before_overlap = len(
        dynamic
    )

    dynamic = dynamic[
        ~dynamic["normalized_url"].isin(
            existing_urls
        )
    ].copy()

    removed_overlap = (
        dynamic_before_overlap
        - len(dynamic)
    )

    # --------------------------------------------------------
    # Protect the external holdout
    # --------------------------------------------------------

    external_urls = set()

    if os.path.isfile(EXTERNAL_PATH):

        external = pd.read_csv(
            EXTERNAL_PATH
        )

        if "url" in external.columns:

            external_urls = set(
                external["url"]
                .map(normalize_url)
                .dropna()
                .astype(str)
            )

    dynamic_before_holdout = len(
        dynamic
    )

    dynamic = dynamic[
        ~dynamic["normalized_url"].isin(
            external_urls
        )
    ].copy()

    removed_holdout = (
        dynamic_before_holdout
        - len(dynamic)
    )

    # --------------------------------------------------------
    # Remove helper column
    # --------------------------------------------------------

    dynamic = dynamic.drop(
        columns=["normalized_url"]
    )

    base = base.drop(
        columns=["normalized_url"]
    )

    # --------------------------------------------------------
    # Combine everything
    # --------------------------------------------------------

    combined = pd.concat(
        [
            base[
                [
                    "url",
                    "label",
                    "source",
                    "collection_date",
                ]
            ],
            dynamic[
                [
                    "url",
                    "label",
                    "source",
                    "collection_date",
                ]
            ],
        ],
        ignore_index=True,
    )

    # Final URL deduplication
    combined = combined.drop_duplicates(
        subset=["url"],
        keep="first",
    ).reset_index(drop=True)

    print(
        f"\nDynamic overlap with existing VIGIL: "
        f"{removed_overlap:,}"
    )

    print(
        f"Dynamic overlap with external holdout: "
        f"{removed_holdout:,}"
    )

    print(
        f"\nFINAL TRAINING CORPUS: "
        f"{len(combined):,}"
    )

    print(
        f"Legitimate: "
        f"{int((combined.label == 0).sum()):,}"
    )

    print(
        f"Phishing: "
        f"{int((combined.label == 1).sum()):,}"
    )

    print("\nSOURCE DISTRIBUTION:")

    print(
        combined["source"]
        .value_counts()
        .to_string()
    )

    return combined


# ============================================================
# LABEL AUDIT
# ============================================================

def assert_labels(frame):

    phi = frame[
        frame.source.astype(str)
        .eq("PhiUSIIL")
    ]

    feed = frame[
        frame.source.astype(str)
        .eq("phishing_database_active")
    ]

    benign = frame[
        frame.source.astype(str)
        .eq("verified_benign_dynamic")
    ]

    assert set(phi.label.unique()) == {
        0,
        1,
    }, (
        "PhiUSIIL must contain both VIGIL classes"
    )

    assert set(feed.label.unique()) == {
        1,
    }, (
        "Phishing.Database must be VIGIL phishing=1"
    )

    assert set(benign.label.unique()) == {
        0,
    }, (
        "Verified dynamic dataset must be VIGIL legitimate=0"
    )

    return {
        "PhiUSIIL": {
            "legitimate": int(
                (phi.label == 0).sum()
            ),
            "phishing": int(
                (phi.label == 1).sum()
            ),
        },

        "phishing_database_active": {
            "legitimate": 0,
            "phishing": int(
                len(feed)
            ),
        },

        "verified_benign_dynamic": {
            "legitimate": int(
                len(benign)
            ),
            "phishing": 0,
        },

        "mapping": [
            "PhiUSIIL source 1 legitimate -> VIGIL 0",
            "PhiUSIIL source 0 phishing -> VIGIL 1",
            "Phishing.Database -> VIGIL 1",
            "Verified dynamic dataset -> VIGIL 0",
        ],
    }


# ============================================================
# FEATURES
# ============================================================

def feature_matrix(frame):

    features = pd.DataFrame(
        frame.url
        .map(extract_features)
        .tolist()
    )

    names = [
        name
        for name in features.columns
        if name not in MODEL_EXCLUDED_FEATURES
    ]

    assert len(names) == 29, (
        f"Expected 29 production features, got {len(names)}"
    )

    return (
        features[names],
        names,
    )


# ============================================================
# METRICS
# ============================================================

def metrics(y, probabilities, threshold=0.5):

    y = np.asarray(
        y,
        dtype=int,
    )

    probabilities = np.asarray(
        probabilities,
        dtype=float,
    )

    predictions = (
        probabilities >= threshold
    )

    tn, fp, fn, tp = confusion_matrix(
        y,
        predictions,
        labels=[0, 1],
    ).ravel()

    return {
        "accuracy": float(
            (tn + tp) / len(y)
        ),

        "precision": float(
            precision_score(
                y,
                predictions,
                zero_division=0,
            )
        ),

        "recall": float(
            recall_score(
                y,
                predictions,
                zero_division=0,
            )
        ),

        "f1": float(
            f1_score(
                y,
                predictions,
                zero_division=0,
            )
        ),

        "roc_auc": float(
            roc_auc_score(
                y,
                probabilities,
            )
        ),

        "pr_auc": float(
            average_precision_score(
                y,
                probabilities,
            )
        ),

        "brier": float(
            brier_score_loss(
                y,
                probabilities,
            )
        ),

        "fpr": float(
            fp / max(fp + tn, 1)
        ),

        "fnr": float(
            fn / max(fn + tp, 1)
        ),

        "confusion_matrix": [
            [
                int(tn),
                int(fp),
            ],
            [
                int(fn),
                int(tp),
            ],
        ],
    }


def calibration_metrics(y, probabilities):

    y = np.asarray(
        y,
        dtype=int,
    )

    probabilities = np.asarray(
        probabilities,
        dtype=float,
    )

    ece = 0.0

    bins = np.linspace(
        0,
        1,
        11,
    )

    reliability = []

    for lower, upper in zip(
        bins[:-1],
        bins[1:],
    ):

        if upper < 1:

            mask = (
                (probabilities >= lower)
                &
                (probabilities < upper)
            )

        else:

            mask = (
                (probabilities >= lower)
                &
                (probabilities <= upper)
            )

        if not mask.any():
            continue

        mean_probability = float(
            probabilities[mask].mean()
        )

        positive_rate = float(
            y[mask].mean()
        )

        ece += (
            float(mask.mean())
            *
            abs(
                mean_probability
                -
                positive_rate
            )
        )

        reliability.append(
            {
                "lower": float(lower),
                "upper": float(upper),
                "count": int(mask.sum()),
                "mean_probability": mean_probability,
                "positive_rate": positive_rate,
            }
        )

    return {
        "expected_calibration_error": float(ece),
        "reliability_bins": reliability,
    }


# ============================================================
# POLICY
# ============================================================

class Thresholds(dict):

    def __getitem__(self, key):

        if key == 0:
            return dict.__getitem__(
                self,
                "safe",
            )

        if key == 1:
            return dict.__getitem__(
                self,
                "phishing",
            )

        return dict.__getitem__(
            self,
            key,
        )


def policy(
    y,
    probabilities,
    thresholds,
):

    y = np.asarray(
        y,
        dtype=int,
    )

    probabilities = np.asarray(
        probabilities,
        dtype=float,
    )

    safe = (
        probabilities
        <
        thresholds["safe"]
    )

    phishing = (
        probabilities
        >=
        thresholds["phishing"]
    )

    benign = y == 0
    phish = y == 1

    return {
        "safe_rate": float(
            safe.mean()
        ),

        "suspicious_rate": float(
            (
                ~safe
                &
                ~phishing
            ).mean()
        ),

        "phishing_rate": float(
            phishing.mean()
        ),

        "false_safe_rate": float(
            safe[phish].mean()
        )
        if phish.any()
        else 0.0,

        "false_phishing_rate": float(
            phishing[benign].mean()
        )
        if benign.any()
        else 0.0,

        "fpr": float(
            phishing[benign].mean()
        )
        if benign.any()
        else 0.0,
    }


def threshold_search(
    y,
    probabilities,
):

    y = np.asarray(
        y,
        dtype=int,
    )

    probabilities = np.asarray(
        probabilities,
        dtype=float,
    )

    positive = probabilities[
        y == 1
    ]

    negative = probabilities[
        y == 0
    ]

    safe_candidates = [
        x
        for x in np.unique(
            np.r_[0.0, positive]
        )
        if np.mean(
            positive < x
        ) <= 0.02
    ]

    phishing_candidates = [
        x
        for x in np.unique(
            np.r_[negative, 1.0]
        )
        if np.mean(
            negative >= x
        ) <= 0.01
    ]

    safe = (
        float(max(safe_candidates))
        if safe_candidates
        else SAFE_THRESHOLD
    )

    phishing = (
        float(min(phishing_candidates))
        if phishing_candidates
        else PHISHING_THRESHOLD
    )

    if phishing <= safe:

        safe = min(
            safe,
            max(
                0.0,
                phishing - 0.05,
            ),
        )

    return Thresholds(
        safe=safe,
        phishing=phishing,
    )


# ============================================================
# MODELS
# ============================================================

def models():

    return {

        "logistic_regression":
            LogisticRegression(
                max_iter=2500,
                class_weight="balanced",
                solver="liblinear",
                random_state=SEED,
            ),

        "random_forest":
            RandomForestClassifier(
                n_estimators=80,
                min_samples_leaf=2,
                min_samples_split=5,
                n_jobs=-1,
                random_state=SEED,
                class_weight="balanced_subsample",
            ),

        "hist_gradient_boosting":
            HistGradientBoostingClassifier(
                learning_rate=0.05,
                max_iter=100,
                max_leaf_nodes=31,
                random_state=SEED,
            ),
    }


# ============================================================
# FIT + CALIBRATION
# ============================================================

def fit_candidate(
    name,
    X_train,
    y_train,
    X_cal,
    y_cal,
    sample_weight,
):

    estimator = models()[name]

    if name == "hist_gradient_boosting":

        estimator.fit(
            X_train,
            y_train,
            sample_weight=sample_weight,
        )

    else:

        estimator.fit(
            X_train,
            y_train,
        )

    raw_calibration = (
        estimator
        .predict_proba(X_cal)[:, 1]
    )

    calibrator = LogisticRegression(
        solver="lbfgs",
        max_iter=1000,
        random_state=SEED,
    )

    calibrator.fit(
        raw_calibration.reshape(-1, 1),
        y_cal,
    )

    return (
        estimator,
        ProbabilityCalibratedModel(
            estimator,
            calibrator,
        ),
    )


# ============================================================
# LATENCY
# ============================================================

def latency(
    model,
    row,
):

    values = []

    for _ in range(40):

        start = time.perf_counter()

        model.predict_proba(row)

        values.append(
            (
                time.perf_counter()
                -
                start
            )
            *
            1000
        )

    return {
        "median_ms": float(
            np.median(values)
        ),

        "p95_ms": float(
            np.percentile(
                values,
                95,
            )
        ),
    }


# ============================================================
# HARD PHISHING COHORTS
# ============================================================

def phishing_cohorts(
    frame,
    probabilities,
    threshold,
):

    parsed = frame.url.map(
        urlsplit
    )

    path = parsed.map(
        lambda value:
        value.path or ""
    )

    masks = {

        "pathless_phishing":
            path.isin(
                ["", "/"]
            ),

        "short_phishing":
            frame.url.str.len()
            <= 60,

        "https_phishing":
            parsed.map(
                lambda value:
                value.scheme.lower()
                == "https"
            ),

        "no_suspicious_token":
            frame.url.map(
                lambda value:
                not bool(
                    extract_features(value)
                    ["HasSuspiciousToken"]
                )
            ),

        "no_suspicious_tld":
            frame.url.map(
                lambda value:
                not bool(
                    extract_features(value)
                    ["HasSuspiciousTLD"]
                )
            ),

        "no_digits":
            frame.url.str.count(
                r"\d"
            ).eq(0),

        "ordinary_looking_domains":
            frame.url.map(
                lambda value:
                not bool(
                    extract_features(value)
                    ["HasSuspiciousToken"]
                    or
                    extract_features(value)
                    ["HasSuspiciousTLD"]
                    or
                    extract_features(value)
                    ["IsDomainIP"]
                )
            ),
    }

    y = frame.label.to_numpy(
        dtype=int
    )

    output = {}

    for name, mask in masks.items():

        selected = (
            np.asarray(mask, bool)
            &
            (y == 1)
        )

        count = int(
            selected.sum()
        )

        missed = int(
            (
                selected
                &
                (
                    probabilities
                    <
                    threshold
                )
            ).sum()
        )

        output[name] = {
            "samples": count,

            "recall": float(
                1
                -
                missed
                /
                max(count, 1)
            ),

            "fnr": float(
                missed
                /
                max(count, 1)
            ),
        }

    return output


# ============================================================
# LEGITIMATE REGRESSION
# ============================================================

def legitimate_references(
    model,
    feature_names,
    thresholds,
):

    X = pd.DataFrame(
        [
            extract_features(url)
            for url in LEGITIMATE_REFERENCES
        ]
    )[feature_names]

    probabilities = (
        model
        .predict_proba(X)[:, 1]
    )

    rows = []

    for url, probability in zip(
        LEGITIMATE_REFERENCES,
        probabilities,
    ):

        verdict = (
            "SAFE"
            if probability < thresholds["safe"]
            else
            (
                "PHISHING"
                if probability >= thresholds["phishing"]
                else "SUSPICIOUS"
            )
        )

        rows.append(
            {
                "url": url,
                "probability": float(
                    probability
                ),
                "verdict": verdict,
            }
        )

    counts = {
        key:
        sum(
            row["verdict"] == key
            for row in rows
        )
        for key in (
            "SAFE",
            "SUSPICIOUS",
            "PHISHING",
        )
    }

    return {
        "results": rows,
        "counts": counts,

        "safe_rate":
            counts["SAFE"]
            /
            len(rows),

        "suspicious_rate":
            counts["SUSPICIOUS"]
            /
            len(rows),

        "phishing_rate":
            counts["PHISHING"]
            /
            len(rows),

        "false_phishing_rate":
            counts["PHISHING"]
            /
            len(rows),

        "fpr":
            counts["PHISHING"]
            /
            len(rows),
    }


# ============================================================
# EXTERNAL HOLDOUT
# ============================================================

def external_evaluation(
    model,
    feature_names,
    thresholds,
):

    holdout = pd.read_csv(
        EXTERNAL_PATH
    )

    assert set(
        holdout.label.unique()
    ) == {1}

    X = pd.DataFrame(
        holdout.url
        .map(extract_features)
        .tolist()
    )[feature_names]

    probabilities = (
        model
        .predict_proba(X)[:, 1]
    )

    return {
        "rows": int(
            len(holdout)
        ),

        "phishing_recall": float(
            np.mean(
                probabilities
                >= thresholds["phishing"]
            )
        ),

        "fnr": float(
            np.mean(
                probabilities
                <
                thresholds["phishing"]
            )
        ),

        "probability_min": float(
            probabilities.min()
        ),

        "probability_median": float(
            np.median(probabilities)
        ),

        "probability_max": float(
            probabilities.max()
        ),

        "fpr": None,

        "statement":
            "External FPR is undefined because "
            "the external holdout contains "
            "phishing URLs only.",
    }


# ============================================================
# SCORE
# ============================================================

def selection_score(metrics_data):

    return (
        0.35
        *
        metrics_data["recall"]
        +
        0.25
        *
        metrics_data["pr_auc"]
        +
        0.20
        *
        metrics_data["f1"]
        -
        0.30
        *
        metrics_data["fpr"]
        -
        0.10
        *
        metrics_data["brier"]
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 72)
    print(
        "VIGIL - OLD + NEW + VERIFIED DYNAMIC URL TRAINING"
    )
    print("=" * 72)

    # --------------------------------------------------------
    # LOAD ALL DATA
    # --------------------------------------------------------

    frame = load_training_data()

    label_audit = assert_labels(
        frame
    )

    # --------------------------------------------------------
    # FEATURES
    # --------------------------------------------------------

    X, names = feature_matrix(
        frame
    )

    y = frame.label.astype(
        int
    ).reset_index(drop=True)

    groups = frame.url.map(
        get_registered_domain
    ).reset_index(drop=True)

    # --------------------------------------------------------
    # DOMAIN-SAFE SPLIT
    # --------------------------------------------------------

    first = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=44,
    )

    fitcal_idx, test_idx = next(
        first.split(
            X,
            y,
            groups,
        )
    )

    second = GroupShuffleSplit(
        n_splits=1,
        test_size=0.25,
        random_state=45,
    )

    fit_rel, threshold_rel = next(
        second.split(
            X.iloc[fitcal_idx],
            y.iloc[fitcal_idx],
            groups.iloc[fitcal_idx],
        )
    )

    fit_idx = fitcal_idx[
        fit_rel
    ]

    threshold_idx = fitcal_idx[
        threshold_rel
    ]

    third = GroupShuffleSplit(
        n_splits=1,
        test_size=0.25,
        random_state=46,
    )

    train_rel, cal_rel = next(
        third.split(
            X.iloc[fit_idx],
            y.iloc[fit_idx],
            groups.iloc[fit_idx],
        )
    )

    train_idx = fit_idx[
        train_rel
    ]

    cal_idx = fit_idx[
        cal_rel
    ]

    domain_sets = [
        set(
            groups.iloc[index]
        )
        for index in (
            train_idx,
            cal_idx,
            threshold_idx,
            test_idx,
        )
    ]

    assert all(
        not (
            domain_sets[i]
            &
            domain_sets[j]
        )
        for i in range(4)
        for j in range(i + 1, 4)
    )

    print(
        "\nDomain overlap: 0"
    )

    print(
        f"Train rows:      {len(train_idx):,}"
    )

    print(
        f"Calibration rows: {len(cal_idx):,}"
    )

    print(
        f"Threshold rows:   {len(threshold_idx):,}"
    )

    print(
        f"Test rows:        {len(test_idx):,}"
    )

    # --------------------------------------------------------
    # BALANCED SAMPLE WEIGHTS FOR HGB
    # --------------------------------------------------------

    train_y = y.iloc[
        train_idx
    ].to_numpy()

    positive_count = max(
        int((train_y == 1).sum()),
        1,
    )

    negative_count = max(
        int((train_y == 0).sum()),
        1,
    )

    # Balanced weighting:
    # minority class gets higher influence.
    #
    # Legitimate URLs are important because false positives
    # are currently VIGIL's biggest real-world problem.

    sample_weight = np.where(
        train_y == 1,
        1.0,
        positive_count
        /
        negative_count,
    )

    print(
        "\nHGB class weights:"
    )

    print(
        f"Phishing weight:   1.0000"
    )

    print(
        f"Legitimate weight: "
        f"{positive_count / negative_count:.4f}"
    )

    # --------------------------------------------------------
    # TRAIN CANDIDATES
    # --------------------------------------------------------

    reports = {}
    fitted = {}

    for name in models():

        print(
            f"\nTraining {name}..."
        )

        started = time.perf_counter()

        estimator, calibrated = fit_candidate(
            name,
            X.iloc[train_idx],
            y.iloc[train_idx],
            X.iloc[cal_idx],
            y.iloc[cal_idx],
            sample_weight,
        )

        threshold_probability = (
            calibrated
            .predict_proba(
                X.iloc[threshold_idx]
            )[:, 1]
        )

        thresholds = threshold_search(
            y.iloc[threshold_idx],
            threshold_probability,
        )

        test_probability = (
            calibrated
            .predict_proba(
                X.iloc[test_idx]
            )[:, 1]
        )

        test_metrics = metrics(
            y.iloc[test_idx],
            test_probability,
        )

        test_metrics[
            "calibration"
        ] = calibration_metrics(
            y.iloc[test_idx],
            test_probability,
        )

        test_metrics[
            "policy"
        ] = policy(
            y.iloc[test_idx],
            test_probability,
            thresholds,
        )

        test_metrics[
            "thresholds"
        ] = thresholds

        test_metrics[
            "hard_cohorts"
        ] = phishing_cohorts(
            frame.iloc[test_idx],
            test_probability,
            thresholds["phishing"],
        )

        test_metrics[
            "latency"
        ] = latency(
            calibrated,
            X.iloc[test_idx].iloc[[0]],
        )

        test_metrics[
            "model_size_bytes"
        ] = len(
            pickle.dumps(
                calibrated,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        )

        test_metrics[
            "fit_seconds"
        ] = (
            time.perf_counter()
            -
            started
        )

        validation_metrics = metrics(
            y.iloc[threshold_idx],
            threshold_probability,
        )

        validation_metrics[
            "selection_score"
        ] = selection_score(
            validation_metrics
        )

        reports[name] = {
            "validation":
                validation_metrics,

            "domain_test":
                test_metrics,
        }

        fitted[name] = calibrated

        print(
            f"{name}: "
            f"Recall={test_metrics['recall']:.4f} "
            f"FNR={test_metrics['fnr']:.4f} "
            f"FPR={test_metrics['fpr']:.4f} "
            f"PR-AUC={test_metrics['pr_auc']:.4f}"
        )

    # --------------------------------------------------------
    # SELECT BEST MODEL
    # --------------------------------------------------------

    selected_name = max(
        reports,
        key=lambda name:
        reports[name]["validation"][
            "selection_score"
        ],
    )

    selected_model = fitted[
        selected_name
    ]

    selected = reports[
        selected_name
    ]["domain_test"]

    thresholds = selected[
        "thresholds"
    ]

    print(
        f"\nSelected candidate: "
        f"{selected_name}"
    )

    # --------------------------------------------------------
    # CURRENT PRODUCTION COMPARISON
    # --------------------------------------------------------

    current_path = os.path.join(
        ROOT,
        "phishing_model.pkl",
    )

    current_model = pickle.load(
        open(
            current_path,
            "rb",
        )
    )

    current_probability = (
        current_model
        .predict_proba(
            X.iloc[test_idx]
        )[:, 1]
    )

    current_metrics = metrics(
        y.iloc[test_idx],
        current_probability,
    )

    current_metrics[
        "policy"
    ] = policy(
        y.iloc[test_idx],
        current_probability,
        {
            "safe":
                SAFE_THRESHOLD,

            "phishing":
                PHISHING_THRESHOLD,
        },
    )

    # --------------------------------------------------------
    # LEGITIMATE REFERENCES
    # --------------------------------------------------------

    references = legitimate_references(
        selected_model,
        names,
        thresholds,
    )

    # --------------------------------------------------------
    # EXTERNAL PHISHING HOLDOUT
    # --------------------------------------------------------

    external = external_evaluation(
        selected_model,
        names,
        thresholds,
    )

    # --------------------------------------------------------
    # PROMOTION GATE
    # --------------------------------------------------------

    phishing_reference_count = (
        references["counts"]["PHISHING"]
    )

    fast_rows = [
        row
        for row in references["results"]
        if "fast.com" in row["url"]
    ]

    fast_pass = all(
        row["verdict"] == "SAFE"
        for row in fast_rows
    )

    legitimate_dynamic_pass = all(
        row["verdict"] != "PHISHING"
        for row in references["results"]
        if any(
            token in row["url"]
            for token in (
                "search?",
                "?feature=",
            )
        )
    )

    promotion_gate = {

        "legitimate_references_no_phishing":
            phishing_reference_count == 0,

        "dynamic_legitimate_no_phishing":
            legitimate_dynamic_pass,

        "fast_com":
            fast_pass,

        "fpr_budget":
            selected["fpr"] <= 0.01,

        "domain_grouped_recall":
            selected["recall"]
            >=
            current_metrics["recall"],

        "external_recall":
            external["phishing_recall"]
            >= 0.9124,

        "calibration":
            selected[
                "calibration"
            ][
                "expected_calibration_error"
            ]
            <= 0.05,
    }

    approved = all(
        promotion_gate.values()
    )

    # --------------------------------------------------------
    # BUILD RESULT
    # --------------------------------------------------------

    final = {

        "decision":
            "PROMOTE"
            if approved
            else
            "DO NOT PROMOTE",

        "selected_model":
            selected_name,

        "training_rows":
            int(len(frame)),

        "legitimate":
            int(
                (y == 0).sum()
            ),

        "phishing":
            int(
                (y == 1).sum()
            ),

        "dynamic_legitimate_rows":
            int(
                (
                    frame.source
                    ==
                    "verified_benign_dynamic"
                ).sum()
            ),

        "label_audit":
            label_audit,

        "domain_split": {
            "train_rows":
                int(len(train_idx)),

            "calibration_rows":
                int(len(cal_idx)),

            "threshold_rows":
                int(len(threshold_idx)),

            "test_rows":
                int(len(test_idx)),

            "overlapping_domains":
                0,
        },

        "candidate_models":
            reports,

        "current_production":
            current_metrics,

        "selected_thresholds":
            thresholds,

        "legitimate_reference":
            references,

        "external_holdout":
            external,

        "promotion_gate":
            promotion_gate,

        "production_artifacts_updated":
            False,
    }

    # --------------------------------------------------------
    # ONLY PROMOTE AFTER ALL GATES PASS
    # --------------------------------------------------------

    if approved:

        backup_path = backup_artifacts()

        final[
            "artifact_backup"
        ] = backup_path

        atomic_write(
            os.path.join(
                ROOT,
                "phishing_model.pkl",
            ),
            pickle.dumps(
                selected_model,
                protocol=pickle.HIGHEST_PROTOCOL,
            ),
        )

        atomic_write(
            os.path.join(
                ROOT,
                "feature_names.pkl",
            ),
            pickle.dumps(
                names,
                protocol=pickle.HIGHEST_PROTOCOL,
            ),
        )

        feature_importance = pd.DataFrame(
            {
                "feature":
                    names,

                "importance_mean":
                    0.0,

                "importance_std":
                    0.0,
            }
        )

        atomic_write(
            os.path.join(
                ROOT,
                "feature_importance.csv",
            ),
            feature_importance.to_csv(
                index=False
            ),
        )

        metadata = {

            "model_version":
                MODEL_VERSION,

            "model_type":
                "Calibrated"
                +
                "".join(
                    x.title()
                    for x
                    in selected_name.split("_")
                ),

            "training_date":
                datetime.now(
                    timezone.utc
                ).isoformat(
                    timespec="seconds"
                ),

            "features":
                names,

            "feature_count":
                len(names),

            "thresholds":
                thresholds,

            "selected_model":
                selected_name,

            "dataset": {

                "base_dataset":
                    os.path.relpath(
                        DATASET_PATH,
                        ROOT,
                    ),

                "dynamic_dataset":
                    os.path.relpath(
                        DYNAMIC_PATH,
                        ROOT,
                    ),

                "rows":
                    int(len(frame)),

                "class_distribution": {
                    str(k):
                        int(v)
                    for k, v
                    in y.value_counts().items()
                },

                "source_distribution": {
                    str(k):
                        int(v)
                    for k, v
                    in frame.source.value_counts().items()
                },
            },

            "domain_grouped_metrics":
                selected,

            "external_validation":
                external,
        }

        atomic_write(
            os.path.join(
                ROOT,
                "model_metadata.json",
            ),
            json.dumps(
                metadata,
                indent=2,
                default=str,
            ),
        )

        final[
            "production_artifacts_updated"
        ] = True

    # --------------------------------------------------------
    # HASHES
    # --------------------------------------------------------

    final[
        "artifact_hashes"
    ] = {
        name:
            sha256(
                os.path.join(
                    ROOT,
                    name,
                )
            )
        for name in (
            "phishing_model.pkl",
            "feature_names.pkl",
            "feature_importance.csv",
        )
    }

    final[
        "generated_at_utc"
    ] = datetime.now(
        timezone.utc
    ).isoformat(
        timespec="seconds"
    )

    # --------------------------------------------------------
    # SAVE REPORT
    # --------------------------------------------------------

    atomic_write(
        REPORT_PATH,
        json.dumps(
            final,
            indent=2,
            default=str,
        ),
    )

    # --------------------------------------------------------
    # SAVE DOC
    # --------------------------------------------------------

    os.makedirs(
        os.path.dirname(DOC_PATH),
        exist_ok=True,
    )

    with open(
        DOC_PATH,
        "w",
        encoding="utf-8",
    ) as stream:

        stream.write(
            "# VIGIL Dynamic URL Training\n\n"
        )

        stream.write(
            f"## {final['decision']}\n\n"
        )

        stream.write(
            f"Selected model: `{selected_name}`\n\n"
        )

        stream.write(
            f"Total training rows: "
            f"**{len(frame):,}**\n\n"
        )

        stream.write(
            f"Legitimate: "
            f"**{int((y == 0).sum()):,}**\n\n"
        )

        stream.write(
            f"Phishing: "
            f"**{int((y == 1).sum()):,}**\n\n"
        )

        stream.write(
            f"Verified dynamic legitimate URLs: "
            f"**{int((frame.source == 'verified_benign_dynamic').sum()):,}**\n\n"
        )

        stream.write(
            "| Model | Recall | FNR | FPR | PR-AUC | F1 | Brier | ECE | Median ms | Size |\n"
        )

        stream.write(
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n"
        )

        for name, report in reports.items():

            m = report[
                "domain_test"
            ]

            stream.write(
                f"| {name} | "
                f"{m['recall']:.4f} | "
                f"{m['fnr']:.4f} | "
                f"{m['fpr']:.4f} | "
                f"{m['pr_auc']:.4f} | "
                f"{m['f1']:.4f} | "
                f"{m['brier']:.4f} | "
                f"{m['calibration']['expected_calibration_error']:.4f} | "
                f"{m['latency']['median_ms']:.3f} | "
                f"{m['model_size_bytes']:,} |\n"
            )

        stream.write(
            "\n## External Holdout\n\n"
        )

        stream.write(
            f"Recall: **{external['phishing_recall']:.4f}**\n\n"
        )

        stream.write(
            f"FNR: **{external['fnr']:.4f}**\n\n"
        )

        stream.write(
            "External FPR is undefined because "
            "the holdout contains phishing URLs only.\n"
        )

    # --------------------------------------------------------
    # FINAL CONSOLE OUTPUT
    # --------------------------------------------------------

    print("\n")
    print("=" * 72)
    print("FINAL TRAINING RESULT")
    print("=" * 72)

    print(
        f"MODEL: {selected_name}"
    )

    print(
        f"Training rows: {len(frame):,}"
    )

    print(
        f"Legitimate: {(y == 0).sum():,}"
    )

    print(
        f"Phishing: {(y == 1).sum():,}"
    )

    print(
        "Verified dynamic legitimate: "
        f"{(frame.source == 'verified_benign_dynamic').sum():,}"
    )

    print(
        f"Domain recall: {selected['recall']:.4f}"
    )

    print(
        f"Domain FNR: {selected['fnr']:.4f}"
    )

    print(
        f"Domain FPR: {selected['fpr']:.4f}"
    )

    print(
        f"External phishing recall: "
        f"{external['phishing_recall']:.4f}"
    )

    print(
        f"External FNR: "
        f"{external['fnr']:.4f}"
    )

    print(
        f"Model size: "
        f"{selected['model_size_bytes']:,} bytes"
    )

    print(
        f"Median latency: "
        f"{selected['latency']['median_ms']:.3f} ms"
    )

    print(
        "\nLEGITIMATE REGRESSION:"
    )

    for row in references[
        "results"
    ]:

        print(
            f"{row['url']}\n"
            f"  {row['verdict']} "
            f"({row['probability']:.6f})"
        )

    print(
        f"\nPRODUCTION ARTIFACTS UPDATED: "
        f"{final['production_artifacts_updated']}"
    )

    print(
        f"FINAL DECISION: "
        f"{final['decision']}"
    )

    print(
        f"\nReport: {REPORT_PATH}"
    )

    return final


if __name__ == "__main__":
    main()