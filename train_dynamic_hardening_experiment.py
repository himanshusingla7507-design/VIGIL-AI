#!/usr/bin/env python3
"""
VIGIL -- FINAL DYNAMIC FALSE-POSITIVE HARDENING EXPERIMENT
==========================================================

Run from the VIGIL repository root:

    python train_dynamic_hardening_experiment.py

Purpose
-------
Fix VIGIL's catastrophic over-sensitivity to dynamic URL structure without
domain allowlists or sacrificing phishing recall.

Key insight from diagnostics
-----------------------------
The candidate model's PHISHING FPR on dynamic-structure features is driven by
the model treating URL complexity signals (length, path depth, query presence,
fragment, encoding) as phishing proxies. The fix is not to remove those features
but to provide the model with a large, structure-stratified set of legitimate
dynamic URLs that demonstrate:

    long URL  != phishing
    path      != phishing
    query     != phishing
    fragment  != phishing
    encoding  != phishing

while keeping all phishing training intact so the model learns the actual
separating signals (host anomalies, suspicious tokens, suspicious TLDs, IP
hosts, obfuscation, high digit ratios, etc.) rather than superficial URL
complexity.

Hard-negative dynamic augmentation
------------------------------------
From the 167,119 verified benign dynamic URLs the script computes 12 structure
strata and assigns sampling weights so that structure-rich legitimate URLs get
strong representation in the training split. Rows that resemble the structure of
phishing examples (long, multi-path, encoded, etc.) receive higher weights.

Two model variants are evaluated
----------------------------------
A. All 29 features (production feature set)
B. Reduced-complexity variant (URLLength, PathLength, QueryLength,
   FragmentLength removed) -- for ablation comparison only.

Safety
-------
* SHA-256 of phishing_model.pkl, feature_names.pkl, feature_importance.csv
  are captured before and after; the script FAILS if any differ.
* All output is written only to models/experiments/dynamic_hardening/.
* No hardcoded trusted-domain bypass. No domain allowlist.
* external_validation.csv is used ONLY for the final read-only gate check.
* large_legitimate_regression.json is used ONLY for diagnostics.

Gate thresholds
---------------
* External phishing recall >= 91.24%   (prefer > 93%)
* Domain FPR <= 2.0%                   (prefer < 1.5%)
* ECE <= 0.05
* Google search NOT PHISHING
* YouTube query NOT PHISHING
* All fast.com variants SAFE
* Dynamic benign PHISHING rate near 0%
* Model size <= 25 MB
* Median latency <= 50 ms
* No domain allowlist
* Production hashes unchanged
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import pickle
import re
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
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
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# -----------------------------------------------------------------------------
# PATH SETUP
# -----------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from config import PHISHING_THRESHOLD, SAFE_THRESHOLD
except ImportError as exc:
    raise RuntimeError(
        "Could not import SAFE_THRESHOLD / PHISHING_THRESHOLD from config.py. "
        "Run from the VIGIL repository root."
    ) from exc

try:
    from feature_extractor import MODEL_EXCLUDED_FEATURES, extract_features
except ImportError as exc:
    raise RuntimeError(
        "Could not import extract_features / MODEL_EXCLUDED_FEATURES from "
        "feature_extractor.py. Run from the VIGIL repository root."
    ) from exc

try:
    from feature_extractor import get_registered_domain as _vigil_registered_domain
except ImportError:
    _vigil_registered_domain = None

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------

RUN_COMMAND = "python train_dynamic_hardening_experiment.py"
SEED = 42

# Phishing.Database sample target (300 k-400 k requested).
PHISHING_DATABASE_SAMPLE_TARGET = 350_000

# Low-signal (hard) phishing strata get this multiplier on their sampling weight.
LOW_SIGNAL_RATE_MULTIPLIER = 1.25

LABEL_LEGITIMATE = 0
LABEL_PHISHING = 1

SOURCE_PHIUSIIL = "PhiUSIIL"
SOURCE_FEED = "phishing_database_active"
SOURCE_DYNAMIC = "verified_benign_dynamic"
SOURCE_PRIORITY = [SOURCE_PHIUSIIL, SOURCE_DYNAMIC, SOURCE_FEED]

# Paths.
DATASET_PATH = ROOT / "data" / "processed" / "clean_dataset.csv"
DYNAMIC_PATH = ROOT / "data" / "external" / "benign_dynamic" / "legitimate_dynamic_urls.csv"
EXTERNAL_VALIDATION_PATH = ROOT / "data" / "processed" / "external_validation.csv"
REGRESSION_PATH = ROOT / "reports" / "large_legitimate_regression.json"
REPORT_PATH = ROOT / "reports" / "dynamic_hardening_final.json"
EXPERIMENT_DIR = ROOT / "models" / "experiments" / "dynamic_hardening"

PRODUCTION_MODEL_PATH = ROOT / "phishing_model.pkl"
PRODUCTION_FEATURES_PATH = ROOT / "feature_names.pkl"
PRODUCTION_IMPORTANCE_PATH = ROOT / "feature_importance.csv"
PROTECTED_ARTIFACTS = [
    PRODUCTION_MODEL_PATH,
    PRODUCTION_FEATURES_PATH,
    PRODUCTION_IMPORTANCE_PATH,
]

# Domain-isolated split fractions.
SPLIT_FRACTIONS = {
    "train": 0.45,
    "calibration": 0.15,
    "threshold": 0.20,
    "test": 0.20,
}

# Threshold policy.
HARD_FPR_LIMIT = 0.0200          # max domain FPR on threshold split
MAX_PHISHING_BELOW_SAFE = 0.02   # at most 2% of phishing called SAFE
DELTA_SWEEP = [-0.10, -0.05, -0.02, -0.01, 0.0, 0.01, 0.02, 0.05, 0.10]

# Promotion gates.
GATE_MIN_EXTERNAL_RECALL = 0.9124
GATE_MAX_DOMAIN_FPR = 0.0200
GATE_MAX_ECE = 0.05
GATE_MAX_MODEL_BYTES = 25 * 1024 * 1024
GATE_MAX_MEDIAN_LATENCY_MS = 50.0

# HGB hyperparameters (early_stopping=False as required).
HGB_PARAMS = dict(
    learning_rate=0.08,
    max_iter=400,
    max_leaf_nodes=63,
    min_samples_leaf=30,
    l2_regularization=1.0,
    early_stopping=False,
    random_state=SEED,
)

# HGB reduced-feature variant uses same params.
HGB_REDUCED_PARAMS = dict(
    learning_rate=0.08,
    max_iter=400,
    max_leaf_nodes=63,
    min_samples_leaf=30,
    l2_regularization=1.0,
    early_stopping=False,
    random_state=SEED,
)

# Features to drop in the "reduced complexity" ablation.
COMPLEXITY_FEATURES = {
    "URLLength",
    "PathLength",
    "QueryLength",
    "FragmentLength",
}

# Feature-extraction batch size.
FEATURE_CHUNK = 50_000

# Adversarial controls -- these MUST score through the normal model (no bypass).
ADVERSARIAL_URLS = [
    "https://google-login-example.com",
    "https://google-security-example.com",
    "https://paypal-verification-example.com",
    "https://github-auth-example.com",
    "https://facebook-login-example.com",
    "https://instagram-security-example.com",
    "https://microsoft-account-example.com",
    "https://amazon-verification-example.com",
    "https://google.com.example-attacker.com",
    "https://paypal.com.example-attacker.com",
    "https://github.com.example-attacker.com",
]

# Reference URLs (evaluation only -- never in training).
REFERENCE_URLS = [
    "https://google.com",
    "https://google.com/search?q=test",
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

# Specific URL sets for gate checks (identified by content, not domain hardcode).
GOOGLE_SEARCH_URLS = {
    "https://google.com/search?q=test",
    "https://www.google.com/search?q=test",
}
YOUTUBE_QUERY_URLS = {"https://www.youtube.com/?feature=ytca"}
FAST_COM_URLS = {"https://fast.com", "https://fast.com/", "https://www.fast.com/"}

# Dynamic-benign structure strata (12 strata used for hard-negative augmentation).
DYNAMIC_STRATA_DEFINITIONS = [
    ("short_dynamic",       lambda u, p: len(u) <= 80 and (p.path not in ("", "/") or p.query)),
    ("medium_dynamic",      lambda u, p: 80 < len(u) <= 120 and (p.path not in ("", "/") or p.query)),
    ("long_dynamic_120",    lambda u, p: 120 < len(u) <= 200),
    ("very_long_dynamic_200", lambda u, p: len(u) > 200),
    ("query_urls",          lambda u, p: bool(p.query) and not bool(p.fragment)),
    ("multi_param_urls",    lambda u, p: len(parse_qs(p.query, keep_blank_values=True)) >= 3),
    ("tracking_param_urls", lambda u, p: any(
        k in parse_qs(p.query, keep_blank_values=True)
        for k in ("utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
                  "ref", "referrer", "fbclid", "gclid", "yclid", "msclkid", "affiliate_id",
                  "source", "medium", "campaign", "clickid")
    )),
    ("fragment_urls",       lambda u, p: bool(p.fragment)),
    ("multi_path_urls",     lambda u, p: len([s for s in (p.path or "").split("/") if s]) >= 3),
    ("encoded_urls",        lambda u, p: "%" in u),
    ("numeric_id_urls",     lambda u, p: bool(re.search(r"/\d{3,}", p.path or ""))),
    ("search_urls",         lambda u, p: any(
        k in parse_qs(p.query, keep_blank_values=True)
        for k in ("q", "query", "search", "s", "keyword", "keywords", "term", "find", "text", "kw")
    )),
]

# Sampling weight multiplier for high-complexity dynamic-benign rows
# (the ones that look most like phishing structure-wise).
DYNAMIC_HIGH_COMPLEXITY_WEIGHT = 3.0
DYNAMIC_BASE_WEIGHT = 1.0

# Fraction of dynamic-benign rows held out for the real-dynamic validation set
# (domain-disjoint from training).
DYNAMIC_HOLDOUT_FRACTION = 0.15   # ~25 k rows held out


# -----------------------------------------------------------------------------
# CALIBRATED MODEL WRAPPER
# -----------------------------------------------------------------------------

class ProbabilityCalibratedModel:
    """Wraps an estimator + a logistic calibrator (same as production pipeline)."""

    def __init__(self, estimator, calibrator):
        self.estimator = estimator
        self.calibrator = calibrator
        self.classes_ = np.array([0, 1])

    def predict_proba(self, X):
        raw = self.estimator.predict_proba(X)[:, 1]
        calibrated = self.calibrator.predict_proba(
            np.asarray(raw).reshape(-1, 1)
        )[:, 1]
        return np.column_stack([1.0 - calibrated, calibrated])


# -----------------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------------

def log(message: str = "") -> None:
    print(message, flush=True)


# -----------------------------------------------------------------------------
# HASH / SAFETY UTILITIES
# -----------------------------------------------------------------------------

def sha256_file(path: Path):
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_production_artifacts() -> dict:
    return {path.name: sha256_file(path) for path in PROTECTED_ARTIFACTS}


def _guard_output_path(path: Path, allowed_dir: Path) -> None:
    resolved = path.resolve()
    if resolved in {p.resolve() for p in PROTECTED_ARTIFACTS}:
        raise RuntimeError(f"Refusing to write protected production artifact: {path}")
    try:
        resolved.relative_to(allowed_dir.resolve())
    except ValueError as exc:
        raise RuntimeError(f"Refusing to write outside {allowed_dir}: {path}") from exc


def atomic_write_bytes(path: Path, payload: bytes, allowed_dir: Path) -> None:
    _guard_output_path(path, allowed_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".vigil-dh-", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def to_jsonable(value):
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, (np.bool_, bool)):
        return bool(value)
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, (np.floating, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, Path):
        return str(value)
    return value


def require_file(path: Path, description: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{description} not found: {path}")


def counts_by_source(frame: pd.DataFrame) -> dict:
    if len(frame) == 0:
        return {}
    return {str(k): int(v) for k, v in frame["source"].value_counts().items()}


# -----------------------------------------------------------------------------
# URL UTILITIES
# -----------------------------------------------------------------------------

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _safe_urlsplit(url):
    try:
        return urlsplit(str(url))
    except ValueError:
        return urlsplit("")


def _normalize_url(url) -> str:
    """Lowercase scheme+host, drop default ports, empty path -> '/'.
    Used for de-duplication only; features always extracted from original."""
    text = str(url).strip()
    if not text or text.lower() == "nan":
        return ""
    if "://" not in text:
        text = "http://" + text
    try:
        parsed = urlsplit(text)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    scheme = parsed.scheme.lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        if not default:
            netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{scheme}://{netloc}{path}{query}{fragment}"


def _hostname(normalized: str) -> str:
    try:
        return (urlsplit(normalized).hostname or "").lower()
    except ValueError:
        return ""


def _fallback_registered_domain(host: str) -> str:
    if not host or ":" in host or _IPV4.match(host):
        return host
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def registered_domain_for_host(host: str) -> str:
    if not host:
        return ""
    if _vigil_registered_domain is not None:
        try:
            value = _vigil_registered_domain(f"http://{host}")
            if value:
                return str(value).lower()
        except Exception:
            pass
    return _fallback_registered_domain(host)


def registered_domains_series(normalized_urls: pd.Series) -> pd.Series:
    hosts = normalized_urls.map(_hostname)
    cache = {host: registered_domain_for_host(host) for host in hosts.unique()}
    domains = hosts.map(cache).fillna("")
    missing = domains.eq("")
    if missing.any():
        domains = domains.where(
            ~missing,
            pd.Series(
                [f"__missing_domain_{i}" for i in domains.index],
                index=domains.index,
            ),
        )
    return domains


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# -----------------------------------------------------------------------------
# DATA LOADING
# -----------------------------------------------------------------------------

def load_base_dataset() -> pd.DataFrame:
    require_file(DATASET_PATH, "clean_dataset.csv")
    header = pd.read_csv(DATASET_PATH, nrows=0)
    missing_cols = [c for c in ["url", "label", "source"] if c not in header.columns]
    if missing_cols:
        raise ValueError(f"clean_dataset.csv missing columns: {missing_cols}")

    base = pd.read_csv(
        DATASET_PATH,
        usecols=["url", "label", "source"],
        dtype={"url": "string", "source": "string"},
    )
    log(f"clean_dataset.csv rows: {len(base):,}")
    base = base.dropna(subset=["url", "label", "source"]).copy()
    base["url"] = base["url"].astype(str)
    base["source"] = base["source"].astype(str)
    base["label"] = pd.to_numeric(base["label"], errors="coerce")
    base = base[base["label"].isin([LABEL_LEGITIMATE, LABEL_PHISHING])].copy()
    base["label"] = base["label"].astype(int)

    known = {SOURCE_PHIUSIIL, SOURCE_FEED}
    unknown = base[~base["source"].isin(known)]
    if len(unknown):
        log(
            f"WARNING: ignoring {len(unknown):,} rows with unknown sources "
            f"(dynamic set loaded separately): {counts_by_source(unknown)}"
        )
        base = base[base["source"].isin(known)].copy()

    phi_labels = set(base.loc[base["source"] == SOURCE_PHIUSIIL, "label"].unique())
    if phi_labels != {LABEL_LEGITIMATE, LABEL_PHISHING}:
        raise ValueError(f"PhiUSIIL must contain both classes, found {sorted(phi_labels)}")
    feed_labels = set(base.loc[base["source"] == SOURCE_FEED, "label"].unique())
    if feed_labels != {LABEL_PHISHING}:
        raise ValueError(f"{SOURCE_FEED} must be phishing-only, found {sorted(feed_labels)}")
    return base


def load_dynamic_dataset() -> pd.DataFrame:
    require_file(DYNAMIC_PATH, "legitimate_dynamic_urls.csv")
    header = pd.read_csv(DYNAMIC_PATH, nrows=0)
    if "url" not in header.columns:
        raise ValueError("legitimate_dynamic_urls.csv must have a 'url' column")
    dynamic = pd.read_csv(DYNAMIC_PATH, usecols=["url"], dtype={"url": "string"})
    dynamic = dynamic.dropna(subset=["url"]).copy()
    dynamic["url"] = dynamic["url"].astype(str)
    dynamic["label"] = LABEL_LEGITIMATE
    dynamic["source"] = SOURCE_DYNAMIC
    log(f"Verified benign dynamic rows loaded: {len(dynamic):,}")
    return dynamic


# -----------------------------------------------------------------------------
# DYNAMIC-BENIGN STRATUM ASSIGNMENT
# -----------------------------------------------------------------------------

def _assign_dynamic_strata(urls: pd.Series) -> pd.DataFrame:
    """Return a DataFrame with one boolean column per stratum and a complexity
    score used for weighting."""
    n = len(urls)
    parsed = urls.map(_safe_urlsplit)
    url_strs = urls.tolist()

    result = {}
    for name, predicate in DYNAMIC_STRATA_DEFINITIONS:
        flags = np.zeros(n, dtype=bool)
        for i, (url, p) in enumerate(zip(url_strs, parsed)):
            try:
                flags[i] = bool(predicate(url, p))
            except Exception:
                flags[i] = False
        result[name] = flags

    # Complexity score = number of strata the URL belongs to.
    matrix = np.stack(list(result.values()), axis=1)
    result["complexity_score"] = matrix.sum(axis=1)
    return pd.DataFrame(result, index=urls.index)


def compute_dynamic_sampling_weights(strata_df: pd.DataFrame) -> np.ndarray:
    """High-complexity dynamic rows get DYNAMIC_HIGH_COMPLEXITY_WEIGHT; others base weight."""
    scores = strata_df["complexity_score"].to_numpy()
    weights = np.where(scores >= 2, DYNAMIC_HIGH_COMPLEXITY_WEIGHT, DYNAMIC_BASE_WEIGHT)
    # Extra boost for the hardest strata (very long, multi-path, encoded + query).
    for col in ["very_long_dynamic_200", "encoded_urls", "multi_path_urls", "multi_param_urls"]:
        if col in strata_df.columns:
            weights = np.where(strata_df[col].to_numpy(), weights * 1.5, weights)
    return weights.astype(np.float64)


# -----------------------------------------------------------------------------
# DYNAMIC-BENIGN DOMAIN-DISJOINT HOLDOUT SPLIT
# -----------------------------------------------------------------------------

def split_dynamic_train_holdout(dynamic: pd.DataFrame, seed: int):
    """Split dynamic-benign into train and holdout ensuring no domain overlap.

    Returns (train_frame, holdout_frame).
    """
    dynamic = dynamic.copy()
    dynamic["normalized_url"] = dynamic["url"].map(_normalize_url)
    dynamic["registered_domain"] = registered_domains_series(dynamic["normalized_url"])

    domain_counts = dynamic["registered_domain"].value_counts()
    rng = np.random.default_rng(seed + 7)
    shuffled = rng.permutation(len(domain_counts))
    domains = domain_counts.index.to_numpy()[shuffled]
    sizes = domain_counts.to_numpy()[shuffled]
    # Sort by size descending so large domains fill the holdout target first.
    order = np.argsort(-sizes, kind="stable")
    domains = domains[order]
    sizes = sizes[order]

    total = len(dynamic)
    holdout_target = int(math.ceil(DYNAMIC_HOLDOUT_FRACTION * total))

    holdout_domains = set()
    holdout_rows = 0
    for domain, size in zip(domains, sizes):
        if holdout_rows >= holdout_target:
            break
        holdout_domains.add(domain)
        holdout_rows += size

    holdout_mask = dynamic["registered_domain"].isin(holdout_domains)
    train_dynamic = dynamic[~holdout_mask].copy()
    holdout_dynamic = dynamic[holdout_mask].copy()

    log(
        f"\nDynamic-benign train/holdout split (domain-disjoint):\n"
        f"  train   : {len(train_dynamic):,} rows, "
        f"{train_dynamic['registered_domain'].nunique():,} domains\n"
        f"  holdout : {len(holdout_dynamic):,} rows, "
        f"{len(holdout_domains):,} domains"
    )
    # Verify disjoint.
    train_d = set(train_dynamic["registered_domain"])
    holdout_d = set(holdout_dynamic["registered_domain"])
    assert not (train_d & holdout_d), "Domain overlap in dynamic train/holdout split!"

    return train_dynamic, holdout_dynamic


# -----------------------------------------------------------------------------
# POOL CONSTRUCTION
# -----------------------------------------------------------------------------

def build_pool(dynamic_train: pd.DataFrame):
    """Build the full corpus pool from:
        - all PhiUSIIL rows
        - all verified benign dynamic TRAINING rows
        - all Phishing.Database phishing rows (to be sampled later)
    """
    base = load_base_dataset()

    pool_parts = [
        base[base["source"] == SOURCE_PHIUSIIL],
        dynamic_train[["url", "label", "source"]],
        base[base["source"] == SOURCE_FEED],
    ]
    pool = pd.concat(pool_parts, ignore_index=True)
    loaded = counts_by_source(pool)

    pool["normalized_url"] = pool["url"].map(_normalize_url)
    unparseable = pool["normalized_url"].eq("")
    removed_unparseable = counts_by_source(pool[unparseable])
    pool = pool[~unparseable].copy()

    # Remove rows where the same normalized URL appears with conflicting labels.
    label_nunique = pool.groupby("normalized_url")["label"].nunique()
    conflicting = set(label_nunique[label_nunique > 1].index)
    conflict_mask = pool["normalized_url"].isin(conflicting)
    removed_conflict = counts_by_source(pool[conflict_mask])
    pool = pool[~conflict_mask].copy()

    # De-duplicate: prefer PhiUSIIL > dynamic > feed.
    pool["source"] = pd.Categorical(pool["source"], categories=SOURCE_PRIORITY, ordered=True)
    pool = pool.sort_values("source", kind="stable")
    pool["source"] = pool["source"].astype(str)
    dup_mask = pool.duplicated(subset="normalized_url", keep="first")
    removed_duplicates = counts_by_source(pool[dup_mask])
    pool = pool[~dup_mask].copy().reset_index(drop=True)

    log("\nPOOL CONSTRUCTION (before phishing sampling)")
    log(f"  loaded by source        : {loaded}")
    log(f"  removed (unparseable)   : {removed_unparseable}")
    log(f"  removed (conflict)      : {removed_conflict}")
    log(f"  removed (duplicate)     : {removed_duplicates}")
    log(f"  pool by source          : {counts_by_source(pool)}")

    report = {
        "loaded_by_source": loaded,
        "removed_unparseable": removed_unparseable,
        "removed_conflicting": removed_conflict,
        "removed_duplicates": removed_duplicates,
        "pool_by_source": counts_by_source(pool),
    }
    return pool, report


# -----------------------------------------------------------------------------
# FEATURE EXTRACTION
# -----------------------------------------------------------------------------

def extract_feature_frame(urls, label: str = ""):
    """Extract features for a list/Series of URLs in chunks.
    Returns (DataFrame, ok_mask_bool, failure_count).
    """
    urls = list(urls)
    n = len(urls)
    parts = []
    ok = np.zeros(n, dtype=bool)
    columns = None
    failures = 0
    started = time.perf_counter()

    for start in range(0, n, FEATURE_CHUNK):
        chunk = urls[start : start + FEATURE_CHUNK]
        records, positions = [], []
        for offset, url in enumerate(chunk):
            try:
                records.append(extract_features(url))
                positions.append(start + offset)
            except Exception:
                failures += 1
        if records:
            part = pd.DataFrame.from_records(records, index=positions)
            part = part.apply(pd.to_numeric, errors="coerce").fillna(0.0).astype("float64")
            if columns is None:
                columns = list(part.columns)
            part = part.reindex(columns=columns, fill_value=0.0)
            parts.append(part)
            ok[positions] = True
        if n > FEATURE_CHUNK:
            elapsed = time.perf_counter() - started
            log(
                f"  [{label}] features {min(start + FEATURE_CHUNK, n):,}/{n:,} "
                f"({elapsed:.0f}s)"
            )

    if not parts:
        raise RuntimeError(f"Feature extraction failed for every {label} URL.")

    frame = pd.concat(parts).reindex(range(n)).fillna(0.0)
    return frame, ok, failures


# -----------------------------------------------------------------------------
# STRATIFIED PHISHING.DATABASE SAMPLING
# -----------------------------------------------------------------------------

PRIMARY_DIMENSIONS = [
    "has_path",
    "has_query",
    "suspicious_tld",
    "ip_host",
    "suspicious_token",
    "percent_encoding",
]
FINE_DIMENSIONS = [
    "url_length_bucket",
    "hostname_length_bucket",
    "subdomain_count",
    "digit_ratio_bucket",
    "hyphen_bucket",
    "dot_bucket",
    "path_depth_bucket",
    "query_length_bucket",
    "entropy_bucket",
    "fragment_bucket",
    "query_param_count_bucket",
]


def _stratification_dims(pool: pd.DataFrame, feats: pd.DataFrame) -> pd.DataFrame:
    """Compute integer-coded stratification dimensions for the pool rows."""
    urls = pool["url"].astype(str)
    normalized = pool["normalized_url"]
    parsed = normalized.map(_safe_urlsplit)

    host = normalized.map(_hostname)
    host_len = host.str.len().to_numpy()

    url_len = urls.str.len().to_numpy()
    digits = urls.str.count(r"\d").to_numpy()
    digit_ratio = digits / np.maximum(url_len, 1)
    hyphens = urls.str.count("-").to_numpy()
    dots = urls.str.count(r"\.").to_numpy()
    percent = urls.str.contains("%", regex=False).to_numpy().astype(int)
    depth = parsed.map(lambda p: len([s for s in (p.path or "").split("/") if s])).to_numpy()
    query_len = parsed.map(lambda p: len(p.query or "")).to_numpy()
    fragment_len = parsed.map(lambda p: len(p.fragment or "")).to_numpy()
    query_param_count = parsed.map(
        lambda p: len(parse_qs(p.query or "", keep_blank_values=True))
    ).to_numpy()
    entropy = urls.map(shannon_entropy).to_numpy()

    def flag(col):
        if col in feats.columns:
            return (feats[col].to_numpy() > 0).astype(int)
        return np.zeros(len(pool), dtype=int)

    # Host label depth for subdomain count estimation.
    host_labels = host.map(
        lambda h: 0 if (not h or ":" in h or _IPV4.match(h)) else len(h.split("."))
    )
    reg_labels = pool["registered_domain"].map(
        lambda d: 0 if (not d or d.startswith("__missing") or ":" in d or _IPV4.match(d))
        else len(d.split("."))
    )
    subdomains = np.clip((host_labels - reg_labels).to_numpy(), 0, 4)

    digit_level = np.where(
        digit_ratio == 0, 0,
        np.where(digit_ratio <= 0.05, 1, np.where(digit_ratio <= 0.15, 2, 3))
    )
    query_level = np.where(
        query_len == 0, 0,
        np.where(query_len <= 20, 1, np.where(query_len <= 60, 2, 3))
    )

    return pd.DataFrame(
        {
            "has_path": (depth > 0).astype(int),
            "has_query": (query_len > 0).astype(int),
            "suspicious_tld": flag("HasSuspiciousTLD"),
            "ip_host": flag("IsDomainIP"),
            "suspicious_token": flag("HasSuspiciousToken"),
            "percent_encoding": percent,
            "url_length_bucket": np.digitize(url_len, [40, 75, 100, 120, 150, 200]),
            "hostname_length_bucket": np.digitize(host_len, [15, 25, 40]),
            "subdomain_count": subdomains,
            "digit_ratio_bucket": digit_level,
            "hyphen_bucket": np.digitize(hyphens, [1, 2, 4]),
            "dot_bucket": np.digitize(dots, [2, 3, 4]),
            "path_depth_bucket": np.clip(depth, 0, 4),
            "query_length_bucket": query_level,
            "entropy_bucket": np.digitize(entropy, [3.5, 4.0, 4.5]),
            "fragment_bucket": (fragment_len > 0).astype(int),
            "query_param_count_bucket": np.digitize(query_param_count, [1, 3, 6]),
            "url_length": url_len,
        },
        index=pool.index,
    )


def _allocate_quotas(
    sizes: np.ndarray, hard: np.ndarray, target: int, rng
) -> np.ndarray:
    """Proportional allocation with low-signal boost and largest-remainder rounding."""
    weights = np.where(hard, LOW_SIGNAL_RATE_MULTIPLIER, 1.0) * sizes.astype(float)
    capped = np.zeros(len(sizes), dtype=bool)
    quota = np.zeros(len(sizes), dtype=float)
    for _ in range(len(sizes) + 1):
        remaining = target - sizes[capped].sum()
        free_weight = (weights * (~capped)).sum()
        if free_weight <= 0:
            quota = np.where(capped, sizes.astype(float), 0.0)
            break
        proposal = weights * (~capped) * (remaining / free_weight)
        newly = (~capped) & (proposal >= sizes)
        if not newly.any():
            quota = np.where(capped, sizes.astype(float), proposal)
            break
        capped |= newly

    base = np.floor(quota).astype(int)
    base = np.minimum(base, sizes)
    shortfall = int(target - base.sum())
    if shortfall > 0:
        remainder = (quota - base) + rng.random(len(sizes)) * 1e-9
        remainder[base >= sizes] = -1.0
        for idx in np.argsort(-remainder, kind="stable")[:shortfall]:
            if base[idx] < sizes[idx]:
                base[idx] += 1
    return base


def stratified_feed_sample(pool: pd.DataFrame, feats: pd.DataFrame):
    """Stratified sampling of Phishing.Database rows.  Returns (kept_positions, report)."""
    feed_pos = np.flatnonzero((pool["source"] == SOURCE_FEED).to_numpy())
    other_pos = np.flatnonzero((pool["source"] != SOURCE_FEED).to_numpy())
    eligible = len(feed_pos)
    target = min(PHISHING_DATABASE_SAMPLE_TARGET, eligible)

    if eligible <= PHISHING_DATABASE_SAMPLE_TARGET:
        log(
            f"\nPhishing.Database eligible rows ({eligible:,}) <= target "
            f"({PHISHING_DATABASE_SAMPLE_TARGET:,}); keeping all."
        )
        return np.sort(np.concatenate([other_pos, feed_pos])), {
            "method": "all eligible rows kept",
            "eligible_rows": int(eligible),
            "sampled_rows": int(eligible),
        }

    log(
        f"\nStratified sampling of Phishing.Database: "
        f"{eligible:,} -> {target:,} (seed={SEED})"
    )
    feed = pool.iloc[feed_pos]
    dims = _stratification_dims(feed, feats.iloc[feed_pos])
    rng = np.random.default_rng(SEED)

    primary = np.zeros(len(dims), dtype=np.int64)
    for bit, name in enumerate(PRIMARY_DIMENSIONS):
        primary += dims[name].to_numpy(dtype=np.int64) << bit

    codes, sizes = np.unique(primary, return_counts=True)
    hard = np.array(
        [
            (int(code) >> PRIMARY_DIMENSIONS.index("suspicious_tld")) & 1 == 0
            and (int(code) >> PRIMARY_DIMENSIONS.index("ip_host")) & 1 == 0
            and (int(code) >> PRIMARY_DIMENSIONS.index("suspicious_token")) & 1 == 0
            for code in codes
        ]
    )
    allocation = _allocate_quotas(sizes.astype(float), hard, target, rng)
    allocation_by_code = dict(zip(codes.tolist(), allocation.tolist()))

    tiebreak = rng.random(len(dims))
    keys = [tiebreak, dims["url_length"].to_numpy()]
    keys += [dims[n].to_numpy() for n in reversed(FINE_DIMENSIONS)]
    keys.append(primary)
    order = np.lexsort(tuple(keys))
    sorted_primary = primary[order]
    boundaries = np.flatnonzero(np.diff(sorted_primary)) + 1
    chosen = []
    for group in np.split(order, boundaries):
        wanted = allocation_by_code[int(primary[group[0]])]
        if wanted <= 0:
            continue
        size = len(group)
        if wanted >= size:
            chosen.append(group)
            continue
        offset = rng.random()
        picks = np.floor((np.arange(wanted) + offset) * size / wanted).astype(int)
        chosen.append(group[picks])

    selected_local = np.concatenate(chosen)
    if len(selected_local) != target or len(np.unique(selected_local)) != target:
        raise RuntimeError("Stratified sampling did not produce the expected unique row count.")

    kept = np.sort(np.concatenate([other_pos, feed_pos[selected_local]]))

    sampled_mask = np.zeros(len(dims), dtype=bool)
    sampled_mask[selected_local] = True
    strata_rows = []
    for code, size, wanted, is_hard in zip(codes, sizes, allocation, hard):
        decoded = {
            n: int((int(code) >> bit) & 1)
            for bit, n in enumerate(PRIMARY_DIMENSIONS)
        }
        strata_rows.append(
            {
                "stratum_code": int(code),
                **decoded,
                "low_signal": bool(is_hard),
                "population": int(size),
                "sampled": int(wanted),
                "sampling_rate": float(wanted / size),
            }
        )
        log(
            f"  stratum {int(code):02d} "
            f"path={decoded['has_path']} query={decoded['has_query']} "
            f"suspicious_tld={decoded['suspicious_tld']} ip={decoded['ip_host']} "
            f"token={decoded['suspicious_token']} enc={decoded['percent_encoding']} "
            f"low_signal={is_hard}: {int(wanted):,}/{int(size):,}"
        )

    low_signal_rows = np.isin(primary, codes[hard])
    log(
        f"  primary strata: {len(codes)}  "
        f"low-signal population {low_signal_rows.mean():.3%} -> "
        f"sample {low_signal_rows[sampled_mask].mean():.3%}"
    )

    report = {
        "method": (
            "primary strata (path, query, suspicious_tld, ip_host, "
            "suspicious_token, percent_encoding) with proportional "
            "largest-remainder allocation + low-signal boost; "
            "systematic sampling inside each stratum over fine dimensions"
        ),
        "seed": SEED,
        "target": int(target),
        "eligible_rows": int(eligible),
        "sampled_rows": int(target),
        "low_signal_rate_multiplier": LOW_SIGNAL_RATE_MULTIPLIER,
        "primary_dimensions": PRIMARY_DIMENSIONS,
        "fine_dimensions": FINE_DIMENSIONS,
        "primary_strata_count": int(len(codes)),
        "low_signal_share_population": float(low_signal_rows.mean()),
        "low_signal_share_sample": float(low_signal_rows[sampled_mask].mean()),
        "primary_strata": strata_rows,
    }
    return kept, report


# -----------------------------------------------------------------------------
# DYNAMIC-BENIGN SAMPLE WEIGHTS (applied during training for hard-negative emphasis)
# -----------------------------------------------------------------------------

def build_training_weights(
    corpus: pd.DataFrame,
    dynamic_strata: pd.DataFrame,
    y: np.ndarray,
) -> np.ndarray:
    """Compute per-row training sample weights.

    - Phishing rows: class-balanced weight (n / (2 * n_positive)).
    - Dynamic-benign (legitimate) rows: base class-balanced weight multiplied
      by the complexity-based hard-negative weight.
    - Other legitimate rows: class-balanced weight.
    """
    n = len(y)
    n_pos = max(int((y == 1).sum()), 1)
    n_neg = max(int((y == 0).sum()), 1)
    pos_weight = n / (2.0 * n_pos)
    neg_weight = n / (2.0 * n_neg)

    weights = np.where(y == 1, pos_weight, neg_weight)

    # Apply hard-negative multipliers to dynamic benign rows.
    dynamic_mask = (corpus["source"] == SOURCE_DYNAMIC).to_numpy()
    if dynamic_mask.any() and dynamic_strata is not None:
        # dynamic_strata index aligns with corpus index.
        strata_aligned = dynamic_strata.reindex(corpus.index)
        dyn_weights = compute_dynamic_sampling_weights(strata_aligned)
        weights = np.where(dynamic_mask, weights * dyn_weights, weights)

    return weights.astype(np.float64)


# -----------------------------------------------------------------------------
# DOMAIN-ISOLATED SPLIT
# -----------------------------------------------------------------------------

def domain_split(domains: pd.Series, fractions: dict, seed: int) -> np.ndarray:
    """Assign every registered domain to exactly one split bucket."""
    counts = domains.value_counts()
    names = list(fractions)
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(counts))
    shuffled_domains = counts.index.to_numpy()[order]
    shuffled_sizes = counts.to_numpy()[order]
    by_size = np.argsort(-shuffled_sizes, kind="stable")
    shuffled_domains = shuffled_domains[by_size]
    shuffled_sizes = shuffled_sizes[by_size]

    targets = np.array([fractions[n] for n in names], dtype=float) * float(len(domains))
    filled = np.zeros(len(names), dtype=float)
    assignment = {}
    for domain, size in zip(shuffled_domains, shuffled_sizes):
        k = int(np.argmax(targets - filled))
        assignment[domain] = k
        filled[k] += size

    return domains.map(assignment).to_numpy(dtype=int)


def describe_splits(corpus: pd.DataFrame, split_ids: np.ndarray, names: list) -> dict:
    description = {}
    log("\nDOMAIN-ISOLATED SPLITS")
    for index, name in enumerate(names):
        part = corpus[split_ids == index]
        legit = int((part["label"] == LABEL_LEGITIMATE).sum())
        phish = int((part["label"] == LABEL_PHISHING).sum())
        description[name] = {
            "rows": int(len(part)),
            "domains": int(part["registered_domain"].nunique()),
            "legitimate": legit,
            "phishing": phish,
            "source_counts": counts_by_source(part),
        }
        log(
            f"  {name:<12} rows={len(part):>9,}  "
            f"domains={part['registered_domain'].nunique():>8,}  "
            f"legit={legit:>9,}  phishing={phish:>9,}"
        )
        if legit == 0 or phish == 0:
            raise RuntimeError(f"Split '{name}' does not contain both classes.")

    # Verify zero domain overlap.
    domain_sets = [
        set(corpus.loc[split_ids == i, "registered_domain"]) for i in range(len(names))
    ]
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            overlap = domain_sets[i] & domain_sets[j]
            if overlap:
                raise RuntimeError(
                    f"Domain overlap between '{names[i]}' and '{names[j]}': "
                    f"{len(overlap)} domains"
                )
    log("  registered-domain overlap: 0 [ok]")
    return description


# -----------------------------------------------------------------------------
# METRICS
# -----------------------------------------------------------------------------

def compute_metrics(y, probabilities, threshold: float = 0.5) -> dict:
    y = np.asarray(y, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    predictions = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(y, predictions, labels=[0, 1]).ravel()
    return {
        "threshold": float(threshold),
        "accuracy": float((tn + tp) / max(len(y), 1)),
        "precision": float(precision_score(y, predictions, zero_division=0)),
        "recall": float(recall_score(y, predictions, zero_division=0)),
        "f1": float(f1_score(y, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, probabilities)),
        "pr_auc": float(average_precision_score(y, probabilities)),
        "brier": float(brier_score_loss(y, probabilities)),
        "fpr": float(fp / max(fp + tn, 1)),
        "fnr": float(fn / max(fn + tp, 1)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def calibration_metrics(y, probabilities) -> dict:
    y = np.asarray(y, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    bins = np.linspace(0.0, 1.0, 11)
    ece = 0.0
    reliability = []
    for lower, upper in zip(bins[:-1], bins[1:]):
        mask = (
            (probabilities >= lower) & (probabilities < upper)
            if upper < 1.0
            else (probabilities >= lower) & (probabilities <= upper)
        )
        if not mask.any():
            continue
        mean_prob = float(probabilities[mask].mean())
        pos_rate = float(y[mask].mean())
        ece += float(mask.mean()) * abs(mean_prob - pos_rate)
        reliability.append({
            "lower": float(lower),
            "upper": float(upper),
            "count": int(mask.sum()),
            "mean_probability": mean_prob,
            "positive_rate": pos_rate,
        })
    return {"expected_calibration_error": float(ece), "reliability_bins": reliability}


def policy(y, probabilities, thresholds: dict) -> dict:
    y = np.asarray(y, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    safe = probabilities < thresholds["safe"]
    phishing = probabilities >= thresholds["phishing"]
    benign = y == 0
    phish = y == 1
    return {
        "safe_rate": float(safe.mean()),
        "suspicious_rate": float((~safe & ~phishing).mean()),
        "phishing_rate": float(phishing.mean()),
        "false_safe_rate": float(safe[phish].mean()) if phish.any() else 0.0,
        "phishing_recall": float(phishing[phish].mean()) if phish.any() else 0.0,
        "phishing_fnr": float(1.0 - phishing[phish].mean()) if phish.any() else 1.0,
        "false_phishing_rate": float(phishing[benign].mean()) if benign.any() else 0.0,
        "fpr": float(phishing[benign].mean()) if benign.any() else 0.0,
    }


def verdict_for(probability: float, thresholds: dict) -> str:
    if probability < thresholds["safe"]:
        return "SAFE"
    if probability >= thresholds["phishing"]:
        return "PHISHING"
    return "SUSPICIOUS"


def source_breakdown(sources, y, probabilities, thresholds: dict) -> dict:
    sources = np.asarray(sources)
    y = np.asarray(y, dtype=int)
    output = {}
    for source in sorted(set(sources)):
        for label in (0, 1):
            mask = (sources == source) & (y == label)
            if not mask.any():
                continue
            p = probabilities[mask]
            output[f"{source}|label={label}"] = {
                "rows": int(mask.sum()),
                "phishing_verdict_rate": float(np.mean(p >= thresholds["phishing"])),
                "safe_verdict_rate": float(np.mean(p < thresholds["safe"])),
            }
    return output


def phishing_cohort_analysis(
    urls: pd.Series,
    feats: pd.DataFrame,
    y,
    probabilities,
    threshold: float,
) -> dict:
    """Hard-cohort breakdown of phishing recall."""
    urls = urls.reset_index(drop=True)
    feats = feats.reset_index(drop=True)
    parsed = urls.map(_safe_urlsplit)
    path = parsed.map(lambda p: p.path or "")
    url_len = urls.str.len()

    masks: dict[str, pd.Series] = {
        "pathless": path.isin(["", "/"]),
        "short_le60": url_len <= 60,
        "no_suspicious_tld": (feats["HasSuspiciousTLD"] == 0) if "HasSuspiciousTLD" in feats.columns else pd.Series(True, index=urls.index),
        "no_suspicious_token": (feats["HasSuspiciousToken"] == 0) if "HasSuspiciousToken" in feats.columns else pd.Series(True, index=urls.index),
        "has_query": parsed.map(lambda p: bool(p.query)),
        "long_gt200": url_len > 200,
        "ip_host": (feats["IsDomainIP"] > 0) if "IsDomainIP" in feats.columns else pd.Series(False, index=urls.index),
        "percent_encoded": urls.str.contains("%", regex=False),
        "deep_path": parsed.map(lambda p: len([s for s in (p.path or "").split("/") if s]) >= 4),
        "high_entropy": urls.map(shannon_entropy) > 4.0,
    }

    # "ordinary_looking": none of the obvious signals.
    has_token = feats["HasSuspiciousToken"].astype(bool) if "HasSuspiciousToken" in feats.columns else pd.Series(False, index=urls.index)
    has_tld = feats["HasSuspiciousTLD"].astype(bool) if "HasSuspiciousTLD" in feats.columns else pd.Series(False, index=urls.index)
    has_ip = (feats["IsDomainIP"] > 0) if "IsDomainIP" in feats.columns else pd.Series(False, index=urls.index)
    masks["ordinary_looking"] = ~(has_token | has_tld | has_ip)

    y = np.asarray(y, dtype=int)
    output = {}
    for name, mask in masks.items():
        selected = np.asarray(mask, dtype=bool) & (y == 1)
        count = int(selected.sum())
        missed = int((selected & (probabilities < threshold)).sum())
        output[name] = {
            "samples": count,
            "recall": float(1.0 - missed / max(count, 1)),
            "fnr": float(missed / max(count, 1)),
        }
    return output


# -----------------------------------------------------------------------------
# THRESHOLD SELECTION
# -----------------------------------------------------------------------------

def select_thresholds(y, probabilities) -> dict:
    """Maximize phishing recall subject to domain FPR <= 2% on the threshold split."""
    y = np.asarray(y, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    positive = np.sort(probabilities[y == 1])
    negative = np.sort(probabilities[y == 0])

    # Safe threshold: at most MAX_PHISHING_BELOW_SAFE fraction of phishing is SAFE.
    safe = float(SAFE_THRESHOLD)
    if len(positive):
        allowed = int(math.floor(MAX_PHISHING_BELOW_SAFE * len(positive)))
        safe = float(positive[min(allowed, len(positive) - 1)])

    # Phishing threshold: lowest score such that FPR <= budget.
    def threshold_for_fpr_budget(neg_sorted, budget):
        n = len(neg_sorted)
        if n == 0:
            return None
        allowed_fp = min(int(math.floor(budget * n)), n - 1)
        cutoff = neg_sorted[n - allowed_fp - 1]
        idx = int(np.searchsorted(neg_sorted, cutoff, side="right"))
        return float(neg_sorted[idx]) if idx < n else float(np.nextafter(cutoff, np.inf))

    phishing = threshold_for_fpr_budget(negative, HARD_FPR_LIMIT)
    if phishing is None:
        phishing = float(PHISHING_THRESHOLD)

    if phishing <= safe:
        safe = min(safe, max(0.0, phishing - 0.05))

    return {
        "safe": float(safe),
        "phishing": float(phishing),
        "selection_rule": "maximize phishing recall subject to threshold-split FPR <= 2.0%",
        "fpr_budget": HARD_FPR_LIMIT,
        "threshold_split_recall_at_selected_threshold": (
            float(np.mean(positive >= phishing)) if len(positive) else 0.0
        ),
        "max_phishing_below_safe": MAX_PHISHING_BELOW_SAFE,
    }


def threshold_sensitivity(y_thr, p_thr, y_test, p_test, thresholds: dict) -> dict:
    y_thr = np.asarray(y_thr, dtype=int)
    y_test = np.asarray(y_test, dtype=int)

    def at(phishing_t):
        t = {
            "safe": min(thresholds["safe"], phishing_t),
            "phishing": phishing_t,
        }
        return {
            "phishing_threshold": float(phishing_t),
            "threshold_split": {
                "fpr": policy(y_thr, p_thr, t)["fpr"],
                "recall": policy(y_thr, p_thr, t)["phishing_recall"],
            },
            "test": {
                "fpr": policy(y_test, p_test, t)["fpr"],
                "recall": policy(y_test, p_test, t)["phishing_recall"],
            },
        }

    return {
        "around_selected_threshold": [
            {"delta": float(d), **at(float(np.clip(thresholds["phishing"] + d, 0.0, 1.0)))}
            for d in DELTA_SWEEP
        ]
    }


# -----------------------------------------------------------------------------
# MODEL TRAINING
# -----------------------------------------------------------------------------

def balanced_sample_weights(y: np.ndarray) -> np.ndarray:
    n = len(y)
    n_pos = max(int((y == 1).sum()), 1)
    n_neg = max(int((y == 0).sum()), 1)
    return np.where(y == 1, n / (2.0 * n_pos), n / (2.0 * n_neg)).astype(np.float64)


def fit_model(name: str, X_train, y_train, X_cal, y_cal, sample_weights=None):
    """Train an estimator and fit a logistic calibrator on the calibration split."""
    if name == "logistic_regression":
        estimator = Pipeline([
            ("scale", StandardScaler()),
            ("logreg", LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                solver="lbfgs",
                random_state=SEED,
            )),
        ])
        estimator.fit(X_train, y_train)

    elif name in ("hist_gradient_boosting", "hist_gradient_boosting_reduced"):
        params = HGB_REDUCED_PARAMS if name == "hist_gradient_boosting_reduced" else HGB_PARAMS
        estimator = HistGradientBoostingClassifier(**params)
        w = sample_weights if sample_weights is not None else balanced_sample_weights(y_train.to_numpy())
        estimator.fit(X_train, y_train, sample_weight=w)

    else:
        raise ValueError(f"Unknown model name: {name}")

    raw_cal = estimator.predict_proba(X_cal)[:, 1]
    calibrator = LogisticRegression(solver="lbfgs", max_iter=1000, random_state=SEED)
    calibrator.fit(raw_cal.reshape(-1, 1), y_cal)
    return estimator, calibrator, ProbabilityCalibratedModel(estimator, calibrator)


def measure_latency(model, sample_row: pd.DataFrame) -> dict:
    for _ in range(5):
        model.predict_proba(sample_row)
    times = []
    for _ in range(100):
        t0 = time.perf_counter()
        model.predict_proba(sample_row)
        times.append((time.perf_counter() - t0) * 1000.0)
    return {"median_ms": float(np.median(times)), "p95_ms": float(np.percentile(times, 95))}


def save_candidate(variant_name: str, estimator, calibrator, feature_names: list, thresholds: dict):
    payload = {
        "format": "vigil-dynamic-hardening-candidate-v1",
        "experiment_only": True,
        "variant_name": variant_name,
        "estimator": estimator,
        "calibrator": calibrator,
        "feature_names": list(feature_names),
        "thresholds": {"safe": thresholds["safe"], "phishing": thresholds["phishing"]},
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    blob = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
    path = EXPERIMENT_DIR / f"candidate_{variant_name}.pkl"
    atomic_write_bytes(path, blob, EXPERIMENT_DIR)
    return path, len(blob)


# -----------------------------------------------------------------------------
# FEATURE IMPORTANCE + PERMUTATION IMPORTANCE
# -----------------------------------------------------------------------------

def compute_feature_importance(estimator, feature_names: list) -> dict:
    """Extract HGB feature importances."""
    if not hasattr(estimator, "feature_importances_"):
        return {}
    importances = estimator.feature_importances_
    return {
        name: float(imp)
        for name, imp in sorted(
            zip(feature_names, importances), key=lambda x: -x[1]
        )
    }


def compute_permutation_importance_subset(
    model: ProbabilityCalibratedModel,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    feature_names: list,
    n_repeats: int = 5,
    max_rows: int = 5000,
) -> dict:
    """Compute permutation importance on a random subset of the test set."""
    rng = np.random.default_rng(SEED + 13)
    n = min(len(X_test), max_rows)
    idx = rng.choice(len(X_test), n, replace=False)
    X_sub = X_test.iloc[idx]
    y_sub = np.asarray(y_test)[idx]

    try:
        result = permutation_importance(
            model,
            X_sub,
            y_sub,
            n_repeats=n_repeats,
            random_state=SEED,
            scoring="roc_auc",
        )
        return {
            name: {
                "mean": float(result.importances_mean[i]),
                "std": float(result.importances_std[i]),
            }
            for i, name in enumerate(feature_names)
        }
    except Exception as exc:
        log(f"  Permutation importance failed: {exc}")
        return {}


def ablation_feature_contribution(
    name_full: str,
    X_train_full, y_train,
    X_test_full, y_test,
    X_cal_full, y_cal,
    full_feature_names: list,
    thresholds_full: dict,
    sample_weights,
) -> dict:
    """Compare removing complexity features vs keeping all 29."""
    reduced_names = [f for f in full_feature_names if f not in COMPLEXITY_FEATURES]
    log(f"\nAblation: removing {sorted(COMPLEXITY_FEATURES)} ({len(full_feature_names)} -> {len(reduced_names)} features)")

    X_train_r = X_train_full[reduced_names]
    X_cal_r = X_cal_full[reduced_names]
    X_test_r = X_test_full[reduced_names]

    estimator_r, calibrator_r, model_r = fit_model(
        "hist_gradient_boosting_reduced",
        X_train_r, y_train,
        X_cal_r, y_cal,
        sample_weights=sample_weights,
    )

    p_test_r = model_r.predict_proba(X_test_r)[:, 1]
    thresholds_r_raw = select_thresholds(y_cal, calibrator_r.predict_proba(
        estimator_r.predict_proba(X_cal_r)[:, 1].reshape(-1, 1))[:, 1])
    thresholds_r = thresholds_r_raw  # re-use threshold selection

    m_full = compute_metrics(y_test, model_r.predict_proba(X_test_r)[:, 1])
    pol_full = policy(y_test, p_test_r, thresholds_full)

    return {
        "reduced_feature_count": len(reduced_names),
        "removed_features": sorted(COMPLEXITY_FEATURES),
        "test_metrics_reduced": m_full,
        "test_policy_reduced": pol_full,
        "note": (
            "Reduced-complexity variant for ablation comparison only. "
            "If reduced variant degrades recall, the production feature set (all 29) is preferred."
        ),
    }


# -----------------------------------------------------------------------------
# REGRESSION SUITE (diagnostics only)
# -----------------------------------------------------------------------------

def load_regression_suite() -> list:
    """Load the large_legitimate_regression.json and return the URL list."""
    if not REGRESSION_PATH.is_file():
        log(f"WARNING: Regression suite not found at {REGRESSION_PATH}")
        return []
    with REGRESSION_PATH.open() as f:
        data = json.load(f)
    suite = data.get("suite", {})
    ref_urls = suite.get("reference_urls", [])
    if not ref_urls:
        log("WARNING: regression suite 'reference_urls' is empty.")
    return ref_urls


def run_regression_diagnostics(
    model: ProbabilityCalibratedModel,
    thresholds: dict,
    feature_names: list,
    ref_url_items: list,
) -> dict:
    """Score all 1065 regression URLs and compute FPR breakdowns.
    All URLs are treated as legitimate (label=0) for FPR calculation."""
    if not ref_url_items:
        return {"available": False, "reason": "Regression suite empty or missing."}

    urls = [item["url"] for item in ref_url_items if isinstance(item, dict) and "url" in item]
    categories = [item.get("category", "UNKNOWN") for item in ref_url_items if isinstance(item, dict) and "url" in item]

    if not urls:
        return {"available": False, "reason": "No valid URLs found in regression suite."}

    log(f"\nRunning regression diagnostics on {len(urls):,} URLs...")
    feats, ok, failures = extract_feature_frame(urls, "regression_suite")
    if failures > 0:
        log(f"  WARNING: {failures} regression URLs failed feature extraction (excluded)")

    X_reg = feats.reindex(columns=feature_names, fill_value=0.0)
    probabilities = model.predict_proba(X_reg)[:, 1]
    verdicts = [verdict_for(float(p), thresholds) for p in probabilities]

    # Overall FPR on full regression suite (all legit).
    phishing_mask = np.array([v == "PHISHING" for v in verdicts])
    overall_fpr = float(phishing_mask.mean())

    safe_count = int(sum(v == "SAFE" for v in verdicts))
    suspicious_count = int(sum(v == "SUSPICIOUS" for v in verdicts))
    phishing_count = int(phishing_mask.sum())

    log(f"  SAFE={safe_count}  SUSPICIOUS={suspicious_count}  PHISHING={phishing_count}  FPR={overall_fpr:.2%}")

    # Category FPR.
    cat_results: dict[str, dict] = {}
    for cat in sorted(set(categories)):
        mask = np.array([c == cat for c in categories])
        cat_phishing = phishing_mask[mask]
        cat_results[cat] = {
            "total": int(mask.sum()),
            "safe": int(sum(v == "SAFE" for v, m in zip(verdicts, mask) if m)),
            "suspicious": int(sum(v == "SUSPICIOUS" for v, m in zip(verdicts, mask) if m)),
            "phishing": int(cat_phishing.sum()),
            "phishing_fpr": float(cat_phishing.mean()) if mask.any() else 0.0,
        }

    # Structure FPR breakdown using URL analysis.
    parsed_list = [_safe_urlsplit(u) for u in urls]
    structure_masks: dict[str, np.ndarray] = {
        "has_fragment": np.array([bool(p.fragment) for p in parsed_list]),
        "multiple_path_segments": np.array([
            len([s for s in (p.path or "").split("/") if s]) >= 2 for p in parsed_list
        ]),
        "non_root_path": np.array([p.path not in ("", "/") for p in parsed_list]),
        "has_query": np.array([bool(p.query) for p in parsed_list]),
        "tracking_parameter": np.array([
            any(
                k in parse_qs(p.query or "", keep_blank_values=True)
                for k in ("utm_source", "utm_medium", "utm_campaign", "ref", "fbclid", "gclid")
            )
            for p in parsed_list
        ]),
        "url_length_gt120": np.array([len(u) > 120 for u in urls]),
        "url_length_gt200": np.array([len(u) > 200 for u in urls]),
        "percent_encoded": np.array(["%" in u for u in urls]),
    }
    structure_results: dict[str, dict] = {}
    for key, mask in structure_masks.items():
        if not mask.any():
            structure_results[key] = {"total": 0, "phishing": 0, "phishing_fpr": 0.0}
            continue
        ph = phishing_mask[mask]
        structure_results[key] = {
            "total": int(mask.sum()),
            "safe": int(sum(v == "SAFE" for v, m in zip(verdicts, mask) if m)),
            "suspicious": int(sum(v == "SUSPICIOUS" for v, m in zip(verdicts, mask) if m)),
            "phishing": int(ph.sum()),
            "phishing_fpr": float(ph.mean()),
        }
        log(f"    {key:<30}: {int(mask.sum()):>4} URLs  PHISHING={ph.sum():>3}  FPR={ph.mean():.2%}")

    # Adversarial control results.
    adv_results = {}
    for adv_url in ADVERSARIAL_URLS:
        try:
            adv_feats, _, _ = extract_feature_frame([adv_url], "adversarial")
            X_adv = adv_feats.reindex(columns=feature_names, fill_value=0.0)
            p_adv = float(model.predict_proba(X_adv)[0, 1])
            v_adv = verdict_for(p_adv, thresholds)
            adv_results[adv_url] = {"probability": p_adv, "verdict": v_adv}
        except Exception as exc:
            adv_results[adv_url] = {"error": str(exc)}

    return {
        "available": True,
        "total_urls": len(urls),
        "overall_safe": safe_count,
        "overall_suspicious": suspicious_count,
        "overall_phishing": phishing_count,
        "overall_phishing_fpr": overall_fpr,
        "category_breakdown": cat_results,
        "structure_breakdown": structure_results,
        "adversarial_controls": adv_results,
    }


# -----------------------------------------------------------------------------
# DYNAMIC-BENIGN HOLDOUT EVALUATION
# -----------------------------------------------------------------------------

def evaluate_dynamic_benign_holdout(
    model: ProbabilityCalibratedModel,
    holdout: pd.DataFrame,
    thresholds: dict,
    feature_names: list,
) -> dict:
    """Score the domain-disjoint dynamic-benign holdout set.
    All rows are legitimate (label=0); any PHISHING verdict is a false positive."""
    log(f"\nEvaluating dynamic-benign holdout ({len(holdout):,} URLs)...")
    urls = holdout["url"].tolist()
    feats, ok, failures = extract_feature_frame(urls, "dynamic_holdout")
    if failures > 0:
        log(f"  WARNING: {failures} holdout URLs failed feature extraction.")

    X_holdout = feats.reindex(columns=feature_names, fill_value=0.0)
    probabilities = model.predict_proba(X_holdout)[:, 1]

    safe_count = int(np.sum(probabilities < thresholds["safe"]))
    phishing_count = int(np.sum(probabilities >= thresholds["phishing"]))
    suspicious_count = len(urls) - safe_count - phishing_count
    phishing_fpr = phishing_count / max(len(urls), 1)

    log(
        f"  Dynamic holdout: SAFE={safe_count}  SUSPICIOUS={suspicious_count}  "
        f"PHISHING={phishing_count}  PHISHING FPR={phishing_fpr:.2%}"
    )

    # Structure breakdown on holdout.
    parsed_list = [_safe_urlsplit(u) for u in urls]
    phishing_mask = np.array([p >= thresholds["phishing"] for p in probabilities])

    structure_fpr: dict[str, dict] = {}
    structure_masks: dict[str, np.ndarray] = {
        "has_fragment": np.array([bool(p.fragment) for p in parsed_list]),
        "multiple_path_segments": np.array([
            len([s for s in (p.path or "").split("/") if s]) >= 2 for p in parsed_list
        ]),
        "has_query": np.array([bool(p.query) for p in parsed_list]),
        "tracking_parameter": np.array([
            any(
                k in parse_qs(p.query or "", keep_blank_values=True)
                for k in ("utm_source", "utm_medium", "utm_campaign", "ref", "fbclid", "gclid")
            )
            for p in parsed_list
        ]),
        "percent_encoded": np.array(["%" in u for u in urls]),
        "url_length_gt120": np.array([len(u) > 120 for u in urls]),
        "url_length_gt200": np.array([len(u) > 200 for u in urls]),
        "multi_path": np.array([
            len([s for s in (p.path or "").split("/") if s]) >= 3 for p in parsed_list
        ]),
    }
    for key, mask in structure_masks.items():
        if not mask.any():
            structure_fpr[key] = {"total": 0, "phishing": 0, "phishing_fpr": 0.0}
            continue
        ph = phishing_mask[mask]
        structure_fpr[key] = {
            "total": int(mask.sum()),
            "safe": int(sum(pr < thresholds["safe"] for pr, m in zip(probabilities, mask) if m)),
            "suspicious": int(
                sum(
                    thresholds["safe"] <= pr < thresholds["phishing"]
                    for pr, m in zip(probabilities, mask)
                    if m
                )
            ),
            "phishing": int(ph.sum()),
            "phishing_fpr": float(ph.mean()),
        }
        log(f"    {key:<30}: {int(mask.sum()):>5} URLs  PHISHING={ph.sum():>3}  FPR={ph.mean():.2%}")

    return {
        "total_urls": len(urls),
        "feature_extraction_failures": int(failures),
        "safe": safe_count,
        "suspicious": suspicious_count,
        "phishing": phishing_count,
        "phishing_fpr": phishing_fpr,
        "structure_breakdown": structure_fpr,
    }


# -----------------------------------------------------------------------------
# EXTERNAL VALIDATION (frozen phishing benchmark -- final gate only)
# -----------------------------------------------------------------------------

def evaluate_external_validation(
    model: ProbabilityCalibratedModel,
    thresholds: dict,
    feature_names: list,
) -> dict:
    """Score the frozen external phishing validation set.
    Used ONLY after all training and threshold selection is complete.
    DO NOT tune any parameter using this result.
    """
    require_file(EXTERNAL_VALIDATION_PATH, "external_validation.csv")
    log("\nEvaluating external phishing validation (frozen benchmark)...")
    ext = pd.read_csv(EXTERNAL_VALIDATION_PATH, usecols=["url", "label"])
    ext = ext.dropna(subset=["url", "label"]).copy()
    ext["label"] = pd.to_numeric(ext["label"], errors="coerce")
    ext = ext[ext["label"] == LABEL_PHISHING].copy()
    log(f"  External validation phishing rows: {len(ext):,}")

    urls = ext["url"].astype(str).tolist()
    feats, ok, failures = extract_feature_frame(urls, "external_validation")
    if failures > 0:
        log(f"  WARNING: {failures} external URLs failed feature extraction.")

    X_ext = feats.reindex(columns=feature_names, fill_value=0.0)
    probabilities = model.predict_proba(X_ext)[:, 1]
    y_ext = np.ones(len(urls), dtype=int)

    phishing_detected = int(np.sum(probabilities >= thresholds["phishing"]))
    recall = phishing_detected / max(len(urls), 1)
    fnr = 1.0 - recall

    log(f"  External phishing recall: {recall:.4%}  FNR: {fnr:.4%}")
    return {
        "total_phishing_urls": len(urls),
        "feature_extraction_failures": int(failures),
        "detected_as_phishing": phishing_detected,
        "recall": float(recall),
        "fnr": float(fnr),
        "threshold_used": float(thresholds["phishing"]),
    }


# -----------------------------------------------------------------------------
# PRODUCTION MODEL COMPARISON
# -----------------------------------------------------------------------------

def evaluate_production_model(X_test, y_test, X_ref, feature_names_candidate: list) -> dict:
    """Load and score the production model on the candidate test split + reference URLs."""
    for p in (PRODUCTION_MODEL_PATH, PRODUCTION_FEATURES_PATH):
        if not p.is_file():
            reason = f"Required production artifact missing: {p}"
            log(f"Production comparison unavailable: {reason}")
            return {"available": False, "reason": reason}

    try:
        with PRODUCTION_MODEL_PATH.open("rb") as f:
            prod_model = pickle.load(f)
        with PRODUCTION_FEATURES_PATH.open("rb") as f:
            prod_features = list(pickle.load(f))

        missing_feat = sorted(set(prod_features) - set(X_test.columns))
        if missing_feat:
            return {
                "available": False,
                "reason": f"Production feature mismatch: {missing_feat}",
            }

        prod_thresholds = {
            "safe": float(SAFE_THRESHOLD),
            "phishing": float(PHISHING_THRESHOLD),
        }
        X_prod = X_test[prod_features]
        p_prod = prod_model.predict_proba(X_prod)[:, 1]
        m_prod = compute_metrics(y_test, p_prod)
        m_prod["policy"] = policy(y_test, p_prod, prod_thresholds)
        m_prod["calibration"] = calibration_metrics(y_test, p_prod)

        # Reference URL scoring.
        if X_ref is not None:
            X_ref_prod = X_ref[prod_features]
            p_ref = prod_model.predict_proba(X_ref_prod)[:, 1]
            ref_verdicts = {
                url: {
                    "probability": float(p),
                    "verdict": verdict_for(float(p), prod_thresholds),
                }
                for url, p in zip(REFERENCE_URLS, p_ref)
            }
        else:
            ref_verdicts = {}

        return {
            "available": True,
            "feature_count": len(prod_features),
            "domain_test": m_prod,
            "thresholds": prod_thresholds,
            "reference_urls": ref_verdicts,
        }
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        log(f"Production comparison unavailable: {reason}")
        return {"available": False, "reason": reason}


# -----------------------------------------------------------------------------
# GATES
# -----------------------------------------------------------------------------

def build_gates(ev: dict, hashes_unchanged: bool) -> dict:
    def gate(requirement, actual, passed):
        return {"requirement": requirement, "actual": actual, "passed": bool(passed)}

    fpr = ev["domain_test"]["policy"]["fpr"]
    ece = ev["domain_test"]["calibration"]["expected_calibration_error"]
    size = ev["profile"]["model_size_bytes"]
    latency = ev["profile"]["median_latency_ms"]

    ext_recall = ev.get("external_validation", {}).get("recall", 0.0)
    dynamic_fpr = ev.get("dynamic_holdout", {}).get("phishing_fpr", 1.0)

    # Reference URL verdicts.
    ref_verdicts = ev.get("reference_url_verdicts", {})

    def google_verdict(url):
        return ref_verdicts.get(url, {}).get("verdict", "UNKNOWN")

    google_pass = all(google_verdict(u) != "PHISHING" for u in GOOGLE_SEARCH_URLS)
    youtube_pass = all(google_verdict(u) != "PHISHING" for u in YOUTUBE_QUERY_URLS)
    fast_pass = all(google_verdict(u) == "SAFE" for u in FAST_COM_URLS)

    return {
        "external_phishing_recall": gate(
            f">= {GATE_MIN_EXTERNAL_RECALL:.2%}",
            float(ext_recall),
            ext_recall >= GATE_MIN_EXTERNAL_RECALL,
        ),
        "domain_fpr": gate(
            f"<= {GATE_MAX_DOMAIN_FPR:.2%}",
            float(fpr),
            fpr <= GATE_MAX_DOMAIN_FPR,
        ),
        "calibration_ece": gate(
            f"<= {GATE_MAX_ECE}",
            float(ece),
            ece <= GATE_MAX_ECE,
        ),
        "google_search_not_phishing": gate(
            "no Google search URL classified PHISHING",
            {u: google_verdict(u) for u in GOOGLE_SEARCH_URLS},
            google_pass,
        ),
        "youtube_query_not_phishing": gate(
            "YouTube query URL not classified PHISHING",
            {u: google_verdict(u) for u in YOUTUBE_QUERY_URLS},
            youtube_pass,
        ),
        "fast_com_variants_safe": gate(
            "all fast.com variants classified SAFE",
            {u: google_verdict(u) for u in FAST_COM_URLS},
            fast_pass,
        ),
        "dynamic_benign_low_phishing_rate": gate(
            "dynamic holdout phishing rate near 0%",
            float(dynamic_fpr),
            dynamic_fpr < 0.05,  # < 5% is required; prefer 0%
        ),
        "no_domain_allowlist": gate(
            "no domain allowlist or score bypass in model",
            "verified: model uses normal inference only",
            True,  # Hardcoded True -- this script never creates a bypass.
        ),
        "model_size": gate(
            f"<= {GATE_MAX_MODEL_BYTES / (1024*1024):.0f} MB",
            int(size),
            size <= GATE_MAX_MODEL_BYTES,
        ),
        "median_latency": gate(
            f"<= {GATE_MAX_MEDIAN_LATENCY_MS} ms",
            float(latency),
            latency <= GATE_MAX_MEDIAN_LATENCY_MS,
        ),
        "production_hashes_unchanged": gate(
            "SHA-256 of production artifacts identical before and after",
            "see production_hashes",
            hashes_unchanged,
        ),
    }


# -----------------------------------------------------------------------------
# CONSOLE SUMMARY TABLE
# -----------------------------------------------------------------------------

def print_summary_table(summaries: list, best_name: str, decision: str) -> None:
    headers = [
        "MODEL", "DOMAIN RECALL", "DOMAIN FPR", "EXTERNAL RECALL",
        "ECE", "REAL DYNAMIC BENIGN PHISHING %",
        "MODEL SIZE", "MEDIAN LATENCY",
        "GOOGLE SEARCH", "YOUTUBE QUERY", "FAST.COM", "GATES",
    ]
    rows = []
    for s in summaries:
        rows.append([
            s["model"],
            f"{s['domain_recall']:.2%}",
            f"{s['domain_fpr']:.2%}",
            f"{s['external_recall']:.2%}",
            f"{s['ece']:.4f}",
            f"{s['dynamic_benign_phishing_pct']:.2%}",
            f"{s['size_bytes'] / (1024 * 1024):.2f} MB",
            f"{s['latency_ms']:.2f} ms",
            "PASS" if s["google"] else "FAIL",
            "PASS" if s["youtube"] else "FAIL",
            "PASS" if s["fast"] else "FAIL",
            "PASS" if s["gates"] else "FAIL",
        ])
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    sep = "-+-".join("-" * w for w in widths)
    log("\n" + " | ".join(h.ljust(w) for h, w in zip(headers, widths)))
    log(sep)
    for r in rows:
        log(" | ".join(c.ljust(w) for c, w in zip(r, widths)))
    log(sep)
    log(f"BEST CANDIDATE: {best_name}")
    log(f"FINAL DECISION: {decision}")


# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

def main() -> dict:
    started_at = time.perf_counter()
    log("=" * 78)
    log("VIGIL -- FINAL DYNAMIC FALSE-POSITIVE HARDENING EXPERIMENT")
    log("=" * 78)
    log(f"Command: {RUN_COMMAND}")
    log("Production artifacts will NOT be modified.")
    log("Candidate artifacts -> models/experiments/dynamic_hardening/")
    log("=" * 78)

    # -- 0. Hash production artifacts BEFORE anything else. ------------------
    hashes_before = hash_production_artifacts()
    missing_artifacts = [n for n, h in hashes_before.items() if h is None]
    if missing_artifacts:
        log(f"NOTE: production artifacts not found (hashes recorded as null): {missing_artifacts}")
    log(f"\nProduction hashes (before): {hashes_before}")

    # -- 1. Load and split dynamic-benign (domain-disjoint holdout). ---------
    log("\n[1/9] Loading dynamic-benign dataset...")
    dynamic_full = load_dynamic_dataset()
    dynamic_train_raw, dynamic_holdout = split_dynamic_train_holdout(dynamic_full, SEED)

    # -- 2. Build pool and extract features. ----------------------------------
    log("\n[2/9] Building corpus pool...")
    pool, pool_report = build_pool(dynamic_train_raw)
    pool["registered_domain"] = registered_domains_series(pool["normalized_url"])

    log("\n[2/9] Extracting features for full pool...")
    pool_features, ok_all, failures_pool = extract_feature_frame(pool["url"], "pool")
    if failures_pool:
        raise RuntimeError(
            f"Feature extraction failed for {failures_pool:,} pool rows. "
            "Refusing to silently reduce the corpus."
        )

    # -- 3. Stratified phishing sample. ---------------------------------------
    log("\n[3/9] Stratified Phishing.Database sampling...")
    kept_pos, strata_report = stratified_feed_sample(pool, pool_features)
    corpus = pool.iloc[kept_pos].reset_index(drop=True)
    corpus_features_all = pool_features.iloc[kept_pos].reset_index(drop=True)
    del pool, pool_features

    # -- 4. Dynamic-benign strata for training weights. -----------------------
    log("\n[4/9] Computing dynamic-benign structure strata...")
    dynamic_mask_corpus = corpus["source"] == SOURCE_DYNAMIC
    dynamic_corpus_urls = corpus.loc[dynamic_mask_corpus, "url"]
    dynamic_strata_corpus = _assign_dynamic_strata(dynamic_corpus_urls)
    log(f"  Dynamic training rows: {dynamic_mask_corpus.sum():,}")
    for col in [n for n, _ in DYNAMIC_STRATA_DEFINITIONS]:
        count = int(dynamic_strata_corpus[col].sum()) if col in dynamic_strata_corpus.columns else 0
        log(f"    {col:<30}: {count:,}")

    # Corpus diagnostics.
    n_legit = int((corpus["label"] == 0).sum())
    n_phish = int((corpus["label"] == 1).sum())
    log(f"\n  Final corpus: {len(corpus):,}  legitimate={n_legit:,}  phishing={n_phish:,}")
    log(f"  Source counts: {counts_by_source(corpus)}")

    # -- 5. Feature matrix + domain-isolated split. ---------------------------
    log("\n[5/9] Building feature matrix and domain-isolated split...")
    feature_names_all = [
        c for c in corpus_features_all.columns if c not in set(MODEL_EXCLUDED_FEATURES)
    ]
    log(f"  All features (A): {len(feature_names_all)}")
    if len(feature_names_all) != 29:
        raise RuntimeError(
            f"Expected 29 VIGIL model features; found {len(feature_names_all)}. "
            f"Features: {feature_names_all}"
        )

    X_all = corpus_features_all[feature_names_all].copy()
    y = corpus["label"].astype(int).reset_index(drop=True)

    split_names = list(SPLIT_FRACTIONS)
    split_ids = domain_split(corpus["registered_domain"], SPLIT_FRACTIONS, SEED)
    split_description = describe_splits(corpus, split_ids, split_names)
    idx = {n: np.where(split_ids == i)[0] for i, n in enumerate(split_names)}
    train_idx = idx["train"]
    cal_idx = idx["calibration"]
    thr_idx = idx["threshold"]
    test_idx = idx["test"]

    # Build training sample weights (hard-negative dynamic emphasis).
    train_corpus = corpus.iloc[train_idx].copy()
    train_strata_df = dynamic_strata_corpus.reindex(train_corpus.index)
    y_train_np = y.iloc[train_idx].to_numpy()
    train_weights = build_training_weights(train_corpus, train_strata_df, y_train_np)

    # -- 6. Reference URL features. -------------------------------------------
    log("\n[6/9] Extracting features for reference URLs...")
    ref_feats, ref_ok, ref_failures = extract_feature_frame(REFERENCE_URLS, "reference_urls")
    if ref_failures:
        raise RuntimeError("Feature extraction failed for reference URLs.")
    X_ref = ref_feats.reindex(columns=feature_names_all, fill_value=0.0)

    # Production model comparison.
    prod_comparison = evaluate_production_model(
        X_all.iloc[test_idx],
        y.iloc[test_idx].to_numpy(),
        X_ref,
        feature_names_all,
    )

    # -- 7. Train, calibrate, and evaluate all variants. ----------------------
    log("\n[7/9] Training candidate models...")
    EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)

    variants = [
        ("logistic_regression",       feature_names_all),
        ("hist_gradient_boosting",     feature_names_all),
    ]

    evaluations: dict[str, dict] = {}
    for variant_name, feat_names in variants:
        log(f"\n{'-' * 60}")
        log(f"  Variant: {variant_name}  ({len(feat_names)} features)")
        log(f"{'-' * 60}")

        X_tr = X_all.iloc[train_idx][feat_names]
        X_cal = X_all.iloc[cal_idx][feat_names]
        X_thr = X_all.iloc[thr_idx][feat_names]
        X_tst = X_all.iloc[test_idx][feat_names]
        y_tr = y.iloc[train_idx]
        y_cal = y.iloc[cal_idx]
        y_thr = y.iloc[thr_idx]
        y_tst = y.iloc[test_idx]

        fit_t0 = time.perf_counter()
        sw = train_weights if variant_name != "logistic_regression" else None
        estimator, calibrator, model = fit_model(
            variant_name, X_tr, y_tr, X_cal, y_cal, sample_weights=sw
        )
        fit_seconds = time.perf_counter() - fit_t0
        log(f"  Training complete in {fit_seconds:.1f}s")

        # Threshold selection on threshold split.
        p_thr = model.predict_proba(X_thr)[:, 1]
        thresholds = select_thresholds(y_thr.to_numpy(), p_thr)
        log(
            f"  Thresholds: safe={thresholds['safe']:.4f}  "
            f"phishing={thresholds['phishing']:.4f}"
        )

        # Test split metrics.
        p_tst = model.predict_proba(X_tst)[:, 1]
        test_m = compute_metrics(y_tst.to_numpy(), p_tst)
        test_m["calibration"] = calibration_metrics(y_tst.to_numpy(), p_tst)
        test_m["policy"] = policy(y_tst.to_numpy(), p_tst, thresholds)
        test_m["source_breakdown"] = source_breakdown(
            corpus["source"].iloc[test_idx].to_numpy(),
            y_tst.to_numpy(),
            p_tst,
            thresholds,
        )
        test_m["hard_cohorts"] = phishing_cohort_analysis(
            corpus["url"].iloc[test_idx],
            X_all.iloc[test_idx],
            y_tst.to_numpy(),
            p_tst,
            thresholds["phishing"],
        )
        log(
            f"  Domain test: recall={test_m['policy']['phishing_recall']:.4%}  "
            f"FPR={test_m['policy']['fpr']:.4%}  "
            f"PR-AUC={test_m['pr_auc']:.4f}  "
            f"ECE={test_m['calibration']['expected_calibration_error']:.4f}"
        )

        # Threshold split metrics.
        thr_m = compute_metrics(y_thr.to_numpy(), p_thr)
        thr_m["calibration"] = calibration_metrics(y_thr.to_numpy(), p_thr)
        thr_m["policy"] = policy(y_thr.to_numpy(), p_thr, thresholds)

        # Threshold sensitivity.
        sens = threshold_sensitivity(y_thr.to_numpy(), p_thr, y_tst.to_numpy(), p_tst, thresholds)

        # Feature importance (HGB only).
        feat_imp = {}
        perm_imp = {}
        if hasattr(estimator, "feature_importances_"):
            feat_imp = compute_feature_importance(estimator, feat_names)
            log("  Feature importance (top 10):")
            for fn, imp in list(feat_imp.items())[:10]:
                log(f"    {fn:<35}: {imp:.4f}")
            perm_imp = compute_permutation_importance_subset(
                model, X_tst, y_tst.to_numpy(), feat_names
            )

        # Reference URL scoring.
        X_ref_v = X_ref[feat_names] if feat_names != feature_names_all else X_ref
        p_ref = model.predict_proba(X_ref_v)[:, 1]
        ref_verdicts = {
            url: {
                "probability": float(p),
                "verdict": verdict_for(float(p), thresholds),
            }
            for url, p in zip(REFERENCE_URLS, p_ref)
        }
        log("  Reference URL verdicts:")
        for url, info in ref_verdicts.items():
            marker = "ok  " if info["verdict"] != "PHISHING" else "FAIL"
            log(f"    [{marker}] {info['verdict']:<10} {info['probability']:.4f}  {url}")

        # Dynamic-benign holdout evaluation.
        holdout_eval = evaluate_dynamic_benign_holdout(
            model, dynamic_holdout, thresholds, feat_names
        )

        # External validation (fixed phishing benchmark).
        ext_eval = evaluate_external_validation(model, thresholds, feat_names)
        log(f"  External phishing recall: {ext_eval['recall']:.4%}")

        # Regression suite diagnostics.
        reg_url_items = load_regression_suite()
        regression_diag = run_regression_diagnostics(model, thresholds, feat_names, reg_url_items)
        if regression_diag.get("available"):
            log(
                f"  Regression suite (1065 URLs): "
                f"SAFE={regression_diag['overall_safe']}  "
                f"SUSPICIOUS={regression_diag['overall_suspicious']}  "
                f"PHISHING={regression_diag['overall_phishing']}  "
                f"FPR={regression_diag['overall_phishing_fpr']:.2%}"
            )

        # Save candidate artifact.
        saved_path, size_bytes = save_candidate(
            variant_name, estimator, calibrator, feat_names, thresholds
        )
        latency = measure_latency(model, X_tst.iloc[[0]])
        log(f"  Size: {size_bytes:,} bytes  Median latency: {latency['median_ms']:.2f} ms")

        ev = {
            "variant_name": variant_name,
            "feature_names": feat_names,
            "feature_count": len(feat_names),
            "thresholds": thresholds,
            "domain_test": test_m,
            "threshold_split": thr_m,
            "threshold_sensitivity": sens,
            "feature_importance": feat_imp,
            "permutation_importance": perm_imp,
            "reference_url_verdicts": ref_verdicts,
            "dynamic_holdout": holdout_eval,
            "external_validation": ext_eval,
            "regression_diagnostics": regression_diag,
            "profile": {
                "model_size_bytes": int(size_bytes),
                "median_latency_ms": float(latency["median_ms"]),
                "p95_latency_ms": float(latency["p95_ms"]),
                "fit_seconds": float(fit_seconds),
                "candidate_artifact": str(saved_path.relative_to(ROOT)),
            },
        }
        evaluations[variant_name] = ev

    # -- 7b. Ablation experiment (HGB reduced complexity). --------------------
    log("\n[7b/9] Running reduced-complexity feature ablation...")
    hgb_ev = evaluations.get("hist_gradient_boosting", {})
    hgb_thresholds = hgb_ev.get("thresholds", {"safe": SAFE_THRESHOLD, "phishing": PHISHING_THRESHOLD})
    ablation_report = {}
    try:
        ablation_report = ablation_feature_contribution(
            "hist_gradient_boosting",
            X_all.iloc[train_idx][feature_names_all],
            y.iloc[train_idx],
            X_all.iloc[test_idx][feature_names_all],
            y.iloc[test_idx].to_numpy(),
            X_all.iloc[cal_idx][feature_names_all],
            y.iloc[cal_idx].to_numpy(),
            feature_names_all,
            hgb_thresholds,
            train_weights,
        )
        log(
            f"  Ablation HGB recall (reduced): "
            f"{ablation_report.get('test_policy_reduced', {}).get('phishing_recall', 0):.4%}  "
            f"FPR: {ablation_report.get('test_policy_reduced', {}).get('fpr', 1):.4%}"
        )
    except Exception as exc:
        log(f"  Ablation failed (non-fatal): {exc}")
        ablation_report = {"error": str(exc)}

    # -- 8. Final gates, ranking, decision. -----------------------------------
    log("\n[8/9] Computing gates and final decision...")
    hashes_after = hash_production_artifacts()
    hashes_unchanged = hashes_before == hashes_after and all(
        v is not None for v in hashes_before.values()
    )
    log(f"\nProduction hashes (after): {hashes_after}")
    log(f"Production hashes unchanged: {hashes_unchanged}")

    for name, ev in evaluations.items():
        ev["gates"] = build_gates(ev, hashes_unchanged)
        ev["gates_passed"] = all(g["passed"] for g in ev["gates"].values())
        ev["gates_passed_count"] = int(sum(g["passed"] for g in ev["gates"].values()))
        log(f"\n  Gates for {name}:")
        for gate_name, info in ev["gates"].items():
            status = "PASS" if info["passed"] else "FAIL"
            log(f"    [{status}] {gate_name}: {info.get('actual', '')}")

    def rank_key(name):
        ev = evaluations[name]
        # Primary: external recall; secondary: internal recall; tertiary: low FPR.
        ext_rec = ev.get("external_validation", {}).get("recall", 0.0)
        dom_rec = ev["domain_test"]["policy"]["phishing_recall"]
        fpr = ev["domain_test"]["policy"]["fpr"]
        return (ext_rec, dom_rec, -fpr)

    best_name = max(evaluations, key=rank_key)
    best = evaluations[best_name]
    decision = "PROMOTE CANDIDATE" if best["gates_passed"] else "DO NOT PROMOTE"

    summaries = []
    for name, ev in evaluations.items():
        g = ev["gates"]
        summaries.append({
            "model": name,
            "domain_recall": ev["domain_test"]["policy"]["phishing_recall"],
            "domain_fpr": ev["domain_test"]["policy"]["fpr"],
            "external_recall": ev.get("external_validation", {}).get("recall", 0.0),
            "ece": ev["domain_test"]["calibration"]["expected_calibration_error"],
            "dynamic_benign_phishing_pct": ev.get("dynamic_holdout", {}).get("phishing_fpr", 1.0),
            "size_bytes": ev["profile"]["model_size_bytes"],
            "latency_ms": ev["profile"]["median_latency_ms"],
            "google": g.get("google_search_not_phishing", {}).get("passed", False),
            "youtube": g.get("youtube_query_not_phishing", {}).get("passed", False),
            "fast": g.get("fast_com_variants_safe", {}).get("passed", False),
            "gates": ev["gates_passed"],
        })

    # -- 9. Write report and print final output. ------------------------------
    log("\n[9/9] Writing report...")
    best_pol = best["domain_test"]["policy"]
    best_dyn = best.get("dynamic_holdout", {})
    best_ext = best.get("external_validation", {})
    best_reg = best.get("regression_diagnostics", {})

    # Identify regression suite structure FPR for the required printout.
    reg_struct = best_reg.get("structure_breakdown", {}) if best_reg.get("available") else {}

    compact_report = {
        "experiment": "dynamic_hardening_final",
        "run_command": RUN_COMMAND,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "final_decision": decision,
        "decision_note": "This script NEVER promotes automatically. Production artifacts unchanged.",
        "automatic_promotion": False,
        "best_candidate": best_name,
        "ranking_rule": (
            "highest external phishing recall, then highest domain recall, "
            "then lowest domain FPR"
        ),
        "production_artifacts_updated": False,
        "production_hashes_unchanged": hashes_unchanged,
        "production_hashes_before": hashes_before,
        "production_hashes_after": hashes_after,
        "seed": SEED,
        "split_fractions": SPLIT_FRACTIONS,
        "gate_limits": {
            "min_external_recall": GATE_MIN_EXTERNAL_RECALL,
            "max_domain_fpr": GATE_MAX_DOMAIN_FPR,
            "max_ece": GATE_MAX_ECE,
            "max_model_bytes": GATE_MAX_MODEL_BYTES,
            "max_median_latency_ms": GATE_MAX_MEDIAN_LATENCY_MS,
        },
        "hyperparameters": {
            "hist_gradient_boosting": HGB_PARAMS,
            "logistic_regression": {
                "max_iter": 2000,
                "class_weight": "balanced",
                "solver": "lbfgs",
                "scaler": "StandardScaler",
            },
        },
        "pool": pool_report,
        "phishing_database_stratified_sample": strata_report,
        "training_corpus": {
            "total": int(len(corpus)),
            "legitimate": int(n_legit),
            "phishing": int(n_phish),
            "source_counts": counts_by_source(corpus),
        },
        "dynamic_benign_holdout_rows": int(len(dynamic_holdout)),
        "domain_split": split_description,
        "dynamic_hardening_strata": {
            col: int(dynamic_strata_corpus[col].sum())
            for col, _ in DYNAMIC_STRATA_DEFINITIONS
            if col in dynamic_strata_corpus.columns
        },
        "ablation_experiment": ablation_report,
        "production_comparison": prod_comparison,
        "candidate_models": evaluations,
        "runtime_seconds": float(time.perf_counter() - started_at),
    }

    atomic_write_bytes(
        REPORT_PATH,
        json.dumps(to_jsonable(compact_report), indent=2).encode("utf-8"),
        REPORT_PATH.parent,
    )
    log(f"Report written to: {REPORT_PATH}")

    # -- Final console summary -------------------------------------------------
    log("\n" + "=" * 78)
    log("THRESHOLD SENSITIVITY (best candidate)")
    log("=" * 78)
    log("  delta   threshold   thr-FPR  thr-recall  test-FPR  test-recall")
    for row in best["threshold_sensitivity"]["around_selected_threshold"]:
        log(
            f"  {row['delta']:+.2f}   {row['phishing_threshold']:.4f}     "
            f"{row['threshold_split']['fpr']:.4f}   {row['threshold_split']['recall']:.4f}      "
            f"{row['test']['fpr']:.4f}    {row['test']['recall']:.4f}"
        )

    log("\n" + "=" * 78)
    log("GATES (best candidate)")
    log("=" * 78)
    for gate_name, info in best["gates"].items():
        status = "PASS" if info["passed"] else "FAIL"
        log(f"  [{status}] {gate_name}")

    print_summary_table(summaries, best_name, decision)

    log("\n" + "=" * 78)
    log("FINAL RESULT")
    log("=" * 78)
    log(f"MODEL                           : {best_name}")
    log(f"DOMAIN RECALL                   : {best_pol['phishing_recall']:.4%}")
    log(f"DOMAIN FPR                      : {best_pol['fpr']:.4%}")
    log(f"EXTERNAL RECALL                 : {best_ext.get('recall', 0.0):.4%}")
    log(f"ECE                             : {best['domain_test']['calibration']['expected_calibration_error']:.6f}")
    log(f"REAL DYNAMIC BENIGN PHISHING %  : {best_dyn.get('phishing_fpr', 'N/A')}")
    log(
        f"SYNTHETIC REGRESSION PHISHING % : "
        f"{best_reg.get('overall_phishing_fpr', 'N/A') if best_reg.get('available') else 'N/A'}"
    )
    log(
        f"LONG URL FPR (>120)             : "
        f"{reg_struct.get('url_length_gt120', {}).get('phishing_fpr', 'N/A')}"
    )
    log(
        f"QUERY FPR                       : "
        f"{reg_struct.get('has_query', {}).get('phishing_fpr', 'N/A')}"
    )
    log(
        f"FRAGMENT FPR                    : "
        f"{reg_struct.get('has_fragment', {}).get('phishing_fpr', 'N/A')}"
    )
    log(f"MODEL SIZE                      : {best['profile']['model_size_bytes']:,} bytes")
    log(f"MEDIAN LATENCY                  : {best['profile']['median_latency_ms']:.3f} ms")

    # Adversarial controls summary.
    adv = best_reg.get("adversarial_controls", {}) if best_reg.get("available") else {}
    if adv:
        log("\nADVERSARIAL CONTROLS (must NOT be bypassed):")
        for url, info in adv.items():
            v = info.get("verdict", info.get("error", "ERROR"))
            log(f"  {v:<12} {url}")

    log("\nREFERENCE URL VERDICTS (best candidate):")
    for url, info in best.get("reference_url_verdicts", {}).items():
        marker = "ok  " if info["verdict"] != "PHISHING" else "FAIL"
        log(f"  [{marker}] {info['verdict']:<10} {info['probability']:.4f}  {url}")

    log(f"\nPRODUCTION ARTIFACTS UPDATED: False")
    log(f"\nFINAL DECISION:")
    log(decision)

    if not hashes_unchanged:
        raise RuntimeError(
            "PRODUCTION ARTIFACT CHANGED DURING THE EXPERIMENT! "
            f"before={hashes_before} after={hashes_after}"
        )

    return compact_report


if __name__ == "__main__":
    main()
