#!/usr/bin/env python3
"""
VIGIL dynamic-recovery experiment (EXPERIMENT ONLY - never promotes anything).

Run from the VIGIL repository root:

    python train_dynamic_recovery_experiment.py

Purpose
-------
Keep the 167,119 verified benign dynamic URLs, but recover phishing detection by
giving the model MORE and BETTER-CHOSEN phishing data than the failed 167k balanced
experiment:

  A. ALL PhiUSIIL rows                         (source: PhiUSIIL)
  B. ALL verified benign dynamic rows          (source: verified_benign_dynamic)
  C. ~350k Phishing.Database phishing URLs     (source: phishing_database_active)
     chosen by STRATIFIED sampling (seed 42), not by taking the first N rows.

Stratified sampling
-------------------
Primary strata (64) are the combinations of: path present, query present,
suspicious-TLD indicator, IP-host indicator, suspicious-token indicator and percent
encoding. Each primary stratum receives a proportional share of the target
(largest-remainder rounding, so the total is exact). Strata with no suspicious token,
no suspicious TLD and no IP host ("low-signal" / hard phishing) are sampled at a
slightly HIGHER rate (LOW_SIGNAL_RATE_MULTIPLIER) so the hard examples are preserved
instead of being diluted by obvious ones.

Inside every primary stratum rows are ordered by URL-length bucket, hostname-length
bucket, subdomain count, digit-ratio bucket, hyphen count, dot count, path depth,
query-length bucket, entropy bucket and exact length, and selected by systematic
sampling with a seeded random start. This spreads the sample proportionally across
ALL of those dimensions at once. The report contains the strata table and a
before/after marginal check for every dimension.

Safety
------
  * SHA-256 hashes of phishing_model.pkl, feature_names.pkl and feature_importance.csv
    are taken before and after the run; the script FAILS if any of them changed.
  * Candidate artifacts are written only to models/experiments/dynamic_recovery/.
  * The report is reports/dynamic_recovery_final.json.
  * No hardcoded trusted domains, no score boosts. Regression URLs are used only as
    an evaluation set, and the report states whether each one (or its domain) was
    present in training/calibration/threshold/test.

Gate definitions
----------------
  * Domain recall and domain FPR are measured on the PHISHING verdict
    (probability >= selected phishing threshold). SUSPICIOUS counts as a miss.
  * No external holdout or active phishing feed file is loaded or used.
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
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
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

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from config import PHISHING_THRESHOLD, SAFE_THRESHOLD
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "Could not import SAFE_THRESHOLD / PHISHING_THRESHOLD from config.py. "
        "Place this script in the VIGIL repository root."
    ) from exc

try:
    from feature_extractor import MODEL_EXCLUDED_FEATURES, extract_features
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "Could not import extract_features / MODEL_EXCLUDED_FEATURES from "
        "feature_extractor.py. Place this script in the VIGIL repository root."
    ) from exc

try:
    from feature_extractor import get_registered_domain as _vigil_registered_domain
except ImportError:  # pragma: no cover
    _vigil_registered_domain = None


# ============================================================
# CONFIGURATION
# ============================================================

RUN_COMMAND = "python train_dynamic_recovery_experiment.py"

SEED = 42

# Phishing.Database sample (target range requested: 300k-400k).
PHISHING_DATABASE_SAMPLE_TARGET = 350_000
LOW_SIGNAL_RATE_MULTIPLIER = 1.20

LABEL_LEGITIMATE = 0
LABEL_PHISHING = 1

SOURCE_PHIUSIIL = "PhiUSIIL"
SOURCE_FEED = "phishing_database_active"
SOURCE_DYNAMIC = "verified_benign_dynamic"
# Keep-priority when the same normalized URL appears in several sources.
SOURCE_PRIORITY = [SOURCE_PHIUSIIL, SOURCE_DYNAMIC, SOURCE_FEED]

DATASET_PATH = ROOT / "data" / "processed" / "clean_dataset.csv"
DYNAMIC_PATH = ROOT / "data" / "external" / "benign_dynamic" / "legitimate_dynamic_urls.csv"
REPORT_PATH = ROOT / "reports" / "dynamic_recovery_final.json"
EXPERIMENT_DIR = ROOT / "models" / "experiments" / "dynamic_recovery"

PRODUCTION_MODEL_PATH = ROOT / "phishing_model.pkl"
PRODUCTION_FEATURES_PATH = ROOT / "feature_names.pkl"
PRODUCTION_IMPORTANCE_PATH = ROOT / "feature_importance.csv"
PROTECTED_ARTIFACTS = [
    PRODUCTION_MODEL_PATH,
    PRODUCTION_FEATURES_PATH,
    PRODUCTION_IMPORTANCE_PATH,
]

# Domain-isolated split targets (fractions of rows).
SPLIT_FRACTIONS = {"train": 0.45, "calibration": 0.15, "threshold": 0.20, "test": 0.20}

# Threshold policy.
HARD_FPR_LIMIT = 0.0200            # maximize recall subject to this threshold-split FPR
MAX_PHISHING_BELOW_SAFE = 0.02     # at most 2% of phishing may be called SAFE
DELTA_SWEEP = [-0.10, -0.05, -0.02, -0.01, 0.0, 0.01, 0.02, 0.05, 0.10]

# Gates.
GATE_MAX_DOMAIN_FPR = 0.0200
GATE_MAX_ECE = 0.05
GATE_MAX_MODEL_BYTES = 25 * 1024 * 1024
GATE_MAX_MEDIAN_LATENCY_MS = 50.0

# HistGradientBoosting capacity (early_stopping stays False).
HGB_PARAMS = dict(
    learning_rate=0.10,
    max_iter=300,
    max_leaf_nodes=63,
    min_samples_leaf=40,
    l2_regularization=1.0,
    early_stopping=False,
    random_state=SEED,
)

FEATURE_CHUNK = 50_000

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

# Expected outcomes are used ONLY to evaluate a model, never to change its output.
GOOGLE_SEARCH_URLS = {
    "https://google.com/search?q=test",
    "https://www.google.com/search?q=test",
}
YOUTUBE_QUERY_URLS = {"https://www.youtube.com/?feature=ytca"}
FAST_COM_URLS = {"https://fast.com", "https://fast.com/", "https://www.fast.com/"}


# ============================================================
# CALIBRATED MODEL (same semantics as the existing VIGIL pipeline)
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
        return np.column_stack([1.0 - calibrated, calibrated])


# ============================================================
# GENERIC UTILITIES
# ============================================================

def log(message: str = "") -> None:
    print(message, flush=True)


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
    fd, temporary = tempfile.mkstemp(prefix=".vigil-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def require_file(path: Path, description: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{description} not found: {path}")


def counts_by_source(frame: pd.DataFrame) -> dict:
    if len(frame) == 0:
        return {}
    return {str(k): int(v) for k, v in frame["source"].value_counts().items()}


# ============================================================
# URL NORMALISATION AND DOMAIN GROUPING
# ============================================================

def normalize_url(url) -> str:
    """VIGIL normalisation (lower-case scheme/host, default ports dropped, empty path
    becomes '/'). Used for de-duplication and overlap tests only; features are always
    extracted from the ORIGINAL url string."""
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
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        if not default_port:
            netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{scheme}://{netloc}{path}{query}{fragment}"


def safe_urlsplit(url):
    try:
        return urlsplit(str(url))
    except ValueError:
        return urlsplit("")


def _hostname(normalized: str) -> str:
    try:
        return (urlsplit(normalized).hostname or "").lower()
    except ValueError:
        return ""


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


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


def registered_domains(normalized_urls: pd.Series) -> pd.Series:
    hosts = normalized_urls.map(_hostname)
    cache = {host: registered_domain_for_host(host) for host in hosts.unique()}
    domains = hosts.map(cache).fillna("")
    missing = domains.eq("")
    if missing.any():
        # Rows without a usable domain get their own group (never one giant empty group).
        domains = domains.where(
            ~missing,
            pd.Series([f"__missing_domain_{i}" for i in domains.index], index=domains.index),
        )
    return domains


# ============================================================
# DATA LOADING
# ============================================================

def read_url_csv(path: Path, description: str) -> pd.DataFrame:
    require_file(path, description)
    header = pd.read_csv(path, nrows=0)
    if "url" not in header.columns:
        raise ValueError(f"{description} must contain a 'url' column: {path}")
    frame = pd.read_csv(path, usecols=["url"], dtype={"url": "string"})
    frame = frame.dropna(subset=["url"]).copy()
    frame["url"] = frame["url"].astype(str)
    return frame


def load_base_dataset() -> pd.DataFrame:
    require_file(DATASET_PATH, "Training dataset")
    header = pd.read_csv(DATASET_PATH, nrows=0)
    required = ["url", "label", "source"]
    missing = [c for c in required if c not in header.columns]
    if missing:
        raise ValueError(f"clean_dataset.csv is missing columns: {missing}")

    base = pd.read_csv(DATASET_PATH, usecols=required, dtype={"url": "string", "source": "string"})
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
        log("WARNING: ignoring clean_dataset.csv rows with other sources "
            f"(the dynamic set is loaded separately): {counts_by_source(unknown)}")
        base = base[base["source"].isin(known)].copy()

    phi_labels = set(base.loc[base["source"] == SOURCE_PHIUSIIL, "label"].unique())
    if phi_labels != {LABEL_LEGITIMATE, LABEL_PHISHING}:
        raise ValueError(f"PhiUSIIL must contain both classes, found labels {sorted(phi_labels)}")
    feed_labels = set(base.loc[base["source"] == SOURCE_FEED, "label"].unique())
    if feed_labels != {LABEL_PHISHING}:
        raise ValueError(f"{SOURCE_FEED} must be phishing (1) only, found labels {sorted(feed_labels)}")
    return base


def load_dynamic_dataset() -> pd.DataFrame:
    dynamic = read_url_csv(DYNAMIC_PATH, "Verified benign dynamic URL dataset")
    dynamic["label"] = LABEL_LEGITIMATE
    dynamic["source"] = SOURCE_DYNAMIC
    log(f"Verified benign dynamic rows loaded: {len(dynamic):,}")
    return dynamic


def build_pool():
    """Build the corpus from only the processed dataset and verified dynamic URLs."""
    base = load_base_dataset()
    dynamic = load_dynamic_dataset()

    frame = pd.concat(
        [
            base[base["source"] == SOURCE_PHIUSIIL],
            dynamic,
            base[base["source"] == SOURCE_FEED],
        ],
        ignore_index=True,
    )
    loaded = counts_by_source(frame)
    frame["normalized_url"] = frame["url"].map(normalize_url)

    unparseable = frame["normalized_url"].eq("")
    removed_unparseable = counts_by_source(frame[unparseable])
    frame = frame[~unparseable].copy()

    label_counts = frame.groupby("normalized_url")["label"].nunique()
    conflicting = set(label_counts[label_counts > 1].index)
    conflict_rows = frame["normalized_url"].isin(conflicting)
    removed_conflict = counts_by_source(frame[conflict_rows])
    frame = frame[~conflict_rows].copy()

    frame["source"] = pd.Categorical(frame["source"], categories=SOURCE_PRIORITY, ordered=True)
    frame = frame.sort_values("source", kind="stable")
    frame["source"] = frame["source"].astype(str)
    duplicate_rows = frame.duplicated(subset="normalized_url", keep="first")
    removed_duplicates = counts_by_source(frame[duplicate_rows])
    frame = frame[~duplicate_rows].copy()

    pool = frame.reset_index(drop=True)

    log("\nPOOL CONSTRUCTION (before sampling)")
    log(f"  loaded by source:              {loaded}")
    log(f"  removed (unparseable URL):     {removed_unparseable}")
    log(f"  removed (conflicting labels):  {removed_conflict}")
    log(f"  removed (duplicate URL):       {removed_duplicates}")
    log(f"  pool by source:                {counts_by_source(pool)}")

    for label, removed in (
        ("unparseable", removed_unparseable),
        ("conflicting labels", removed_conflict),
        ("duplicates", removed_duplicates),
    ):
        for source, count in removed.items():
            share = count / max(loaded.get(source, 1), 1)
            if share > 0.05:
                log(f"  WARNING: {count:,} {source} rows ({share:.1%}) removed as {label}.")

    report = {
        "loaded_by_source": loaded,
        "removed_unparseable_url": removed_unparseable,
        "removed_conflicting_labels": removed_conflict,
        "removed_duplicate_urls": removed_duplicates,
        "pool_by_source": counts_by_source(pool),
    }
    return pool, report


# ============================================================
# FEATURES
# ============================================================

def extract_feature_frame(urls, label: str):
    """Run the existing VIGIL extractor in chunks (bounded memory).
    Returns (frame, ok_mask, failures). Failed rows are zero-filled and ok_mask False."""
    urls = list(urls)
    n = len(urls)
    parts = []
    ok = np.zeros(n, dtype=bool)
    columns = None
    failures = 0
    started = time.perf_counter()
    for start in range(0, n, FEATURE_CHUNK):
        chunk = urls[start:start + FEATURE_CHUNK]
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
            log(f"  [{label}] features {min(start + FEATURE_CHUNK, n):,}/{n:,} "
                f"({time.perf_counter() - started:.0f}s)")
    if not parts:
        raise RuntimeError(f"Feature extraction failed for every {label} URL.")
    frame = pd.concat(parts).reindex(range(n)).fillna(0.0)
    return frame, ok, failures


# ============================================================
# STRATIFIED PHISHING.DATABASE SAMPLING
# ============================================================

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def stratification_dimensions(feed: pd.DataFrame, feats: pd.DataFrame) -> pd.DataFrame:
    """Integer level codes for every stratification characteristic."""
    urls = feed["url"].astype(str)
    normalized = feed["normalized_url"]
    parsed = normalized.map(safe_urlsplit)

    host = normalized.map(_hostname)
    host_len = host.str.len().to_numpy()
    host_labels = host.map(lambda h: 0 if (not h or ":" in h or _IPV4.match(h)) else len(h.split(".")))
    reg_labels = feed["registered_domain"].map(
        lambda d: 0 if (not d or d.startswith("__missing") or ":" in d or _IPV4.match(d)) else len(d.split("."))
    )
    subdomains = np.clip((host_labels - reg_labels).to_numpy(), 0, 3)

    url_len = urls.str.len().to_numpy()
    digits = urls.str.count(r"\d").to_numpy()
    digit_ratio = digits / np.maximum(url_len, 1)
    hyphens = urls.str.count("-").to_numpy()
    dots = urls.str.count(r"\.").to_numpy()
    percent = urls.str.contains("%", regex=False).to_numpy().astype(int)

    depth = parsed.map(lambda p: len([s for s in p.path.split("/") if s])).to_numpy()
    query_len = parsed.map(lambda p: len(p.query)).to_numpy()
    entropy = urls.map(shannon_entropy).to_numpy()

    def flag(column):
        if column in feats.columns:
            return (feats[column].to_numpy() > 0).astype(int)
        return np.zeros(len(feed), dtype=int)

    digit_level = np.where(digit_ratio == 0, 0, np.where(digit_ratio <= 0.05, 1,
                           np.where(digit_ratio <= 0.15, 2, 3)))
    query_level = np.where(query_len == 0, 0, np.where(query_len <= 20, 1,
                           np.where(query_len <= 60, 2, 3)))

    return pd.DataFrame(
        {
            "has_path": (depth > 0).astype(int),
            "has_query": (query_len > 0).astype(int),
            "suspicious_tld": flag("HasSuspiciousTLD"),
            "ip_host": flag("IsDomainIP"),
            "suspicious_token": flag("HasSuspiciousToken"),
            "percent_encoding": percent,
            "url_length_bucket": np.digitize(url_len, [40, 75, 100, 150]),
            "hostname_length_bucket": np.digitize(host_len, [15, 25, 40]),
            "subdomain_count": subdomains,
            "digit_ratio_bucket": digit_level,
            "hyphen_bucket": np.digitize(hyphens, [1, 2, 4]),
            "dot_bucket": np.digitize(dots, [2, 3, 4]),
            "path_depth_bucket": np.clip(depth, 0, 3),
            "query_length_bucket": query_level,
            "entropy_bucket": np.digitize(entropy, [3.5, 4.0, 4.5]),
            "url_length": url_len,
        },
        index=feed.index,
    )


PRIMARY_DIMENSIONS = [
    "has_path", "has_query", "suspicious_tld", "ip_host", "suspicious_token", "percent_encoding",
]
FINE_DIMENSIONS = [
    "url_length_bucket", "hostname_length_bucket", "subdomain_count", "digit_ratio_bucket",
    "hyphen_bucket", "dot_bucket", "path_depth_bucket", "query_length_bucket", "entropy_bucket",
]


def allocate_quotas(sizes: np.ndarray, hard: np.ndarray, target: int, rng) -> np.ndarray:
    """Proportional allocation with a mild boost for low-signal strata and
    largest-remainder rounding so the total equals `target` exactly."""
    weights = np.where(hard, LOW_SIGNAL_RATE_MULTIPLIER, 1.0) * sizes
    capped = np.zeros(len(sizes), dtype=bool)
    quota = np.zeros(len(sizes), dtype=float)
    for _ in range(len(sizes) + 1):
        remaining = target - sizes[capped].sum()
        free_weight = (weights * (~capped)).sum()
        if free_weight <= 0:
            quota = np.where(capped, sizes, 0.0)
            break
        proposal = weights * (~capped) * (remaining / free_weight)
        newly = (~capped) & (proposal >= sizes)
        if not newly.any():
            quota = np.where(capped, sizes, proposal)
            break
        capped |= newly

    base = np.floor(quota).astype(int)
    base = np.minimum(base, sizes)
    shortfall = int(target - base.sum())
    if shortfall > 0:
        remainder = (quota - base) + rng.random(len(sizes)) * 1e-9
        remainder[base >= sizes] = -1.0
        for index in np.argsort(-remainder, kind="stable")[:shortfall]:
            if base[index] < sizes[index]:
                base[index] += 1
    return base


def stratified_feed_sample(pool: pd.DataFrame, feats: pd.DataFrame):
    """Returns (kept_positions, strata_report)."""
    feed_positions = np.flatnonzero((pool["source"] == SOURCE_FEED).to_numpy())
    other_positions = np.flatnonzero((pool["source"] != SOURCE_FEED).to_numpy())
    eligible = len(feed_positions)
    target = min(PHISHING_DATABASE_SAMPLE_TARGET, eligible)

    if eligible <= PHISHING_DATABASE_SAMPLE_TARGET:
        log(f"\nPhishing.Database eligible rows ({eligible:,}) <= target "
            f"({PHISHING_DATABASE_SAMPLE_TARGET:,}); keeping all of them.")
        return np.sort(np.concatenate([other_positions, feed_positions])), {
            "method": "all eligible rows kept (no sampling needed)",
            "eligible_rows": int(eligible),
            "sampled_rows": int(eligible),
        }

    log(f"\nStratified sampling of Phishing.Database: {eligible:,} eligible -> {target:,} (seed={SEED})")
    feed = pool.iloc[feed_positions]
    dims = stratification_dimensions(feed, feats.iloc[feed_positions])

    rng = np.random.default_rng(SEED)
    primary = np.zeros(len(dims), dtype=np.int64)
    for bit, name in enumerate(PRIMARY_DIMENSIONS):
        primary += dims[name].to_numpy(dtype=np.int64) << bit

    codes, sizes = np.unique(primary, return_counts=True)
    hard = np.array([
        (code >> PRIMARY_DIMENSIONS.index("suspicious_tld")) & 1 == 0
        and (code >> PRIMARY_DIMENSIONS.index("ip_host")) & 1 == 0
        and (code >> PRIMARY_DIMENSIONS.index("suspicious_token")) & 1 == 0
        for code in codes
    ])
    allocation = allocate_quotas(sizes.astype(float), hard, target, rng)
    allocation_by_code = dict(zip(codes.tolist(), allocation.tolist()))

    # Order rows inside each primary stratum by the fine dimensions, then pick with a
    # systematic (every k-th) rule from a random start. This spreads the sample
    # proportionally across every fine dimension simultaneously.
    tiebreak = rng.random(len(dims))
    keys = [tiebreak, dims["url_length"].to_numpy()]
    keys += [dims[name].to_numpy() for name in reversed(FINE_DIMENSIONS)]
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

    kept = np.sort(np.concatenate([other_positions, feed_positions[selected_local]]))

    # ----- reporting -----
    sampled_mask = np.zeros(len(dims), dtype=bool)
    sampled_mask[selected_local] = True
    strata_rows = []
    for code, size, wanted, is_hard in zip(codes, sizes, allocation, hard):
        decoded = {name: int((int(code) >> bit) & 1) for bit, name in enumerate(PRIMARY_DIMENSIONS)}
        stratum = {
            "stratum_code": int(code),
            **decoded,
            "low_signal": bool(is_hard),
            "population": int(size),
            "sampled": int(wanted),
            "sampling_rate": float(wanted / size),
        }
        strata_rows.append(stratum)
        log(
            "  stratum "
            f"{int(code):02d} "
            f"path={stratum['has_path']} query={stratum['has_query']} "
            f"suspicious_tld={stratum['suspicious_tld']} "
            f"ip_host={stratum['ip_host']} "
            f"suspicious_token={stratum['suspicious_token']} "
            f"percent_encoding={stratum['percent_encoding']} "
            f"low_signal={stratum['low_signal']}: "
            f"selected {int(wanted):,} / {int(size):,}"
        )

    marginal_check = {}
    for name in PRIMARY_DIMENSIONS + FINE_DIMENSIONS:
        before = dims[name].value_counts(normalize=True)
        after = dims.loc[sampled_mask, name].value_counts(normalize=True)
        levels = before.index.union(after.index)
        deviation = float(max(abs(before.get(l, 0.0) - after.get(l, 0.0)) for l in levels))
        marginal_check[name] = {
            "population_share": {str(l): float(before.get(l, 0.0)) for l in levels},
            "sample_share": {str(l): float(after.get(l, 0.0)) for l in levels},
            "max_abs_share_difference": deviation,
        }

    low_signal_rows = np.isin(primary, codes[hard])
    fine_cells = int(len(dims[FINE_DIMENSIONS + PRIMARY_DIMENSIONS].drop_duplicates()))
    fine_cells_sampled = int(len(dims.loc[sampled_mask, FINE_DIMENSIONS + PRIMARY_DIMENSIONS].drop_duplicates()))

    log(f"  primary strata: {len(codes)}   occupied fine cells: {fine_cells:,} "
        f"(sample covers {fine_cells_sampled:,})")
    log(f"  low-signal share: population {low_signal_rows.mean():.3%} -> "
        f"sample {low_signal_rows[sampled_mask].mean():.3%}")
    worst = max(marginal_check.items(), key=lambda kv: kv[1]["max_abs_share_difference"])
    log(f"  largest marginal share difference: {worst[1]['max_abs_share_difference']:.4f} ({worst[0]})")

    report = {
        "method": (
            "primary strata (path, query, suspicious TLD, IP host, suspicious token, percent "
            "encoding) with proportional largest-remainder allocation and a low-signal boost; "
            "systematic sampling inside each stratum over rows ordered by the fine dimensions"
        ),
        "seed": SEED,
        "target": int(target),
        "eligible_rows": int(eligible),
        "sampled_rows": int(target),
        "low_signal_rate_multiplier": LOW_SIGNAL_RATE_MULTIPLIER,
        "primary_dimensions": PRIMARY_DIMENSIONS,
        "fine_dimensions": FINE_DIMENSIONS,
        "primary_strata_count": int(len(codes)),
        "occupied_fine_cells": fine_cells,
        "fine_cells_covered_by_sample": fine_cells_sampled,
        "low_signal_share_population": float(low_signal_rows.mean()),
        "low_signal_share_sample": float(low_signal_rows[sampled_mask].mean()),
        "primary_strata": strata_rows,
        "marginal_check": marginal_check,
    }
    return kept, report


# ============================================================
# CORPUS DIAGNOSTICS
# ============================================================

def structure_stats(frame: pd.DataFrame) -> dict:
    parsed = frame["normalized_url"].map(safe_urlsplit)
    table = pd.DataFrame(
        {
            "source": frame["source"].to_numpy(),
            "label": frame["label"].to_numpy(),
            "has_path": parsed.map(lambda p: p.path not in ("", "/")).to_numpy(),
            "has_query": parsed.map(lambda p: bool(p.query)).to_numpy(),
            "has_fragment": parsed.map(lambda p: bool(p.fragment)).to_numpy(),
        }
    )
    output = {}
    for (source, label), group in table.groupby(["source", "label"]):
        output[f"{source}|label={label}"] = {
            "rows": int(len(group)),
            "has_path_rate": float(group["has_path"].mean()),
            "has_query_rate": float(group["has_query"].mean()),
            "has_fragment_rate": float(group["has_fragment"].mean()),
        }
    return output


def corpus_diagnostics(corpus: pd.DataFrame) -> dict:
    corpus_domains = set(corpus["registered_domain"])
    domain_label = corpus.groupby("registered_domain")["label"].nunique()
    mixed = domain_label[domain_label > 1].index
    mixed_rows = corpus[corpus["registered_domain"].isin(mixed)]
    top_domains = corpus["registered_domain"].value_counts().head(10)

    n_legit = int((corpus["label"] == LABEL_LEGITIMATE).sum())
    n_phish = int((corpus["label"] == LABEL_PHISHING).sum())
    composition = {
        "legitimate": {k: int(v) for k, v in corpus[corpus["label"] == 0]["source"].value_counts().items()},
        "phishing": {k: int(v) for k, v in corpus[corpus["label"] == 1]["source"].value_counts().items()},
    }
    structure = structure_stats(corpus)

    log(f"\nFINAL TRAINING CORPUS: {len(corpus):,}")
    log(f"  legitimate: {n_legit:,}")
    log(f"  phishing:   {n_phish:,}")
    log("  source distribution:")
    for source, count in corpus["source"].value_counts().items():
        log(f"    {source:<28}{count:>10,}")
    log(f"  class composition by source: {composition}")
    log(f"  registered domains: {len(corpus_domains):,}")
    log(f"  domains carrying both labels: {len(mixed):,} ({len(mixed_rows):,} rows)")
    log("  largest domains: " + ", ".join(f"{d} ({c:,})" for d, c in top_domains.items()))
    log("  URL structure by source/label (path / query / fragment rates):")
    for key, value in structure.items():
        log(f"    {key:<42}{value['rows']:>9,}  {value['has_path_rate']:.3f} / "
            f"{value['has_query_rate']:.3f} / {value['has_fragment_rate']:.3f}")

    return {
        "final_rows": int(len(corpus)),
        "legitimate": n_legit,
        "phishing": n_phish,
        "source_distribution": {str(k): int(v) for k, v in corpus["source"].value_counts().items()},
        "class_composition_by_source": composition,
        "registered_domains": int(len(corpus_domains)),
        "domains_with_both_labels": int(len(mixed)),
        "rows_in_domains_with_both_labels": int(len(mixed_rows)),
        "largest_domains": {str(d): int(c) for d, c in top_domains.items()},
        "url_structure_by_source_label": structure,
    }


# ============================================================
# DOMAIN-ISOLATED SPLIT
# ============================================================

def domain_split(domains: pd.Series, fractions: dict, seed: int) -> np.ndarray:
    """Assign every registered domain to exactly one split. Domains are placed largest
    first into the split with the largest remaining row deficit, so split sizes stay
    close to the targets even when a few domains hold very many rows."""
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
        sources = counts_by_source(part)
        description[name] = {
            "rows": int(len(part)),
            "domains": int(part["registered_domain"].nunique()),
            "legitimate": legit,
            "phishing": phish,
            "source_counts": sources,
        }
        log(f"  {name:<12} rows={len(part):>9,}  domains={part['registered_domain'].nunique():>8,}  "
            f"legit={legit:>9,}  phishing={phish:>9,}")
        log(f"  {'':<12} sources={sources}")
        if legit == 0 or phish == 0:
            raise RuntimeError(f"Split '{name}' does not contain both classes.")

    domain_sets = [set(corpus.loc[split_ids == i, "registered_domain"]) for i in range(len(names))]
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            if domain_sets[i] & domain_sets[j]:
                raise RuntimeError(f"Registered-domain overlap between '{names[i]}' and '{names[j]}'.")
    log("  registered-domain overlap between splits: 0")
    return description


# ============================================================
# METRICS
# ============================================================

def metrics(y, probabilities, threshold: float = 0.5) -> dict:
    y = np.asarray(y, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    predictions = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(y, predictions, labels=[0, 1]).ravel()
    return {
        "threshold": float(threshold),
        "accuracy": float((tn + tp) / len(y)),
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
        if upper < 1.0:
            mask = (probabilities >= lower) & (probabilities < upper)
        else:
            mask = (probabilities >= lower) & (probabilities <= upper)
        if not mask.any():
            continue
        mean_probability = float(probabilities[mask].mean())
        positive_rate = float(y[mask].mean())
        ece += float(mask.mean()) * abs(mean_probability - positive_rate)
        reliability.append({
            "lower": float(lower), "upper": float(upper), "count": int(mask.sum()),
            "mean_probability": mean_probability, "positive_rate": positive_rate,
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
        "not_safe_recall": float((~safe)[phish].mean()) if phish.any() else 0.0,
        "false_phishing_rate": float(phishing[benign].mean()) if benign.any() else 0.0,
        "fpr": float(phishing[benign].mean()) if benign.any() else 0.0,
        "legitimate_not_safe_rate": float((~safe)[benign].mean()) if benign.any() else 0.0,
    }


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


def phishing_cohorts(urls: pd.Series, feats: pd.DataFrame, y, probabilities, threshold) -> dict:
    urls = urls.reset_index(drop=True)
    feats = feats.reset_index(drop=True)
    parsed = urls.map(safe_urlsplit)
    path = parsed.map(lambda p: p.path or "")
    masks = {
        "pathless_phishing": path.isin(["", "/"]),
        "short_phishing": urls.str.len() <= 60,
        "https_phishing": parsed.map(lambda p: p.scheme.lower() == "https"),
        "no_digits": urls.str.count(r"\d").eq(0),
    }

    def flag(column):
        return feats[column].astype(bool) if column in feats.columns else None

    token, tld, ip = flag("HasSuspiciousToken"), flag("HasSuspiciousTLD"), flag("IsDomainIP")
    if token is not None:
        masks["no_suspicious_token"] = ~token
    if tld is not None:
        masks["no_suspicious_tld"] = ~tld
    present = [f for f in (token, tld, ip) if f is not None]
    if present:
        combined = present[0].copy()
        for extra in present[1:]:
            combined = combined | extra
        masks["ordinary_looking_domains"] = ~combined

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


# ============================================================
# THRESHOLD SEARCH
# ============================================================

def threshold_for_fpr_budget(negative_sorted: np.ndarray, budget: float):
    """Lowest x such that mean(legitimate >= x) <= budget."""
    n = len(negative_sorted)
    if n == 0:
        return None
    allowed = min(int(math.floor(budget * n)), n - 1)
    cutoff = negative_sorted[n - allowed - 1]
    index = int(np.searchsorted(negative_sorted, cutoff, side="right"))
    if index < n:
        return float(negative_sorted[index])
    return float(np.nextafter(cutoff, np.inf))


def select_thresholds(y, probabilities) -> dict:
    """Maximise phishing recall subject to domain FPR <= 2% on the threshold split."""
    y = np.asarray(y, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    positive = np.sort(probabilities[y == 1])
    negative = np.sort(probabilities[y == 0])

    safe = float(SAFE_THRESHOLD)
    if len(positive):
        allowed = int(math.floor(MAX_PHISHING_BELOW_SAFE * len(positive)))
        safe = float(positive[min(allowed, len(positive) - 1)])

    phishing = threshold_for_fpr_budget(negative, HARD_FPR_LIMIT)
    if phishing is None:
        phishing = float(PHISHING_THRESHOLD)
    rule = "maximum phishing recall subject to threshold-split FPR <= 2.0%"

    if phishing <= safe:
        safe = min(safe, max(0.0, phishing - 0.05))

    return {
        "safe": float(safe),
        "phishing": float(phishing),
        "selection_rule": rule,
        "fpr_budget": HARD_FPR_LIMIT,
        "threshold_split_recall_at_selected_threshold": (
            float(np.mean(positive >= phishing))
            if len(positive)
            else 0.0
        ),
        "max_phishing_below_safe": MAX_PHISHING_BELOW_SAFE,
    }


def verdict_for(probability: float, thresholds: dict) -> str:
    if probability < thresholds["safe"]:
        return "SAFE"
    if probability >= thresholds["phishing"]:
        return "PHISHING"
    return "SUSPICIOUS"


def sensitivity(y_thr, p_thr, y_test, p_test, thresholds: dict) -> dict:
    """Report threshold-split and test sensitivity around the selected threshold."""
    y_thr, y_test = np.asarray(y_thr, int), np.asarray(y_test, int)

    def at(phishing_threshold):
        t = {"safe": min(thresholds["safe"], phishing_threshold), "phishing": phishing_threshold}
        thr_pol = policy(y_thr, p_thr, t)
        test_pol = policy(y_test, p_test, t)
        return {
            "phishing_threshold": float(phishing_threshold),
            "threshold_split": {"fpr": thr_pol["fpr"], "recall": thr_pol["phishing_recall"]},
            "test": {"fpr": test_pol["fpr"], "recall": test_pol["phishing_recall"]},
        }

    by_delta = [
        {"delta": float(d), **at(float(np.clip(thresholds["phishing"] + d, 0.0, 1.0)))}
        for d in DELTA_SWEEP
    ]
    return {"around_selected_threshold": by_delta}


# ============================================================
# MODELS
# ============================================================

def candidate_estimators() -> dict:
    return {
        "logistic_regression": Pipeline([
            ("scale", StandardScaler()),
            ("logreg", LogisticRegression(
                max_iter=2000, class_weight="balanced", solver="lbfgs", random_state=SEED)),
        ]),
        "hist_gradient_boosting": HistGradientBoostingClassifier(**HGB_PARAMS),
    }


def balanced_sample_weights(y: np.ndarray) -> np.ndarray:
    n = len(y)
    positives = max(int((y == 1).sum()), 1)
    negatives = max(int((y == 0).sum()), 1)
    return np.where(y == 1, n / (2.0 * positives), n / (2.0 * negatives))


def fit_candidate(name, X_train, y_train, X_cal, y_cal):
    estimator = candidate_estimators()[name]
    if name == "hist_gradient_boosting":
        estimator.fit(X_train, y_train, sample_weight=balanced_sample_weights(y_train.to_numpy()))
    else:
        estimator.fit(X_train, y_train)

    raw_calibration = estimator.predict_proba(X_cal)[:, 1]
    calibrator = LogisticRegression(solver="lbfgs", max_iter=1000, random_state=SEED)
    calibrator.fit(raw_calibration.reshape(-1, 1), y_cal)
    return estimator, calibrator, ProbabilityCalibratedModel(estimator, calibrator)


def measure_latency(model, row: pd.DataFrame) -> dict:
    for _ in range(5):
        model.predict_proba(row)
    values = []
    for _ in range(100):
        start = time.perf_counter()
        model.predict_proba(row)
        values.append((time.perf_counter() - start) * 1000.0)
    return {"median_ms": float(np.median(values)), "p95_ms": float(np.percentile(values, 95))}


def save_candidate(name, estimator, calibrator, feature_names, thresholds) -> tuple:
    """Portable payload (plain scikit-learn objects). Written ONLY inside the
    experiment directory. Returns (path, serialized_size_bytes)."""
    payload = {
        "format": "vigil-dynamic-recovery-candidate-v1",
        "experiment_only": True,
        "model_name": name,
        "estimator": estimator,
        "calibrator": calibrator,
        "feature_names": list(feature_names),
        "thresholds": {"safe": thresholds["safe"], "phishing": thresholds["phishing"]},
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    blob = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
    path = EXPERIMENT_DIR / f"candidate_{name}.pkl"
    atomic_write_bytes(path, blob, EXPERIMENT_DIR)
    return path, len(blob)


# ============================================================
# REGRESSION + EXTERNAL
# ============================================================

def regression_results(model, X_ref, thresholds, membership) -> dict:
    probabilities = model.predict_proba(X_ref)[:, 1]
    rows = []
    for url, probability in zip(REFERENCE_URLS, probabilities):
        verdict = verdict_for(float(probability), thresholds)
        if url in FAST_COM_URLS:
            expectation, passed = "SAFE", verdict == "SAFE"
        else:
            expectation, passed = "NOT_PHISHING", verdict != "PHISHING"
        rows.append({
            "url": url,
            "probability": float(probability),
            "verdict": verdict,
            "expectation": expectation,
            "passed": bool(passed),
            **membership[url],
        })
    counts = {k: sum(r["verdict"] == k for r in rows) for k in ("SAFE", "SUSPICIOUS", "PHISHING")}
    return {"results": rows, "counts": counts}


def evaluate_production_model(X_test, y_test, X_ref, membership) -> dict:
    """Compare the installed production model on the candidate test domains."""
    required_paths = (PRODUCTION_MODEL_PATH, PRODUCTION_FEATURES_PATH)
    missing = [str(path) for path in required_paths if not path.is_file()]
    if missing:
        reason = f"Required production artifact(s) missing: {missing}"
        log(f"Production comparison unavailable: {reason}")
        return {"available": False, "reason": reason}

    try:
        with PRODUCTION_MODEL_PATH.open("rb") as stream:
            model = pickle.load(stream)
        with PRODUCTION_FEATURES_PATH.open("rb") as stream:
            feature_names = pickle.load(stream)

        if not isinstance(feature_names, (list, tuple)):
            raise TypeError("feature_names.pkl must contain a list or tuple.")
        feature_names = list(feature_names)
        missing_features = sorted(set(feature_names) - set(X_test.columns))
        if missing_features:
            reason = (
                "Production feature set is incompatible with the candidate "
                f"extractor output; missing features: {missing_features}"
            )
            log(f"Production comparison unavailable: {reason}")
            return {
                "available": False,
                "reason": reason,
            }

        production_thresholds = {
            "safe": float(SAFE_THRESHOLD),
            "phishing": float(PHISHING_THRESHOLD),
        }
        production_test = X_test.loc[:, feature_names]
        probabilities = model.predict_proba(production_test)[:, 1]
        test_metrics = metrics(y_test, probabilities)
        test_metrics["calibration"] = calibration_metrics(y_test, probabilities)
        test_metrics["policy"] = policy(
            y_test,
            probabilities,
            production_thresholds,
        )

        regression = regression_results(
            model,
            X_ref.loc[:, feature_names],
            production_thresholds,
            membership,
        )
        return {
            "available": True,
            "model_path": str(PRODUCTION_MODEL_PATH.relative_to(ROOT)),
            "feature_count": len(feature_names),
            "domain_test": test_metrics,
            "regression": regression,
            "thresholds": production_thresholds,
        }
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        log(f"Production comparison unavailable: {reason}")
        return {"available": False, "reason": reason}


# ============================================================
# GATES
# ============================================================

def build_gates(ev: dict) -> dict:
    results = ev["regression"]["results"]

    def verdicts(predicate):
        return {r["url"]: r["verdict"] for r in results if predicate(r["url"])}

    google = verdicts(lambda u: u in GOOGLE_SEARCH_URLS)
    youtube = verdicts(lambda u: u in YOUTUBE_QUERY_URLS)
    fast = verdicts(lambda u: u in FAST_COM_URLS)
    other = verdicts(lambda u: u not in GOOGLE_SEARCH_URLS | YOUTUBE_QUERY_URLS | FAST_COM_URLS)

    def gate(requirement, actual, passed):
        return {"requirement": requirement, "actual": actual, "passed": bool(passed)}

    fpr = ev["domain_test"]["policy"]["fpr"]
    ece = ev["domain_test"]["calibration"]["expected_calibration_error"]
    size = ev["profile"]["model_size_bytes"]
    latency = ev["profile"]["median_latency_ms"]

    return {
        "domain_fpr": gate(f"<= {GATE_MAX_DOMAIN_FPR}", fpr, fpr <= GATE_MAX_DOMAIN_FPR),
        "calibration_ece": gate(f"<= {GATE_MAX_ECE}", ece, ece <= GATE_MAX_ECE),
        "google_search_not_phishing": gate(
            "no Google search URL classified PHISHING", google,
            bool(google) and all(v != "PHISHING" for v in google.values())),
        "youtube_query_not_phishing": gate(
            "YouTube query URL not classified PHISHING", youtube,
            bool(youtube) and all(v != "PHISHING" for v in youtube.values())),
        "fast_com_variants_safe": gate(
            "all fast.com variants classified SAFE", fast,
            bool(fast) and all(v == "SAFE" for v in fast.values())),
        "other_legitimate_not_phishing": gate(
            "no other legitimate reference classified PHISHING", other,
            bool(other) and all(v != "PHISHING" for v in other.values())),
        "model_size": gate(f"<= {GATE_MAX_MODEL_BYTES / (1024 * 1024):.0f} MB", size,
                           size <= GATE_MAX_MODEL_BYTES),
        "median_latency": gate(f"<= {GATE_MAX_MEDIAN_LATENCY_MS} ms", latency,
                               latency <= GATE_MAX_MEDIAN_LATENCY_MS),
    }


# ============================================================
# CONSOLE TABLE
# ============================================================

def print_table(summaries: list, best_name: str, decision: str) -> None:
    headers = ["MODEL", "DOMAIN RECALL", "DOMAIN FPR", "PR-AUC", "ROC-AUC", "ECE",
               "MODEL SIZE", "LATENCY", "GOOGLE SEARCH", "YOUTUBE QUERY", "FAST.COM", "GATES"]
    rows = []
    for s in summaries:
        rows.append([
            s["model"],
            f"{s['domain_recall']:.2%}",
            f"{s['domain_fpr']:.2%}",
            f"{s['pr_auc']:.4f}",
            f"{s['roc_auc']:.4f}",
            f"{s['ece']:.4f}",
            f"{s['size_bytes'] / (1024 * 1024):.2f} MB",
            f"{s['latency_ms']:.2f} ms",
            "PASS" if s["google"] else "FAIL",
            "PASS" if s["youtube"] else "FAIL",
            "PASS" if s["fast"] else "FAIL",
            "PASS" if s["gates"] else "FAIL",
        ])
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    line = "-+-".join("-" * w for w in widths)
    log("\n" + " | ".join(h.ljust(w) for h, w in zip(headers, widths)))
    log(line)
    for r in rows:
        log(" | ".join(c.ljust(w) for c, w in zip(r, widths)))
    log(line)
    log(f"BEST CANDIDATE: {best_name}")
    log(f"FINAL DECISION: {decision}")


# ============================================================
# MAIN
# ============================================================

def main() -> dict:
    started_at = time.perf_counter()
    log("=" * 78)
    log("VIGIL - DYNAMIC RECOVERY EXPERIMENT (EXPERIMENT ONLY)")
    log("=" * 78)
    log(f"Command: {RUN_COMMAND}")
    log("EXTERNAL HOLDOUT: NOT USED IN THIS EXPERIMENT")
    log("Expect several minutes: features are extracted for every training-pool row "
        "and regression reference.")

    hashes_before = hash_production_artifacts()
    missing_artifacts = [n for n, h in hashes_before.items() if h is None]
    if missing_artifacts:
        log(f"NOTE: production artifacts not found (hash recorded as null): {missing_artifacts}")

    # ------------------------------------------------------------------
    # Pool, features, stratified sample
    # ------------------------------------------------------------------
    pool, pool_report = build_pool()
    pool["registered_domain"] = registered_domains(pool["normalized_url"])

    log("\nExtracting features for the candidate pool...")
    pool_features, ok, failures = extract_feature_frame(pool["url"], "pool")
    failed_by_source = counts_by_source(pool[~ok])
    if failures:
        raise RuntimeError(
            f"Feature extraction failed for {failures:,} corpus rows: "
            f"{failed_by_source}. Refusing to silently reduce the requested corpus."
        )

    kept, strata_report = stratified_feed_sample(pool, pool_features)
    corpus = pool.iloc[kept].reset_index(drop=True)
    features_all = pool_features.iloc[kept].reset_index(drop=True)
    del pool, pool_features

    corpus_report = corpus_diagnostics(corpus)

    names = [c for c in features_all.columns if c not in set(MODEL_EXCLUDED_FEATURES)]
    log(f"\nModel features: {len(names)}")
    if len(names) != 29:
        raise RuntimeError(
            f"Expected the existing 29 VIGIL model features, found {len(names)}."
        )
    X = features_all[names].copy()
    y = corpus["label"].astype(int).reset_index(drop=True)

    # ------------------------------------------------------------------
    # Domain-isolated split
    # ------------------------------------------------------------------
    split_names = list(SPLIT_FRACTIONS)
    split_ids = domain_split(corpus["registered_domain"], SPLIT_FRACTIONS, SEED)
    split_description = describe_splits(corpus, split_ids, split_names)
    idx = {name: np.where(split_ids == i)[0] for i, name in enumerate(split_names)}
    train_idx, cal_idx, thr_idx, test_idx = idx["train"], idx["calibration"], idx["threshold"], idx["test"]

    # ------------------------------------------------------------------
    # Regression references are evaluation-only and never alter training.
    # ------------------------------------------------------------------
    ref_frame, ref_ok, ref_failures = extract_feature_frame(REFERENCE_URLS, "regression")
    if ref_failures:
        raise RuntimeError("Feature extraction failed for one or more regression URLs.")
    X_ref = ref_frame.reindex(columns=names, fill_value=0.0)

    # Membership of the regression URLs (exact normalised URL and domain).
    split_by_url = dict(zip(corpus["normalized_url"], (split_names[i] for i in split_ids)))
    split_by_domain = dict(zip(corpus["registered_domain"], (split_names[i] for i in split_ids)))
    domain_rows = corpus["registered_domain"].value_counts()
    reference_norm = [normalize_url(u) for u in REFERENCE_URLS]
    reference_domains = registered_domains(pd.Series(reference_norm)).tolist()
    membership = {}
    for url, norm, domain in zip(REFERENCE_URLS, reference_norm, reference_domains):
        membership[url] = {
            "normalized_url": norm,
            "exact_url_split": split_by_url.get(norm, "absent"),
            "exact_url_in_split": {
                name: split_by_url.get(norm) == name
                for name in split_names
            },
            "registered_domain": domain,
            "domain_split": split_by_domain.get(domain, "absent"),
            "domain_in_split": {
                name: split_by_domain.get(domain) == name
                for name in split_names
            },
            "corpus_rows_in_domain": int(domain_rows.get(domain, 0)),
        }
    log("\nREGRESSION URL MEMBERSHIP (exact normalised URL / registered domain)")
    for url in REFERENCE_URLS:
        m = membership[url]
        log(f"  {url:<42} url: {m['exact_url_split']:<12} domain: {m['domain_split']:<12} "
            f"(domain rows {m['corpus_rows_in_domain']:,})")
    seen_exact = [u for u, m in membership.items() if m["exact_url_split"] != "absent"]
    if seen_exact:
        log(f"  NOTE: these regression URLs appear verbatim in the corpus, so passing them is "
            f"not evidence of generalisation: {seen_exact}")
    outside_train = sorted({m["registered_domain"] for m in membership.values()
                            if m["domain_split"] not in ("train", "absent")})
    if outside_train:
        log(f"  NOTE: these regression domains are NOT in the training split: {outside_train}")

    production_comparison = evaluate_production_model(
        X.iloc[test_idx],
        y.iloc[test_idx],
        X_ref,
        membership,
    )

    # ------------------------------------------------------------------
    # Train / calibrate / threshold / evaluate each candidate
    # ------------------------------------------------------------------
    y_thr, y_test = y.iloc[thr_idx], y.iloc[test_idx]
    sources_test = corpus["source"].iloc[test_idx].to_numpy()
    X_ref_row = X.iloc[test_idx].iloc[[0]]
    evaluations = {}
    saved_paths = {}

    for name in candidate_estimators():
        log(f"\nTraining {name}...")
        fit_started = time.perf_counter()
        estimator, calibrator, model = fit_candidate(
            name, X.iloc[train_idx], y.iloc[train_idx], X.iloc[cal_idx], y.iloc[cal_idx])
        fit_seconds = time.perf_counter() - fit_started

        p_thr = model.predict_proba(X.iloc[thr_idx])[:, 1]
        thresholds = select_thresholds(y_thr, p_thr)

        p_test = model.predict_proba(X.iloc[test_idx])[:, 1]
        test_metrics = metrics(y_test, p_test)
        test_metrics["calibration"] = calibration_metrics(y_test, p_test)
        test_metrics["policy"] = policy(y_test, p_test, thresholds)
        test_metrics["by_source"] = source_breakdown(sources_test, y_test, p_test, thresholds)
        test_metrics["hard_cohorts"] = phishing_cohorts(
            corpus["url"].iloc[test_idx], features_all.iloc[test_idx], y_test, p_test,
            thresholds["phishing"])

        threshold_metrics = metrics(y_thr, p_thr)
        threshold_metrics["calibration"] = calibration_metrics(y_thr, p_thr)
        threshold_metrics["policy"] = policy(y_thr, p_thr, thresholds)

        sens = sensitivity(y_thr, p_thr, y_test, p_test, thresholds)
        regression = regression_results(model, X_ref, thresholds, membership)

        path, size_bytes = save_candidate(name, estimator, calibrator, names, thresholds)
        saved_paths[name] = str(path.relative_to(ROOT))
        latency = measure_latency(model, X_ref_row)
        profile = {
            "model_size_bytes": int(size_bytes),
            "median_latency_ms": latency["median_ms"],
            "p95_latency_ms": latency["p95_ms"],
            "fit_seconds": float(fit_seconds),
            "candidate_artifact": saved_paths[name],
        }

        ev = {
            "thresholds": thresholds,
            "threshold_split": threshold_metrics,
            "domain_test": test_metrics,
            "threshold_sensitivity": sens,
            "regression": regression,
            "profile": profile,
        }
        ev["gates"] = build_gates(ev)
        evaluations[name] = ev

        pol = test_metrics["policy"]
        log(f"  thresholds: safe={thresholds['safe']:.4f} phishing={thresholds['phishing']:.4f} "
            f"({thresholds['selection_rule']})")
        log(f"  domain test: recall={pol['phishing_recall']:.4f} FPR={pol['fpr']:.4f} "
            f"PR-AUC={test_metrics['pr_auc']:.4f} ROC-AUC={test_metrics['roc_auc']:.4f} "
            f"ECE={test_metrics['calibration']['expected_calibration_error']:.4f}")
        log(f"  size={size_bytes:,} bytes  median latency={latency['median_ms']:.3f} ms  "
            f"fit={fit_seconds:.1f}s")
        log("  by source (test): " + "; ".join(
            f"{k}: phish-verdict {v['phishing_verdict_rate']:.3f}"
            for k, v in test_metrics["by_source"].items()))

    # ------------------------------------------------------------------
    # Production safety check, final gates, ranking
    # ------------------------------------------------------------------
    hashes_after = hash_production_artifacts()
    hashes_unchanged = (
        hashes_before == hashes_after
        and all(value is not None for value in hashes_before.values())
    )

    for ev in evaluations.values():
        ev["gates"]["production_hashes_unchanged"] = {
            "requirement": "SHA-256 of production artifacts identical before and after",
            "actual": {"before": hashes_before, "after": hashes_after},
            "passed": bool(hashes_unchanged),
        }
        ev["gates_passed"] = all(g["passed"] for g in ev["gates"].values())
        ev["gates_passed_count"] = int(sum(g["passed"] for g in ev["gates"].values()))

    def rank_key(name):
        ev = evaluations[name]
        return (
            ev["threshold_split"]["policy"]["phishing_recall"],
            -ev["threshold_split"]["policy"]["fpr"],
            -ev["threshold_split"]["calibration"]["expected_calibration_error"],
        )

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
            "pr_auc": ev["domain_test"]["pr_auc"],
            "roc_auc": ev["domain_test"]["roc_auc"],
            "ece": ev["domain_test"]["calibration"]["expected_calibration_error"],
            "size_bytes": ev["profile"]["model_size_bytes"],
            "latency_ms": ev["profile"]["median_latency_ms"],
            "google": g["google_search_not_phishing"]["passed"],
            "youtube": g["youtube_query_not_phishing"]["passed"],
            "fast": g["fast_com_variants_safe"]["passed"],
            "gates": ev["gates_passed"],
        })

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    report = {
        "experiment": "dynamic_recovery",
        "final_decision": decision,
        "decision_note": "Informational only: this script never promotes a model automatically.",
        "automatic_promotion": False,
        "best_candidate": best_name,
        "ranking_rule": (
            "highest threshold-split phishing recall, then lowest threshold-split domain FPR, "
            "then lowest threshold-split ECE"
        ),
        "run_command": RUN_COMMAND,
        "external_holdout": {
            "used": False,
            "statement": "EXTERNAL HOLDOUT: NOT USED IN THIS EXPERIMENT",
        },
        "production_comparison": production_comparison,
        "production_artifacts_updated": False,
        "production_hashes_unchanged": hashes_unchanged,
        "production_hashes_before": hashes_before,
        "production_hashes_after": hashes_after,
        "pool": pool_report,
        "feature_extraction_failures_pool": {"count": int(failures), "by_source": failed_by_source},
        "phishing_database_stratified_sample": strata_report,
        "training_corpus": corpus_report,
        "source_counts": counts_by_source(corpus),
        "feature_count": len(names),
        "feature_names": names,
        "domain_split": split_description,
        "regression_url_membership": membership,
        "candidate_artifacts": saved_paths,
        "hyperparameters": {
            "hist_gradient_boosting": {k: v for k, v in HGB_PARAMS.items()},
            "logistic_regression": {"max_iter": 2000, "class_weight": "balanced",
                                    "solver": "lbfgs", "scaler": "StandardScaler"},
        },
        "gate_limits": {
            "max_domain_fpr": GATE_MAX_DOMAIN_FPR,
            "max_ece": GATE_MAX_ECE,
            "max_model_bytes": GATE_MAX_MODEL_BYTES,
            "max_median_latency_ms": GATE_MAX_MEDIAN_LATENCY_MS,
        },
        "candidate_models": evaluations,
        "seed": SEED,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runtime_seconds": float(time.perf_counter() - started_at),
    }
    atomic_write_bytes(
        REPORT_PATH,
        json.dumps(to_jsonable(report), indent=2).encode("utf-8"),
        REPORT_PATH.parent,
    )

    # ------------------------------------------------------------------
    # Console summary
    # ------------------------------------------------------------------
    log("\n" + "=" * 78)
    log("REGRESSION URLS (best candidate)")
    log("=" * 78)
    for row in best["regression"]["results"]:
        log(f"  [{'ok  ' if row['passed'] else 'FAIL'}] {row['verdict']:<10} "
            f"{row['probability']:.6f}  {row['url']}")

    log("\nGATES (best candidate)")
    for gate, info in best["gates"].items():
        log(f"  {'PASS' if info['passed'] else 'FAIL'}  {gate}")

    log("\nTHRESHOLD SENSITIVITY (best candidate, around selected phishing threshold)")
    log("  delta   threshold   thr-FPR  thr-recall  test-FPR  test-recall")
    for row in best["threshold_sensitivity"]["around_selected_threshold"]:
        log(f"  {row['delta']:+.2f}   {row['phishing_threshold']:.4f}     "
            f"{row['threshold_split']['fpr']:.4f}   {row['threshold_split']['recall']:.4f}      "
            f"{row['test']['fpr']:.4f}    {row['test']['recall']:.4f}")

    print_table(summaries, best_name, decision)
    log(f"\nProduction artifacts unchanged: {hashes_unchanged}")
    log(f"Candidate artifacts: {EXPERIMENT_DIR}")
    log(f"Report: {REPORT_PATH}")
    log(f"Run command: {RUN_COMMAND}")

    best_pol = best["domain_test"]["policy"]
    regression_rows = {
        row["url"]: row["verdict"]
        for row in best["regression"]["results"]
    }
    google_pass = all(
        regression_rows[url] != "PHISHING"
        for url in GOOGLE_SEARCH_URLS
    )
    youtube_pass = all(
        regression_rows[url] != "PHISHING"
        for url in YOUTUBE_QUERY_URLS
    )
    fast_pass = all(
        regression_rows[url] == "SAFE"
        for url in FAST_COM_URLS
    )
    log("\n" + "=" * 78)
    log("FINAL RESULT")
    log("=" * 78)
    log(f"MODEL: {best_name}")
    log(f"DOMAIN RECALL: {best_pol['phishing_recall']:.4%}")
    log(f"DOMAIN FPR: {best_pol['fpr']:.4%}")
    log(f"PR-AUC: {best['domain_test']['pr_auc']:.6f}")
    log(f"ROC-AUC: {best['domain_test']['roc_auc']:.6f}")
    log(f"ECE: {best['domain_test']['calibration']['expected_calibration_error']:.6f}")
    log(f"MODEL SIZE: {best['profile']['model_size_bytes']:,} bytes")
    log(f"LATENCY: {best['profile']['median_latency_ms']:.3f} ms median")
    log(f"GOOGLE SEARCH: {'PASS' if google_pass else 'FAIL'}")
    log(f"YOUTUBE QUERY: {'PASS' if youtube_pass else 'FAIL'}")
    log(f"FAST.COM: {'PASS' if fast_pass else 'FAIL'}")
    if production_comparison["available"]:
        production_metrics = production_comparison["domain_test"]
        production_regressions = {
            row["url"]: row["verdict"]
            for row in production_comparison["regression"]["results"]
        }
        production_google = [
            production_regressions[url]
            for url in GOOGLE_SEARCH_URLS
        ]
        production_youtube = [
            production_regressions[url]
            for url in YOUTUBE_QUERY_URLS
        ]
        production_fast = [
            production_regressions[url]
            for url in FAST_COM_URLS
        ]
        log(
            "PRODUCTION COMPARISON: "
            f"recall={production_metrics['policy']['phishing_recall']:.4%}, "
            f"FPR={production_metrics['policy']['fpr']:.4%}, "
            f"PR-AUC={production_metrics['pr_auc']:.6f}, "
            f"ROC-AUC={production_metrics['roc_auc']:.6f}, "
            f"ECE={production_metrics['calibration']['expected_calibration_error']:.6f}"
        )
        log(
            "PRODUCTION REGRESSION VERDICTS: "
            f"Google search={production_google}; YouTube query={production_youtube}; "
            f"fast.com={production_fast}"
        )
    else:
        log(f"PRODUCTION COMPARISON: UNAVAILABLE ({production_comparison['reason']})")
    log(f"GATES: {'PASS' if best['gates_passed'] else 'FAIL'}")
    log("PRODUCTION ARTIFACTS UPDATED: False")
    log("FINAL DECISION:")
    log(decision)

    if not hashes_unchanged:
        raise RuntimeError(
            "PRODUCTION ARTIFACT CHANGED DURING THE EXPERIMENT. "
            f"before={hashes_before} after={hashes_after}"
        )
    return report


if __name__ == "__main__":
    main()
