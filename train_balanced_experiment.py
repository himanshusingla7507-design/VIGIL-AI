#!/usr/bin/env python3
"""
VIGIL balanced-training experiment (EXPERIMENT ONLY).

Corpus
------
  * ALL PhiUSIIL rows                                 (source: PhiUSIIL)
  * ALL verified benign dynamic URLs                  (source: verified_benign_dynamic)
  * ~167,000 uniformly sampled Phishing.Database URLs (source: phishing_database_active)

Labels: 0 = legitimate, 1 = phishing.

Models: LogisticRegression (standardised) and HistGradientBoostingClassifier.
RandomForest is intentionally not used.

Safety
------
  * Never writes phishing_model.pkl, feature_names.pkl or feature_importance.csv.
  * Never promotes the candidate. The only file written is
    reports/dynamic_training_comparison.json.
  * SHA-256 hashes of the production artifacts are taken before and after the run
    and the report states whether any of them changed.
  * No hardcoded trusted domains and no score boosts. The regression URLs are used
    only as an evaluation set.

Run from anywhere:   python train_balanced_experiment.py
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

SEED = 42
PHISHING_DATABASE_SAMPLE_SIZE = 167_000

LABEL_LEGITIMATE = 0
LABEL_PHISHING = 1

SOURCE_PHIUSIIL = "PhiUSIIL"
SOURCE_FEED = "phishing_database_active"
SOURCE_DYNAMIC = "verified_benign_dynamic"

# Order matters: it is the keep-priority when the same URL appears in several sources.
SOURCE_PRIORITY = [SOURCE_PHIUSIIL, SOURCE_DYNAMIC, SOURCE_FEED]

DATASET_PATH = ROOT / "data" / "processed" / "clean_dataset.csv"
EXTERNAL_PATH = ROOT / "data" / "processed" / "external_validation.csv"
DYNAMIC_PATH = ROOT / "data" / "external" / "benign_dynamic" / "legitimate_dynamic_urls.csv"
REPORT_PATH = ROOT / "reports" / "dynamic_training_comparison.json"

PRODUCTION_MODEL_PATH = ROOT / "phishing_model.pkl"
PRODUCTION_FEATURES_PATH = ROOT / "feature_names.pkl"
PRODUCTION_IMPORTANCE_PATH = ROOT / "feature_importance.csv"
PROTECTED_ARTIFACTS = [
    PRODUCTION_MODEL_PATH,
    PRODUCTION_FEATURES_PATH,
    PRODUCTION_IMPORTANCE_PATH,
]

# Domain-isolated split targets (fractions of rows, approximate because whole
# registered domains are assigned to a single split).
SPLIT_FRACTIONS = {
    "train": 0.45,
    "calibration": 0.15,
    "threshold": 0.20,
    "test": 0.20,
}

# Threshold-search policy (same budgets as the existing VIGIL pipeline).
MAX_PHISHING_BELOW_SAFE = 0.02      # at most 2% of phishing may be called SAFE
MAX_BENIGN_AT_PHISHING = 0.01       # at most 1% of legitimate may be called PHISHING

# Gates.
GATE_MAX_DOMAIN_FPR = 0.01
GATE_MIN_EXTERNAL_RECALL = 0.9124
PRODUCTION_RECALL_BASELINE = 0.9124   # used only if production cannot be re-measured
GATE_MAX_ECE = 0.05
GATE_MAX_MODEL_BYTES = 25 * 1024 * 1024
GATE_MAX_MEDIAN_LATENCY_MS = 50.0

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

# Expected outcomes used ONLY to evaluate the model, never to alter its output.
GOOGLE_SEARCH_URLS = {
    "https://google.com/search?q=test",
    "https://www.google.com/search?q=test",
}
YOUTUBE_QUERY_URLS = {"https://www.youtube.com/?feature=ytca"}
FAST_COM_URLS = {"https://fast.com", "https://fast.com/", "https://www.fast.com/"}


# ============================================================
# PROBABILITY CALIBRATION
# (same class name / semantics as the existing VIGIL pipeline, so a production
#  pickle that references it can still be unpickled for comparison)
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


def atomic_write_text(path: Path, text: str) -> None:
    protected = {p.resolve() for p in PROTECTED_ARTIFACTS}
    if path.resolve() in protected:
        raise RuntimeError(f"Refusing to write protected production artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".vigil-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
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
    """Normalisation used for de-duplication and overlap tests only.
    Features are always extracted from the ORIGINAL url string."""
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
    domains = hosts.map(cache)
    # A row with no usable domain gets its own unique group instead of
    # collapsing into one giant empty-string group.
    missing = domains.fillna("").eq("")
    if missing.any():
        domains = domains.where(~missing, pd.Series(
            [f"__missing_domain_{i}" for i in domains.index], index=domains.index))
    return domains


# ============================================================
# DATA LOADING
# ============================================================

def read_url_column(path: Path, description: str) -> pd.DataFrame:
    require_file(path, description)
    header = pd.read_csv(path, nrows=0)
    if "url" not in header.columns:
        raise ValueError(f"{description} must contain a 'url' column: {path}")
    columns = ["url"] + [c for c in ("label",) if c in header.columns]
    frame = pd.read_csv(path, usecols=columns, dtype={"url": "string"})
    frame = frame.dropna(subset=["url"]).copy()
    frame["url"] = frame["url"].astype(str)
    return frame


def load_external_holdout() -> pd.DataFrame:
    holdout = read_url_column(EXTERNAL_PATH, "External phishing holdout")
    if "label" in holdout.columns:
        labels = set(pd.to_numeric(holdout["label"], errors="coerce").dropna().astype(int).unique())
        if labels and labels != {LABEL_PHISHING}:
            raise ValueError("External phishing holdout must contain phishing label 1 only.")
    holdout = holdout[["url"]].reset_index(drop=True)
    if holdout.empty:
        raise ValueError("External phishing holdout is empty.")
    return holdout


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
        log(
            "WARNING: ignoring clean_dataset.csv rows with other sources "
            f"(the dynamic set is loaded separately): {counts_by_source(unknown)}"
        )
        base = base[base["source"].isin(known)].copy()

    phi_labels = set(base.loc[base["source"] == SOURCE_PHIUSIIL, "label"].unique())
    if phi_labels != {LABEL_LEGITIMATE, LABEL_PHISHING}:
        raise ValueError(f"PhiUSIIL must contain both classes, found labels {sorted(phi_labels)}")
    feed_labels = set(base.loc[base["source"] == SOURCE_FEED, "label"].unique())
    if feed_labels != {LABEL_PHISHING}:
        raise ValueError(
            f"{SOURCE_FEED} must be phishing (1) only, found labels {sorted(feed_labels)}"
        )
    return base


def load_dynamic_dataset() -> pd.DataFrame:
    dynamic = read_url_column(DYNAMIC_PATH, "Verified benign dynamic URL dataset")
    dynamic = dynamic[["url"]].copy()
    dynamic["label"] = LABEL_LEGITIMATE
    dynamic["source"] = SOURCE_DYNAMIC
    log(f"Verified benign dynamic rows loaded: {len(dynamic):,}")
    return dynamic


def structure_stats(frame: pd.DataFrame) -> dict:
    """How many URLs of each source/label carry a path, query or fragment.
    Large differences between classes reveal shortcut features."""
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


def build_corpus(external_urls: set, external_domains: set):
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
    loaded_by_source = counts_by_source(frame)
    frame["normalized_url"] = frame["url"].map(normalize_url)

    # 1. Unparseable URLs (reported, never silent).
    unparseable = frame["normalized_url"].eq("")
    removed_unparseable = counts_by_source(frame[unparseable])
    frame = frame[~unparseable].copy()

    # 2. Exact URL overlap with the external phishing holdout.
    in_holdout = frame["normalized_url"].isin(external_urls)
    removed_holdout = counts_by_source(frame[in_holdout])
    frame = frame[~in_holdout].copy()

    # 3. URLs that appear with BOTH labels are ambiguous: drop every copy.
    label_counts = frame.groupby("normalized_url")["label"].nunique()
    conflicting = set(label_counts[label_counts > 1].index)
    conflict_rows = frame["normalized_url"].isin(conflicting)
    removed_conflict = counts_by_source(frame[conflict_rows])
    frame = frame[~conflict_rows].copy()

    # 4. Remove duplicate URLs, keeping the highest-priority source.
    frame["source"] = pd.Categorical(frame["source"], categories=SOURCE_PRIORITY, ordered=True)
    frame = frame.sort_values("source", kind="stable")
    before = len(frame)
    frame["source"] = frame["source"].astype(str)
    duplicate_rows = frame.duplicated(subset="normalized_url", keep="first")
    removed_duplicates = counts_by_source(frame[duplicate_rows])
    frame = frame[~duplicate_rows].copy()
    assert before - len(frame) == int(duplicate_rows.sum())

    # 5. Keep all PhiUSIIL and all dynamic rows; sample the feed reproducibly.
    feed_mask = frame["source"] == SOURCE_FEED
    feed = frame[feed_mask]
    keep = frame[~feed_mask]
    eligible = len(feed)
    sample_n = min(PHISHING_DATABASE_SAMPLE_SIZE, eligible)
    feed_sample = feed.sample(n=sample_n, random_state=SEED)

    corpus = pd.concat([keep, feed_sample], ignore_index=True)
    corpus["registered_domain"] = registered_domains(corpus["normalized_url"])

    # Diagnostics: overlap with external holdout domains (reported, not filtered).
    corpus_domains = set(corpus["registered_domain"])
    domain_overlap = corpus_domains & external_domains
    overlap_rows = corpus[corpus["registered_domain"].isin(domain_overlap)]
    top_overlap = (
        overlap_rows.groupby(["registered_domain", "label"]).size()
        .sort_values(ascending=False).head(10)
    )

    # Diagnostics: domains carrying both labels and domain concentration.
    domain_label = corpus.groupby("registered_domain")["label"].nunique()
    mixed_domains = domain_label[domain_label > 1].index
    mixed_rows = corpus[corpus["registered_domain"].isin(mixed_domains)]
    top_domains = corpus["registered_domain"].value_counts().head(10)

    n_legit = int((corpus["label"] == LABEL_LEGITIMATE).sum())
    n_phish = int((corpus["label"] == LABEL_PHISHING).sum())
    by_label_source = {
        "legitimate": {k: int(v) for k, v in corpus[corpus["label"] == 0]["source"].value_counts().items()},
        "phishing": {k: int(v) for k, v in corpus[corpus["label"] == 1]["source"].value_counts().items()},
    }

    log("\nCORPUS CONSTRUCTION")
    log(f"  loaded by source:              {loaded_by_source}")
    log(f"  removed (unparseable URL):     {removed_unparseable}")
    log(f"  removed (exact holdout URL):   {removed_holdout}")
    log(f"  removed (conflicting labels):  {removed_conflict}")
    log(f"  removed (duplicate URL):       {removed_duplicates}")
    log(f"  Phishing.Database eligible:    {eligible:,}")
    log(f"  Phishing.Database sampled:     {sample_n:,} (seed={SEED})")
    log(f"\nFINAL TRAINING CORPUS: {len(corpus):,}")
    log(f"  legitimate: {n_legit:,}")
    log(f"  phishing:   {n_phish:,}")
    log("  source distribution:")
    for source, count in corpus["source"].value_counts().items():
        log(f"    {source:<28}{count:>10,}")
    log(f"  class composition by source: {by_label_source}")
    log(f"  registered domains: {len(corpus_domains):,}; "
        f"shared with external holdout: {len(domain_overlap):,} "
        f"({len(overlap_rows):,} rows, kept - only exact URLs are removed)")
    log(f"  domains carrying both labels: {len(mixed_domains):,} ({len(mixed_rows):,} rows)")
    log("  largest domains: " + ", ".join(f"{d} ({c:,})" for d, c in top_domains.items()))

    structure = structure_stats(corpus)
    log("  URL structure by source/label (path / query / fragment rates):")
    for key, value in structure.items():
        log(f"    {key:<42}{value['rows']:>9,}  "
            f"{value['has_path_rate']:.3f} / {value['has_query_rate']:.3f} / "
            f"{value['has_fragment_rate']:.3f}")

    report = {
        "sampling_seed": SEED,
        "phishing_database_sampling_method": "uniform random sample without replacement",
        "phishing_database_sample_target": PHISHING_DATABASE_SAMPLE_SIZE,
        "phishing_database_eligible_rows": int(eligible),
        "phishing_database_sampled_rows": int(sample_n),
        "loaded_by_source": loaded_by_source,
        "removed_unparseable_url": removed_unparseable,
        "removed_exact_holdout_url_overlap": removed_holdout,
        "removed_conflicting_labels": removed_conflict,
        "removed_duplicate_urls": removed_duplicates,
        "final_rows": int(len(corpus)),
        "legitimate": n_legit,
        "phishing": n_phish,
        "source_distribution": {str(k): int(v) for k, v in corpus["source"].value_counts().items()},
        "class_composition_by_source": by_label_source,
        "registered_domains": int(len(corpus_domains)),
        "domains_shared_with_external_holdout": int(len(domain_overlap)),
        "rows_in_domains_shared_with_external_holdout": int(len(overlap_rows)),
        "top_shared_holdout_domains": {
            f"{d}|label={l}": int(c) for (d, l), c in top_overlap.items()
        },
        "domains_with_both_labels": int(len(mixed_domains)),
        "rows_in_domains_with_both_labels": int(len(mixed_rows)),
        "largest_domains": {str(d): int(c) for d, c in top_domains.items()},
        "url_structure_by_source_label": structure,
    }
    return corpus.reset_index(drop=True), report


# ============================================================
# FEATURES
# ============================================================

def extract_feature_rows(urls, label: str):
    """Run the existing VIGIL extractor. Returns (records, failure_count) where
    records[i] is None if extraction failed for urls[i]."""
    urls = list(urls)
    records = []
    failures = 0
    started = time.perf_counter()
    for start in range(0, len(urls), FEATURE_CHUNK):
        for url in urls[start:start + FEATURE_CHUNK]:
            try:
                records.append(extract_features(url))
            except Exception:
                records.append(None)
                failures += 1
        done = min(start + FEATURE_CHUNK, len(urls))
        if len(urls) > FEATURE_CHUNK:
            log(f"  [{label}] features {done:,}/{len(urls):,} "
                f"({time.perf_counter() - started:.0f}s)")
    return records, failures


def records_to_frame(records) -> pd.DataFrame:
    valid = [r for r in records if r is not None]
    frame = pd.DataFrame.from_records(valid)
    return frame.apply(pd.to_numeric, errors="coerce").fillna(0.0).astype("float64")


# ============================================================
# DOMAIN-ISOLATED SPLIT
# ============================================================

def domain_split(domains: pd.Series, fractions: dict, seed: int) -> np.ndarray:
    """Assign every registered domain to exactly one split.

    Domains are processed largest first and each goes to the split with the
    biggest remaining row deficit. Unlike a group-count based shuffle split,
    this keeps split sizes close to the targets even when a few domains
    (for example big dynamic-URL domains) hold many rows."""
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
            "legitimate": legit,
            "phishing": phish,
            "source_counts": sources,
            "registered_domains": int(part["registered_domain"].nunique()),
        }
        log(f"  {name:<12} rows={len(part):>9,}  legit={legit:>9,}  phishing={phish:>9,}  "
            f"domains={part['registered_domain'].nunique():>8,}")
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
        reliability.append(
            {
                "lower": float(lower),
                "upper": float(upper),
                "count": int(mask.sum()),
                "mean_probability": mean_probability,
                "positive_rate": positive_rate,
            }
        )
    return {"expected_calibration_error": float(ece), "reliability_bins": reliability}


# ============================================================
# SAFE / SUSPICIOUS / PHISHING POLICY
# ============================================================

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
        "legitimate_flagged_not_safe_rate": float((~safe)[benign].mean()) if benign.any() else 0.0,
    }


def threshold_search(y, probabilities) -> dict:
    """Search SAFE and PHISHING thresholds on the threshold split only.

    SAFE:     highest x with  mean(phishing < x)  <= MAX_PHISHING_BELOW_SAFE
    PHISHING: lowest  x with  mean(legitimate >= x) <= MAX_BENIGN_AT_PHISHING
    (Vectorised equivalent of scanning every candidate value.)"""
    y = np.asarray(y, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    positive = np.sort(probabilities[y == 1])
    negative = np.sort(probabilities[y == 0])

    safe = float(SAFE_THRESHOLD)
    safe_source = "config fallback"
    if len(positive):
        allowed = int(math.floor(MAX_PHISHING_BELOW_SAFE * len(positive)))
        safe = float(positive[min(allowed, len(positive) - 1)])
        safe_source = "threshold split"

    phishing = float(PHISHING_THRESHOLD)
    phishing_source = "config fallback"
    if len(negative):
        allowed = int(math.floor(MAX_BENIGN_AT_PHISHING * len(negative)))
        cutoff = negative[len(negative) - allowed - 1]
        index = int(np.searchsorted(negative, cutoff, side="right"))
        if index < len(negative):
            candidate = float(negative[index])
        else:
            # every value up to the cutoff is tied/exhausted: lowest value strictly above it
            candidate = float(np.nextafter(cutoff, np.inf))
        if float(np.mean(negative >= candidate)) <= MAX_BENIGN_AT_PHISHING:
            phishing = candidate
            phishing_source = "threshold split"

    if phishing <= safe:
        safe = min(safe, max(0.0, phishing - 0.05))

    return {
        "safe": float(safe),
        "phishing": float(phishing),
        "safe_source": safe_source,
        "phishing_source": phishing_source,
        "max_phishing_below_safe": MAX_PHISHING_BELOW_SAFE,
        "max_benign_at_phishing": MAX_BENIGN_AT_PHISHING,
    }


def verdict_for(probability: float, thresholds: dict) -> str:
    if probability < thresholds["safe"]:
        return "SAFE"
    if probability >= thresholds["phishing"]:
        return "PHISHING"
    return "SUSPICIOUS"


def selection_score(m: dict, pol: dict) -> float:
    return (
        0.35 * pol["phishing_recall"]
        + 0.25 * m["pr_auc"]
        + 0.20 * m["f1"]
        - 0.30 * pol["fpr"]
        - 0.10 * m["brier"]
    )


# ============================================================
# MODELS
# ============================================================

def candidate_estimators() -> dict:
    return {
        "logistic_regression": Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "logreg",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",
                        solver="lbfgs",
                        random_state=SEED,
                    ),
                ),
            ]
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            learning_rate=0.05,
            max_iter=100,
            max_leaf_nodes=31,
            early_stopping=False,
            random_state=SEED,
        ),
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
    return ProbabilityCalibratedModel(estimator, calibrator)


def measure_latency(model, row: pd.DataFrame) -> dict:
    for _ in range(5):
        model.predict_proba(row)
    values = []
    for _ in range(100):
        start = time.perf_counter()
        model.predict_proba(row)
        values.append((time.perf_counter() - start) * 1000.0)
    return {
        "median_ms": float(np.median(values)),
        "p95_ms": float(np.percentile(values, 95)),
    }


# ============================================================
# HARD PHISHING COHORTS
# ============================================================

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

    token = flag("HasSuspiciousToken")
    tld = flag("HasSuspiciousTLD")
    ip = flag("IsDomainIP")
    if token is not None:
        masks["no_suspicious_token"] = ~token
    if tld is not None:
        masks["no_suspicious_tld"] = ~tld
    available = [f for f in (token, tld, ip) if f is not None]
    if available:
        combined = available[0].copy()
        for extra in available[1:]:
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
# REGRESSION + EXTERNAL EVALUATION
# ============================================================

def regression_results(model, X_ref: pd.DataFrame, thresholds: dict, in_corpus: dict,
                       domain_split_name: dict) -> dict:
    probabilities = model.predict_proba(X_ref)[:, 1]
    rows = []
    for url, probability in zip(REFERENCE_URLS, probabilities):
        verdict = verdict_for(float(probability), thresholds)
        if url in FAST_COM_URLS:
            expectation = "SAFE"
            passed = verdict == "SAFE"
        else:
            expectation = "NOT_PHISHING"
            passed = verdict != "PHISHING"
        rows.append(
            {
                "url": url,
                "probability": float(probability),
                "verdict": verdict,
                "expectation": expectation,
                "passed": bool(passed),
                "exact_url_in_training_corpus": bool(in_corpus.get(url, False)),
                "domain_split": domain_split_name.get(url),
            }
        )
    counts = {k: sum(r["verdict"] == k for r in rows) for k in ("SAFE", "SUSPICIOUS", "PHISHING")}
    return {"results": rows, "counts": counts}


def external_evaluation(probabilities: np.ndarray, extraction_failures: int, total_rows: int,
                        thresholds: dict) -> dict:
    # Rows whose features could not be extracted are counted as missed.
    hits = int(np.sum(probabilities >= thresholds["phishing"]))
    recall = hits / max(total_rows, 1)
    return {
        "rows": int(total_rows),
        "rows_scored": int(len(probabilities)),
        "feature_extraction_failures": int(extraction_failures),
        "phishing_recall": float(recall),
        "fnr": float(1.0 - recall),
        "not_safe_rate": float(np.sum(probabilities >= thresholds["safe"]) / max(total_rows, 1)),
        "probability_min": float(probabilities.min()) if len(probabilities) else None,
        "probability_median": float(np.median(probabilities)) if len(probabilities) else None,
        "probability_max": float(probabilities.max()) if len(probabilities) else None,
        "fpr": None,
        "statement": (
            "External FPR is undefined because the external holdout contains "
            "phishing URLs only."
        ),
    }


# ============================================================
# PRODUCTION COMPARISON (read-only)
# ============================================================

def production_comparison(X_all: pd.DataFrame, names: list, test_idx: np.ndarray, y_test,
                          X_ext: pd.DataFrame) -> dict:
    """Load the existing production model ONLY to measure it on the same test split."""
    result = {
        "available": False,
        "baseline_recall_fallback": PRODUCTION_RECALL_BASELINE,
        "thresholds": {"safe": float(SAFE_THRESHOLD), "phishing": float(PHISHING_THRESHOLD)},
    }
    if not PRODUCTION_MODEL_PATH.is_file():
        result["reason"] = f"{PRODUCTION_MODEL_PATH.name} not found"
        return result
    try:
        with PRODUCTION_MODEL_PATH.open("rb") as stream:
            model = pickle.load(stream)

        columns = list(names)
        if PRODUCTION_FEATURES_PATH.is_file():
            with PRODUCTION_FEATURES_PATH.open("rb") as stream:
                stored = [str(c) for c in pickle.load(stream)]
            if stored and all(c in X_all.columns for c in stored):
                columns = stored

        probabilities = model.predict_proba(X_all.iloc[test_idx][columns])[:, 1]
        pol = policy(y_test, probabilities, result["thresholds"])
        result.update(
            {
                "available": True,
                "feature_columns_used": len(columns),
                "domain_test_policy": pol,
                "domain_test_metrics": metrics(y_test, probabilities),
                "note": (
                    "The production model may have seen some of these test rows during "
                    "its own training, so its recall here can be optimistic."
                ),
            }
        )
        if X_ext is not None and len(X_ext):
            external_prob = model.predict_proba(X_ext[columns])[:, 1]
            result["external_recall_at_production_threshold"] = float(
                np.mean(external_prob >= PHISHING_THRESHOLD)
            )
    except Exception as exc:  # comparison must never break the experiment
        result["available"] = False
        result["reason"] = f"{type(exc).__name__}: {exc}"
    return result


# ============================================================
# GATES
# ============================================================

def build_gates(evaluation: dict, production: dict) -> dict:
    pol = evaluation["domain_test"]["policy"]
    results = evaluation["regression"]["results"]

    def group(predicate):
        return [r for r in results if predicate(r["url"])]

    google = group(lambda u: u in GOOGLE_SEARCH_URLS)
    youtube = group(lambda u: u in YOUTUBE_QUERY_URLS)
    fast = group(lambda u: u in FAST_COM_URLS)
    other = group(lambda u: u not in GOOGLE_SEARCH_URLS | YOUTUBE_QUERY_URLS | FAST_COM_URLS)

    if production.get("available"):
        production_recall = production["domain_test_policy"]["phishing_recall"]
        recall_source = "measured on the same test split with production thresholds"
    else:
        production_recall = PRODUCTION_RECALL_BASELINE
        recall_source = "documented baseline (production model could not be re-measured)"

    ece = evaluation["domain_test"]["calibration"]["expected_calibration_error"]

    def entry(requirement, actual, passed, **extra):
        return {"requirement": requirement, "actual": actual, "passed": bool(passed), **extra}

    return {
        "domain_fpr": entry(f"<= {GATE_MAX_DOMAIN_FPR}", pol["fpr"], pol["fpr"] <= GATE_MAX_DOMAIN_FPR),
        "domain_recall": entry(
            ">= current production recall",
            pol["phishing_recall"],
            pol["phishing_recall"] >= production_recall,
            production_recall=production_recall,
            production_recall_source=recall_source,
        ),
        "external_phishing_recall": entry(
            f">= {GATE_MIN_EXTERNAL_RECALL}",
            evaluation["external"]["phishing_recall"],
            evaluation["external"]["phishing_recall"] >= GATE_MIN_EXTERNAL_RECALL,
        ),
        "calibration_ece": entry(f"<= {GATE_MAX_ECE}", ece, ece <= GATE_MAX_ECE),
        "google_search_not_phishing": entry(
            "no Google search URL classified PHISHING",
            {r["url"]: r["verdict"] for r in google},
            bool(google) and all(r["verdict"] != "PHISHING" for r in google),
        ),
        "youtube_query_not_phishing": entry(
            "YouTube query URL not classified PHISHING",
            {r["url"]: r["verdict"] for r in youtube},
            bool(youtube) and all(r["verdict"] != "PHISHING" for r in youtube),
        ),
        "fast_com_variants_safe": entry(
            "all fast.com variants classified SAFE",
            {r["url"]: r["verdict"] for r in fast},
            bool(fast) and all(r["verdict"] == "SAFE" for r in fast),
        ),
        "other_legitimate_not_phishing": entry(
            "no other legitimate reference classified PHISHING",
            {r["url"]: r["verdict"] for r in other},
            bool(other) and all(r["verdict"] != "PHISHING" for r in other),
        ),
        "model_size": entry(
            f"<= {GATE_MAX_MODEL_BYTES / (1024 * 1024):.0f} MB",
            evaluation["profile"]["model_size_bytes"],
            evaluation["profile"]["model_size_bytes"] <= GATE_MAX_MODEL_BYTES,
        ),
        "median_latency": entry(
            f"<= {GATE_MAX_MEDIAN_LATENCY_MS} ms",
            evaluation["profile"]["median_latency_ms"],
            evaluation["profile"]["median_latency_ms"] <= GATE_MAX_MEDIAN_LATENCY_MS,
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main() -> dict:
    started_at = time.perf_counter()
    log("=" * 74)
    log("VIGIL - BALANCED TRAINING EXPERIMENT (EXPERIMENT ONLY)")
    log("=" * 74)

    hashes_before = hash_production_artifacts()

    # ------------------------------------------------------------------
    # External holdout (needed first so training excludes its exact URLs)
    # ------------------------------------------------------------------
    holdout = load_external_holdout()
    holdout["normalized_url"] = holdout["url"].map(normalize_url)
    valid_holdout = holdout[holdout["normalized_url"].astype(bool)]
    external_urls = set(valid_holdout["normalized_url"])
    external_domains = set(registered_domains(valid_holdout["normalized_url"]))
    log(f"External phishing holdout rows: {len(holdout):,} "
        f"({len(external_urls):,} unique normalised URLs)")

    # ------------------------------------------------------------------
    # Corpus
    # ------------------------------------------------------------------
    corpus, corpus_report = build_corpus(external_urls, external_domains)

    # ------------------------------------------------------------------
    # Features (existing VIGIL extractor; nothing new is invented)
    # ------------------------------------------------------------------
    log("\nExtracting features for the training corpus...")
    records, failures = extract_feature_rows(corpus["url"], "corpus")
    ok = np.array([r is not None for r in records])
    if failures:
        log(f"WARNING: feature extraction failed for {failures:,} corpus URLs; they are dropped.")
        corpus = corpus[ok].reset_index(drop=True)
    features_all = records_to_frame(records)
    if len(features_all) != len(corpus):
        raise RuntimeError("Feature rows and corpus rows are misaligned.")

    names = [c for c in features_all.columns if c not in set(MODEL_EXCLUDED_FEATURES)]
    log(f"Model features: {len(names)}")
    if len(names) != 29:
        log("WARNING: expected about 29 production features; "
            f"found {len(names)}. Continuing with the extractor's output.")
    X = features_all[names].copy()
    y = corpus["label"].astype(int).reset_index(drop=True)

    # ------------------------------------------------------------------
    # Domain-isolated split
    # ------------------------------------------------------------------
    split_names = list(SPLIT_FRACTIONS)
    split_ids = domain_split(corpus["registered_domain"], SPLIT_FRACTIONS, SEED)
    split_description = describe_splits(corpus, split_ids, split_names)
    idx = {name: np.where(split_ids == i)[0] for i, name in enumerate(split_names)}
    train_idx, cal_idx, thr_idx, test_idx = (
        idx["train"], idx["calibration"], idx["threshold"], idx["test"]
    )

    # ------------------------------------------------------------------
    # Regression URLs and external holdout features
    # ------------------------------------------------------------------
    ref_records, ref_failures = extract_feature_rows(REFERENCE_URLS, "regression")
    if ref_failures:
        raise RuntimeError("Feature extraction failed for one or more regression URLs.")
    X_ref = records_to_frame(ref_records)[names]

    log("\nExtracting features for the external phishing holdout...")
    ext_records, ext_failures = extract_feature_rows(holdout["url"], "external")
    X_ext_all = records_to_frame(ext_records)
    X_ext = X_ext_all[names] if len(X_ext_all) else X_ext_all

    # Where do the regression URLs' domains live? (reporting only)
    reference_norm = pd.Series([normalize_url(u) for u in REFERENCE_URLS])
    reference_domains = registered_domains(reference_norm)
    corpus_url_set = set(
        corpus["url"].map(normalize_url)
    )
    domain_lookup = dict(zip(corpus["registered_domain"], split_ids))
    domain_rows = corpus["registered_domain"].value_counts()
    in_corpus = {u: (normalize_url(u) in corpus_url_set) for u in REFERENCE_URLS}
    reference_split = {
        u: (split_names[domain_lookup[d]] if d in domain_lookup else "not_in_corpus")
        for u, d in zip(REFERENCE_URLS, reference_domains)
    }
    placement = {}
    for url, domain in zip(REFERENCE_URLS, reference_domains):
        placement[domain] = {
            "split": reference_split[url],
            "corpus_rows_in_domain": int(domain_rows.get(domain, 0)),
        }
    log("\nREGRESSION DOMAIN PLACEMENT (reporting only)")
    for domain, info in placement.items():
        log(f"  {domain:<24} split={info['split']:<14} corpus rows={info['corpus_rows_in_domain']:,}")
    leaked = [u for u, flag in in_corpus.items() if flag]
    if leaked:
        log(f"  NOTE: these regression URLs appear verbatim in the training corpus: {leaked}")
    not_in_train = [d for d, i in placement.items()
                    if i["split"] not in ("train", "not_in_corpus")]
    if not_in_train:
        log(f"  NOTE: these regression domains are NOT in the training split "
            f"(the model never trains on them): {not_in_train}")

    # ------------------------------------------------------------------
    # Production comparison (read-only)
    # ------------------------------------------------------------------
    production = production_comparison(X, names, test_idx, y.iloc[test_idx], X_ext)
    if production["available"]:
        log("\nProduction model re-measured on the same domain test split: "
            f"recall={production['domain_test_policy']['phishing_recall']:.4f} "
            f"FPR={production['domain_test_policy']['fpr']:.4f}")
    else:
        log(f"\nProduction comparison unavailable ({production.get('reason')}); "
            f"using baseline recall {PRODUCTION_RECALL_BASELINE}")

    # ------------------------------------------------------------------
    # Train, calibrate, threshold, evaluate every candidate
    # ------------------------------------------------------------------
    evaluations = {}
    for name in candidate_estimators():
        log(f"\nTraining {name}...")
        fit_started = time.perf_counter()
        model = fit_candidate(
            name,
            X.iloc[train_idx], y.iloc[train_idx],
            X.iloc[cal_idx], y.iloc[cal_idx],
        )
        fit_seconds = time.perf_counter() - fit_started

        thr_prob = model.predict_proba(X.iloc[thr_idx])[:, 1]
        thresholds = threshold_search(y.iloc[thr_idx], thr_prob)
        thr_metrics = metrics(y.iloc[thr_idx], thr_prob)
        thr_policy = policy(y.iloc[thr_idx], thr_prob, thresholds)
        score = selection_score(thr_metrics, thr_policy)

        test_prob = model.predict_proba(X.iloc[test_idx])[:, 1]
        test_metrics = metrics(y.iloc[test_idx], test_prob)
        test_metrics["calibration"] = calibration_metrics(y.iloc[test_idx], test_prob)
        test_metrics["policy"] = policy(y.iloc[test_idx], test_prob, thresholds)
        test_metrics["hard_cohorts"] = phishing_cohorts(
            corpus["url"].iloc[test_idx],
            features_all.iloc[test_idx],
            y.iloc[test_idx],
            test_prob,
            thresholds["phishing"],
        )

        ext_prob = (
            model.predict_proba(X_ext)[:, 1] if len(X_ext) else np.array([], dtype=float)
        )
        external = external_evaluation(ext_prob, ext_failures, len(holdout), thresholds)
        regression = regression_results(model, X_ref, thresholds, in_corpus, reference_split)

        latency = measure_latency(model, X.iloc[test_idx].iloc[[0]])
        profile = {
            "model_size_bytes": len(pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL)),
            "median_latency_ms": latency["median_ms"],
            "p95_latency_ms": latency["p95_ms"],
            "fit_seconds": float(fit_seconds),
        }

        evaluation = {
            "thresholds": thresholds,
            "threshold_split": {"metrics": thr_metrics, "policy": thr_policy, "selection_score": float(score)},
            "domain_test": test_metrics,
            "external": external,
            "regression": regression,
            "profile": profile,
        }
        evaluation["gates"] = build_gates(evaluation, production)
        evaluation["gates_passed"] = all(g["passed"] for g in evaluation["gates"].values())
        evaluations[name] = evaluation

        pol = test_metrics["policy"]
        log(f"  thresholds: safe={thresholds['safe']:.4f} phishing={thresholds['phishing']:.4f}")
        log(f"  domain test: recall={pol['phishing_recall']:.4f} FNR={pol['phishing_fnr']:.4f} "
            f"FPR={pol['fpr']:.4f} PR-AUC={test_metrics['pr_auc']:.4f} "
            f"ROC-AUC={test_metrics['roc_auc']:.4f} "
            f"ECE={test_metrics['calibration']['expected_calibration_error']:.4f}")
        log(f"  external: recall={external['phishing_recall']:.4f} FNR={external['fnr']:.4f}")
        log(f"  size={profile['model_size_bytes']:,} bytes  "
            f"median latency={profile['median_latency_ms']:.3f} ms  fit={fit_seconds:.1f}s")
        log(f"  gates passed: {evaluation['gates_passed']}")

    # ------------------------------------------------------------------
    # Select the best candidate (prefer ones that pass every gate)
    # ------------------------------------------------------------------
    passing = [n for n, e in evaluations.items() if e["gates_passed"]]
    pool = passing if passing else list(evaluations)
    selected_name = max(pool, key=lambda n: evaluations[n]["threshold_split"]["selection_score"])
    selected = evaluations[selected_name]
    final_result = "PASS" if selected["gates_passed"] else "FAIL"

    hashes_after = hash_production_artifacts()
    production_updated = hashes_before != hashes_after
    if production_updated:
        log("CRITICAL: a production artifact changed during the experiment run!")

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    report = {
        "decision": "EXPERIMENT ONLY - DO NOT PROMOTE",
        "final_result": final_result,
        "selected_model": selected_name,
        "selection_rule": (
            "highest threshold-split selection score among candidates that pass every "
            "gate; if none passes, highest score overall"
        ),
        "promotion_gate_passed": bool(selected["gates_passed"]),
        "promotion_allowed": False,
        "promotion_block_reason": "This script is experiment-only; production promotion is disabled.",
        "production_artifacts_updated": bool(production_updated),
        "production_artifact_hashes_before": hashes_before,
        "production_artifact_hashes_after": hashes_after,
        "training_corpus": corpus_report,
        "training_rows": int(len(corpus)),
        "legitimate": int((y == 0).sum()),
        "phishing": int((y == 1).sum()),
        "dynamic_legitimate_rows": int((corpus["source"] == SOURCE_DYNAMIC).sum()),
        "feature_count": len(names),
        "feature_names": names,
        "feature_extraction_failures_corpus": int(failures),
        "domain_split": split_description,
        "regression_domain_placement": placement,
        "regression_urls_present_in_training_corpus": leaked,
        "selected_thresholds": selected["thresholds"],
        "selected_gates": selected["gates"],
        "selected_model_profile": {
            "model_size_bytes": selected["profile"]["model_size_bytes"],
            "median_latency_ms": selected["profile"]["median_latency_ms"],
        },
        "candidate_models": evaluations,
        "current_production": production,
        "gate_limits": {
            "max_domain_fpr": GATE_MAX_DOMAIN_FPR,
            "min_external_recall": GATE_MIN_EXTERNAL_RECALL,
            "max_ece": GATE_MAX_ECE,
            "max_model_bytes": GATE_MAX_MODEL_BYTES,
            "max_median_latency_ms": GATE_MAX_MEDIAN_LATENCY_MS,
        },
        "seeds": {"sampling_and_models": SEED},
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runtime_seconds": float(time.perf_counter() - started_at),
    }
    atomic_write_text(REPORT_PATH, json.dumps(to_jsonable(report), indent=2))

    # ------------------------------------------------------------------
    # Console summary
    # ------------------------------------------------------------------
    pol = selected["domain_test"]["policy"]
    log("\n" + "=" * 74)
    log("FINAL RESULT")
    log("=" * 74)
    log(f"Selected model:     {selected_name}")
    log(f"Training rows:      {len(corpus):,} "
        f"(legitimate {int((y == 0).sum()):,} / phishing {int((y == 1).sum()):,})")
    log(f"Thresholds:         safe={selected['thresholds']['safe']:.4f}  "
        f"phishing={selected['thresholds']['phishing']:.4f}")
    log(f"Domain recall/FNR/FPR: {pol['phishing_recall']:.4f} / "
        f"{pol['phishing_fnr']:.4f} / {pol['fpr']:.4f}")
    log(f"PR-AUC / ROC-AUC:   {selected['domain_test']['pr_auc']:.4f} / "
        f"{selected['domain_test']['roc_auc']:.4f}")
    log(f"ECE:                {selected['domain_test']['calibration']['expected_calibration_error']:.4f}")
    log(f"External recall/FNR: {selected['external']['phishing_recall']:.4f} / "
        f"{selected['external']['fnr']:.4f}")
    log(f"Model size / median latency: {selected['profile']['model_size_bytes']:,} bytes / "
        f"{selected['profile']['median_latency_ms']:.3f} ms")

    log("\nREGRESSION URLS")
    for row in selected["regression"]["results"]:
        mark = "ok  " if row["passed"] else "FAIL"
        log(f"  [{mark}] {row['verdict']:<10} {row['probability']:.6f}  {row['url']}")

    log("\nGATES")
    for gate, info in selected["gates"].items():
        log(f"  {'PASS' if info['passed'] else 'FAIL'}  {gate}")

    log(f"\nPRODUCTION ARTIFACTS UPDATED: {production_updated}")
    log(f"FINAL RESULT: {final_result}   (decision: {report['decision']})")
    log(f"Report: {REPORT_PATH}")
    return report


if __name__ == "__main__":
    main()
