"""Single source of truth for validation, inference, risk, labels, and evidence."""
import hashlib
import hmac
import json, os, pickle
import math
from datetime import datetime, timezone
from functools import lru_cache

import pandas as pd

from config import PHISHING_THRESHOLD, SAFE_THRESHOLD
from feature_extractor import extract_features, normalize_url

ROOT = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH, FEATURE_PATH, METADATA_PATH = [os.path.join(ROOT, x) for x in ("phishing_model.pkl", "feature_names.pkl", "model_metadata.json")]


@lru_cache(maxsize=1)
def load_model_bundle():
    if not all(os.path.exists(p) for p in (MODEL_PATH, FEATURE_PATH, METADATA_PATH)):
        raise FileNotFoundError("model_unavailable")
    try:
        with open(METADATA_PATH, encoding="utf-8") as f:
            metadata = json.load(f)
        artifact_hashes = metadata.get("artifacts", {})
        for path, hash_key in ((MODEL_PATH, "model_sha256"), (FEATURE_PATH, "feature_names_sha256")):
            expected = artifact_hashes.get(hash_key)
            if expected and not hmac.compare_digest(expected, _sha256_file(path)):
                raise ValueError("model_artifact_integrity_check_failed")
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(FEATURE_PATH, "rb") as f:
            names = list(pickle.load(f))
    except Exception as exc:
        raise RuntimeError("model_unavailable") from exc
    return model, names, metadata


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _thresholds_from_metadata(metadata):
    raw = metadata.get("thresholds", {}) if isinstance(metadata.get("thresholds", {}), dict) else {}
    try:
        safe = float(raw.get("safe", raw.get("suspicious", SAFE_THRESHOLD)))
        phishing = float(raw.get("phishing", PHISHING_THRESHOLD))
    except (TypeError, ValueError):
        safe, phishing = SAFE_THRESHOLD, PHISHING_THRESHOLD
    if not math.isfinite(safe) or not math.isfinite(phishing):
        safe, phishing = SAFE_THRESHOLD, PHISHING_THRESHOLD
    safe = min(max(safe, 0.0), 1.0)
    phishing = min(max(phishing, 0.0), 1.0)
    if phishing <= safe:
        if safe < 1.0:
            phishing = 1.0
        else:
            safe, phishing = min(SAFE_THRESHOLD, 0.8), max(PHISHING_THRESHOLD, 0.85)
    return {"safe": safe, "phishing": phishing}


def _evidence(features):
    out = []

    def add(i, sev, pol, title, detail, feature, value):
        out.append({"id": i, "severity": sev, "polarity": pol, "title": title, "detail": detail, "feature": feature, "value": value})

    if features["IsHTTPS"]:
        add("https_enabled", "info", "neutral", "HTTPS is enabled", "HTTPS protects transport; it does not by itself prove a domain is safe.", "IsHTTPS", features["IsHTTPS"])
    else:
        add("http_scheme", "warning", "negative", "HTTP is used", "The URL does not use HTTPS; scheme alone is not a phishing verdict.", "IsHTTPS", features["IsHTTPS"])
    if features["IsDomainIP"]:
        add("ip_host", "danger", "negative", "IP address host", "The hostname is an IP literal rather than a named domain.", "IsDomainIP", features["IsDomainIP"])
    if features["HasSuspiciousToken"]:
        add("suspicious_token", "warning", "negative", "Suspicious URL token", "A token commonly associated with account or payment lures appears in the hostname, path, query, or fragment.", "HasSuspiciousToken", features["HasSuspiciousToken"])
    if features["HasUserInfo"]:
        add("userinfo", "danger", "negative", "Userinfo present", "The URL contains userinfo before the hostname.", "HasUserInfo", features["HasUserInfo"])
    if features["HasPort"]:
        add("explicit_port", "warning", "negative", "Explicit port", "The URL specifies a non-default port.", "HasPort", features["HasPort"])
    if features["URLPercentEncodingCount"]:
        add("encoding", "warning", "negative", "Percent encoding", "The URL contains percent-encoded characters.", "URLPercentEncodingCount", features["URLPercentEncodingCount"])
    if features["SubdomainDepth"] >= 3:
        add("deep_subdomains", "warning", "negative", "Deep subdomain structure", "The hostname contains multiple subdomain levels.", "SubdomainDepth", features["SubdomainDepth"])
    if not out:
        add("no_rule_signal", "info", "neutral", "No structural warning signals", "No documented structural warning rule fired; this does not guarantee safety.", None, None)
    return out


def _classify(probability, safe_threshold, phishing_threshold):
    if probability >= phishing_threshold:
        return "PHISHING", probability
    if probability >= safe_threshold:
        return "SUSPICIOUS", probability
    return "SAFE", probability


def scan(url: str):
    if isinstance(url, str) and len(url.strip()) > 2048:
        raise ValueError("url_too_long")
    normalized = normalize_url(url)
    features = extract_features(normalized)
    model, names, metadata = load_model_bundle()
    if len(names) != len(set(names)) or any(n not in features for n in names):
        raise RuntimeError("model_feature_mismatch")

    row = pd.DataFrame([[features[n] for n in names]], columns=names)
    probability = float(model.predict_proba(row)[0][list(model.classes_).index(1)])
    thresholds = _thresholds_from_metadata(metadata)
    safe_threshold = thresholds["safe"]
    phishing_threshold = thresholds["phishing"]
    probability = min(max(probability, 0.0), 1.0)
    label, probability = _classify(probability, safe_threshold, phishing_threshold)
    risk_span = max(phishing_threshold - safe_threshold, 1e-6)
    risk_score = int(round(max(0, min(100, ((probability - safe_threshold) / risk_span) * 100))))
    evidence = _evidence(features)
    if label == "SUSPICIOUS":
        evidence.insert(0, {"id": "intermediate_model_score", "severity": "warning", "polarity": "negative", "title": "Intermediate model score", "detail": "The calibrated model score is above the SAFE threshold but below the PHISHING threshold.", "feature": None, "value": round(probability, 6)})
    elif label == "PHISHING":
        evidence.insert(0, {"id": "high_model_score", "severity": "danger", "polarity": "negative", "title": "High model score", "detail": "The calibrated model score meets the PHISHING threshold; this is a URL-only prediction, not proof of site behavior.", "feature": None, "value": round(probability, 6)})
    return {
        "url": url,
        "normalized_url": normalized,
        "label": label,
        "risk_score": risk_score,
        "probability": round(probability, 6),
        "model_probability": round(probability, 6),
        "evidence": evidence,
        "features": features,
        "model_version": metadata.get("model_version", "unknown"),
        "thresholds": {"safe": safe_threshold, "phishing": phishing_threshold},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def model_info():
    return load_model_bundle()[2]
