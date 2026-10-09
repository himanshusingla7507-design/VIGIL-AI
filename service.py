"""Single source of truth for validation, inference, risk, labels, and evidence."""
import hashlib
import hmac
import json, os, pickle
import ipaddress
import math
import re
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import parse_qsl, urlsplit

import pandas as pd

from config import AMAZON_SHOPPING_HOSTS, PHISHING_THRESHOLD, SAFE_THRESHOLD, VERIFIED_OFFICIAL_HOSTS
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
    metadata["model_fingerprint"] = hashlib.sha256(
        f"{_sha256_file(MODEL_PATH)}:{_sha256_file(FEATURE_PATH)}".encode("ascii")
    ).hexdigest()
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


def _local_host_decision(normalized_url, model_probability, thresholds):
    """Keep loopback and the reserved localhost namespace out of phishing blocks."""
    host = (urlsplit(normalized_url).hostname or "").lower().rstrip(".")
    is_local = host == "localhost" or host.endswith(".localhost")
    try:
        is_local = is_local or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if not is_local:
        return None
    return {
        "applied": True,
        "host": host,
        "source": "local_host_policy",
        "reason": "Loopback IP or reserved .localhost host; the raw model score remains available for audit.",
        "model_probability": model_probability,
        "effective_probability": min(model_probability, max(0.0, thresholds["safe"] - 1e-6)),
    }


def _verified_official_route_decision(normalized_url, features, model_probability, thresholds):
    """Apply only an exact-host, safe-context official-route policy.

    This is not an ML result.  It refuses authority tricks, lookalike hosts,
    redirect-like paths, and embedded external destinations before it can
    reduce an otherwise blocking/suspicious model score.
    """
    parsed = urlsplit(normalized_url)
    host = (parsed.hostname or "").lower().rstrip(".")
    approved_paths = VERIFIED_OFFICIAL_HOSTS.get(host)
    authority_is_clean = not any(features.get(name) for name in (
        "HasUserInfo", "HasPort", "IsDomainIP", "IsShortened", "HasObfuscation",
    ))
    route_is_approved = approved_paths is not None and parsed.path in approved_paths
    # Netflix playback IDs are numeric.  Allow only its two observed playback
    # parameters; this does not make arbitrary Netflix routes trustworthy.
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    is_netflix_playback = (
        host in {"netflix.com", "www.netflix.com"}
        and re.fullmatch(r"/watch/[0-9]+", parsed.path) is not None
        and all(key in {"trackId", "ctx"} for key, _value in query_pairs)
        and all(key != "trackId" or value.isdigit() for key, value in query_pairs)
    )
    route_is_approved = route_is_approved or is_netflix_playback
    is_amazon_shopping_route = (
        host in AMAZON_SHOPPING_HOSTS
        and (
            parsed.path in {
                "/", "/s", "/cart",
                "/gp/buy/spc/handlers/display.html",
            }
            or re.fullmatch(r"/gp/cart/view\.html(?:/.*)?", parsed.path, re.IGNORECASE) is not None
            or re.fullmatch(r"/(?:[^/]+/)?dp/[A-Z0-9]{10}(?:/.*)?", parsed.path, re.IGNORECASE) is not None
            or re.fullmatch(r"/gp/product/[A-Z0-9]{10}(?:/.*)?", parsed.path, re.IGNORECASE) is not None
        )
    )
    route_is_approved = route_is_approved or is_amazon_shopping_route
    # Do not cover endpoints that commonly forward to a user-provided target,
    # or a query value that itself embeds an absolute URL/host.
    redirect_markers = {"continue", "dest", "destination", "next", "redirect", "return", "target", "url"}
    has_embedded_destination = any(
        key.lower() in redirect_markers
        or value.lower().startswith(("http://", "https://", "//"))
        for key, value in query_pairs
    )
    # Parsing decodes one level for inspection.  Do not recursively decode a
    # second level into an apparently harmless official playback route.
    has_double_encoded_value = "%25" in parsed.query.lower()
    if (
        parsed.scheme == "https"
        and authority_is_clean
        and route_is_approved
        and not has_embedded_destination
        and not has_double_encoded_value
        and model_probability >= thresholds["safe"]
    ):
        effective_probability = max(0.0, thresholds["safe"] - 1e-6)
        return {
            "applied": True,
            "host": host,
            "source": "verified_official_route_policy",
            "reason": "An exact verified official host and approved non-redirect route matched; the raw ML score remains available for audit.",
            "model_probability": model_probability,
            "effective_probability": effective_probability,
        }
    return {
        "applied": False,
        "host": host,
        "source": "model",
        "model_probability": model_probability,
        "effective_probability": model_probability,
    }


def _raw_probabilities(model, row):
    calibrated_classifiers = getattr(model, "calibrated_classifiers_", None)
    if not calibrated_classifiers:
        return []
    probabilities = []
    for calibrated_classifier in calibrated_classifiers:
        estimator = calibrated_classifier.estimator
        classes = list(calibrated_classifier.classes)
        probabilities.append(float(estimator.predict_proba(row)[0][classes.index(1)]))
    return probabilities


def _prediction(normalized, features, model, names, metadata):
    """Compute one fresh, auditable decision for one normalized URL."""
    if len(names) != len(set(names)) or any(n not in features for n in names):
        raise RuntimeError("model_feature_mismatch")
    row = pd.DataFrame([[features[n] for n in names]], columns=names)
    raw_probabilities = _raw_probabilities(model, row)
    if not raw_probabilities:
        raw_estimator = getattr(model, "estimator", None)
        if raw_estimator is not None:
            raw_probabilities = [float(raw_estimator.predict_proba(row)[0][list(raw_estimator.classes_).index(1)])]
    model_probability = min(max(float(model.predict_proba(row)[0][list(model.classes_).index(1)]), 0.0), 1.0)
    thresholds = _thresholds_from_metadata(metadata)
    safe_threshold, phishing_threshold = thresholds["safe"], thresholds["phishing"]
    policy = _local_host_decision(normalized, model_probability, thresholds)
    if policy is None:
        policy = _verified_official_route_decision(normalized, features, model_probability, thresholds)
    probability = float(policy["effective_probability"])
    label, probability = _classify(probability, safe_threshold, phishing_threshold)
    if policy["source"] == "local_host_policy":
        label = "SAFE"
    risk_span = max(phishing_threshold - safe_threshold, 1e-6)
    risk_score = int(round(max(0, min(100, ((probability - safe_threshold) / risk_span) * 100))))
    evidence = _evidence(features)
    if policy["applied"]:
        evidence.insert(0, {
            "id": policy["source"],
            "severity": "info",
            "polarity": "positive",
            "title": "Local host policy applied" if policy["source"] == "local_host_policy" else "Verified official-route policy applied",
            "detail": policy["reason"],
            "feature": None,
            "value": policy["host"],
        })
    if label == "SUSPICIOUS":
        evidence.insert(0, {"id": "intermediate_model_score", "severity": "warning", "polarity": "negative", "title": "Intermediate model score", "detail": "The calibrated model score is above the SAFE threshold but below the PHISHING threshold.", "feature": None, "value": round(probability, 6)})
    elif label == "PHISHING":
        evidence.insert(0, {"id": "high_model_score", "severity": "danger", "polarity": "negative", "title": "High model score", "detail": "The calibrated model score meets the PHISHING threshold; this is a URL-only prediction, not proof of site behavior.", "feature": None, "value": round(probability, 6)})
    return {"normalized_url": normalized, "label": label, "risk_score": risk_score, "probability": round(probability, 6), "model_probability": round(model_probability, 6), "effective_probability": round(probability, 6), "probability_source": policy["source"], "reputation": policy, "evidence": evidence, "features": features, "model_version": metadata.get("model_version", "unknown"), "thresholds": {"safe": safe_threshold, "phishing": phishing_threshold}, "model_fingerprint": metadata["model_fingerprint"], "diagnostics": {"raw_fold_probabilities": raw_probabilities, "calibrated_probability": round(model_probability, 6), "raw_model_probability": round(model_probability, 6), "effective_probability": round(probability, 6), "hostname": urlsplit(normalized).hostname}}


def scan(url: str, request_id=None, include_diagnostics=False):
    if isinstance(url, str) and len(url.strip()) > 2048:
        raise ValueError("url_too_long")
    normalized = normalize_url(url)
    features = extract_features(normalized)
    model, names, metadata = load_model_bundle()
    prediction = _prediction(normalized, features, model, names, metadata)
    result = {
        "url": url,
        **prediction,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id or str(uuid.uuid4()),
    }
    if not include_diagnostics:
        result.pop("diagnostics", None)
    return result


def model_info():
    return load_model_bundle()[2]
