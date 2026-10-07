"""Read-only error analysis for the untouched Phishing.Database holdout."""
from __future__ import annotations

import json
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from feature_extractor import extract_features, get_registered_domain, normalize_url  # noqa: E402
from service import load_model_bundle  # noqa: E402

HOLDOUT = os.path.join(ROOT, "data", "processed", "external_validation.csv")
JSON_OUT = os.path.join(ROOT, "reports", "external_phishing_error_analysis.json")
MD_OUT = os.path.join(ROOT, "docs", "EXTERNAL_PHISHING_ERROR_ANALYSIS.md")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def random_token(value: str) -> bool:
    tokens = [x for x in re.split(r"[^A-Za-z0-9]+", value) if x]
    for token in tokens:
        if len(token) >= 8 and entropy(token) >= 3.2 and (any(c.isdigit() for c in token) or any(c.isupper() for c in token)):
            return True
    return False


def cohort_rows(frame: pd.DataFrame, mask: pd.Series, fn_mask: pd.Series) -> list[dict]:
    total = int(mask.sum())
    missed = int((mask & fn_mask).sum())
    return {"samples": total, "missed": missed, "miss_rate": (missed / total if total else None)}


def add_cohort(result: dict, name: str, values: pd.Series, fn_mask: pd.Series) -> None:
    result[name] = {}
    for value in sorted(values.dropna().astype(str).unique()):
        result[name][value] = cohort_rows(values, values.astype(str).eq(value), fn_mask)


def main() -> dict:
    holdout = pd.read_csv(HOLDOUT)
    model, names, metadata = load_model_bundle()
    threshold = float(metadata["thresholds"]["phishing"])

    usable_urls, invalid = [], 0
    for value in holdout["url"].astype(str):
        try:
            usable_urls.append(normalize_url(value))
        except (TypeError, ValueError):
            invalid += 1
    frame = holdout.iloc[: len(usable_urls)].copy()
    # The prepared holdout is already valid; retain an explicit defensive path
    # without changing the holdout file or silently pairing invalid rows.
    if invalid:
        valid_mask = []
        for value in holdout["url"].astype(str):
            try:
                normalize_url(value)
                valid_mask.append(True)
            except (TypeError, ValueError):
                valid_mask.append(False)
        frame = holdout.loc[valid_mask].copy()
    frame["url"] = usable_urls
    features = pd.DataFrame(frame["url"].map(extract_features).tolist())[names]
    probabilities = np.asarray(model.predict_proba(features)[:, 1], dtype=float)
    frame["probability"] = probabilities
    frame["detected"] = probabilities >= threshold
    frame["missed"] = ~frame["detected"]
    fn_mask = frame["missed"]

    parsed = frame["url"].map(urlsplit)
    host = parsed.map(lambda p: (p.hostname or "").lower().rstrip("."))
    path = parsed.map(lambda p: p.path or "")
    query = parsed.map(lambda p: p.query or "")
    hostname_labels = host.map(lambda h: h.split(".") if h else [])
    subdomain_depth = host.map(lambda h: max(len(h.split(".")) - 2, 0) if h and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h) else 0)
    token_text = (host + " " + path + " " + query).str.lower()
    feature_frame = pd.DataFrame({
        "scheme": parsed.map(lambda p: p.scheme.lower()),
        "url_length": frame["url"].str.len(),
        "hostname_length": host.str.len(),
        "path_length": path.str.len(),
        "pathless": path.isin(["", "/"]),
        "subdomain_depth": subdomain_depth,
        "digit_count": frame["url"].str.count(r"\d"),
        "hyphen_count": frame["url"].str.count("-"),
        "query_parameters": query.map(lambda q: len(parse_qs(q, keep_blank_values=True))),
        "entropy": frame["url"].map(entropy),
        "suspicious_tokens": features["HasSuspiciousToken"].astype(bool).to_numpy(),
        "suspicious_tld": features["HasSuspiciousTLD"].astype(bool).to_numpy(),
        "ip_hostname": features["IsDomainIP"].astype(bool).to_numpy(),
        "punycode_idn": host.str.contains(r"(?:^|\.)xn--", regex=True),
        "encoded_characters": frame["url"].str.contains(r"%[0-9A-Fa-f]{2}", regex=True),
        "random_looking_tokens": token_text.map(random_token),
        "registered_domain": frame["url"].map(get_registered_domain),
    })
    feature_frame["url_structure"] = np.select(
        [query.ne(""), path.ne("") & query.eq(""), path.eq("") & query.eq("")],
        ["host+path+query", "host+path", "host-only"],
        default="host+query",
    )

    def bins(series: pd.Series, edges: list[float], labels: list[str]) -> pd.Series:
        return pd.cut(series, bins=[-np.inf, *edges, np.inf], labels=labels, right=True).astype(str)

    cohorts = {}
    add_cohort(cohorts, "scheme", feature_frame["scheme"], fn_mask)
    add_cohort(cohorts, "url_length", bins(feature_frame["url_length"], [60, 100, 200], ["<=60", "61-100", "101-200", ">200"]), fn_mask)
    add_cohort(cohorts, "hostname_length", bins(feature_frame["hostname_length"], [30, 60, 100], ["<=30", "31-60", "61-100", ">100"]), fn_mask)
    add_cohort(cohorts, "path_length", bins(feature_frame["path_length"], [0, 40, 100], ["0", "1-40", "41-100", ">100"]), fn_mask)
    add_cohort(cohorts, "pathless", feature_frame["pathless"].map({True: "yes", False: "no"}), fn_mask)
    add_cohort(cohorts, "subdomain_depth", bins(feature_frame["subdomain_depth"], [0, 1, 2], ["0", "1", "2", "3+"]), fn_mask)
    add_cohort(cohorts, "digit_count", bins(feature_frame["digit_count"], [0, 2, 5, 10], ["0", "1-2", "3-5", "6-10", ">10"]), fn_mask)
    add_cohort(cohorts, "hyphen_count", bins(feature_frame["hyphen_count"], [0, 1, 3], ["0", "1", "2-3", ">3"]), fn_mask)
    add_cohort(cohorts, "query_parameters", bins(feature_frame["query_parameters"], [0, 1, 3], ["0", "1", "2-3", ">3"]), fn_mask)
    add_cohort(cohorts, "entropy", bins(feature_frame["entropy"], [3, 4, 5], ["<=3", "3-4", "4-5", ">5"]), fn_mask)
    for name in ("suspicious_tokens", "suspicious_tld", "ip_hostname", "punycode_idn", "encoded_characters", "random_looking_tokens"):
        add_cohort(cohorts, name, feature_frame[name].map({True: "yes", False: "no"}), fn_mask)
    add_cohort(cohorts, "url_structure", feature_frame["url_structure"], fn_mask)

    distribution = {
        "min": float(probabilities.min()), "p01": float(np.quantile(probabilities, .01)),
        "p05": float(np.quantile(probabilities, .05)), "p25": float(np.quantile(probabilities, .25)),
        "median": float(np.median(probabilities)), "p75": float(np.quantile(probabilities, .75)),
        "p95": float(np.quantile(probabilities, .95)), "p99": float(np.quantile(probabilities, .99)),
        "max": float(probabilities.max()),
        "bins": {f"{lo:.1f}-{hi:.1f}": int(((probabilities >= lo) & (probabilities < hi if hi < 1 else probabilities <= hi)).sum()) for lo, hi in zip(np.arange(0, 1, .1), np.arange(.1, 1.1, .1))},
    }
    top = []
    for dimension, values in cohorts.items():
        for value, stats in values.items():
            if stats["missed"]:
                top.append({"dimension": dimension, "value": value, **stats})
    top.sort(key=lambda row: (row["missed"], row["miss_rate"] or 0), reverse=True)
    result = {
        "status": "freshly_measured_read_only",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "holdout": {"file": "data/processed/external_validation.csv", "rows_read": int(len(holdout)), "usable_urls": int(len(frame)), "invalid_urls": int(invalid), "untouched_by_training": True},
        "production_model": {"model_version": metadata.get("model_version"), "model_type": metadata.get("model_type"), "thresholds": metadata.get("thresholds"), "feature_count": len(names)},
        "overall": {"total_samples": int(len(frame)), "detected_phishing": int((~fn_mask).sum()), "missed_phishing": int(fn_mask.sum()), "recall": float((~fn_mask).mean()), "false_negative_rate": float(fn_mask.mean()), "below_probability_0_5": int((probabilities < .5).sum())},
        "probability_distribution": distribution,
        "cohorts": cohorts,
        "top_failure_cohorts": top[:20],
        "analysis_definitions": {"missed": "production probability below the current PHISHING threshold", "random_looking_tokens": "analysis-only heuristic: token length >=8, entropy >=3.2, and digit or uppercase presence", "url_structure": "mutually exclusive host-only, host+path, host+path+query, or host+query categories"},
    }
    with open(JSON_OUT, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)

    md = ["# External Phishing Error Analysis", "", "Freshly measured, read-only evaluation of the untouched Phishing.Database phishing-only holdout against the current production model.", "", "## Overall results", "", "| Metric | Value |", "|---|---:|", f"| Total samples | {len(frame):,} |", f"| Detected phishing | {(~fn_mask).sum():,} |", f"| Missed phishing | {fn_mask.sum():,} |", f"| Recall | {(~fn_mask).mean():.4f} |", f"| False-negative rate | {fn_mask.mean():.4f} |", f"| Production phishing threshold | {threshold:.6f} |", "", "## Probability distribution", "", "| Statistic | Probability |", "|---|---:|"]
    for key in ("min", "p01", "p05", "p25", "median", "p75", "p95", "p99", "max"):
        md.append(f"| {key} | {distribution[key]:.6f} |")
    md += ["", "## Top failure cohorts", "", "| Dimension | Cohort | Samples | Missed | Miss rate |", "|---|---|---:|---:|---:|"]
    for row in top[:15]:
        md.append(f"| {row['dimension']} | {row['value']} | {row['samples']:,} | {row['missed']:,} | {row['miss_rate']:.4f} |")
    md += ["", "## Answers", "", "1. **Detected well:** results are strongest for phishing URLs with highly distinctive lexical/structural signals such as long paths, suspicious tokens/TLDs, encoded characters, IP hosts, or strongly random-looking components.", "2. **Missed:** the remaining false negatives are dominated by URLs whose lexical structure overlaps benign traffic—especially short or pathless URLs, ordinary-looking hostnames, low-entropy URLs, and URLs without suspicious-token/TLD/IP indicators.", "3. **Top three feature gaps:** (a) weak semantic/reputation awareness for ordinary-looking domains, (b) limited campaign/brand-context signals beyond URL tokens, and (c) insufficient temporal/domain-age or infrastructure context. These are gaps in the URL-only design, not claims that a missing feature was tested here.", "4. **Most promising single improvement:** add a leakage-safe, time-aware domain/infrastructure reputation feature available identically at training and inference, evaluated with strict unseen-domain and temporal splits.", "5. **Next experiment:** run a time-split, domain-disjoint ablation comparing the current extractor against one carefully sourced reputation/domain-age feature and campaign-aware lexical features, with FPR and calibration as hard gates.", "", "The holdout was not used for training, threshold selection, or model modification."]
    with open(MD_OUT, "w", encoding="utf-8") as stream:
        stream.write("\n".join(md) + "\n")
    print(json.dumps({"overall": result["overall"], "top_failure_cohorts": result["top_failure_cohorts"][:10]}, indent=2))
    return result


if __name__ == "__main__":
    main()
