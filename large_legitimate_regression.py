#!/usr/bin/env python3
"""Evaluate production and experiment models on broad legitimate URL regressions.

This is an evaluation-only script. It does not train, tune, promote, or modify models.
"""

from __future__ import annotations

import hashlib
import json
import pickle
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import service
import train_dynamic_recovery_experiment as experiment


REPORT_PATH = ROOT / "reports" / "large_legitimate_regression.json"
CANDIDATE_PATH = (
    ROOT / "models" / "experiments" / "dynamic_recovery"
    / "candidate_hist_gradient_boosting.pkl"
)
PRODUCTION_PATHS = [
    ROOT / "phishing_model.pkl",
    ROOT / "feature_names.pkl",
    ROOT / "feature_importance.csv",
]

CATEGORIES: dict[str, list[str]] = {
    "SEARCH": [
        "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com",
        "yandex.com", "naver.com", "ecosia.org",
    ],
    "VIDEO": [
        "youtube.com", "netflix.com", "twitch.tv", "spotify.com",
        "soundcloud.com", "dailymotion.com", "vimeo.com",
    ],
    "SOCIAL": [
        "facebook.com", "instagram.com", "x.com", "twitter.com", "reddit.com",
        "tiktok.com", "linkedin.com", "pinterest.com", "threads.net",
        "snapchat.com", "discord.com", "whatsapp.com", "telegram.org",
    ],
    "DEVELOPMENT": [
        "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
        "stackexchange.com", "npmjs.com", "pypi.org", "python.org",
        "nodejs.org", "docker.com", "dockerhub.com", "kaggle.com",
        "huggingface.co", "openai.com", "microsoft.com", "azure.microsoft.com",
        "windows.com", "apple.com", "developer.apple.com",
        "developer.mozilla.org", "wikipedia.org", "archive.org", "cloudflare.com",
    ],
    "SHOPPING": [
        "amazon.com", "ebay.com", "walmart.com", "etsy.com", "aliexpress.com",
        "shopify.com", "bestbuy.com",
    ],
    "FINANCE": [
        "paypal.com", "stripe.com", "wise.com", "revolut.com", "binance.com",
        "coinbase.com",
    ],
    "EDUCATION": [
        "coursera.org", "edx.org", "udemy.com", "mit.edu", "stanford.edu",
        "harvard.edu", "arxiv.org", "researchgate.net",
    ],
    "TRAVEL": [
        "booking.com", "airbnb.com", "tripadvisor.com", "uber.com", "expedia.com",
    ],
    "NEWS": [
        "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
        "forbes.com",
    ],
    "CLOUD": [
        "dropbox.com", "drive.google.com", "docs.google.com", "notion.so",
        "slack.com", "zoom.us", "trello.com", "canva.com", "figma.com",
    ],
    "ADULT/NSFW": ["pornhub.com", "xvideos.com", "xnxx.com", "redgifs.com"],
}

EXACT_REFERENCES = [
    ("SEARCH", "https://google.com"),
    ("SEARCH", "https://google.com/search?q=test"),
    ("SEARCH", "https://www.google.com/"),
    ("SEARCH", "https://www.google.com/search?q=test"),
    ("VIDEO", "https://www.youtube.com/"),
    ("VIDEO", "https://www.youtube.com/?feature=ytca"),
    ("DEVELOPMENT", "https://github.com"),
    ("DEVELOPMENT", "https://microsoft.com"),
    ("DEVELOPMENT", "https://apple.com"),
    ("SHOPPING", "https://amazon.com"),
    ("DEVELOPMENT", "https://python.org"),
    ("DEVELOPMENT", "https://cloudflare.com"),
    ("SEARCH", "https://fast.com"),
    ("SEARCH", "https://fast.com/"),
    ("SEARCH", "https://www.fast.com/"),
    ("SEARCH", "https://example.com/"),
]

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

PATHS = {
    "SEARCH": [
        "/about", "/search?q=cybersecurity", "/search?query=hello+world",
        "/search?query=test&page=2&sort=recent",
        "/search?lang=en&region=us&page=2#results",
        "/help/search/advanced-options/overview",
        "/search?q=computer%20security%20basics",
        "/search?q=security%2Fprivacy%3F&source=home",
    ],
    "VIDEO": [
        "/about", "/watch?v=dQw4w9WgXcQ", "/video/12345",
        "/search?q=music%20documentary",
        "/playlist?list=PL123456789&page=2&feature=share",
        "/help/account/settings?lang=en#overview",
        "/videos/technology/channel/12345?sort=recent",
        "/watch?v=dQw4w9WgXcQ&utm_source=google&utm_medium=referral",
    ],
    "SOCIAL": [
        "/about", "/settings?lang=en", "/search?q=cybersecurity",
        "/user/profile/posts/12345?sort=recent&page=2",
        "/community/topic/technology/discussion/12345#comments",
        "/help/account/privacy/settings?region=us",
        "/posts/caf%C3%A9%20discussion?source=home",
        "/feed?utm_source=google&utm_medium=referral&utm_campaign=test",
    ],
    "DEVELOPMENT": [
        "/about", "/search?q=python%20documentation",
        "/user/repository/issues/123?sort=recent&page=2",
        "/docs/guides/getting-started?lang=en#overview",
        "/projects/open-source/releases/12345?ref=home",
        "/packages/example-library/versions/2.1.0",
        "/help/account/settings?utm_source=google&utm_campaign=test",
        "/search?query=hello%20world&page=2&sort=recent#results",
    ],
    "SHOPPING": [
        "/about", "/products/123456", "/products/123456?sort=recent&page=2",
        "/search?q=wireless%20headphones&ref=home",
        "/category/electronics/audio/headphones?lang=en&region=us",
        "/help/orders/returns-and-refunds#overview",
        "/products/123456?utm_source=google&utm_medium=cpc&utm_campaign=test",
        "/search?query=computer%20security&page=2&sort=recent",
    ],
    "FINANCE": [
        "/about", "/help/account/security", "/help/article/12345?lang=en",
        "/settings/profile?region=us#overview",
        "/business/services/payments/international?source=home",
        "/help/account/verification/troubleshooting?ref=home",
        "/articles/security%20and%20privacy?utm_source=google",
        "/help/search?query=account%20settings&page=2",
    ],
    "EDUCATION": [
        "/about", "/courses/12345", "/courses/12345/lessons/67890",
        "/search?q=computer%20security&sort=recent",
        "/library/research/machine-learning/overview#section",
        "/help/account/settings?lang=en&region=us",
        "/articles/learning%20resources?source=home",
        "/courses/12345?utm_source=google&utm_medium=referral",
    ],
    "TRAVEL": [
        "/about", "/search?query=hotels&page=2&sort=recent",
        "/hotels/123456?checkin=2026-11-15&guests=2",
        "/destinations/europe/france/paris?lang=en&region=us",
        "/trips/itinerary/12345#overview",
        "/help/booking/changes-and-cancellations",
        "/search?q=weekend%20trip&utm_source=google",
        "/activities/city/tour/12345?ref=home",
    ],
    "NEWS": [
        "/about", "/world/article/12345",
        "/technology/security/article/12345?utm_source=google",
        "/search?q=computer%20security&page=2",
        "/news/business/markets/2026/10/08#overview",
        "/help/subscriptions/account/settings?lang=en",
        "/article/long-form/reporting/technology/privacy-and-security",
        "/article/12345?source=home&ref=homepage#comments",
    ],
    "CLOUD": [
        "/about", "/help/account/settings?lang=en",
        "/workspace/projects/12345/documents/67890",
        "/search?q=project%20notes&sort=recent&page=2",
        "/files/shared/folder/12345?ref=home#overview",
        "/docs/guides/collaboration/notifications?region=us",
        "/app/boards/12345/cards/67890?feature=share",
        "/help/search?query=account%20security&utm_source=google",
    ],
    "ADULT/NSFW": [
        "/about", "/search?q=music%20video", "/video/12345",
        "/categories/entertainment/videos?page=2&sort=recent",
        "/channels/creator-name/videos/67890",
        "/help/account/settings?lang=en#overview",
        "/video/12345?feature=share&utm_source=google",
        "/search?query=video%20library&page=2#results",
    ],
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_reference_rows() -> list[dict[str, str | bool]]:
    rows: list[dict[str, str | bool]] = []
    seen: set[str] = set()

    def add(category: str, url: str, exact: bool = False) -> None:
        normalized = experiment.normalize_url(url)
        key = f"{category}\0{url}"
        if not normalized or key in seen:
            return
        seen.add(key)
        rows.append({
            "category": category,
            "url": url,
            "normalized_url": normalized,
            "required_safe": url in {
                "https://fast.com", "https://fast.com/", "https://www.fast.com/"
            },
            "exact_existing_reference": exact,
        })

    for category, url in EXACT_REFERENCES:
        add(category, url, exact=True)
    for category, domains in CATEGORIES.items():
        for domain in domains:
            add(category, f"https://{domain}")
            add(category, f"https://{domain}/")
            add(
                category,
                f"https://{domain}/help/account/security/privacy/preferences/"
                "notifications/manage-your-settings?lang=en&region=us&page=2#overview",
            )
            for path in PATHS[category]:
                add(category, f"https://{domain}{path}")
    return rows


def extract_matrix(urls: list[str], feature_names: list[str]) -> tuple[pd.DataFrame, int]:
    normalized = [service.normalize_url(url) for url in urls]
    if any(not value for value in normalized):
        raise ValueError("A regression URL could not be normalized by VIGIL.")
    features, okay, failures = experiment.extract_feature_frame(normalized, "large-regression")
    if failures or not okay.all():
        raise RuntimeError(f"Feature extraction failed for {failures} URLs.")
    missing = sorted(set(feature_names) - set(features.columns))
    if missing:
        raise ValueError(f"Production features missing from extractor: {missing}")
    return features.reindex(columns=feature_names), failures


def predict(model, matrix: pd.DataFrame) -> tuple[np.ndarray, float]:
    started = time.perf_counter()
    probabilities = np.asarray(model.predict_proba(matrix), dtype=float)
    elapsed = (time.perf_counter() - started) * 1000
    if probabilities.shape != (len(matrix), 2):
        raise ValueError(f"Unexpected probability array shape {probabilities.shape}")
    if not np.isfinite(probabilities).all() or (
        (probabilities < 0).any() or (probabilities > 1).any()
    ):
        raise ValueError("Model returned invalid probabilities.")
    return probabilities[:, 1], elapsed


def classify(probabilities: np.ndarray, thresholds: dict[str, float]) -> list[str]:
    return [
        service._classify(float(probability), thresholds["safe"], thresholds["phishing"])[0]
        for probability in probabilities
    ]


def summarize(rows: list[dict], verdict_key: str) -> dict:
    verdicts = [
        value["verdict"] if isinstance(value := row[verdict_key], dict) else value
        for row in rows
    ]
    counts = Counter(verdicts)
    total = len(rows)
    return {
        "total": total,
        "safe": counts["SAFE"],
        "suspicious": counts["SUSPICIOUS"],
        "phishing": counts["PHISHING"],
        "phishing_false_positive_rate": counts["PHISHING"] / total if total else 0.0,
    }


def by_category(rows: list[dict], verdict_key: str) -> dict:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["category"]].append(row)
    return {category: summarize(items, verdict_key) for category, items in grouped.items()}


def by_url_structure(rows: list[dict], verdict_key: str) -> dict:
    structure_rows: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        parsed = urlsplit(row["normalized_url"])
        query_keys = set(parse_qs(parsed.query, keep_blank_values=True))
        segments = [segment for segment in parsed.path.split("/") if segment]
        flags = {
            "has_non_root_path": bool(segments),
            "has_query": bool(parsed.query),
            "has_fragment": bool(parsed.fragment),
            "has_tracking_parameter": bool(
                query_keys & {
                    "utm_source", "utm_medium", "utm_campaign", "ref", "source",
                    "fbclid", "gclid",
                }
            ),
            "has_percent_encoding": "%" in parsed.path or "%" in parsed.query,
            "has_multiple_path_segments": len(segments) >= 3,
            "url_length_over_120": len(row["url"]) > 120,
        }
        for name, active in flags.items():
            if active:
                structure_rows[name].append(row)
    return {
        structure: summarize(items, verdict_key)
        for structure, items in sorted(structure_rows.items())
    }


def evaluate(model, matrix: pd.DataFrame, thresholds: dict[str, float]) -> tuple[list[str], list[float], float]:
    probabilities, elapsed_ms = predict(model, matrix)
    return classify(probabilities, thresholds), probabilities.tolist(), elapsed_ms


def main() -> None:
    hashes_before = {path.name: sha256(path) for path in PRODUCTION_PATHS}
    production_model, production_names, production_metadata = service.load_model_bundle()
    with CANDIDATE_PATH.open("rb") as stream:
        candidate = pickle.load(stream)
    if not isinstance(candidate, dict) or not candidate.get("experiment_only"):
        raise TypeError("Candidate artifact is not a marked experiment-only bundle.")
    candidate_names = list(candidate["feature_names"])
    if candidate_names != production_names:
        raise ValueError("Production and candidate feature order differs.")

    reference_rows = build_reference_rows()
    if len(reference_rows) < 300:
        raise RuntimeError(f"Regression suite has only {len(reference_rows)} URLs; at least 300 required.")
    feature_matrix, _ = extract_matrix(
        [str(row["url"]) for row in reference_rows], production_names
    )
    production_thresholds = service._thresholds_from_metadata(production_metadata)
    candidate_thresholds = {
        "safe": float(candidate["thresholds"]["safe"]),
        "phishing": float(candidate["thresholds"]["phishing"]),
    }
    production_verdicts, production_probabilities, production_runtime = evaluate(
        production_model, feature_matrix, production_thresholds
    )
    candidate_model = experiment.ProbabilityCalibratedModel(
        candidate["estimator"], candidate["calibrator"]
    )
    candidate_verdicts, candidate_probabilities, candidate_runtime = evaluate(
        candidate_model, feature_matrix, candidate_thresholds
    )

    evaluated_rows = []
    for index, row in enumerate(reference_rows):
        evaluated_rows.append({
            **row,
            "production": {
                "probability": production_probabilities[index],
                "verdict": production_verdicts[index],
            },
            "candidate": {
                "probability": candidate_probabilities[index],
                "verdict": candidate_verdicts[index],
            },
        })

    adversarial_matrix, _ = extract_matrix(ADVERSARIAL_URLS, production_names)
    adversarial_rows = []
    prod_adv_v, prod_adv_p, _ = evaluate(
        production_model, adversarial_matrix, production_thresholds
    )
    cand_adv_v, cand_adv_p, _ = evaluate(
        candidate_model, adversarial_matrix, candidate_thresholds
    )
    for index, url in enumerate(ADVERSARIAL_URLS):
        adversarial_rows.append({
            "url": url,
            "normalized_url": service.normalize_url(url),
            "production": {"probability": prod_adv_p[index], "verdict": prod_adv_v[index]},
            "candidate": {"probability": cand_adv_p[index], "verdict": cand_adv_v[index]},
        })

    adversarial_summary = {}
    for model_name in ("production", "candidate"):
        counts = Counter(row[model_name]["verdict"] for row in adversarial_rows)
        adversarial_summary[model_name] = {
            "total": len(adversarial_rows),
            "safe": counts["SAFE"],
            "suspicious": counts["SUSPICIOUS"],
            "phishing": counts["PHISHING"],
        }

    # Include source feature comparisons for false positives; these are correlations,
    # not causal attribution or domain reputation.
    candidate_fp_indices = [
        i for i, verdict in enumerate(candidate_verdicts) if verdict == "PHISHING"
    ]
    production_fp_indices = [
        i for i, verdict in enumerate(production_verdicts) if verdict == "PHISHING"
    ]
    feature_diagnostics = {}
    for model_name, indices in (
        ("production", production_fp_indices),
        ("candidate", candidate_fp_indices),
    ):
        means = (
            feature_matrix.iloc[indices].mean().sort_values(ascending=False).head(12)
            if indices else pd.Series(dtype=float)
        )
        feature_diagnostics[model_name] = {
            "false_positive_count": len(indices),
            "top_mean_features_on_false_positives": {
                str(name): float(value) for name, value in means.items()
            },
            "interpretation": "Correlational feature summary; not causal attribution.",
        }

    fast_rows = [row for row in evaluated_rows if row["required_safe"]]
    google_search_rows = [
        row for row in evaluated_rows
        if row["url"] in {
            "https://google.com/search?q=test",
            "https://www.google.com/search?q=test",
        }
    ]
    youtube_query_rows = [
        row for row in evaluated_rows
        if row["url"] == "https://www.youtube.com/?feature=ytca"
    ]
    hashes_after = {path.name: sha256(path) for path in PRODUCTION_PATHS}
    if hashes_before != hashes_after:
        raise RuntimeError("Production model artifacts changed during regression evaluation.")

    models = {}
    for name, verdict_key, runtime_ms, thresholds in (
        ("production", "production", production_runtime, production_thresholds),
        ("candidate", "candidate", candidate_runtime, candidate_thresholds),
    ):
        models[name] = {
            **summarize(evaluated_rows, verdict_key),
            "category_results": by_category(evaluated_rows, verdict_key),
            "url_structure_results": by_url_structure(evaluated_rows, verdict_key),
            "thresholds": thresholds,
            "batch_inference_ms": runtime_ms,
        }
    gates = {
        "at_least_300_legitimate_urls": len(evaluated_rows) >= 300,
        "production_no_legitimate_reference_phishing": models["production"]["phishing"] == 0,
        "candidate_no_legitimate_reference_phishing": models["candidate"]["phishing"] == 0,
        "production_fast_com_all_safe": all(
            row["production"]["verdict"] == "SAFE" for row in fast_rows
        ),
        "candidate_fast_com_all_safe": all(
            row["candidate"]["verdict"] == "SAFE" for row in fast_rows
        ),
        "google_search_not_phishing": all(
            row["production"]["verdict"] != "PHISHING"
            and row["candidate"]["verdict"] != "PHISHING"
            for row in google_search_rows
        ),
        "youtube_query_not_phishing": all(
            row["production"]["verdict"] != "PHISHING"
            and row["candidate"]["verdict"] != "PHISHING"
            for row in youtube_query_rows
        ),
        "production_artifact_hashes_unchanged": hashes_before == hashes_after,
    }
    report = {
        "experiment": "large_legitimate_url_regression",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "evaluation_only": True,
        "normalization": "service.normalize_url (production normalization)",
        "model_identity": {
            "production_estimator": type(production_model).__name__,
            "production_thresholds": production_thresholds,
            "candidate_name": candidate.get("model_name"),
            "candidate_estimator": type(candidate["estimator"]).__name__,
            "candidate_thresholds": candidate_thresholds,
            "candidate_artifact": str(CANDIDATE_PATH.relative_to(ROOT)),
        },
        "suite": {
            "total_urls": len(evaluated_rows),
            "category_domain_counts": {
                category: len(domains) for category, domains in CATEGORIES.items()
            },
            "reference_urls": evaluated_rows,
        },
        "models": models,
        "adversarial_controls": {
            "total": len(adversarial_rows),
            "production_summary": adversarial_summary["production"],
            "candidate_summary": adversarial_summary["candidate"],
            "results": adversarial_rows,
            "domain_reputation_bypass": False,
        },
        "required_regression_checks": {
            "google_search": [
                {**row, "production_not_phishing": row["production"]["verdict"] != "PHISHING",
                 "candidate_not_phishing": row["candidate"]["verdict"] != "PHISHING"}
                for row in google_search_rows
            ],
            "youtube_query": [
                {**row, "production_not_phishing": row["production"]["verdict"] != "PHISHING",
                 "candidate_not_phishing": row["candidate"]["verdict"] != "PHISHING"}
                for row in youtube_query_rows
            ],
            "fast_com": fast_rows,
        },
        "false_positive_feature_diagnostics": feature_diagnostics,
        "false_positive_structure_diagnostics": {
            "production": models["production"]["url_structure_results"],
            "candidate": models["candidate"]["url_structure_results"],
        },
        "diagnosis_and_recommendations": [
            "Treat false-positive feature patterns as hypotheses, not proof of causality.",
            "Audit legitimate dynamic-URL training examples for host/path/query coverage and label noise; add representative examples across structures, not domain exceptions.",
            "Review feature behavior on ordinary query strings, percent-encoding, long paths and tracking parameters; consider separating URL length/complexity signals from phishing evidence.",
            "Re-train and recalibrate candidates against a held-out, domain-disjoint benign dynamic URL set while preserving phishing recall and false-positive gates.",
            "Keep lookalike domains and suspicious paths on real platforms in adversarial/negative evaluation; do not grant reputation based on registrable-domain text.",
        ],
        "production_artifacts": {
            "modified": False,
            "sha256_before": hashes_before,
            "sha256_after": hashes_after,
        },
        "gates": gates,
        "final_regression_gate": "PASS" if all(gates.values()) else "FAIL",
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")

    print("=" * 60)
    print("VIGIL LARGE LEGITIMATE REGRESSION REPORT")
    print("=" * 60)
    print(f"Total legitimate reference URLs: {len(evaluated_rows)}")
    for name, title in (("production", "PRODUCTION"), ("candidate", "CANDIDATE")):
        summary = models[name]
        print(f"\n{title}")
        print(f"SAFE: {summary['safe']}")
        print(f"SUSPICIOUS: {summary['suspicious']}")
        print(f"PHISHING: {summary['phishing']}")
        print(f"PHISHING FPR: {summary['phishing_false_positive_rate']:.6%}")
    print("\nCATEGORY RESULTS:")
    for name, title in (("production", "PRODUCTION"), ("candidate", "CANDIDATE")):
        print(f"{title}:")
        for category in CATEGORIES:
            print(f"  {category}: {models[name]['category_results'][category]}")
    print("\nADVERSARIAL LOOKALIKE RESULTS:")
    for row in adversarial_rows:
        print(
            f"{row['url']} | production={row['production']['verdict']} "
            f"({row['production']['probability']:.4f}) | "
            f"candidate={row['candidate']['verdict']} "
            f"({row['candidate']['probability']:.4f})"
        )
    print("\nGOOGLE SEARCH:")
    for row in google_search_rows:
        print(f"{row['url']} | production={row['production']['verdict']} candidate={row['candidate']['verdict']}")
    print("\nYOUTUBE QUERY:")
    for row in youtube_query_rows:
        print(f"{row['url']} | production={row['production']['verdict']} candidate={row['candidate']['verdict']}")
    print("\nFAST.COM:")
    for row in fast_rows:
        print(f"{row['url']} | production={row['production']['verdict']} candidate={row['candidate']['verdict']}")
    print("\nPRODUCTION ARTIFACTS MODIFIED:")
    print("False")
    print("\nFINAL REGRESSION GATE:")
    print(report["final_regression_gate"])
    print(f"\nReport: {REPORT_PATH}")


if __name__ == "__main__":
    main()
