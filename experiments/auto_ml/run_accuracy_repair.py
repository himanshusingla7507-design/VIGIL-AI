from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feature_extractor import get_registered_domain, normalize_url
from experiments.auto_ml import repair_false_positives as repair
from experiments.auto_ml import run_realworld_experiments as base

RUN_DIR = ROOT / "experiments" / "auto_ml" / "accuracy_repair_20261009"
PHISHTANK_PATH = RUN_DIR / "phishtank_online_valid.csv"
LEGIT_PATH = RUN_DIR / "new_legitimate_observations.csv"
RUN_REPORT = RUN_DIR / "accuracy_repair_final.json"
LEADERBOARD = RUN_DIR / "accuracy_repair_leaderboard.json"
DATASET_PATH = RUN_DIR / "fresh_labeled_rows.csv"
SPLIT_PATH = RUN_DIR / "domain_splits.json"
FAILURE_PATH = RUN_DIR / "accuracy_repair_failure_analysis.json"
OLD_BEST_PATH = (
    ROOT
    / "experiments"
    / "auto_ml"
    / "false_positive_repair_20261009T084933Z"
    / "best_validation_candidate.joblib"
)

SPLIT_NAMES = ("train", "calibration", "validation", "test")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assign_phishing_domain(domain: str) -> str:
    bucket = int(hashlib.sha256(domain.encode("utf-8")).hexdigest()[:8], 16) % 100
    if bucket < 60:
        return "train"
    if bucket < 70:
        return "calibration"
    if bucket < 80:
        return "validation"
    return "test"


def assign_legitimate_domains(rows: list[dict]) -> dict[str, str]:
    domains = sorted(
        {row["registered_domain"] for row in rows},
        key=lambda domain: hashlib.sha256(
            f"fresh-legitimate-domains-v1:{domain}".encode("utf-8")
        ).hexdigest(),
    )
    count = len(domains)
    train_end = round(count * 0.35)
    calibration_end = train_end + round(count * 0.15)
    validation_end = calibration_end + round(count * 0.15)
    assignments = {}
    for index, domain in enumerate(domains):
        if index < train_end:
            split = "train"
        elif index < calibration_end:
            split = "calibration"
        elif index < validation_end:
            split = "validation"
        else:
            split = "test"
        assignments[domain] = split
    return assignments


def flatten_split(rows_by_split: dict, split: str) -> list[dict]:
    return [
        row
        for label in (0, 1)
        for cohort_rows in rows_by_split[split][label].values()
        for row in cohort_rows
    ]


def load_phishtank() -> tuple[list[dict], dict]:
    if not PHISHTANK_PATH.is_file():
        raise FileNotFoundError(f"PhishTank snapshot is missing: {PHISHTANK_PATH}")
    rows: dict[str, dict] = {}
    counts = Counter()
    with PHISHTANK_PATH.open(encoding="utf-8-sig", newline="") as stream:
        for source_row in csv.DictReader(stream):
            if source_row.get("verified") != "yes" or source_row.get("online") != "yes":
                counts["not_verified_and_online"] += 1
                continue
            try:
                url = normalize_url(source_row["url"])
                domain = get_registered_domain(url)
            except (KeyError, TypeError, ValueError):
                counts["invalid_url"] += 1
                continue
            if url in rows:
                counts["duplicate_normalized_url"] += 1
                continue
            rows[url] = {
                "url": url,
                "label": 1,
                "source_name": "PhishTank verified online feed",
                "source_page": "https://phishtank.org/developer_info.php",
                "category": base.primary_cohort(url),
                "verification_method": "PhishTank snapshot fields verified=yes and online=yes",
                "registered_domain": domain,
                "verification_time": source_row.get("verification_time", ""),
                "submission_time": source_row.get("submission_time", ""),
            }
    return list(rows.values()), {
        "raw_snapshot_sha256": sha256(PHISHTANK_PATH),
        "valid_unique_verified_online_urls": len(rows),
        "registered_domains": len({row["registered_domain"] for row in rows.values()}),
        "filtered_counts": dict(counts),
    }


def load_new_legitimate() -> tuple[list[dict], dict]:
    if not LEGIT_PATH.is_file():
        raise FileNotFoundError(
            f"New legitimate observations are missing: {LEGIT_PATH}. "
            "Run collect_accuracy_repair_data.py first."
        )
    rows: dict[str, dict] = {}
    counts = Counter()
    with LEGIT_PATH.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"url", "label", "source", "source_page_url", "verification_status"}
        if not required.issubset(reader.fieldnames or set()):
            raise ValueError(f"Unexpected legitimate collector columns: {reader.fieldnames}")
        for source_row in reader:
            if source_row.get("label") != "0":
                counts["invalid_label"] += 1
                continue
            try:
                url = normalize_url(source_row["url"])
                domain = get_registered_domain(url)
            except (KeyError, TypeError, ValueError):
                counts["invalid_url"] += 1
                continue
            if url in rows:
                counts["duplicate_normalized_url"] += 1
                continue
            rows[url] = {
                "url": url,
                "label": 0,
                "source_name": source_row.get("source", ""),
                "source_page": source_row.get("source_page_url", ""),
                "category": source_row.get("category", base.primary_cohort(url)),
                "verification_method": source_row.get("verification_status", ""),
                "registered_domain": domain,
            }
    return list(rows.values()), {
        "raw_snapshot_sha256": sha256(LEGIT_PATH),
        "valid_unique_urls": len(rows),
        "registered_domains": len({row["registered_domain"] for row in rows.values()}),
        "filtered_counts": dict(counts),
    }


def add_to_buckets(rows_by_split: dict, split: str, row: dict) -> None:
    cohort = base.primary_cohort(row["url"])
    row["primary_cohort"] = cohort
    row["split"] = split
    rows_by_split[split][row["label"]][cohort].append(row)


def capped_rows(rows: list[dict], per_cohort_label: int, per_domain: int) -> list[dict]:
    grouped: dict[tuple[int, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["label"], base.primary_cohort(row["url"]))].append(row)
    selected = []
    for key in sorted(grouped):
        domain_counts = Counter()
        candidates = sorted(grouped[key], key=lambda row: base.stable_rank(row["url"]))
        kept = 0
        for row in candidates:
            domain = row["registered_domain"]
            if domain_counts[domain] >= per_domain:
                continue
            selected.append(row)
            domain_counts[domain] += 1
            kept += 1
            if kept >= per_cohort_label:
                break
    return selected


def prepare_rows() -> tuple[dict, list[dict], dict]:
    benchmark_domains, _, _ = base.load_benchmark_reservations()
    legacy_by_split, legacy_report = base.load_inputs(benchmark_domains)
    legacy_rows = [
        row
        for split in SPLIT_NAMES
        for row in flatten_split(legacy_by_split, split)
    ]
    legacy_domains = {row["registered_domain"] for row in legacy_rows}
    legacy_training = flatten_split(legacy_by_split, "train")

    fresh_phishing, phishing_input_report = load_phishtank()
    fresh_legitimate, legitimate_input_report = load_new_legitimate()

    known_domains = legacy_domains | benchmark_domains
    phish_domains = {row["registered_domain"] for row in fresh_phishing}
    fresh_legit_domains = {row["registered_domain"] for row in fresh_legitimate}
    conflict_domains = phish_domains & fresh_legit_domains
    excluded = Counter()
    selected_phishing = []
    for row in fresh_phishing:
        domain = row["registered_domain"]
        if domain in known_domains:
            excluded["phishing_domain_seen_in_prior_data_or_benchmark"] += 1
        elif domain in conflict_domains:
            excluded["phishing_domain_conflicts_with_new_legitimate_source"] += 1
        else:
            selected_phishing.append(row)

    selected_legitimate = []
    for row in fresh_legitimate:
        domain = row["registered_domain"]
        if domain in known_domains:
            excluded["legitimate_domain_seen_in_prior_data_or_benchmark"] += 1
        elif domain in conflict_domains:
            excluded["legitimate_domain_conflicts_with_phishtank"] += 1
        else:
            selected_legitimate.append(row)

    normalized_seen = set()
    fresh_rows = []
    for row in selected_legitimate + selected_phishing:
        url = row["url"]
        if url in normalized_seen:
            excluded["cross_or_within_class_normalized_duplicate"] += 1
            continue
        normalized_seen.add(url)
        fresh_rows.append(row)

    domain_assignments = assign_legitimate_domains(
        [row for row in fresh_rows if row["label"] == 0]
    )
    domain_assignments.update({
        row["registered_domain"]: assign_phishing_domain(row["registered_domain"])
        for row in fresh_rows
        if row["label"] == 1
    })
    new_rows_by_split = {
        split: {0: defaultdict(list), 1: defaultdict(list)} for split in SPLIT_NAMES
    }
    for row in fresh_rows:
        add_to_buckets(new_rows_by_split, domain_assignments[row["registered_domain"]], row)

    legacy_sample = capped_rows(legacy_training, per_cohort_label=350, per_domain=20)
    fresh_train_rows = flatten_split(new_rows_by_split, "train")
    fresh_train_legitimate = [row for row in fresh_train_rows if row["label"] == 0]
    fresh_train_phishing = [row for row in fresh_train_rows if row["label"] == 1]
    legitimate_by_cohort = Counter(base.primary_cohort(row["url"]) for row in fresh_train_legitimate)
    phishing_by_cohort: dict[str, list[dict]] = defaultdict(list)
    for row in fresh_train_phishing:
        phishing_by_cohort[base.primary_cohort(row["url"])].append(row)
    matched_phishing = []
    for cohort, candidates in phishing_by_cohort.items():
        limit = min(400, max(75, 3 * legitimate_by_cohort[cohort]))
        matched_phishing.extend(
            sorted(candidates, key=lambda row: base.stable_rank(row["url"]))[:limit]
        )

    rows_by_split = {
        split: {0: defaultdict(list), 1: defaultdict(list)} for split in SPLIT_NAMES
    }
    for row in legacy_sample:
        add_to_buckets(rows_by_split, "train", row)
        row["split"] = "legacy_train_only"
    for row in fresh_train_legitimate + matched_phishing:
        add_to_buckets(rows_by_split, "train", row)
    for split in ("calibration", "validation"):
        for label in (0, 1):
            for cohort_rows in new_rows_by_split[split][label].values():
                for row in cohort_rows:
                    add_to_buckets(rows_by_split, split, row)
    test_rows = flatten_split(new_rows_by_split, "test")

    split_domains = {
        split: {
            row["registered_domain"]
            for label in (0, 1)
            for cohort_rows in rows_by_split[split][label].values()
            for row in cohort_rows
        }
        for split in SPLIT_NAMES
    }
    split_domains["test"] = {row["registered_domain"] for row in test_rows}
    overlap = {}
    for index, left in enumerate(SPLIT_NAMES):
        for right in SPLIT_NAMES[index + 1 :]:
            shared = split_domains[left] & split_domains[right]
            if shared:
                overlap[f"{left}_{right}"] = sorted(shared)
    if overlap:
        raise RuntimeError(f"Registered domains cross fresh-data splits: {overlap}")

    selected_new_domains = {row["registered_domain"] for row in fresh_rows}
    if selected_new_domains & legacy_domains:
        raise RuntimeError("A fresh evaluation domain appeared in prior data.")
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input_hashes": {
            "legacy_legitimate_csv": legacy_report["input_sha256"]["legitimate_csv"],
            "legacy_phishing_feed": legacy_report["input_sha256"]["phishing_feed"],
            "fixed_benchmark_manifest": legacy_report["input_sha256"]["benchmark_manifest"],
            "new_legitimate_observations": legitimate_input_report["raw_snapshot_sha256"],
            "phishtank_verified_online_snapshot": phishing_input_report["raw_snapshot_sha256"],
        },
        "inputs": {
            "legacy": legacy_report["retained_candidate_pool"],
            "new_legitimate": legitimate_input_report,
            "phishtank": phishing_input_report,
        },
        "exclusions": dict(excluded),
        "new_dataset_unique_rows": len(fresh_rows),
        "new_dataset_class_rows": dict(Counter(row["label"] for row in fresh_rows)),
        "new_dataset_domains_by_class": {
            str(label): len({row["registered_domain"] for row in fresh_rows if row["label"] == label})
            for label in (0, 1)
        },
        "new_dataset_source_counts": dict(Counter(row["source_name"] for row in fresh_rows)),
        "new_dataset_cohort_counts_by_class": {
            str(label): dict(
                Counter(base.primary_cohort(row["url"]) for row in fresh_rows if row["label"] == label)
            )
            for label in (0, 1)
        },
        "split_method": (
            "Novel legitimate source domains are deterministically ordered by a salted "
            "SHA-256 rank and assigned 35% train, 15% calibration, 15% validation, "
            "and the remainder to untouched test, ensuring an adequate count of unseen "
            "legitimate test domains. Novel PhishTank domains are assigned by SHA-256 "
            "bucket to 60% train, 10% calibration, 10% validation, and 20% untouched test. "
            "Conflicting registered domains are excluded; legacy rows are training-only."
        ),
        "split_counts": {
            split: {
                "rows": sum(len(items) for label in (0, 1) for items in new_rows_by_split[split][label].values()),
                "legitimate": sum(len(items) for items in new_rows_by_split[split][0].values()),
                "phishing": sum(len(items) for items in new_rows_by_split[split][1].values()),
                "domains": len(split_domains[split]),
                "legitimate_domains": len({
                    row["registered_domain"]
                    for row in fresh_rows
                    if row["label"] == 0 and domain_assignments[row["registered_domain"]] == split
                }),
                "phishing_domains": len({
                    row["registered_domain"]
                    for row in fresh_rows
                    if row["label"] == 1 and domain_assignments[row["registered_domain"]] == split
                }),
            }
            for split in SPLIT_NAMES
        },
        "train_sampling": {
            "legacy_train_cap_per_cohort_and_label": 350,
            "legacy_train_cap_per_registered_domain": 20,
            "fresh_legitimate_train_rows": len(fresh_train_legitimate),
            "fresh_phishing_train_rows": len(matched_phishing),
            "fresh_phishing_limit_per_cohort": "min(400, max(75, 3 * fresh legitimate count))",
        },
        "registered_domain_split_overlap": overlap,
        "known_prior_domains_excluded_from_fresh_rows": len(known_domains),
        "fresh_test_domain_overlap_with_prior": sorted(
            split_domains["test"] & known_domains
        ),
        "duplicate_policy": "feature_extractor.normalize_url; conflicting registered domains are excluded.",
        "phishing_label_policy": "PhishTank rows retained only when verified=yes and online=yes; no target URL was fetched.",
    }
    return rows_by_split, test_rows, manifest


def write_reproducibility_data(rows_by_split: dict, test_rows: list[dict], manifest: dict) -> None:
    combined = []
    for split in SPLIT_NAMES:
        for label in (0, 1):
            for cohort_rows in rows_by_split[split][label].values():
                combined.extend(cohort_rows)
    combined.extend(test_rows)
    unique = {}
    for row in combined:
        key = (row["url"], row["label"], row["registered_domain"])
        unique[key] = row
    with DATASET_PATH.open("x", encoding="utf-8", newline="") as stream:
        fields = (
            "url", "label", "registered_domain", "source_name", "source_page",
            "category", "verification_method", "split",
        )
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in sorted(unique.values(), key=lambda item: (item["label"], item["registered_domain"], item["url"])):
            writer.writerow(
                {field: row.get(field, "") for field in fields[:-1]}
                | {"split": row.get("split", "legacy_train_only")}
            )
    SPLIT_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def primary_metrics(rows: list[dict], probabilities: np.ndarray, threshold: float) -> dict:
    result = repair.metrics(rows, probabilities, threshold)
    structures = repair.feature_groups(rows, probabilities, threshold)
    result["by_structure"] = structures["url_structure"]
    result["by_source"] = structures["source"]
    result["by_registered_domain"] = structures["registered_domain"]
    result["failure_count"] = structures["failure_count"]
    result["false_positive_examples"] = structures["false_positive_examples"]
    result["false_negative_examples"] = structures["false_negative_examples"]
    return result


def load_regression_benchmark() -> tuple[list[dict], list[dict]]:
    _, benchmark_sets, fixed = base.load_benchmark_reservations()
    rows = []
    for source_file, source_rows in benchmark_sets.items():
        for source_row in source_rows:
            url = normalize_url(source_row["url"])
            rows.append({
                "url": url,
                "label": int(source_row["label"]),
                "source_name": source_row.get("source", source_file),
                "source_page": source_row.get("provenance", ""),
                "registered_domain": get_registered_domain(url),
            })
    core = [
        {
            "url": normalize_url(url),
            "label": 0,
            "source_name": "fixed core legitimate regression set",
            "source_page": "benchmark_v1/fixed_urls.json",
            "registered_domain": get_registered_domain(url),
        }
        for url in fixed["baseline_legitimate_urls"]
    ]
    return rows, core


def main() -> None:
    if RUN_REPORT.exists() or LEADERBOARD.exists() or DATASET_PATH.exists() or SPLIT_PATH.exists():
        raise FileExistsError("Refusing to overwrite existing accuracy-repair reports.")
    initial_hashes = repair.reliability_hashes()
    rows_by_split, test_rows, manifest = prepare_rows()
    write_reproducibility_data(rows_by_split, test_rows, manifest)

    validation_rows = base.choose_rows(rows_by_split, "validation")
    calibration_rows = base.choose_rows(rows_by_split, "calibration")
    if not test_rows or not validation_rows or not calibration_rows:
        raise ValueError(
            "Fresh domain-disjoint train, calibration, validation, and test data are required; "
            f"counts: validation={len(validation_rows)}, calibration={len(calibration_rows)}, test={len(test_rows)}"
        )
    for split_name, rows in (
        ("validation", validation_rows),
        ("calibration", calibration_rows),
    ):
        if {row["label"] for row in rows} != {0, 1}:
            raise ValueError(f"Fresh {split_name} set lacks one of the two classes.")

    initial_candidate = joblib.load(OLD_BEST_PATH)
    initial_threshold = float(initial_candidate["thresholds"]["phishing"])
    initial_validation_probabilities = repair.predict(initial_candidate, validation_rows)
    initial_validation = {
        "experiment": "previous_best_repair_candidate_reference",
        "threshold": initial_threshold,
        "validation_metrics": repair.metrics(
            validation_rows, initial_validation_probabilities, initial_threshold
        ),
        "artifact": str(OLD_BEST_PATH.relative_to(ROOT)),
        "artifact_sha256": repair.sha256(OLD_BEST_PATH),
        "selection_role": "reference only; threshold was chosen in prior run",
    }

    specs = repair.candidate_specs()
    selected_specs = [specs[0], specs[1], specs[4]]
    leaderboard = [initial_validation]
    best_candidate = initial_candidate
    best_record = initial_validation
    trial_records = []
    for spec in selected_specs:
        trial_dir = RUN_DIR / "candidates" / spec["name"]
        trial_dir.mkdir(parents=True, exist_ok=True)
        (trial_dir / "dataset_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        candidate, record = repair.train_trial(spec, rows_by_split, trial_dir)
        record["hypothesis"] = spec["hypothesis"]
        record["change"] = spec["change"]
        record["validation_production_reference"] = {
            "metrics": repair.service_metrics(
                validation_rows,
                *repair.production_prediction(validation_rows),
            ),
            "same_examples": len(validation_rows),
        }
        record["outcome_vs_best_validation"] = {
            "previous_best": best_record["experiment"],
            "meaningful_improvement": repair.meaningfully_improves(record, best_record)
            if "validation_metrics" in best_record
            else True,
        }
        trial_records.append(record)
        leaderboard.append(record)
        if repair.validation_rank(record) > repair.validation_rank(best_record):
            best_candidate = candidate
            best_record = record
        (trial_dir / "experiment.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if best_record is initial_validation:
        selected_candidate = initial_candidate
        selected_name = initial_validation["experiment"]
        selected_artifact = OLD_BEST_PATH
    else:
        selected_candidate = best_candidate
        selected_name = best_record["experiment"]
        selected_artifact = RUN_DIR / "best_validation_candidate.joblib"
        joblib.dump(selected_candidate, selected_artifact, compress=3)

    test_probabilities = repair.predict(selected_candidate, test_rows)
    threshold = float(selected_candidate["thresholds"]["phishing"])
    test_metrics = primary_metrics(test_rows, test_probabilities, threshold)
    production_probabilities, production_labels = repair.production_prediction(test_rows)
    production_metrics = repair.service_metrics(
        test_rows, production_probabilities, production_labels
    )
    prior_best_probabilities = repair.predict(initial_candidate, test_rows)
    prior_best_metrics = repair.metrics(
        test_rows, prior_best_probabilities, initial_threshold
    )
    # This previously exposed benchmark is evaluated only after model selection.
    regression_rows, core_rows = load_regression_benchmark()
    regression_probabilities = repair.predict(selected_candidate, regression_rows)
    regression_metrics = repair.metrics(
        regression_rows, regression_probabilities, threshold
    )
    core_probabilities = repair.predict(selected_candidate, core_rows)
    core_metrics = repair.metrics(core_rows, core_probabilities, threshold)
    failure_report = {
        "test_data_status": (
            "Fresh PhishTank verified-online entries whose registered domains did not occur "
            "in prior datasets, plus first-party verified URLs from unused legitimate domains."
        ),
        "candidate": test_metrics,
        "previous_best_candidate": prior_best_metrics,
        "production_service": production_metrics,
        "previously_exposed_regression_benchmark": regression_metrics,
        "fixed_core_legitimate_regression": core_metrics,
    }
    FAILURE_PATH.write_text(
        json.dumps(failure_report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    test_legit = [row for row in test_rows if row["label"] == 0]
    test_phish = [row for row in test_rows if row["label"] == 1]
    validation_legit = [row for row in validation_rows if row["label"] == 0]
    calibration_legit = [row for row in calibration_rows if row["label"] == 0]
    observed_fpr = test_metrics["legitimate_false_phishing"]["percentage"]
    fpr_denominator = test_metrics["legitimate_false_phishing"]["denominator"]
    metric_gates = {
        "fresh_test_legitimate_fpr": {
            **test_metrics["legitimate_false_phishing"],
            "target_percentage": 0.5,
            "status": (
                "FAIL"
                if (observed_fpr or 0.0) > 0.5
                else "UNVERIFIED"
                if fpr_denominator < 600
                or len({row["registered_domain"] for row in test_legit}) < 20
                else "PASS"
            ),
            "reason": (
                "The observed rate already exceeds the target; a result at or below the target "
                "would require at least 600 legitimate test URLs across 20+ domains to pass."
            ),
        },
        "fresh_test_phishing_recall": {
            **test_metrics["phishing_recall"],
            "target_percentage": 98.0,
            "status": (
                "UNVERIFIED"
                if len({row["registered_domain"] for row in test_phish}) < 100
                or len(test_phish) < 500
                else "PASS"
                if (test_metrics["phishing_recall"]["percentage"] or 0.0) >= 98.0
                else "FAIL"
            ),
            "source_limit": "PhishTank verified-online feed; independent from the earlier active feed.",
        },
        "validation_threshold_evidence": {
            "legitimate_urls": len(validation_legit),
            "legitimate_domains": len({row["registered_domain"] for row in validation_legit}),
            "calibration_legitimate_urls": len(calibration_legit),
            "calibration_legitimate_domains": len({
                row["registered_domain"] for row in calibration_legit
            }),
            "status": "UNVERIFIED"
            if len(validation_legit) < 100
            or len({row["registered_domain"] for row in validation_legit}) < 10
            or len(calibration_legit) < 100
            or len({row["registered_domain"] for row in calibration_legit}) < 10
            else "MEASURED",
        },
        "previously_exposed_benchmark_regression_only": {
            "independent_evidence": False,
            "fixed_benchmark_v1_fpr": regression_metrics["legitimate_false_phishing"],
            "fixed_benchmark_v1_fpr_target_percentage": 0.5,
            "fixed_benchmark_v1_fpr_status": "FAIL"
            if (regression_metrics["legitimate_false_phishing"]["percentage"] or 0.0) > 0.5
            else "PASS",
            "core_legitimate_phishing_verdicts": core_metrics["legitimate_false_phishing"],
            "core_legitimate_zero_phishing_verdicts_status": "FAIL"
            if core_metrics["legitimate_false_phishing"]["numerator"] > 0
            else "PASS",
            "selection_or_threshold_tuning_used": False,
        },
        "domain_leakage": {
            "status": "PASS" if not manifest["registered_domain_split_overlap"] else "FAIL",
            "overlap": manifest["registered_domain_split_overlap"],
        },
        "test_domains_absent_from_prior_data": {
            "status": "PASS" if not manifest["fresh_test_domain_overlap_with_prior"] else "FAIL",
            "overlap": manifest["fresh_test_domain_overlap_with_prior"],
        },
        "production_artifact_hashes_unchanged": {
            "status": "PASS" if initial_hashes == repair.reliability_hashes() else "FAIL",
            "initial": initial_hashes,
            "final": repair.reliability_hashes(),
        },
    }
    if selected_artifact.exists():
        metric_gates["candidate_artifact_integrity"] = {
            "status": "PASS",
            "path": str(selected_artifact.relative_to(ROOT)),
            "sha256": repair.sha256(selected_artifact),
            "size_bytes": selected_artifact.stat().st_size,
        }
    else:
        metric_gates["candidate_artifact_integrity"] = {
            "status": "UNVERIFIED",
            "reason": "Previous candidate remained the validation incumbent; no new artifact was created.",
        }

    final = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_directory": str(RUN_DIR.relative_to(ROOT)),
        "experiment_count": len(trial_records),
        "candidate_selection": {
            "selected_on": "fresh domain-disjoint validation only",
            "selected_model": selected_name,
            "threshold": threshold,
            "artifact": str(selected_artifact.relative_to(ROOT)),
        },
        "fresh_dataset_manifest": manifest,
        "previous_best_validation_reference": initial_validation,
        "leaderboard": [
            {
                "experiment": record["experiment"],
                "threshold": record["thresholds"]["phishing"]
                if "thresholds" in record
                else record["threshold"],
                "validation_metrics": record["validation_metrics"],
                "artifact": record.get("artifact"),
                "artifact_sha256": record.get("artifact_sha256"),
            }
            for record in leaderboard
        ],
        "independent_test": {
            "class_balance_is_natural_prevalence": False,
            "prevalence_note": (
                "The set is a class-labeled evaluation sample; precision is not a deployment "
                "estimate without a representative URL prevalence."
            ),
            "candidate": test_metrics,
            "previous_best_candidate": prior_best_metrics,
            "production_service": production_metrics,
        },
        "previously_exposed_regression_only": {
            "selection_or_threshold_tuning_used": False,
            "fixed_benchmark_v1": regression_metrics,
            "fixed_core_legitimate": core_metrics,
        },
        "gates": metric_gates,
        "backend_and_extension_tests": repair.regression_tests(),
        "production_files_modified": False,
        "promoted": False,
        "limitations": [
            "PhishTank positives are community-verified and marked online at snapshot time; this does not independently verify current page contents.",
            "Fresh legitimate sample size and source count determine whether its FPR is sufficiently precise.",
            "Test precision is not representative without deployment class prevalence.",
            "The fixed benchmark and previously exposed test sets were not used for selection in this run.",
        ],
    }
    RUN_REPORT.write_text(json.dumps(final, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LEADERBOARD.write_text(
        json.dumps({"experiments": leaderboard, "selected_model": selected_name}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"Selected {selected_name}; fresh-test FPR="
        f"{test_metrics['legitimate_false_phishing']['numerator']}/"
        f"{test_metrics['legitimate_false_phishing']['denominator']}, "
        f"recall={test_metrics['phishing_recall']['numerator']}/"
        f"{test_metrics['phishing_recall']['denominator']}."
    )


if __name__ == "__main__":
    main()
