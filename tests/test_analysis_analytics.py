import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


@pytest.fixture
def analysis_client(tmp_path, monkeypatch):
    import api

    monkeypatch.setattr(api, "DB_PATH", str(tmp_path / "history.sqlite3"))
    return api.app.test_client()


def test_scan_analytics_counts_all_database_rows_not_latest_100(analysis_client):
    import api

    labels = ("SAFE", "SUSPICIOUS", "PHISHING")
    with api.db() as conn:
        for index in range(107):
            label = labels[index % len(labels)]
            scanned_at = (datetime.now(timezone.utc) - timedelta(days=index % 7)).isoformat()
            result = {"label": label, "url": f"https://event-{index}.example/"}
            conn.execute(
                "INSERT INTO scans(scanned_at, url, result) VALUES (?, ?, ?)",
                (scanned_at, result["url"], json.dumps(result)),
            )

    recent = analysis_client.get("/history").get_json()
    response = analysis_client.get("/analysis/scan-analytics")
    analytics = response.get_json()

    assert response.status_code == 200
    assert len(recent) == 100
    assert analytics["total_scans"] == 107
    assert analytics["verdict_counts"] == {"SAFE": 36, "SUSPICIOUS": 36, "PHISHING": 35}
    assert analytics["verdict_percentages"] == {"SAFE": 33.6, "SUSPICIOUS": 33.6, "PHISHING": 32.7}
    assert sum(analytics["verdict_counts"].values()) == analytics["total_scans"]
    assert len(analytics["trend"]["daily"]) == 7
    assert sum(day["total"] for day in analytics["trend"]["daily"]) == 107


def test_scan_analytics_empty_database_has_no_fabricated_percentages(analysis_client):
    analytics = analysis_client.get("/analysis/scan-analytics").get_json()

    assert analytics["total_scans"] == 0
    assert analytics["verdict_counts"] == {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0}
    assert analytics["verdict_percentages"] == {"SAFE": None, "SUSPICIOUS": None, "PHISHING": None}
    assert all(day["total"] == 0 for day in analytics["trend"]["daily"])


def test_model_info_reports_loaded_artifact_training_splits_and_offline_test():
    import service

    service.load_model_bundle.cache_clear()
    info = service.model_info()

    assert info["model_version"] == "v3.0.0"
    assert info["model_path"] == "phishing_model.pkl"
    assert info["model_load_status"] == "loaded"
    assert len(info["artifact_sha256"]) == 64
    assert info["artifact_sha256"] == "aac10b885770c479a0e5501af32d8af423dc5b8ae3c3156f481fc7ecb5943688"
    assert info["model_architecture"] == "HistGradientBoostingClassifier"
    assert info["calibration_method"] == "Sigmoid (LogisticRegression)"
    recorded_metadata = json.loads(
        (Path(service.ROOT) / "model_metadata.json").read_text(encoding="utf-8")
    )
    assert info["features"] == recorded_metadata["features"]
    assert info["feature_count"] == len(info["features"]) == 29
    assert info["training"]["dataset_rows"] == 11510
    assert info["training"]["dataset_sha256"] == "890c6b41e54fe2e8a72a03c628e945dc4a3434d3739c9204794e9225ebcbfc11"
    assert info["training"]["dataset_source_status"] == "verified"
    assert info["training"]["sample_count"] == 7772
    assert info["training"]["legitimate_samples"] == 3886
    assert info["training"]["phishing_samples"] == 3886
    assert info["training"]["calibration_samples"] == 640
    assert info["training"]["validation_samples"] == 1020
    assert info["training"]["test_samples"] == 2078
    assert info["training"]["unique_urls"] == 7772
    assert info["training"]["registered_domains"] == 2852
    assert info["evaluation"]["type"] == "offline_held_out_test"
    assert info["evaluation"]["sample_count"] == 2078
    assert info["evaluation"]["precision"] == pytest.approx(752 / (752 + 30))
    assert info["evaluation"]["recall"] == pytest.approx(752 / (752 + 287))
    assert info["evaluation"]["false_positive_rate"] == pytest.approx(30 / (1009 + 30))
    assert info["evaluation"]["false_negative_rate"] == pytest.approx(287 / (287 + 752))
    assert info["evaluation"]["f1_score"] == pytest.approx(2 * 752 / (2 * 752 + 30 + 287))
    assert info["evaluation"]["confusion_matrix"] == [[1009, 30], [287, 752]]
    assert info["evaluation"]["evaluated_at"] is None
    assert info["evaluation"]["pr_auc"] is None


def test_model_info_uses_active_metadata_and_missing_values_remain_unavailable(monkeypatch):
    import service

    class Estimator:
        pass

    class ActiveModel:
        estimator = Estimator()
        calibrator = None

    active_metadata = {
        "model_version": "active",
        "model_type": "active model",
        "dataset": {"file": "active-data.csv", "rows": 10},
        "split_rows": {"train": 8},
        "active_artifact": {"path": "phishing_model.pkl", "sha256": "a" * 64},
        "model_load_status": "loaded",
        "last_successful_load_at": "2026-10-10T00:00:00+00:00",
    }
    monkeypatch.setattr(service, "load_model_bundle", lambda: (ActiveModel(), ["only_feature"], active_metadata))

    info = service.model_info()

    assert info["model_path"] == "phishing_model.pkl"
    assert info["training"]["sample_count"] == 8
    assert info["training"]["dataset_source_status"] == "checksum_unavailable"
    assert info["training"]["legitimate_samples"] is None
    assert info["training"]["phishing_samples"] is None
    assert info["training"]["unique_urls"] is None
    assert info["training"]["registered_domains"] is None
    assert info["evaluation"]["sample_count"] is None
    assert info["evaluation"]["precision"] is None
    assert info["artifact_sha256"] == "a" * 64


def test_model_cache_reloads_when_active_metadata_changes(tmp_path, monkeypatch):
    import service

    service.load_model_bundle.cache_clear()
    copied_paths = {}
    for name, original in (
        ("MODEL_PATH", service.MODEL_PATH),
        ("FEATURE_PATH", service.FEATURE_PATH),
        ("METADATA_PATH", service.METADATA_PATH),
    ):
        target = tmp_path / name
        shutil.copy2(original, target)
        copied_paths[name] = target
        monkeypatch.setattr(service, name, str(target))

    try:
        original_info = service.model_info()
        metadata = json.loads(copied_paths["METADATA_PATH"].read_text(encoding="utf-8"))
        metadata["model_version"] = "updated-active-bundle"
        copied_paths["METADATA_PATH"].write_text(json.dumps(metadata), encoding="utf-8")

        updated_info = service.model_info()

        assert original_info["model_version"] == "v3.0.0"
        assert updated_info["model_version"] == "updated-active-bundle"
    finally:
        service.load_model_bundle.cache_clear()
