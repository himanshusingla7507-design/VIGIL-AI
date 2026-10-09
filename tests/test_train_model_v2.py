import numpy as np
import pandas as pd
import pytest

import train_model_v2 as trainer


def tiny_grouped_frame() -> pd.DataFrame:
    rows = []
    for index in range(30):
        label = index % 2
        rows.append(
            {
                "url": f"https://{'phish' if label else 'safe'}{index}.example.test/path",
                "normalized_url": f"https://{'phish' if label else 'safe'}{index}.example.test/path",
                "registered_domain": f"{'phish' if label else 'safe'}{index}.example.test",
                "label": label,
            }
        )
    return pd.DataFrame(rows)


def test_domain_split_has_both_classes_and_no_registered_domain_overlap():
    frame = tiny_grouped_frame()
    splits = trainer.make_domain_splits(frame, seed=12)
    domain_sets = {
        name: set(frame.iloc[indices]["registered_domain"])
        for name, indices in splits.items()
    }
    assert all(
        not domain_sets[left] & domain_sets[right]
        for left, right in (
            ("train", "calibration"),
            ("train", "test"),
            ("calibration", "test"),
        )
    )
    assert all(set(frame.iloc[index]["label"]) == {0, 1} for index in splits.values())


def test_domain_split_stops_when_one_class_cannot_be_assigned():
    frame = tiny_grouped_frame()
    frame.loc[frame["label"] == 0, "registered_domain"] = "one.example.test"
    frame.loc[frame["label"] == 1, "registered_domain"] = "two.example.test"
    with pytest.raises(
        ValueError,
        match="Could not create registered-domain splits|does not contain both classes",
    ):
        trainer.make_domain_splits(frame, seed=12)


def test_normalized_duplicate_label_conflicts_fail_instead_of_dropping_a_class():
    frame = pd.DataFrame(
        {
            "url": ["https://example.test/a", "https://example.test/a"],
            "label": [0, 1],
        }
    )
    with pytest.raises(ValueError, match="conflicting labels"):
        trainer.normalize_and_validate_urls(frame, "test")


def test_metrics_include_required_discrimination_and_calibration_fields():
    result = trainer.classification_metrics(
        np.asarray([0, 0, 1, 1]),
        np.asarray([0.1, 0.4, 0.7, 0.9]),
    )
    assert {
        "accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc",
        "brier_score", "confusion_matrix", "class_counts",
    }.issubset(result)
    assert result["confusion_matrix"]["matrix"] == [[2, 0], [0, 2]]


def test_source_class_weights_equalize_total_mass_per_source_and_class():
    labels = np.asarray([0, 0, 0, 1, 1, 1, 1])
    sources = np.asarray(
        ["large_legit", "large_legit", "small_legit", "feed", "feed", "feed", "other"]
    )
    weights = trainer.source_class_balanced_weights(labels, sources)
    for label in (0, 1):
        per_source_mass = {
            source: float(weights[(labels == label) & (sources == source)].sum())
            for source in set(sources[labels == label])
        }
        assert all(mass == pytest.approx(1 / len(per_source_mass)) for mass in per_source_mass.values())
        assert float(weights[labels == label].sum()) == pytest.approx(1.0)


def test_dynamic_training_rows_are_added_before_domain_splitting_and_deduplicated():
    primary = pd.DataFrame(
        [
            {
                "url": "https://safe.example.test/a",
                "normalized_url": "https://safe.example.test/a",
                "registered_domain": "example.test",
                "label": 0,
                "source": "PhiUSIIL",
            },
            {
                "url": "https://bad.example.test/a",
                "normalized_url": "https://bad.example.test/a",
                "registered_domain": "bad.example.test",
                "label": 1,
                "source": "PhiUSIIL",
            },
        ]
    )
    dynamic = pd.DataFrame(
        [
            {
                "url": "https://safe.example.test/a",
                "normalized_url": "https://safe.example.test/a",
                "registered_domain": "example.test",
                "label": 0,
            },
            {
                "url": "https://dynamic.example.test/search?q=one",
                "normalized_url": "https://dynamic.example.test/search?q=one",
                "registered_domain": "example.test",
                "label": 0,
            },
        ]
    )
    combined, audit = trainer.combine_training_data(
        primary, {"observed_dynamic": dynamic}
    )
    assert len(combined) == 3
    assert audit["dynamic_duplicate_rows_removed"] == 0
    assert audit["combined_same_label_duplicate_rows_removed"] == 1
    assert combined.loc[
        combined["normalized_url"] == "https://safe.example.test/a", "source_group"
    ].item() == "verified_legitimate_dynamic"
    assert "observed_dynamic" in combined.loc[
        combined["normalized_url"] == "https://safe.example.test/a",
        "dataset_memberships",
    ].item()


def test_url_cohorts_identify_observed_structure_without_modifying_urls():
    url = "https://docs.example.org/search?term=a%20b&page=2#results"
    assert trainer.url_cohorts(url) == [
        "content_path",
        "query",
        "search",
        "multiple_query_parameters",
        "query_heavy",
        "encoded",
        "fragment",
    ]


def test_observed_legitimate_urls_keep_production_feature_values():
    feature_names, _, _ = trainer.production_feature_contract()
    urls = pd.Series(
        [
            "https://en.wikipedia.org/wiki/Main_Page",
            "https://szl.wikipedia.org/wiki/Przodni%C5%8F_zajta",
            "https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements",
            "https://github.com/team",
        ]
    )
    matrix = trainer.feature_matrix(urls, feature_names)
    by_name = pd.DataFrame(matrix, columns=feature_names)
    assert len(feature_names) == 29
    assert by_name["PathLength"].tolist() == [15.0, 25.0, 39.0, 5.0]
    assert by_name["URLPercentEncodingCount"].tolist() == [0.0, 2.0, 0.0, 0.0]
    assert by_name["QueryParameterCount"].tolist() == [0.0, 0.0, 0.0, 0.0]
