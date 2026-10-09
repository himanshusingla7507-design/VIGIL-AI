import pytest

from feature_extractor import FEATURE_NAMES, MODEL_EXCLUDED_FEATURES, extract_features, get_registered_domain, normalize_url
from phishing_detector import check_phishing, predict_url
from service import scan

LEGITIMATE_URLS = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://apple.com",
    "https://amazon.com",
    "https://python.org",
    "https://cloudflare.com",
    "https://fast.com/",
]

SUSPICIOUS_URLS = [
    "https://paypal-login.example.com/verify-account",
    "http://secure-bank-login.example.com/update-account",
    "http://microsoft-security.example.com/login",
    "http://free-iphone-winner.example.com/claim",
    "http://account-verify.example.com/signin/password",
]


def test_fast_com_not_phishing():
    result = predict_url("https://fast.com/")
    assert result["label"] != "PHISHING"
    assert result["probability"] < 0.85


def test_legitimate_urls_are_not_flagged():
    for url in LEGITIMATE_URLS:
        result = predict_url(url)
        assert result["label"] in {"SAFE", "SUSPICIOUS"}, (url, result)


def test_suspicious_urls_are_flagged_mostly_as_high_risk():
    for url in SUSPICIOUS_URLS:
        result = predict_url(url)
        assert result["label"] in {"SUSPICIOUS", "PHISHING"}, (url, result)


def test_app_and_api_share_pipeline():
    api_result = check_phishing("https://github.com")
    direct_result = predict_url("https://github.com")
    assert api_result["label"] == direct_result["label"]
    assert api_result["probability"] == pytest.approx(direct_result["probability"], abs=1e-6)


def test_scan_trace_identifies_model_request_and_backend(tmp_path, monkeypatch):
    import api
    import uuid

    monkeypatch.setattr(api, "DB_PATH", str(tmp_path / "history.sqlite3"))
    client = api.app.test_client()
    health = client.get("/health").get_json()
    assert health["model_fingerprint"]
    assert health["backend"]["backend_pid"] > 0
    assert health["backend"]["api_endpoint"].endswith("/health")

    urls = [
        "https://chatgpt.com",
        "https://chatgpt.com/",
        "https://chatgpt.com/?q=hello",
        "https://www.instagram.com/accounts/onetap/?lsrc=ci",
        "https://www.google.com/search?q=cybersecurity",
        "https://accounts.google.com/signin/v2",
        "https://github.com",
        "https://www.microsoft.com/",
        "https://paypal-login.example.com/verify-account",
        "http://secure-bank-login.example.com/update-account",
    ]
    response_by_url = {}
    for index, url in enumerate(urls):
        request_id = str(uuid.uuid4())
        response = client.post(
            "/scan",
            json={"url": url},
            headers={"X-Vigil-Request-Id": request_id},
        )
        result = response.get_json()
        direct = scan(url)

        assert response.status_code == 200
        assert result["request_id"] == request_id
        assert result["normalized_url"] == normalize_url(url)
        assert result["model_fingerprint"] == health["model_fingerprint"]
        assert result["backend"]["backend_pid"] == health["backend"]["backend_pid"]
        assert result["backend"]["backend_instance_id"] == health["backend"]["backend_instance_id"]
        assert result["backend"]["api_endpoint"].endswith("/scan")
        assert result["label"] == direct["label"], url
        assert result["probability"] == pytest.approx(direct["probability"], abs=1e-6), url
        response_by_url[url] = result

    bare = response_by_url["https://chatgpt.com"]
    slash = response_by_url["https://chatgpt.com/"]
    assert bare["label"] == slash["label"]
    assert bare["probability"] == slash["probability"]


def test_development_scan_diagnostics_include_raw_and_calibrated_scores(tmp_path, monkeypatch):
    import api

    monkeypatch.setattr(api, "DB_PATH", str(tmp_path / "history.sqlite3"))
    monkeypatch.setattr(api, "DEBUG_DIAGNOSTICS", True)
    response = api.app.test_client().post(
        "/scan",
        json={"url": "https://chatgpt.com/auth/login"},
    )
    result = response.get_json()

    assert response.status_code == 200
    assert result["diagnostics"]["hostname"] == "chatgpt.com"
    assert len(result["diagnostics"]["raw_fold_probabilities"]) >= 1
    assert result["diagnostics"]["calibrated_probability"] == result["model_probability"]
    assert result["thresholds"]["phishing"] > result["thresholds"]["safe"]


def test_canonical_variants_have_identical_predictions():
    variants = ["https://fast.com", "https://fast.com/", "https://www.fast.com/"]
    results = [predict_url(url) for url in variants]
    assert {r["label"] for r in results} == {"SAFE"}
    assert len({r["probability"] for r in results}) == 1
    assert len({r["risk_score"] for r in results}) == 1


def test_api_history_does_not_persist_query_string(tmp_path, monkeypatch):
    import api

    monkeypatch.setattr(api, "DB_PATH", str(tmp_path / "history.sqlite3"))
    client = api.app.test_client()
    response = client.post("/scan", json={"url": "https://github.com/path?token=SECRET"})
    assert response.status_code == 200
    item = client.get("/history").get_json()[0]
    assert "SECRET" not in item["url"]
    assert "?" not in item["url"]


def test_protocol_does_not_change_model_features_or_prediction():
    https_features = extract_features("https://example.com/path?a=1")
    http_features = extract_features("http://example.com/path?a=1")
    assert https_features["IsHTTPS"] == 1
    assert http_features["IsHTTPS"] == 0
    assert {key: value for key, value in https_features.items() if key != "IsHTTPS"} == {
        key: value for key, value in http_features.items() if key != "IsHTTPS"
    }

    https_result = scan("https://example.com/path?a=1")
    http_result = scan("http://example.com/path?a=1")
    assert https_result["probability"] == http_result["probability"]
    assert https_result["label"] == http_result["label"]
    assert https_result["risk_score"] == http_result["risk_score"]


def test_model_excludes_transport_alias_and_constant_features():
    from service import load_model_bundle

    model, feature_names, metadata = load_model_bundle()
    assert len(FEATURE_NAMES) == 35
    assert metadata["feature_count"] == len(feature_names)
    assert metadata["features"] == feature_names
    assert model.n_features_in_ == len(feature_names)
    assert not (set(feature_names) & MODEL_EXCLUDED_FEATURES)
    assert "IsHTTPS" not in feature_names


def test_serving_features_share_url_canonicalization():
    variants = [
        "https://fast.com/",
        "https://fast.com",
        "https://www.fast.com/",
    ]
    features = [extract_features(url) for url in variants]
    assert features[0] == features[1]
    assert features[1] == features[2]


def test_model_bundle_rejects_tampered_pickle(tmp_path, monkeypatch):
    import shutil
    import service

    service.load_model_bundle.cache_clear()
    copied = {}
    for key, source in (
        ("MODEL_PATH", service.MODEL_PATH),
        ("FEATURE_PATH", service.FEATURE_PATH),
        ("METADATA_PATH", service.METADATA_PATH),
    ):
        destination = tmp_path / (key + ".bin")
        shutil.copy2(source, destination)
        copied[key] = destination
        monkeypatch.setattr(service, key, str(destination))

    model_copy = copied["MODEL_PATH"]
    model_copy.write_bytes(model_copy.read_bytes() + b"tampered")
    service.load_model_bundle.cache_clear()
    with pytest.raises(RuntimeError, match="model_unavailable"):
        service.load_model_bundle()
    service.load_model_bundle.cache_clear()


def test_url_normalization_handles_idn_ipv6_and_bad_authorities():
    assert normalize_url(" https://BÜCHER.de:443/ ") == "https://xn--bcher-kva.de/"
    assert normalize_url("http://[2001:db8::1]:80/a") == "http://[2001:db8::1]/a"
    assert get_registered_domain("https://www.example.co.uk/") == "example.co.uk"
    assert extract_features("https://user:pass@example.com/")["HasUserInfo"] == 1

    for url in (
        "https://exa mple.com",
        "https://example..com",
        "https://-bad.com",
        "https://_bad.example/",
        "https://[gggg::1]/",
        "https://example.com/%",
        "https://example.com/a b",
    ):
        with pytest.raises(ValueError, match="invalid_url"):
            normalize_url(url)


def test_feature_extraction_covers_url_edge_cases():
    ipv4 = extract_features("http://192.0.2.10:8080/a?x=1&y=2#frag")
    ipv6 = extract_features("https://[2001:db8::1]/a")
    nested = extract_features("https://a.b.c.example.com/a/b/c?login=1&verify=2")
    shortened = extract_features("https://bit.ly/abc123")
    unicode_host = extract_features("https://bücher.de/")

    assert ipv4["IsDomainIP"] == 1
    assert ipv4["HasPort"] == 1
    assert ipv4["QueryParameterCount"] == 2
    assert ipv4["FragmentLength"] == 4
    assert ipv6["IsDomainIP"] == 1
    assert nested["SubdomainDepth"] == 3
    assert nested["HasSuspiciousToken"] == 1
    assert shortened["IsShortened"] == 1
    assert unicode_host["HostnameLength"] == len("xn--bcher-kva.de")


def test_userinfo_evidence_matches_extracted_feature():
    result = scan("https://alice:secret@example.com/")
    assert result["features"]["HasUserInfo"] == 1
    evidence = [item for item in result["evidence"] if item["id"] == "userinfo"]
    assert len(evidence) == 1
    assert evidence[0]["value"] == 1


def test_api_health_model_info_and_request_errors(tmp_path, monkeypatch):
    import api

    monkeypatch.setattr(api, "DB_PATH", str(tmp_path / "history.sqlite3"))
    client = api.app.test_client()
    health = client.get("/health")
    assert health.status_code == 200
    assert health.get_json()["model_loaded"] is True

    model_info = client.get("/model-info")
    assert model_info.status_code == 200
    assert model_info.get_json()["feature_count"] == 29

    malformed = client.post("/scan", data="{bad", content_type="application/json")
    assert malformed.status_code == 400
    assert malformed.get_json()["error"] == "invalid_json"

    oversized = client.post("/scan", json={"url": "https://example.com/" + ("a" * 2050)})
    assert oversized.status_code == 413
    assert oversized.get_json()["error"] == "url_too_long"


def test_history_redacts_userinfo_query_and_fragment(tmp_path, monkeypatch):
    import api

    monkeypatch.setattr(api, "DB_PATH", str(tmp_path / "history.sqlite3"))
    client = api.app.test_client()
    response = client.post(
        "/scan",
        json={"url": "https://alice:secret@example.com/path?token=SECRET#fragment"},
    )
    assert response.status_code == 200
    items = client.get("/history").get_json()
    assert len(items) == 1
    serialized = str(items[0])
    for secret in ("alice", "secret", "SECRET", "fragment"):
        assert secret not in serialized


@pytest.mark.parametrize("url", [
    "https://chatgpt.com/?q=hello",
    "https://www.instagram.com/accounts/onetap/?lsrc=ci",
    "https://www.google.com/search?q=cybersecurity",
])
def test_legitimate_dynamic_urls_use_the_model_without_score_override(url):
    result = scan(url)
    assert result["label"] != "PHISHING"
    assert result["probability_source"] == "model"
    assert result["model_probability"] == result["effective_probability"] == result["probability"]


@pytest.mark.parametrize("url", [
    "https://chatgpt.com/",
    "https://www.youtube.com/",
    "https://gemini.google.com/app?hl=en-IN",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.netflix.com/browse",
    "https://netflix.com/watch/81666170?trackId=264163088&ctx=",
    "https://www.canva.com/templates",
    "https://www.instagram.com/accounts/onetap/?lsrc=ci",
])
def test_known_legitimate_urls_are_never_phishing(url):
    result = scan(url)
    assert result["label"] != "PHISHING", (url, result)
    assert result["probability_source"] in {"model", "verified_official_route_policy"}
    assert result["effective_probability"] == result["probability"]
    if result["reputation"]["applied"]:
        assert result["model_probability"] >= result["thresholds"]["safe"]
        assert result["effective_probability"] < result["thresholds"]["safe"]
    else:
        assert result["probability"] == result["model_probability"]


def test_verified_host_policy_does_not_trust_lookalikes_or_unapproved_subdomains():
    for url in ("https://www.netflix.com.attacker.example/", "https://canva-login.example/", "https://evil.netflix.com/"):
        result = scan(url)
        assert result["probability_source"] == "model"
        assert result["reputation"]["applied"] is False


def test_verified_official_route_policy_rejects_redirects_and_authority_tricks(monkeypatch):
    import service

    model, names, metadata = service.load_model_bundle()
    features = extract_features("https://www.netflix.com/browse")
    monkeypatch.setattr(model, "predict_proba", lambda _row: [[0.001, 0.999]])
    trusted = service._prediction("https://www.netflix.com/browse", features, model, names, metadata)
    redirect = service._prediction("https://www.netflix.com/browse?next=https://evil.example", extract_features("https://www.netflix.com/browse?next=https://evil.example"), model, names, metadata)
    assert trusted["reputation"]["applied"] is True
    assert trusted["label"] == "SAFE"
    assert redirect["reputation"]["applied"] is False


@pytest.mark.parametrize("url", [
    "http://localhost:5173/",
    "http://dev.localhost:8080/",
    "http://127.0.0.1:5000/",
    "http://127.42.0.8:5173/",
    "http://[::1]:5173/",
])
def test_localhost_urls_are_not_blocked_by_high_model_scores(url, monkeypatch):
    import service

    model, names, metadata = service.load_model_bundle()
    monkeypatch.setattr(model, "predict_proba", lambda _row: [[0.001, 0.999]])
    result = service._prediction(
        normalize_url(url),
        extract_features(url),
        model,
        names,
        metadata,
    )

    assert result["label"] == "SAFE"
    assert result["model_probability"] == 0.999
    assert result["effective_probability"] < result["thresholds"]["safe"]
    assert result["probability_source"] == "local_host_policy"
    assert result["reputation"]["applied"] is True


@pytest.mark.parametrize("url", [
    "http://192.168.1.10:5173/",
    "http://localhost.attacker.example/",
    "http://dev.localhost.attacker.example/",
])
def test_localhost_policy_does_not_cover_other_hosts(url, monkeypatch):
    import service

    model, names, metadata = service.load_model_bundle()
    monkeypatch.setattr(model, "predict_proba", lambda _row: [[0.001, 0.999]])
    result = service._prediction(
        normalize_url(url),
        extract_features(url),
        model,
        names,
        metadata,
    )

    assert result["label"] == "PHISHING"
    assert result["probability_source"] == "model"
    assert result["reputation"]["applied"] is False


def test_verified_netflix_playback_policy_is_route_and_query_constrained(monkeypatch):
    import service

    model, names, metadata = service.load_model_bundle()
    monkeypatch.setattr(model, "predict_proba", lambda _row: [[0.001, 0.999]])
    allowed_url = "https://netflix.com/watch/81666170?trackId=264163088&ctx="
    disallowed_url = "https://netflix.com/watch/not-an-id?trackId=264163088"
    encoded_destination = "https://netflix.com/watch/81666170?ctx=%252F%252Fevil.example"
    allowed = service._prediction(allowed_url, extract_features(allowed_url), model, names, metadata)
    invalid_path = service._prediction(disallowed_url, extract_features(disallowed_url), model, names, metadata)
    double_encoded = service._prediction(encoded_destination, extract_features(encoded_destination), model, names, metadata)
    assert allowed["reputation"]["applied"] is True
    assert invalid_path["reputation"]["applied"] is False
    assert double_encoded["reputation"]["applied"] is False


@pytest.mark.parametrize("url", [
    "https://www.amazon.com/",
    "https://www.amazon.com/s?k=usb+c+hub",
    "https://www.amazon.com/cart",
    "https://www.amazon.com/gp/cart/view.html",
    "https://www.amazon.com/dp/B0C1H4M9K4",
    "https://www.amazon.com/usb-hub/dp/B0C1H4M9K4/ref=sr_1_1",
    "https://www.amazon.com/gp/product/B0C1H4M9K4",
    "https://www.amazon.com/gp/buy/spc/handlers/display.html",
])
def test_amazon_shopping_routes_do_not_block_on_url_shape_alone(url, monkeypatch):
    import service

    model, names, metadata = service.load_model_bundle()
    monkeypatch.setattr(model, "predict_proba", lambda _row: [[0.001, 0.999]])
    result = service._prediction(url, extract_features(url), model, names, metadata)

    assert result["label"] == "SAFE"
    assert result["model_probability"] == 0.999
    assert result["effective_probability"] < result["thresholds"]["safe"]
    assert result["probability_source"] == "verified_official_route_policy"


def test_amazon_route_policy_rejects_lookalikes_invalid_products_and_redirects(monkeypatch):
    import service

    model, names, metadata = service.load_model_bundle()
    monkeypatch.setattr(model, "predict_proba", lambda _row: [[0.001, 0.999]])
    urls = [
        "https://amazon.com.attacker.example/dp/B0C1H4M9K4",
        "https://evil.amazon.com/dp/B0C1H4M9K4",
        "https://www.amazon.com/dp/not-an-asin",
        "https://www.amazon.com/dp/B0C1H4M9K4?url=https://attacker.example",
        "https://www.amazon.com/gp/redirect.html?url=https://attacker.example",
    ]

    for url in urls:
        result = service._prediction(url, extract_features(url), model, names, metadata)
        assert result["reputation"]["applied"] is False, url
        assert result["probability_source"] == "model", url
