from detector import analyze_email, analyze_url, extract_urls


def test_extract_urls():
    assert extract_urls("Visit https://example.com/path now") == [
        "https://example.com/path"
    ]


def test_url_inspection_detects_non_https_and_ip():
    findings = analyze_url("http://127.0.0.1/login")
    assert any("HTTPS" in item for item in findings)
    assert any("IP address" in item for item in findings)


def test_email_result_has_expected_fields():
    result = analyze_email(
        "Urgent action required",
        "security@example.test",
        "Verify your account at http://example.test/login",
    )
    assert 0 <= result["risk_score"] <= 100
    assert result["classification"] in {"Low Risk", "Suspicious", "High Risk"}
    assert isinstance(result["findings"], list)
