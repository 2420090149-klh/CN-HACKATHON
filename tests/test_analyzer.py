from phish_detector import analyze_url


def test_detects_ip_address_host():
    result = analyze_url("http://185.199.108.153/login")

    assert result["score"] >= 35
    assert result["verdict"] != "Probably safe"
    assert any(signal["label"] == "IP address host" for signal in result["signals"])


def test_detects_shortener_and_login_terms():
    result = analyze_url("https://bit.ly/secure-login-update")

    labels = {signal["label"] for signal in result["signals"]}
    assert "URL shortener" in labels
    assert any(label.startswith("Contains '") for label in labels)
    assert result["verdict"] == "Likely phishing" or result["verdict"] == "Suspicious"


def test_detects_redirect_parameters_and_targets():
    result = analyze_url("https://example.com/continue?next=https://evil.example/login")

    labels = {signal["label"] for signal in result["signals"]}
    assert "Redirect parameter" in labels
    assert "Open redirect target" in labels


def test_domain_age_context_increases_risk():
    result = analyze_url("https://example.com", domain_age_days=12, redirect_hops=3)

    labels = {signal["label"] for signal in result["signals"]}
    assert "Very new domain" in labels
    assert "Redirect chain" in labels
    assert result["score"] >= 40


def test_safe_domain_stays_low_risk():
    result = analyze_url("https://www.python.org")

    assert result["score"] < 40
    assert result["verdict"] == "Probably safe"
