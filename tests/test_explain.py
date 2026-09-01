from src.explain import (
    generate_explanation,
    generate_header_explanations,
    generate_url_explanations,
    generate_language_explanations,
    generate_threat_intel_explanations,
    generate_full_explanation,
)


# ---------------------------------------------------------------------------
# Basic explanation tests
# ---------------------------------------------------------------------------

def test_basic_url_explanation():
    features = {
        "url_count": 1,
        "shortened_url": False,
        "brand_impersonation": False,
        "urgent_words": 0,
        "executable_link": False,
    }

    reasons = generate_explanation(
        features,
        0.0,
    )

    assert "Contains external link" in reasons


def test_shortened_url_explanation():
    features = {
        "url_count": 1,
        "shortened_url": True,
        "brand_impersonation": False,
        "urgent_words": 0,
        "executable_link": False,
    }

    reasons = generate_explanation(
        features,
        0.0,
    )

    assert "Uses shortened URL" in reasons


def test_brand_impersonation_explanation():
    features = {
        "url_count": 0,
        "shortened_url": False,
        "brand_impersonation": True,
        "urgent_words": 0,
        "executable_link": False,
    }

    reasons = generate_explanation(
        features,
        0.0,
    )

    assert "Possible brand impersonation" in reasons


def test_emotional_manipulation_explanation():
    features = {
        "url_count": 0,
        "shortened_url": False,
        "brand_impersonation": False,
        "urgent_words": 0,
        "executable_link": False,
    }

    reasons = generate_explanation(
        features,
        0.8,
    )

    assert "Emotional manipulation detected" in reasons


# ---------------------------------------------------------------------------
# Header explanation tests
# ---------------------------------------------------------------------------

def test_reply_to_mismatch_explanation():
    header_analysis = {
        "domains": {
            "reply_to_mismatch": True,
            "return_path_mismatch": False,
        },
        "authentication": {},
    }

    reasons = generate_header_explanations(
        header_analysis
    )

    assert (
        "Reply-To domain differs from the sender domain"
        in reasons
    )


def test_return_path_mismatch_explanation():
    header_analysis = {
        "domains": {
            "reply_to_mismatch": False,
            "return_path_mismatch": True,
        },
        "authentication": {},
    }

    reasons = generate_header_explanations(
        header_analysis
    )

    assert (
        "Return-Path domain differs from the sender domain"
        in reasons
    )


def test_spf_failure_explanation():
    header_analysis = {
        "domains": {},
        "authentication": {
            "spf": "fail",
        },
    }

    reasons = generate_header_explanations(
        header_analysis
    )

    assert "SPF authentication result: fail" in reasons


def test_dkim_failure_explanation():
    header_analysis = {
        "domains": {},
        "authentication": {
            "dkim": "fail",
        },
    }

    reasons = generate_header_explanations(
        header_analysis
    )

    assert "DKIM authentication result: fail" in reasons


def test_dmarc_failure_explanation():
    header_analysis = {
        "domains": {},
        "authentication": {
            "dmarc": "fail",
        },
    }

    reasons = generate_header_explanations(
        header_analysis
    )

    assert "DMARC authentication result: fail" in reasons


# ---------------------------------------------------------------------------
# URL explanation tests
# ---------------------------------------------------------------------------

def test_url_indicator_explanation():
    url_analysis = {
        "indicators": [
            "Shortened URL detected",
        ],
    }

    reasons = generate_url_explanations(
        url_analysis
    )

    assert "URL: Shortened URL detected" in reasons


def test_empty_url_analysis():
    reasons = generate_url_explanations({})

    assert reasons == []


# ---------------------------------------------------------------------------
# Language explanation tests
# ---------------------------------------------------------------------------

def test_language_indicator_explanation():
    language_analysis = {
        "indicators": [
            "Urgency detected",
        ],
    }

    reasons = generate_language_explanations(
        language_analysis
    )

    assert "Language: Urgency detected" in reasons


def test_empty_language_analysis():
    reasons = generate_language_explanations({})

    assert reasons == []


# ---------------------------------------------------------------------------
# Threat intelligence explanation tests
# ---------------------------------------------------------------------------

def test_malicious_threat_intel_explanation():
    threat_intel = {
        "malicious_count": 1,
        "suspicious_count": 0,
    }

    reasons = generate_threat_intel_explanations(
        threat_intel
    )

    assert (
        "Threat intelligence identified a malicious indicator"
        in reasons
    )


def test_suspicious_threat_intel_explanation():
    threat_intel = {
        "malicious_count": 0,
        "suspicious_count": 1,
    }

    reasons = generate_threat_intel_explanations(
        threat_intel
    )

    assert (
        "Threat intelligence identified a suspicious indicator"
        in reasons
    )


def test_malicious_takes_priority_over_suspicious():
    threat_intel = {
        "malicious_count": 2,
        "suspicious_count": 3,
    }

    reasons = generate_threat_intel_explanations(
        threat_intel
    )

    assert (
        "Threat intelligence identified a malicious indicator"
        in reasons
    )

    assert (
        "Threat intelligence identified a suspicious indicator"
        not in reasons
    )


# ---------------------------------------------------------------------------
# Full explanation tests
# ---------------------------------------------------------------------------

def test_full_explanation_combines_all_signals():
    features = {
        "url_count": 1,
        "shortened_url": True,
        "brand_impersonation": True,
        "urgent_words": 3,
        "executable_link": False,
    }

    header_analysis = {
        "domains": {
            "reply_to_mismatch": True,
            "return_path_mismatch": False,
        },
        "authentication": {
            "spf": "fail",
            "dkim": "pass",
            "dmarc": "fail",
        },
    }

    url_analysis = {
        "indicators": [
            "Shortened URL detected",
        ],
    }

    language_analysis = {
        "indicators": [
            "Urgency detected",
        ],
    }

    threat_intel = {
        "malicious_count": 1,
        "suspicious_count": 0,
    }

    reasons = generate_full_explanation(
        features,
        emotion_score=0.8,
        header_analysis=header_analysis,
        url_analysis=url_analysis,
        language_analysis=language_analysis,
        threat_intel=threat_intel,
    )

    assert "Contains external link" in reasons
    assert "Uses shortened URL" in reasons
    assert "Possible brand impersonation" in reasons
    assert "Urgent or threatening language" in reasons
    assert "Emotional manipulation detected" in reasons

    assert (
        "Reply-To domain differs from the sender domain"
        in reasons
    )

    assert "SPF authentication result: fail" in reasons
    assert "DMARC authentication result: fail" in reasons

    assert "URL: Shortened URL detected" in reasons
    assert "Language: Urgency detected" in reasons

    assert (
        "Threat intelligence identified a malicious indicator"
        in reasons
    )


def test_full_explanation_removes_duplicates():
    features = {
        "url_count": 1,
        "shortened_url": True,
        "brand_impersonation": False,
        "urgent_words": 0,
        "executable_link": False,
    }

    url_analysis = {
        "indicators": [
            "Uses shortened URL",
        ],
    }

    reasons = generate_full_explanation(
        features,
        url_analysis=url_analysis,
    )

    assert reasons.count(
        "Uses shortened URL"
    ) == 1


def test_clean_email_has_no_reasons():
    features = {
        "url_count": 0,
        "shortened_url": False,
        "brand_impersonation": False,
        "urgent_words": 0,
        "executable_link": False,
    }

    reasons = generate_full_explanation(
        features,
        emotion_score=0.0,
        header_analysis={
            "domains": {},
            "authentication": {},
        },
        url_analysis={},
        language_analysis={},
        threat_intel={
            "malicious_count": 0,
            "suspicious_count": 0,
        },
    )

    assert reasons == []