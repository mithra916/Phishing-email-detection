import pytest

from src.risk_engine import (
    DEFAULT_WEIGHTS,
    calculate_header_score,
    calculate_risk_score,
    calculate_threat_intel_score,
)


# ---------------------------------------------------------------------------
# Risk calculation
# ---------------------------------------------------------------------------

def test_default_weights_sum_to_one():
    assert sum(DEFAULT_WEIGHTS.values()) == pytest.approx(1.0)


def test_all_zero_scores_produce_low_risk():
    result = calculate_risk_score(
        0,
        0,
        0,
        0,
        0,
    )

    assert result["score"] == 0.0
    assert result["risk_level"] == "Low"


def test_all_max_scores_produce_high_risk():
    result = calculate_risk_score(
        1,
        1,
        1,
        1,
        1,
        1,
    )

    assert result["score"] == 1.0
    assert result["risk_level"] == "High"


def test_ml_score_has_expected_weight():
    result = calculate_risk_score(
        1,
        0,
        0,
        0,
        0,
        0,
    )

    assert result["score"] == 0.35
    assert result["contributions"]["ml"] == 0.35


def test_threat_intel_contributes_to_score():
    result = calculate_risk_score(
        0,
        0,
        0,
        0,
        0,
        1,
    )

    assert result["score"] == 0.15


def test_scores_are_clamped():
    result = calculate_risk_score(
        2,
        -1,
        5,
        -3,
        10,
        -5,
    )

    assert result["signal_scores"]["ml"] == 1.0
    assert result["signal_scores"]["rules"] == 0.0
    assert result["signal_scores"]["language"] == 1.0
    assert result["signal_scores"]["emotion"] == 0.0
    assert result["signal_scores"]["header"] == 1.0
    assert result["signal_scores"]["threat_intel"] == 0.0


def test_medium_risk_threshold():
    result = calculate_risk_score(
        1,
        1,
        0,
        0,
        0,
        0,
    )

    assert result["score"] == 0.5
    assert result["risk_level"] == "Medium"


def test_high_risk_threshold():
    result = calculate_risk_score(
        1,
        1,
        0,
        0,
        1,
        0,
    )

    assert result["score"] == 0.65
    assert result["risk_level"] == "Medium"


def test_custom_weights():
    weights = {
        "ml": 1.0,
        "rules": 0.0,
        "language": 0.0,
        "emotion": 0.0,
        "header": 0.0,
        "threat_intel": 0.0,
    }

    result = calculate_risk_score(
        0.8,
        0.1,
        0.2,
        0.3,
        0.4,
        1.0,
        weights=weights,
    )

    assert result["score"] == 0.8


def test_invalid_weights_sum():
    weights = {
        "ml": 0.5,
        "rules": 0.5,
        "language": 0.5,
        "emotion": 0.0,
        "header": 0.0,
        "threat_intel": 0.0,
    }

    with pytest.raises(ValueError):
        calculate_risk_score(
            0,
            0,
            0,
            0,
            0,
            0,
            weights=weights,
        )


def test_negative_weights_rejected():
    weights = {
        "ml": 1.2,
        "rules": -0.2,
        "language": 0.0,
        "emotion": 0.0,
        "header": 0.0,
        "threat_intel": 0.0,
    }

    with pytest.raises(ValueError):
        calculate_risk_score(
            0,
            0,
            0,
            0,
            0,
            0,
            weights=weights,
        )


# ---------------------------------------------------------------------------
# Header scoring
# ---------------------------------------------------------------------------

def test_clean_headers_have_zero_risk():
    analysis = {
        "domains": {
            "reply_to_mismatch": False,
            "return_path_mismatch": False,
        },
        "authentication": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
    }

    assert calculate_header_score(analysis) == 0.0


def test_header_mismatch_increases_risk():
    analysis = {
        "domains": {
            "reply_to_mismatch": True,
            "return_path_mismatch": True,
        },
        "authentication": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
    }

    assert calculate_header_score(analysis) == 0.5


def test_authentication_failures_increase_risk():
    analysis = {
        "domains": {
            "reply_to_mismatch": False,
            "return_path_mismatch": False,
        },
        "authentication": {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        },
    }

    assert calculate_header_score(analysis) == 0.5


def test_header_score_is_bounded():
    analysis = {
        "domains": {
            "reply_to_mismatch": True,
            "return_path_mismatch": True,
        },
        "authentication": {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        },
    }

    assert 0.0 <= calculate_header_score(analysis) <= 1.0


# ---------------------------------------------------------------------------
# Threat intelligence scoring
# ---------------------------------------------------------------------------

def test_empty_threat_intel_has_zero_risk():
    assert calculate_threat_intel_score([]) == 0.0


def test_clean_threat_intel_has_zero_risk():
    results = [
        {
            "malicious": False,
            "suspicious": False,
        }
    ]

    assert calculate_threat_intel_score(results) == 0.0


def test_suspicious_threat_intel_score():
    results = [
        {
            "malicious": False,
            "suspicious": True,
        }
    ]

    assert calculate_threat_intel_score(results) == 0.75


def test_malicious_threat_intel_score():
    results = [
        {
            "malicious": True,
            "suspicious": False,
        }
    ]

    assert calculate_threat_intel_score(results) == 1.0


def test_malicious_overrides_suspicious():
    results = [
        {
            "malicious": False,
            "suspicious": True,
        },
        {
            "malicious": True,
            "suspicious": False,
        },
    ]

    assert calculate_threat_intel_score(results) == 1.0