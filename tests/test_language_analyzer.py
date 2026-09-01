import pytest

from src.language_analyzer import (
    analyze_email_language,
    analyze_urgency,
    analyze_threat_language,
    analyze_credential_requests,
    analyze_authority_language,
    analyze_pressure_language,
    analyze_financial_language,
)


def test_urgency_detection():
    result = analyze_urgency(
        "URGENT action required. Please act now."
    )

    assert result["count"] >= 2
    assert result["score"] > 0
    assert "urgent" in result["hits"]


def test_threat_detection():
    result = analyze_threat_language(
        "Your account will be suspended immediately."
    )

    assert result["count"] >= 1
    assert result["score"] > 0
    assert "suspended" in result["hits"]


def test_credential_detection():
    result = analyze_credential_requests(
        "Please provide your password and OTP."
    )

    assert result["count"] >= 2
    assert result["score"] > 0
    assert "password" in result["hits"]
    assert "otp" in result["hits"]


def test_authority_detection():
    result = analyze_authority_language(
        "This request comes from the security team."
    )

    assert result["count"] >= 1
    assert result["score"] > 0
    assert "security team" in result["hits"]


def test_pressure_detection():
    result = analyze_pressure_language(
        "Keep this confidential. Do not tell anyone."
    )

    assert result["count"] >= 2
    assert result["score"] > 0


def test_financial_detection():
    result = analyze_financial_language(
        "Please complete the wire transfer today."
    )

    assert result["count"] >= 1
    assert result["score"] > 0
    assert "wire transfer" in result["hits"]


def test_normal_email_has_low_language_score():
    result = analyze_email_language(
        """
        Hi team,

        The project meeting is scheduled for tomorrow at 10 AM.
        Please review the attached agenda before the meeting.

        Thanks.
        """
    )

    assert result["overall_score"] < 0.2
    assert result["indicators"] == []


def test_phishing_email_has_multiple_indicators():
    result = analyze_email_language(
        """
        URGENT ACTION REQUIRED.

        Your account will be suspended immediately.
        Please provide your password and OTP now.

        This request is confidential.
        Do not tell anyone.

        Complete the payment today.
        """
    )

    assert result["overall_score"] > 0.5
    assert len(result["indicators"]) >= 4


def test_case_insensitive_detection():
    result = analyze_email_language(
        "URGENT: PLEASE PROVIDE YOUR PASSWORD."
    )

    assert result["urgency"]["count"] >= 1
    assert result["credential_request"]["count"] >= 1


def test_empty_email():
    result = analyze_email_language("")

    assert result["overall_score"] == 0.0
    assert result["indicators"] == []


def test_whitespace_email():
    result = analyze_email_language("   ")

    assert result["overall_score"] == 0.0
    assert result["indicators"] == []


def test_invalid_input_type():
    with pytest.raises(TypeError):
        analyze_email_language(None)


def test_scores_are_bounded():
    result = analyze_email_language(
        "urgent immediate asap now "
        "password otp credentials login "
        "suspended blocked disabled "
        "confidential secret do not tell "
        "wire transfer payment invoice "
        "security team administrator"
    )

    assert 0.0 <= result["overall_score"] <= 1.0

    for category in [
        "urgency",
        "threat",
        "credential_request",
        "authority",
        "pressure",
        "financial",
    ]:
        assert 0.0 <= result[category]["score"] <= 1.0