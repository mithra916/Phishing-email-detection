"""
BodWid - Email Language Analyzer

Analyzes the language used in an email for phishing and
social-engineering indicators.

This module does NOT make the final phishing decision.
It returns structured linguistic evidence for the risk engine.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Keyword groups
# ---------------------------------------------------------------------------

URGENCY_WORDS = {
    "urgent",
    "urgently",
    "immediately",
    "immediate",
    "asap",
    "now",
    "quickly",
    "hurry",
    "deadline",
    "today",
    "within 24 hours",
    "act now",
    "action required",
}

THREAT_WORDS = {
    "suspend",
    "suspended",
    "suspension",
    "terminate",
    "terminated",
    "termination",
    "blocked",
    "disable",
    "disabled",
    "locked",
    "expired",
    "expire",
    "penalty",
    "legal action",
    "account will be closed",
}

CREDENTIAL_WORDS = {
    "password",
    "passcode",
    "otp",
    "verification code",
    "security code",
    "login",
    "sign in",
    "username",
    "credentials",
    "bank details",
    "card details",
    "account details",
}

AUTHORITY_WORDS = {
    "administrator",
    "admin",
    "security team",
    "security department",
    "it department",
    "it support",
    "support team",
    "system administrator",
    "ceo",
    "manager",
    "director",
    "finance department",
    "bank",
    "microsoft support",
    "google support",
}

PRESSURE_WORDS = {
    "do not tell",
    "don't tell",
    "keep this confidential",
    "confidential",
    "secret",
    "do not share",
    "don't share",
    "bypass",
    "ignore normal procedure",
    "without informing",
}

FINANCIAL_WORDS = {
    "wire transfer",
    "transfer funds",
    "send money",
    "payment",
    "invoice",
    "refund",
    "bank account",
    "bank transfer",
    "gift card",
    "crypto",
    "cryptocurrency",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_text(text: str) -> str:
    """Normalize email text for linguistic analysis."""

    if not isinstance(text, str):
        raise TypeError("email_text must be a string")

    return re.sub(r"\s+", " ", text.lower()).strip()


def _count_keyword_hits(
    text: str,
    keywords: set[str],
) -> List[str]:
    """
    Return unique keyword matches found in the text.

    Longer phrases are checked before shorter phrases so that
    phrase-based indicators are preserved.
    """

    hits = []

    for keyword in sorted(keywords, key=len, reverse=True):
        if keyword in text:
            hits.append(keyword)

    return hits


def _score_from_hits(
    hit_count: int,
    *,
    multiplier: float = 0.25,
) -> float:
    """
    Convert number of detected indicators into a bounded score.

    The score is capped at 1.0.
    """

    return min(hit_count * multiplier, 1.0)


# ---------------------------------------------------------------------------
# Individual language analysis
# ---------------------------------------------------------------------------


def analyze_urgency(text: str) -> Dict[str, Any]:
    """Analyze urgency-related language."""

    normalized = _normalize_text(text)
    hits = _count_keyword_hits(normalized, URGENCY_WORDS)

    return {
        "score": _score_from_hits(len(hits)),
        "hits": hits,
        "count": len(hits),
    }


def analyze_threat_language(text: str) -> Dict[str, Any]:
    """Analyze threatening or consequence-based language."""

    normalized = _normalize_text(text)
    hits = _count_keyword_hits(normalized, THREAT_WORDS)

    return {
        "score": _score_from_hits(len(hits)),
        "hits": hits,
        "count": len(hits),
    }


def analyze_credential_requests(text: str) -> Dict[str, Any]:
    """Analyze requests for credentials or sensitive account information."""

    normalized = _normalize_text(text)
    hits = _count_keyword_hits(normalized, CREDENTIAL_WORDS)

    return {
        "score": _score_from_hits(
            len(hits),
            multiplier=0.30,
        ),
        "hits": hits,
        "count": len(hits),
    }


def analyze_authority_language(text: str) -> Dict[str, Any]:
    """Analyze authority or organizational impersonation language."""

    normalized = _normalize_text(text)
    hits = _count_keyword_hits(normalized, AUTHORITY_WORDS)

    return {
        "score": _score_from_hits(len(hits)),
        "hits": hits,
        "count": len(hits),
    }


def analyze_pressure_language(text: str) -> Dict[str, Any]:
    """Analyze secrecy and pressure-to-bypass-process language."""

    normalized = _normalize_text(text)
    hits = _count_keyword_hits(normalized, PRESSURE_WORDS)

    return {
        "score": _score_from_hits(
            len(hits),
            multiplier=0.30,
        ),
        "hits": hits,
        "count": len(hits),
    }


def analyze_financial_language(text: str) -> Dict[str, Any]:
    """Analyze financial transaction or payment language."""

    normalized = _normalize_text(text)
    hits = _count_keyword_hits(normalized, FINANCIAL_WORDS)

    return {
        "score": _score_from_hits(
            len(hits),
            multiplier=0.25,
        ),
        "hits": hits,
        "count": len(hits),
    }


# ---------------------------------------------------------------------------
# Overall analysis
# ---------------------------------------------------------------------------


def analyze_email_language(email_text: str) -> Dict[str, Any]:
    """
    Perform complete language analysis.

    Returns structured evidence that can later be combined with
    ML, emotion, header and threat-intelligence signals.
    """

    normalized = _normalize_text(email_text)

    if not normalized:
        return {
            "urgency": {
                "score": 0.0,
                "hits": [],
                "count": 0,
            },
            "threat": {
                "score": 0.0,
                "hits": [],
                "count": 0,
            },
            "credential_request": {
                "score": 0.0,
                "hits": [],
                "count": 0,
            },
            "authority": {
                "score": 0.0,
                "hits": [],
                "count": 0,
            },
            "pressure": {
                "score": 0.0,
                "hits": [],
                "count": 0,
            },
            "financial": {
                "score": 0.0,
                "hits": [],
                "count": 0,
            },
            "overall_score": 0.0,
            "indicators": [],
        }

    urgency = analyze_urgency(normalized)
    threat = analyze_threat_language(normalized)
    credential = analyze_credential_requests(normalized)
    authority = analyze_authority_language(normalized)
    pressure = analyze_pressure_language(normalized)
    financial = analyze_financial_language(normalized)

    categories = [
        ("Urgent language detected", urgency),
        ("Threatening or consequence-based language detected", threat),
        ("Credential or sensitive information request detected", credential),
        ("Authority-related language detected", authority),
        ("Pressure or secrecy language detected", pressure),
        ("Financial transaction language detected", financial),
    ]

    indicators = [
        label
        for label, result in categories
        if result["count"] > 0
    ]

    # Weighted combination.
    #
    # Credential and pressure indicators receive slightly more weight
    # because they are particularly relevant to social engineering.
    overall_score = (
        urgency["score"] * 0.20
        + threat["score"] * 0.15
        + credential["score"] * 0.25
        + authority["score"] * 0.10
        + pressure["score"] * 0.20
        + financial["score"] * 0.10
    )

    return {
        "urgency": urgency,
        "threat": threat,
        "credential_request": credential,
        "authority": authority,
        "pressure": pressure,
        "financial": financial,
        "overall_score": round(
            min(overall_score, 1.0),
            3,
        ),
        "indicators": indicators,
    }


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    sample_email = """
    URGENT ACTION REQUIRED.

    Your account will be suspended immediately unless you verify
    your password and OTP.

    This request is confidential. Do not tell anyone.

    Please complete the payment today.
    """

    from pprint import pprint

    pprint(analyze_email_language(sample_email))