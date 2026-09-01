"""
BodWid - Risk Engine

Combines independent phishing-risk signals into one normalized score.

Signals:
- ML prediction
- Rule-based attack features
- Language analysis
- Emotion analysis
- Email header analysis
- Threat intelligence

The risk engine does not perform detection itself.
It only combines already-computed signals.
"""

from __future__ import annotations

from typing import Any, Dict


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS = {
    "ml": 0.35,
    "rules": 0.15,
    "language": 0.10,
    "emotion": 0.10,
    "header": 0.15,
    "threat_intel": 0.15,
}

RISK_THRESHOLDS = {
    "medium": 0.50,
    "high": 0.70,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clamp(value: float) -> float:
    """Keep a score between 0.0 and 1.0."""

    return max(0.0, min(1.0, float(value)))


def _validate_weights(weights: Dict[str, float]) -> None:
    """Validate that risk weights are valid and sum to 1."""

    expected_keys = set(DEFAULT_WEIGHTS)

    if set(weights) != expected_keys:
        raise ValueError(
            "Weights must contain exactly: "
            + ", ".join(sorted(expected_keys))
        )

    if any(weight < 0 for weight in weights.values()):
        raise ValueError("Weights cannot be negative.")

    total = sum(weights.values())

    if abs(total - 1.0) > 1e-9:
        raise ValueError("Risk weights must sum to 1.0.")


def _risk_level(score: float) -> str:
    """Convert a normalized score into a risk level."""

    if score >= RISK_THRESHOLDS["high"]:
        return "High"

    if score >= RISK_THRESHOLDS["medium"]:
        return "Medium"

    return "Low"


# ---------------------------------------------------------------------------
# Main risk calculation
# ---------------------------------------------------------------------------

def calculate_risk_score(
    ml_score: float,
    rule_score: float,
    language_score: float,
    emotion_score: float,
    header_score: float,
    threat_intel_score: float=0.0,
    weights: Dict[str, float] | None = None,
) -> Dict[str, Any]:
    """
    Combine phishing-risk signals into one normalized score.

    All input scores are expected to be between 0.0 and 1.0.
    Values outside that range are safely clamped.

    Args:
        ml_score:
            Probability/risk score produced by the ML model.

        rule_score:
            Risk score from cyber-specific rules.

        language_score:
            Risk score from language analysis.

        emotion_score:
            Risk score from emotional manipulation analysis.

        header_score:
            Risk score from email-header analysis.

        threat_intel_score:
            Risk score from threat-intelligence results.

        weights:
            Optional custom weights. If omitted, DEFAULT_WEIGHTS is used.

    Returns:
        Dictionary containing:
        - final score
        - risk level
        - individual signal scores
        - weighted contributions
        - weights
    """

    active_weights = (
        DEFAULT_WEIGHTS.copy()
        if weights is None
        else weights.copy()
    )

    _validate_weights(active_weights)

    signal_scores = {
        "ml": _clamp(ml_score),
        "rules": _clamp(rule_score),
        "language": _clamp(language_score),
        "emotion": _clamp(emotion_score),
        "header": _clamp(header_score),
        "threat_intel": _clamp(threat_intel_score),
    }

    contributions = {
        signal: round(
            signal_scores[signal] * active_weights[signal],
            4,
        )
        for signal in signal_scores
    }

    final_score = _clamp(sum(contributions.values()))

    return {
        "score": round(final_score, 2),
        "risk_level": _risk_level(final_score),
        "signal_scores": signal_scores,
        "contributions": contributions,
        "weights": active_weights,
    }


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def calculate_header_score(header_analysis: Dict[str, Any]) -> float:
    """
    Convert header-analysis evidence into a normalized risk score.

    Evidence considered:
    - Reply-To mismatch
    - Return-Path mismatch
    - SPF failure
    - DKIM failure
    - DMARC failure
    """

    if not header_analysis:
        return 0.0

    score = 0.0

    domains = header_analysis.get("domains", {})
    authentication = header_analysis.get(
        "authentication",
        {},
    )

    if domains.get("reply_to_mismatch"):
        score += 0.25

    if domains.get("return_path_mismatch"):
        score += 0.25

    if authentication.get("spf") in {
        "fail",
        "softfail",
        "permerror",
    }:
        score += 0.15

    if authentication.get("dkim") in {
        "fail",
        "permerror",
    }:
        score += 0.15

    if authentication.get("dmarc") in {
        "fail",
        "permerror",
    }:
        score += 0.20

    return round(_clamp(score), 2)



def calculate_threat_intel_score(results):
    """
    Convert threat-intelligence results into a normalized 0-1 score.

    Malicious indicator -> 1.0
    Suspicious indicator -> 0.75
    Clean/unknown -> 0.0

    Malicious always takes priority over suspicious.
    """

    if not results:
        return 0.0

    has_suspicious = False

    for result in results:
        if not isinstance(result, dict):
            continue

        if result.get("malicious") is True:
            return 1.0

        if result.get("suspicious") is True:
            has_suspicious = True

    if has_suspicious:
        return 0.75

    return 0.0