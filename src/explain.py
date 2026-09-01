"""
BodWid - Explainable Risk Analysis

Generates human-readable explanations for phishing risk signals.

The explanation layer does not make the final phishing decision.
It only converts structured security signals into understandable reasons.
"""


# ---------------------------------------------------------------------------
# Basic ML / rule-based explanation
# ---------------------------------------------------------------------------

def generate_explanation(features, emotion_score):
    """
    Generate explanations from rule-based and emotion signals.

    Kept backward-compatible with the original BodWid interface.
    """

    reasons = []

    if features.get("url_count", 0) > 0:
        reasons.append("Contains external link")

    if features.get("shortened_url"):
        reasons.append("Uses shortened URL")

    if features.get("brand_impersonation"):
        reasons.append("Possible brand impersonation")

    if features.get("urgent_words", 0) >= 2:
        reasons.append("Urgent or threatening language")

    if features.get("executable_link"):
        reasons.append("Executable file link detected")

    if emotion_score > 0.4:
        reasons.append("Emotional manipulation detected")

    return reasons


# ---------------------------------------------------------------------------
# Header explanation
# ---------------------------------------------------------------------------

def generate_header_explanations(header_analysis):
    """
    Generate explanations from email header analysis.
    """

    reasons = []

    domains = header_analysis.get("domains", {})
    authentication = header_analysis.get(
        "authentication",
        {},
    )

    if domains.get("reply_to_mismatch"):
        reasons.append(
            "Reply-To domain differs from the sender domain"
        )

    if domains.get("return_path_mismatch"):
        reasons.append(
            "Return-Path domain differs from the sender domain"
        )

    if authentication.get("spf") in {
        "fail",
        "softfail",
        "permerror",
    }:
        reasons.append(
            f"SPF authentication result: "
            f"{authentication['spf']}"
        )

    if authentication.get("dkim") in {
        "fail",
        "permerror",
    }:
        reasons.append(
            f"DKIM authentication result: "
            f"{authentication['dkim']}"
        )

    if authentication.get("dmarc") in {
        "fail",
        "permerror",
    }:
        reasons.append(
            f"DMARC authentication result: "
            f"{authentication['dmarc']}"
        )

    return reasons


# ---------------------------------------------------------------------------
# URL explanation
# ---------------------------------------------------------------------------

def generate_url_explanations(url_analysis):
    """
    Generate explanations from URL analysis.
    """

    reasons = []

    indicators = url_analysis.get(
        "indicators",
        [],
    )

    for indicator in indicators:
        reason = f"URL: {indicator}"

        if reason not in reasons:
            reasons.append(reason)

    return reasons


# ---------------------------------------------------------------------------
# Language explanation
# ---------------------------------------------------------------------------

def generate_language_explanations(language_analysis):
    """
    Generate explanations from language analysis.
    """

    reasons = []

    indicators = language_analysis.get(
        "indicators",
        [],
    )

    for indicator in indicators:
        reason = f"Language: {indicator}"

        if reason not in reasons:
            reasons.append(reason)

    return reasons


# ---------------------------------------------------------------------------
# Threat Intelligence explanation
# ---------------------------------------------------------------------------

def generate_threat_intel_explanations(threat_intel):
    """
    Generate explanations from VirusTotal threat-intelligence results.
    """

    reasons = []

    malicious_count = threat_intel.get(
        "malicious_count",
        0,
    )

    suspicious_count = threat_intel.get(
        "suspicious_count",
        0,
    )

    if malicious_count > 0:
        reasons.append(
            "Threat intelligence identified a malicious indicator"
        )
    elif suspicious_count > 0:
        reasons.append(
            "Threat intelligence identified a suspicious indicator"
        )

    return reasons


# ---------------------------------------------------------------------------
# Combined explanation
# ---------------------------------------------------------------------------

def generate_full_explanation(
    features,
    emotion_score=0.0,
    header_analysis=None,
    url_analysis=None,
    language_analysis=None,
    threat_intel=None,
):
    """
    Generate a complete explanation from all BodWid analysis layers.

    This function only generates evidence-based reasons.
    It does not calculate or modify the risk score.
    """

    reasons = generate_explanation(
        features,
        emotion_score,
    )

    if header_analysis:
        reasons.extend(
            generate_header_explanations(
                header_analysis
            )
        )

    if url_analysis:
        reasons.extend(
            generate_url_explanations(
                url_analysis
            )
        )

    if language_analysis:
        reasons.extend(
            generate_language_explanations(
                language_analysis
            )
        )

    if threat_intel:
        reasons.extend(
            generate_threat_intel_explanations(
                threat_intel
            )
        )

    # Remove duplicate explanations while
    # preserving their original order.
    return list(dict.fromkeys(reasons))