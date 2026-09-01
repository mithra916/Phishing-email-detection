"""
BodWid - Email Prediction Pipeline

Combines all email-security analysis layers:

- TF-IDF + ML classification
- Rule-based attack features
- Language analysis
- Emotion analysis
- Email header analysis
- URL analysis
- VirusTotal threat intelligence
- Risk engine
- Threat classification
- Explainable risk reasons

Returns a normalized result suitable for the Flask API.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from src.preprocess import clean_email
from src.rules import extract_attack_features
from src.emotion import get_emotion_score
from src.explain import generate_full_explanation
from src.threat import classify_threat
from src.header_analyzer import analyze_headers
from src.url_analyzer import analyze_urls
from src.language_analyzer import analyze_email_language

from src.threat_intel import (
    VirusTotalClient,
    ThreatIntelError,
)

from src.risk_engine import (
    calculate_risk_score,
    calculate_header_score,
    calculate_threat_intel_score,
)


# ---------------------------------------------------------------------------
# Keywords
# ---------------------------------------------------------------------------

NEWSLETTER_WORDS = [
    "newsletter",
    "weekly",
    "unsubscribe",
    "highlights",
]

BEC_KEYWORDS = [
    "transfer funds",
    "wire transfer",
    "send money",
    "urgent request",
    "need you to",
    "asap",
    "confidential",
    "do not tell",
    "im in a meeting",
]


# ---------------------------------------------------------------------------
# Threat Intelligence
# ---------------------------------------------------------------------------

def _run_threat_intelligence(
    header_analysis: Dict[str, Any],
    email_text: str,
) -> Dict[str, Any]:
    """
    Run optional VirusTotal lookups against:

    - Sender-related domains
    - Public IPs from Received headers
    - URLs extracted from the email body

    Threat intelligence is optional.

    If no API key is configured, the feature is disabled.

    Network/API failures never break the main email analysis.
    """

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    # -----------------------------------------------------------------------
    # Threat Intel disabled
    # -----------------------------------------------------------------------

    if not api_key:
        return {
            "enabled": False,
            "provider": None,
            "results": [],
            "malicious_count": 0,
            "suspicious_count": 0,
            "error": None,
            "url_analysis": analyze_urls(email_text),
        }

    # -----------------------------------------------------------------------
    # Create VirusTotal client
    # -----------------------------------------------------------------------

    try:
        client = VirusTotalClient(api_key=api_key)

    except ThreatIntelError as exc:
        return {
            "enabled": False,
            "provider": "VirusTotal",
            "results": [],
            "malicious_count": 0,
            "suspicious_count": 0,
            "error": str(exc),
            "url_analysis": analyze_urls(email_text),
        }

    results = []

    # -----------------------------------------------------------------------
    # Domain lookups
    # -----------------------------------------------------------------------

    domains = header_analysis.get("domains", {})

    domain_values = {
        domains.get("from_domain"),
        domains.get("reply_to_domain"),
        domains.get("return_path_domain"),
    }

    for domain in sorted(
        domain
        for domain in domain_values
        if domain
    ):
        try:
            result = client.lookup_domain(domain)
            results.append(result)

        except (
            ThreatIntelError,
            ValueError,
        ):
            # Threat intelligence failure must not break analysis.
            continue

    # -----------------------------------------------------------------------
    # Public IP lookups
    # -----------------------------------------------------------------------

    received_ips = header_analysis.get(
        "received_ips",
        [],
    )

    seen_ips = set()

    for ip_data in received_ips:

        ip = ip_data.get("ip")

        if not ip:
            continue

        if ip in seen_ips:
            continue

        seen_ips.add(ip)

        # Private/internal IPs do not need external reputation lookup.
        if ip_data.get("private"):
            continue

        try:
            result = client.lookup_ip(ip)
            results.append(result)

        except (
            ThreatIntelError,
            ValueError,
        ):
            continue

    # -----------------------------------------------------------------------
    # URL lookups
    # -----------------------------------------------------------------------

    url_analysis = analyze_urls(email_text)

    urls = url_analysis.get(
        "urls",
        [],
    )

    seen_urls = set()

    for url_data in urls:

        url = url_data.get("url")

        if not url:
            continue

        if url in seen_urls:
            continue

        seen_urls.add(url)

        try:
            result = client.lookup_url(url)

            # Preserve URL analyzer information.
            result["shortened"] = url_data.get(
                "shortened",
                False,
            )

            results.append(result)

        except (
            ThreatIntelError,
            ValueError,
        ):
            continue

    # -----------------------------------------------------------------------
    # Reputation counts
    # -----------------------------------------------------------------------

    malicious_count = sum(
        1
        for result in results
        if result.get("malicious") is True
    )

    suspicious_count = sum(
        1
        for result in results
        if result.get("suspicious") is True
    )

    # -----------------------------------------------------------------------
    # Return normalized result
    # -----------------------------------------------------------------------

    return {
        "enabled": True,
        "provider": "VirusTotal",
        "results": results,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "error": None,
        "url_analysis": url_analysis,
    }


# ---------------------------------------------------------------------------
# Email prediction
# ---------------------------------------------------------------------------

def predict_email(
    email_text: str,
    model: Any,
    vectorizer: Any,
) -> Dict[str, Any]:
    """
    Analyze an email using all BodWid analysis layers.

    Analysis layers:

    1. Email preprocessing
    2. ML classification
    3. Rule-based attack detection
    4. Language analysis
    5. Emotion analysis
    6. Header analysis
    7. URL analysis
    8. Threat intelligence
    9. Risk engine
    10. Threat classification
    11. Explainable reasons

    Returns:
        Structured prediction result.
    """

    # -----------------------------------------------------------------------
    # Input validation
    # -----------------------------------------------------------------------

    if not isinstance(email_text, str):
        raise TypeError(
            "email_text must be a string"
        )

    if not email_text.strip():
        raise ValueError(
            "email_text cannot be empty"
        )

    # -----------------------------------------------------------------------
    # Header analysis
    # -----------------------------------------------------------------------

    header_analysis = analyze_headers(
        email_text
    )

    # -----------------------------------------------------------------------
    # URL analysis
    # -----------------------------------------------------------------------

    url_analysis = analyze_urls(
        email_text
    )

    # -----------------------------------------------------------------------
    # Threat Intelligence
    # -----------------------------------------------------------------------

    threat_intel = _run_threat_intelligence(
        header_analysis,
        email_text,
    )

    # -----------------------------------------------------------------------
    # Email preprocessing
    # -----------------------------------------------------------------------

    cleaned = clean_email(
        email_text
    )

    # -----------------------------------------------------------------------
    # ML prediction
    # -----------------------------------------------------------------------

    vec = vectorizer.transform(
        [cleaned]
    )

    ml_proba = float(
        model.predict_proba(vec)[0][1]
    )

    # -----------------------------------------------------------------------
    # Rule-based attack features
    # -----------------------------------------------------------------------

    features = extract_attack_features(
        email_text
    )

    # -----------------------------------------------------------------------
    # Language analysis
    # -----------------------------------------------------------------------

    language_analysis = analyze_email_language(
        email_text
    )

    # -----------------------------------------------------------------------
    # Emotion analysis
    # -----------------------------------------------------------------------

    emotion_score = 0.0

    if ml_proba > 0.4:
        emotion_score = get_emotion_score(
            email_text
        )

    # -----------------------------------------------------------------------
    # Threat categorization
    # -----------------------------------------------------------------------

    threat_type = classify_threat(
        features
    )

    # -----------------------------------------------------------------------
    # Explanation
    # -----------------------------------------------------------------------

    reasons = generate_full_explanation(
    features,
    emotion_score,
    header_analysis=header_analysis,
    url_analysis=url_analysis,
    language_analysis=language_analysis,
    threat_intel=threat_intel,
)

    # -----------------------------------------------------------------------
    # Header score
    # -----------------------------------------------------------------------

    header_score = calculate_header_score(
        header_analysis
    )

    # -----------------------------------------------------------------------
    # Threat intelligence score
    # -----------------------------------------------------------------------

    threat_intel_score = calculate_threat_intel_score(
        threat_intel
    )

    # -----------------------------------------------------------------------
    # Risk engine inputs
    # -----------------------------------------------------------------------

    language_score = language_analysis.get(
    "overall_score",
    0.0,
)

    rule_score = 0.0

    if features.get("url_count", 0) > 0:
        rule_score += 0.2

    if features.get("brand_impersonation"):
        rule_score += 0.3

    if features.get("shortened_url"):
        rule_score += 0.4

    if features.get("executable_link"):
        rule_score += 0.5

    if features.get("urgent_words", 0) >= 2:
        rule_score += 0.2

    rule_score = min(rule_score, 1.0)

    risk_result = calculate_risk_score(
    ml_proba,
    rule_score,
    language_score,
    emotion_score,
    header_score,
    threat_intel_score=threat_intel_score,
)

    score = risk_result["score"]

    # -----------------------------------------------------------------------
    # Cyber security overrides
    # -----------------------------------------------------------------------

    if (
        features.get("brand_impersonation")
        and features.get("url_count")
    ):
        score = max(
            score,
            0.80,
        )

    if features.get("shortened_url"):
        score = max(
            score,
            0.85,
        )

    if features.get("executable_link"):
        score = max(
            score,
            0.90,
        )

    if (
        features.get("urgent_words", 0) >= 2
        and emotion_score > 0.4
    ):
        score = max(
            score,
            0.60,
        )

    # -----------------------------------------------------------------------
    # Newsletter downgrade
    # -----------------------------------------------------------------------

    email_lower = email_text.lower()

    newsletter_hits = sum(
        word in email_lower
        for word in NEWSLETTER_WORDS
    )

    if newsletter_hits >= 2:
        score *= 0.5

    # -----------------------------------------------------------------------
    # BEC / CEO fraud detection
    # -----------------------------------------------------------------------

    bec_hits = [
        keyword
        for keyword in BEC_KEYWORDS
        if keyword in email_lower
    ]

    if bec_hits:

        reasons.append(
            "Possible CEO fraud / BEC attack"
        )

        threat_type = (
            "Business Email Compromise"
        )

        score = max(
            score,
            0.75,
        )

    # -----------------------------------------------------------------------
    # Header-based reasons
    # -----------------------------------------------------------------------

    header_indicators = header_analysis.get(
        "indicators",
        [],
    )

    for indicator in header_indicators:

        reason = f"Header: {indicator}"

        if reason not in reasons:
            reasons.append(reason)

    # -----------------------------------------------------------------------
    # Header-specific overrides
    # -----------------------------------------------------------------------

    domains = header_analysis.get(
        "domains",
        {},
    )

    authentication = header_analysis.get(
        "authentication",
        {},
    )

    # Reply-To mismatch
    if domains.get(
        "reply_to_mismatch"
    ):
        score = max(
            score,
            0.65,
        )

    # Return-Path mismatch
    if domains.get(
        "return_path_mismatch"
    ):
        score = max(
            score,
            0.60,
        )

    # DMARC failure
    if authentication.get(
        "dmarc"
    ) == "fail":
        score = max(
            score,
            0.70,
        )

    # SPF failure
    elif authentication.get(
        "spf"
    ) == "fail":
        score = max(
            score,
            0.65,
        )

    # -----------------------------------------------------------------------
    # Threat Intelligence overrides
    # -----------------------------------------------------------------------

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

        score = max(
            score,
            0.90,
        )

    elif suspicious_count > 0:

        reasons.append(
            "Threat intelligence identified a suspicious indicator"
        )

        score = max(
            score,
            0.75,
        )

    # -----------------------------------------------------------------------
    # URL-based explanation
    # -----------------------------------------------------------------------

    url_indicators = url_analysis.get(
        "indicators",
        [],
    )

    for indicator in url_indicators:

        reason = f"URL: {indicator}"

        if reason not in reasons:
            reasons.append(reason)

    # -----------------------------------------------------------------------
    # Language-based explanation
    # -----------------------------------------------------------------------

    language_indicators = language_analysis.get(
        "indicators",
        [],
    )

    for indicator in language_indicators:

        reason = f"Language: {indicator}"

        if reason not in reasons:
            reasons.append(reason)

    # -----------------------------------------------------------------------
    # Final score normalization
    # -----------------------------------------------------------------------

    score = min(
        max(
            float(score),
            0.0,
        ),
        1.0,
    )

    # -----------------------------------------------------------------------
    # Final classification
    # -----------------------------------------------------------------------

    if score >= 0.7:

        label = "Phishing Email"
        risk = "High"

    elif score >= 0.5:

        label = "Suspicious Email"
        risk = "Medium"

    else:

        label = "Safe Email"
        risk = "Low"

    # -----------------------------------------------------------------------
    # Final result
    # -----------------------------------------------------------------------

    return {
        "prediction": label,
        "confidence": round(
            score,
            2,
        ),
        "risk_level": risk,

        "url_count": features.get(
            "url_count",
            0,
        ),

        "emotion_score": round(
            emotion_score,
            2,
        ),

        "language_score": round(
            language_analysis.get(
                "score",
                0.0,
            ),
            2,
        ),

        "header_score": round(
            header_score,
            2,
        ),

        "threat_intel_score": round(
            threat_intel_score,
            2,
        ),

        "threat_type": threat_type,

        "reasons": reasons,

        "language_analysis": language_analysis,

        "url_analysis": url_analysis,

        "header_analysis": header_analysis,

        "threat_intel": threat_intel,
    }