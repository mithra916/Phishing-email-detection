"""
BodWid - Email Header Analyzer

Analyzes raw email headers for security-relevant indicators.

Current checks:
- Basic header extraction
- From / Reply-To / Return-Path parsing
- Domain mismatch detection
- Authentication-Results parsing
- SPF / DKIM / DMARC result extraction
- Received header parsing
- Public/private IP identification

This module does NOT make the final phishing decision.
It only returns structured evidence for the risk engine.
"""

from __future__ import annotations

import ipaddress
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Header extraction
# ---------------------------------------------------------------------------

def parse_email_headers(raw_email: str) -> Dict[str, Any]:
    """
    Parse a raw email message and extract security-relevant headers.

    Args:
        raw_email: Complete raw email message as a string.

    Returns:
        Dictionary containing extracted header information.
    """

    if not isinstance(raw_email, str):
        raise TypeError("raw_email must be a string")

    if not raw_email.strip():
        raise ValueError("raw_email cannot be empty")

    message = Parser(policy=policy.default).parsestr(raw_email)

    from_address = _extract_address(message.get("From"))
    reply_to_address = _extract_address(message.get("Reply-To"))
    return_path_address = _extract_address(message.get("Return-Path"))

    authentication_results = message.get_all(
        "Authentication-Results", []
    )

    received_headers = message.get_all("Received", [])

    return {
        "from": from_address,
        "reply_to": reply_to_address,
        "return_path": return_path_address,
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "message_id": message.get("Message-ID"),
        "authentication_results": authentication_results,
        "received": received_headers,
    }


def _extract_address(header_value: Optional[str]) -> Optional[Dict[str, str]]:
    """
    Extract display name, email address and domain from an email header.
    """

    if not header_value:
        return None

    display_name, email_address = parseaddr(header_value)

    if not email_address or "@" not in email_address:
        return None

    local_part, domain = email_address.rsplit("@", 1)

    return {
        "display_name": display_name,
        "address": email_address,
        "local_part": local_part,
        "domain": domain.lower(),
    }


# ---------------------------------------------------------------------------
# Domain analysis
# ---------------------------------------------------------------------------

def analyze_domain_mismatches(
    headers: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Compare From, Reply-To and Return-Path domains.

    Returns mismatch indicators that can later contribute to risk scoring.
    """

    from_data = headers.get("from")
    reply_to_data = headers.get("reply_to")
    return_path_data = headers.get("return_path")

    from_domain = (
        from_data.get("domain")
        if from_data
        else None
    )

    reply_to_domain = (
        reply_to_data.get("domain")
        if reply_to_data
        else None
    )

    return_path_domain = (
        return_path_data.get("domain")
        if return_path_data
        else None
    )

    indicators: List[str] = []

    reply_to_mismatch = False
    return_path_mismatch = False

    if from_domain and reply_to_domain:
        if from_domain != reply_to_domain:
            reply_to_mismatch = True
            indicators.append(
                "Reply-To domain differs from From domain"
            )

    if from_domain and return_path_domain:
        if from_domain != return_path_domain:
            return_path_mismatch = True
            indicators.append(
                "Return-Path domain differs from From domain"
            )

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "indicators": indicators,
    }


# ---------------------------------------------------------------------------
# Authentication analysis
# ---------------------------------------------------------------------------

def analyze_authentication(
    authentication_results: List[str]
) -> Dict[str, Any]:
    """
    Parse Authentication-Results headers.

    Extracts:
    - SPF
    - DKIM
    - DMARC

    This parser reads the authentication results already present in the
    email headers. It does not perform SPF/DKIM/DMARC validation itself.
    """

    result = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "raw": authentication_results,
    }

    for header in authentication_results:
        if not header:
            continue

        # SPF
        spf_match = re.search(
            r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            header,
            re.IGNORECASE,
        )

        if spf_match:
            result["spf"] = spf_match.group(1).lower()

        # DKIM
        dkim_match = re.search(
            r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b",
            header,
            re.IGNORECASE,
        )

        if dkim_match:
            result["dkim"] = dkim_match.group(1).lower()

        # DMARC
        dmarc_match = re.search(
            r"\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b",
            header,
            re.IGNORECASE,
        )

        if dmarc_match:
            result["dmarc"] = dmarc_match.group(1).lower()

    indicators = []

    if result["spf"] in {"fail", "softfail", "permerror"}:
        indicators.append(
            f"SPF result: {result['spf']}"
        )

    if result["dkim"] in {"fail", "permerror"}:
        indicators.append(
            f"DKIM result: {result['dkim']}"
        )

    if result["dmarc"] in {"fail", "permerror"}:
        indicators.append(
            f"DMARC result: {result['dmarc']}"
        )

    result["indicators"] = indicators

    return result


# ---------------------------------------------------------------------------
# Received header / IP analysis
# ---------------------------------------------------------------------------

IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}"
    r")\b"
)


def extract_ips_from_received(
    received_headers: List[str]
) -> List[Dict[str, Any]]:
    """
    Extract IP addresses from Received headers.

    Returns unique IP addresses with basic classification.
    """

    found_ips = []
    seen = set()

    for received in received_headers:
        if not received:
            continue

        matches = IP_PATTERN.findall(received)

        for ip_string in matches:
            try:
                ip_obj = ipaddress.ip_address(ip_string)
            except ValueError:
                continue

            normalized_ip = str(ip_obj)

            if normalized_ip in seen:
                continue

            seen.add(normalized_ip)

            found_ips.append(
                {
                    "ip": normalized_ip,
                    "version": ip_obj.version,
                    "private": ip_obj.is_private,
                    "global": ip_obj.is_global,
                    "loopback": ip_obj.is_loopback,
                    "reserved": ip_obj.is_reserved,
                }
            )

    return found_ips


# ---------------------------------------------------------------------------
# Complete analysis
# ---------------------------------------------------------------------------

def analyze_headers(raw_email: str) -> Dict[str, Any]:
    """
    Perform complete email header analysis.

    Args:
        raw_email: Complete raw email message.

    Returns:
        Structured header analysis.
    """

    headers = parse_email_headers(raw_email)

    domain_analysis = analyze_domain_mismatches(headers)

    authentication_analysis = analyze_authentication(
        headers["authentication_results"]
    )

    received_ips = extract_ips_from_received(
        headers["received"]
    )

    all_indicators = (
        domain_analysis["indicators"]
        + authentication_analysis["indicators"]
    )

    return {
        "headers": headers,
        "domains": domain_analysis,
        "authentication": authentication_analysis,
        "received_ips": received_ips,
        "indicators": all_indicators,
        "indicator_count": len(all_indicators),
    }


# ---------------------------------------------------------------------------
# Simple manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    sample_email = """\
From: Microsoft Support <support@microsoft-example.com>
To: user@example.com
Reply-To: attacker@malicious-example.com
Return-Path: attacker@malicious-example.com
Subject: Urgent account verification
Date: Thu, 27 Aug 2026 10:00:00 +0000
Message-ID: <12345@example.com>
Authentication-Results: mx.example.com;
    spf=fail;
    dkim=pass;
    dmarc=fail
Received: from mail.example.com (192.168.1.10)
    by mx.example.com with ESMTP;
Received: from suspicious-host (203.0.113.50)
    by mail.example.com with ESMTP;

This is the email body.
"""

    result = analyze_headers(sample_email)

    from pprint import pprint

    pprint(result)