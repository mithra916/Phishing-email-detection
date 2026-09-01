import pytest

from src.header_analyzer import (
    parse_email_headers,
    analyze_domain_mismatches,
    analyze_authentication,
    extract_ips_from_received,
    analyze_headers,
)


# ---------------------------------------------------------------------------
# Sample email
# ---------------------------------------------------------------------------

SAMPLE_EMAIL = """\
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


# ---------------------------------------------------------------------------
# Header parsing tests
# ---------------------------------------------------------------------------

def test_parse_email_headers():
    result = parse_email_headers(SAMPLE_EMAIL)

    assert result["from"]["address"] == "support@microsoft-example.com"
    assert result["reply_to"]["address"] == "attacker@malicious-example.com"
    assert result["return_path"]["address"] == "attacker@malicious-example.com"
    assert result["subject"] == "Urgent account verification"


def test_extract_sender_domains():
    result = parse_email_headers(SAMPLE_EMAIL)

    assert result["from"]["domain"] == "microsoft-example.com"
    assert result["reply_to"]["domain"] == "malicious-example.com"
    assert result["return_path"]["domain"] == "malicious-example.com"


# ---------------------------------------------------------------------------
# Domain mismatch tests
# ---------------------------------------------------------------------------

def test_reply_to_domain_mismatch():
    headers = parse_email_headers(SAMPLE_EMAIL)

    result = analyze_domain_mismatches(headers)

    assert result["reply_to_mismatch"] is True
    assert "Reply-To domain differs from From domain" in result["indicators"]


def test_return_path_domain_mismatch():
    headers = parse_email_headers(SAMPLE_EMAIL)

    result = analyze_domain_mismatches(headers)

    assert result["return_path_mismatch"] is True
    assert "Return-Path domain differs from From domain" in result["indicators"]


def test_matching_domains():
    email = """\
From: Alice <alice@example.com>
Reply-To: alice@example.com
Return-Path: alice@example.com
Subject: Hello

Hello.
"""

    headers = parse_email_headers(email)
    result = analyze_domain_mismatches(headers)

    assert result["reply_to_mismatch"] is False
    assert result["return_path_mismatch"] is False
    assert result["indicators"] == []


def test_missing_reply_to():
    email = """\
From: Alice <alice@example.com>
Subject: Hello

Hello.
"""

    headers = parse_email_headers(email)
    result = analyze_domain_mismatches(headers)

    assert result["reply_to_domain"] is None
    assert result["reply_to_mismatch"] is False


# ---------------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------------

def test_authentication_results():
    headers = parse_email_headers(SAMPLE_EMAIL)

    result = analyze_authentication(
        headers["authentication_results"]
    )

    assert result["spf"] == "fail"
    assert result["dkim"] == "pass"
    assert result["dmarc"] == "fail"


def test_authentication_fail_indicators():
    headers = parse_email_headers(SAMPLE_EMAIL)

    result = analyze_authentication(
        headers["authentication_results"]
    )

    assert "SPF result: fail" in result["indicators"]
    assert "DMARC result: fail" in result["indicators"]


def test_authentication_pass():
    auth_headers = [
        "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
    ]

    result = analyze_authentication(auth_headers)

    assert result["spf"] == "pass"
    assert result["dkim"] == "pass"
    assert result["dmarc"] == "pass"
    assert result["indicators"] == []


def test_missing_authentication_results():
    result = analyze_authentication([])

    assert result["spf"] is None
    assert result["dkim"] is None
    assert result["dmarc"] is None
    assert result["indicators"] == []


# ---------------------------------------------------------------------------
# Received / IP tests
# ---------------------------------------------------------------------------

def test_extract_received_ips():
    headers = parse_email_headers(SAMPLE_EMAIL)

    result = extract_ips_from_received(
        headers["received"]
    )

    ips = [item["ip"] for item in result]

    assert "192.168.1.10" in ips
    assert "203.0.113.50" in ips


def test_private_ip_detection():
    received_headers = [
        "from internal-host (192.168.1.20)"
    ]

    result = extract_ips_from_received(received_headers)

    assert len(result) == 1
    assert result[0]["ip"] == "192.168.1.20"
    assert result[0]["private"] is True


def test_duplicate_ips_are_removed():
    received_headers = [
        "from host1 (192.168.1.10)",
        "from host2 (192.168.1.10)",
    ]

    result = extract_ips_from_received(received_headers)

    ips = [item["ip"] for item in result]

    assert ips.count("192.168.1.10") == 1


# ---------------------------------------------------------------------------
# Complete analyzer tests
# ---------------------------------------------------------------------------

def test_complete_header_analysis():
    result = analyze_headers(SAMPLE_EMAIL)

    assert "headers" in result
    assert "domains" in result
    assert "authentication" in result
    assert "received_ips" in result
    assert "indicators" in result
    assert "indicator_count" in result

    assert result["authentication"]["spf"] == "fail"
    assert result["authentication"]["dmarc"] == "fail"

    assert result["domains"]["reply_to_mismatch"] is True
    assert result["domains"]["return_path_mismatch"] is True

    assert result["indicator_count"] >= 3


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------

def test_empty_email():
    with pytest.raises(ValueError):
        parse_email_headers("")


def test_whitespace_only_email():
    with pytest.raises(ValueError):
        parse_email_headers("   ")


def test_invalid_input_type():
    with pytest.raises(TypeError):
        parse_email_headers(None)


def test_malformed_address_does_not_crash():
    email = """\
From: this-is-not-a-valid-email
Subject: Test

Hello.
"""

    result = parse_email_headers(email)

    assert result["from"] is None