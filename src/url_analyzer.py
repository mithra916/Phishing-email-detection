"""
BodWid - URL Analyzer

Extracts and analyzes URLs found in email content.

This module:
- Extracts HTTP/HTTPS URLs
- Removes duplicates
- Extracts URL domains
- Detects commonly shortened URLs
- Identifies basic URL characteristics

This module does NOT determine whether a URL is malicious.
Threat intelligence is handled separately by threat_intel.py.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# URL patterns
# ---------------------------------------------------------------------------

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"()]+",
    re.IGNORECASE,
)


# Common URL-shortening services.
# This is only a heuristic; it does not mean the URL is malicious.
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "rebrand.ly",
    "tiny.cc",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_url(url: str) -> str:
    """
    Remove punctuation commonly attached to URLs in email text.
    """

    return url.rstrip(".,;:!?)]}")


def _normalize_domain(domain: str) -> str:
    """Normalize a URL domain."""

    return domain.lower().strip().rstrip(".")


def _is_shortened_domain(domain: str) -> bool:
    """
    Determine whether a domain belongs to a known URL shortener.
    """

    domain = _normalize_domain(domain)

    if domain in SHORTENER_DOMAINS:
        return True

    return any(
        domain.endswith("." + shortener)
        for shortener in SHORTENER_DOMAINS
    )


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

def extract_urls(email_text: str) -> List[str]:
    """
    Extract unique HTTP/HTTPS URLs from email text.

    Args:
        email_text: Email body or complete email text.

    Returns:
        List of unique URLs.
    """

    if not isinstance(email_text, str):
        raise TypeError("email_text must be a string")

    if not email_text.strip():
        return []

    matches = URL_PATTERN.findall(email_text)

    urls = []
    seen = set()

    for raw_url in matches:

        url = _clean_url(raw_url)

        if not url:
            continue

        normalized = url.lower()

        if normalized in seen:
            continue

        seen.add(normalized)
        urls.append(url)

    return urls


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> Dict[str, Any]:
    """
    Analyze a single URL.

    This performs structural analysis only.
    It does not contact external services.
    """

    if not isinstance(url, str):
        raise TypeError("url must be a string")

    url = url.strip()

    if not url:
        raise ValueError("url cannot be empty")

    parsed = urlparse(url)

    domain = _normalize_domain(parsed.hostname or "")

    path = parsed.path or ""

    query = parsed.query or ""

    shortened = _is_shortened_domain(domain)

    return {
        "url": url,
        "domain": domain,
        "scheme": parsed.scheme.lower(),
        "path": path,
        "query": query,
        "shortened": shortened,
        "has_query": bool(query),
        "has_path": bool(path),
        "uses_https": parsed.scheme.lower() == "https",
    }


# ---------------------------------------------------------------------------
# Complete URL analysis
# ---------------------------------------------------------------------------

def analyze_urls(email_text: str) -> Dict[str, Any]:
    """
    Extract and analyze all URLs in an email.

    Returns structured URL evidence.
    """

    urls = extract_urls(email_text)

    analyzed_urls = [
        analyze_url(url)
        for url in urls
    ]

    shortened_count = sum(
        1
        for url_data in analyzed_urls
        if url_data["shortened"]
    )

    https_count = sum(
        1
        for url_data in analyzed_urls
        if url_data["uses_https"]
    )

    http_count = len(analyzed_urls) - https_count

    domains = []
    seen_domains = set()

    for url_data in analyzed_urls:

        domain = url_data["domain"]

        if not domain:
            continue

        if domain in seen_domains:
            continue

        seen_domains.add(domain)
        domains.append(domain)

    return {
        "urls": analyzed_urls,
        "url_count": len(analyzed_urls),
        "domains": domains,
        "domain_count": len(domains),
        "shortened_url_count": shortened_count,
        "http_count": http_count,
        "https_count": https_count,
        "shortened_urls_present": shortened_count > 0,
    }


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    sample_email = """
    Please verify your account:

    https://example.com/login

    Backup link:
    https://bit.ly/verify-account

    Thank you.
    """

    from pprint import pprint

    pprint(analyze_urls(sample_email))