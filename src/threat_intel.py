"""
BodWid - Threat Intelligence

Provides threat-intelligence lookups for:
- IP addresses
- Domains
- URLs

Current provider:
- VirusTotal

The module returns normalized results so the rest of BodWid does not
depend directly on a specific threat-intelligence provider.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ThreatIntelError(Exception):
    """Base exception for threat-intelligence errors."""


class ThreatIntelConfigurationError(ThreatIntelError):
    """Raised when threat-intelligence configuration is missing."""


class ThreatIntelRequestError(ThreatIntelError):
    """Raised when the threat-intelligence provider cannot be reached."""


# ---------------------------------------------------------------------------
# VirusTotal client
# ---------------------------------------------------------------------------

class VirusTotalClient:
    """
    Small VirusTotal API client.

    The API key is read from the VIRUSTOTAL_API_KEY environment variable.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:

        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.timeout = timeout

        if not self.api_key:
            raise ThreatIntelConfigurationError(
                "VIRUSTOTAL_API_KEY environment variable is not configured."
            )

        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    # -----------------------------------------------------------------------
    # Internal request method
    # -----------------------------------------------------------------------

    def _get(self, endpoint: str) -> Dict[str, Any]:
        """
        Perform a GET request against VirusTotal.
        """

        url = f"{VIRUSTOTAL_BASE_URL}/{endpoint.lstrip('/')}"

        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise ThreatIntelRequestError(
                f"VirusTotal request failed: {exc}"
            ) from exc

        if response.status_code == 404:
            return {}

        if response.status_code == 401:
            raise ThreatIntelRequestError(
                "VirusTotal API authentication failed."
            )

        if response.status_code == 429:
            raise ThreatIntelRequestError(
                "VirusTotal API rate limit reached."
            )

        if not response.ok:
            raise ThreatIntelRequestError(
                f"VirusTotal API returned HTTP {response.status_code}."
            )

        try:
            return response.json()
        except ValueError as exc:
            raise ThreatIntelRequestError(
                "VirusTotal returned invalid JSON."
            ) from exc

    # -----------------------------------------------------------------------
    # Generic object lookup
    # -----------------------------------------------------------------------

    def _lookup_object(
        self,
        object_type: str,
        identifier: str,
    ) -> Dict[str, Any]:
        """
        Retrieve a VirusTotal object.

        Examples:
            domain/example.com
            ip_addresses/8.8.8.8
            urls/<sha256>
        """

        endpoint = f"{object_type}/{identifier}"

        response = self._get(endpoint)

        if not response:
            return {}

        return response.get("data", {})

    # -----------------------------------------------------------------------
    # Domain lookup
    # -----------------------------------------------------------------------

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Look up a domain in VirusTotal.
        """

        domain = domain.strip().lower()

        if not domain:
            raise ValueError("domain cannot be empty")

        object_data = self._lookup_object(
            "domains",
            quote(domain, safe=""),
        )

        return self._normalize_result(
            indicator=domain,
            indicator_type="domain",
            object_data=object_data,
        )

    # -----------------------------------------------------------------------
    # IP lookup
    # -----------------------------------------------------------------------

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address in VirusTotal.
        """

        ip = ip.strip()

        if not ip:
            raise ValueError("ip cannot be empty")

        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc

        object_data = self._lookup_object(
            "ip_addresses",
            quote(ip, safe=":"),
        )

        return self._normalize_result(
            indicator=ip,
            indicator_type="ip",
            object_data=object_data,
        )

    # -----------------------------------------------------------------------
    # URL lookup
    # -----------------------------------------------------------------------

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """
        Look up a URL in VirusTotal.

        VirusTotal identifies URL objects using a URL-safe SHA-256-like
        identifier generated from the URL representation.
        """

        url = url.strip()

        if not url:
            raise ValueError("url cannot be empty")

        url_id = self._url_id(url)

        object_data = self._lookup_object(
            "urls",
            url_id,
        )

        return self._normalize_result(
            indicator=url,
            indicator_type="url",
            object_data=object_data,
        )

    @staticmethod
    def _url_id(url: str) -> str:
        """
        Generate the VirusTotal URL object identifier.
        """

        return hashlib.sha256(
            url.encode("utf-8")
        ).hexdigest()

    # -----------------------------------------------------------------------
    # Result normalization
    # -----------------------------------------------------------------------

    @staticmethod
    def _normalize_result(
        indicator: str,
        indicator_type: str,
        object_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Convert a VirusTotal response into a provider-independent format.
        """

        if not object_data:
            return {
                "indicator": indicator,
                "type": indicator_type,
                "found": False,
                "reputation": "unknown",
                "malicious": False,
                "suspicious": False,
                "harmless": False,
                "stats": {},
                "reputation_score": None,
                "tags": [],
                "categories": {},
            }

        attributes = object_data.get("attributes", {})

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        malicious_count = int(
            stats.get("malicious", 0)
        )

        suspicious_count = int(
            stats.get("suspicious", 0)
        )

        harmless_count = int(
            stats.get("harmless", 0)
        )

        # Determine normalized reputation.
        if malicious_count > 0:
            reputation = "malicious"
        elif suspicious_count > 0:
            reputation = "suspicious"
        elif harmless_count > 0:
            reputation = "harmless"
        else:
            reputation = "unknown"

        return {
            "indicator": indicator,
            "type": indicator_type,
            "found": True,
            "reputation": reputation,
            "malicious": malicious_count > 0,
            "suspicious": suspicious_count > 0,
            "harmless": harmless_count > 0,
            "stats": stats,
            "reputation_score": attributes.get("reputation"),
            "tags": attributes.get("tags", []),
            "categories": attributes.get("categories", {}),
        }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def create_threat_intel_client() -> VirusTotalClient:
    """
    Create a configured VirusTotal client.
    """

    return VirusTotalClient()


def lookup_domain(
    domain: str,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function for domain lookup.
    """

    client = VirusTotalClient(api_key=api_key)

    return client.lookup_domain(domain)


def lookup_ip(
    ip: str,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function for IP lookup.
    """

    client = VirusTotalClient(api_key=api_key)

    return client.lookup_ip(ip)


def lookup_url(
    url: str,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function for URL lookup.
    """

    client = VirusTotalClient(api_key=api_key)

    return client.lookup_url(url)