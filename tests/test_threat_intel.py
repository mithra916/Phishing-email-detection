import pytest

from src.threat_intel import (
    VirusTotalClient,
    ThreatIntelConfigurationError,
    ThreatIntelRequestError,
)


# ---------------------------------------------------------------------------
# Fake VirusTotal responses
# ---------------------------------------------------------------------------

MALICIOUS_DOMAIN_RESPONSE = {
    "data": {
        "id": "malicious-example.com",
        "type": "domain",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 3,
                "harmless": 75,
                "undetected": 10,
            },
            "reputation": -50,
            "tags": ["phishing", "malware"],
            "categories": {
                "Google Safebrowsing": "phishing",
            },
        },
    }
}


CLEAN_DOMAIN_RESPONSE = {
    "data": {
        "id": "example.com",
        "type": "domain",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 85,
                "undetected": 15,
            },
            "reputation": 100,
            "tags": [],
            "categories": {},
        },
    }
}


SUSPICIOUS_IP_RESPONSE = {
    "data": {
        "id": "203.0.113.50",
        "type": "ip_address",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 2,
                "suspicious": 5,
                "harmless": 60,
                "undetected": 20,
            },
            "reputation": -10,
            "tags": ["suspicious"],
            "categories": {},
        },
    }
}


EMPTY_RESPONSE = {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """
    Create a VirusTotal client using a fake API key.

    No real API request will be made.
    """

    return VirusTotalClient(
        api_key="fake-test-api-key"
    )


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------

def test_missing_api_key(monkeypatch):
    """
    Client should fail clearly when no API key is configured.
    """

    monkeypatch.delenv(
        "VIRUSTOTAL_API_KEY",
        raising=False,
    )

    with pytest.raises(ThreatIntelConfigurationError):
        VirusTotalClient()


def test_explicit_api_key():
    client = VirusTotalClient(
        api_key="test-key"
    )

    assert client.api_key == "test-key"
    assert client.headers["x-apikey"] == "test-key"


# ---------------------------------------------------------------------------
# Domain lookup tests
# ---------------------------------------------------------------------------

def test_malicious_domain(client, monkeypatch):
    """
    Malicious domain should be normalized correctly.
    """

    def fake_get(endpoint):
        assert endpoint == "domains/malicious-example.com"
        return MALICIOUS_DOMAIN_RESPONSE

    monkeypatch.setattr(
        client,
        "_get",
        fake_get,
    )

    result = client.lookup_domain(
        "malicious-example.com"
    )

    assert result["indicator"] == "malicious-example.com"
    assert result["type"] == "domain"
    assert result["found"] is True
    assert result["reputation"] == "malicious"
    assert result["malicious"] is True
    assert result["suspicious"] is True
    assert result["harmless"] is True
    assert result["reputation_score"] == -50
    assert "phishing" in result["tags"]


def test_clean_domain(client, monkeypatch):
    """
    Clean domain should be identified correctly.
    """

    def fake_get(endpoint):
        assert endpoint == "domains/example.com"
        return CLEAN_DOMAIN_RESPONSE

    monkeypatch.setattr(
        client,
        "_get",
        fake_get,
    )

    result = client.lookup_domain(
        "example.com"
    )

    assert result["found"] is True
    assert result["reputation"] == "harmless"
    assert result["malicious"] is False
    assert result["suspicious"] is False
    assert result["harmless"] is True


def test_domain_is_normalized(client, monkeypatch):
    """
    Domain input should be stripped and lowercased.
    """

    def fake_get(endpoint):
        assert endpoint == "domains/example.com"
        return CLEAN_DOMAIN_RESPONSE

    monkeypatch.setattr(
        client,
        "_get",
        fake_get,
    )

    result = client.lookup_domain(
        "  EXAMPLE.COM  "
    )

    assert result["indicator"] == "example.com"


def test_empty_domain(client):
    with pytest.raises(ValueError):
        client.lookup_domain("")


# ---------------------------------------------------------------------------
# IP lookup tests
# ---------------------------------------------------------------------------

def test_suspicious_ip(client, monkeypatch):
    """
    Suspicious/malicious IP response should be normalized.
    """

    def fake_get(endpoint):
        assert endpoint == "ip_addresses/203.0.113.50"
        return SUSPICIOUS_IP_RESPONSE

    monkeypatch.setattr(
        client,
        "_get",
        fake_get,
    )

    result = client.lookup_ip(
        "203.0.113.50"
    )

    assert result["indicator"] == "203.0.113.50"
    assert result["type"] == "ip"
    assert result["found"] is True
    assert result["reputation"] == "malicious"
    assert result["malicious"] is True


def test_invalid_ip(client):
    with pytest.raises(ValueError):
        client.lookup_ip(
            "not-an-ip"
        )


def test_empty_ip(client):
    with pytest.raises(ValueError):
        client.lookup_ip("")


# ---------------------------------------------------------------------------
# URL lookup tests
# ---------------------------------------------------------------------------

def test_url_id_generation(client):
    """
    URL ID should be generated in VirusTotal's URL-safe format.
    """

    url = "https://example.com/login"

    url_id = client._url_id(url)

    assert isinstance(url_id, str)
    assert "=" not in url_id
    assert "/" not in url_id
    assert "+" not in url_id


def test_url_lookup(client, monkeypatch):
    """
    URL lookup should use the generated URL identifier.
    """

    url = "https://example.com/login"

    expected_response = {
        "data": {
            "id": client._url_id(url),
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 50,
                    "undetected": 10,
                },
                "reputation": -20,
                "tags": ["phishing"],
                "categories": {
                    "Google Safebrowsing": "phishing",
                },
            },
        }
    }

    def fake_get(endpoint):
        assert endpoint.startswith("urls/")
        return expected_response

    monkeypatch.setattr(
        client,
        "_get",
        fake_get,
    )

    result = client.lookup_url(url)

    assert result["indicator"] == url
    assert result["type"] == "url"
    assert result["found"] is True
    assert result["reputation"] == "malicious"
    assert result["malicious"] is True


def test_empty_url(client):
    with pytest.raises(ValueError):
        client.lookup_url("")


# ---------------------------------------------------------------------------
# Unknown indicator tests
# ---------------------------------------------------------------------------

def test_indicator_not_found(client, monkeypatch):
    """
    404/empty VirusTotal response should not crash.
    """

    def fake_get(endpoint):
        return EMPTY_RESPONSE

    monkeypatch.setattr(
        client,
        "_get",
        fake_get,
    )

    result = client.lookup_domain(
        "unknown-domain.example"
    )

    assert result["found"] is False
    assert result["reputation"] == "unknown"
    assert result["malicious"] is False
    assert result["suspicious"] is False
    assert result["harmless"] is False


# ---------------------------------------------------------------------------
# HTTP error tests
# ---------------------------------------------------------------------------

def test_authentication_error(client, monkeypatch):
    """
    Authentication errors should become ThreatIntelRequestError.
    """

    def fake_get(endpoint):
        raise ThreatIntelRequestError(
            "VirusTotal API authentication failed."
        )

    monkeypatch.setattr(
        client,
        "_get",
        fake_get,
    )

    with pytest.raises(ThreatIntelRequestError):
        client.lookup_domain(
            "example.com"
        )


def test_request_error(client, monkeypatch):
    """
    Network/API errors should propagate as ThreatIntelRequestError.
    """

    def fake_get(endpoint):
        raise ThreatIntelRequestError(
            "VirusTotal request failed."
        )

    monkeypatch.setattr(
        client,
        "_get",
        fake_get,
    )

    with pytest.raises(ThreatIntelRequestError):
        client.lookup_ip(
            "8.8.8.8"
        )