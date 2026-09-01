import pytest

from src.url_analyzer import (
    extract_urls,
    analyze_url,
    analyze_urls,
)


def test_extract_single_url():
    result = extract_urls(
        "Please visit https://example.com/login"
    )

    assert result == [
        "https://example.com/login"
    ]


def test_extract_multiple_urls():
    result = extract_urls(
        """
        Visit https://example.com
        or https://example.org/login
        """
    )

    assert len(result) == 2


def test_duplicate_urls_are_removed():
    result = extract_urls(
        """
        https://example.com/login
        https://example.com/login
        """
    )

    assert len(result) == 1


def test_url_trailing_punctuation_is_removed():
    result = extract_urls(
        "Visit https://example.com/login."
    )

    assert result == [
        "https://example.com/login"
    ]


def test_empty_email():
    result = extract_urls("")

    assert result == []


def test_whitespace_email():
    result = extract_urls("   ")

    assert result == []


def test_invalid_input_type():
    with pytest.raises(TypeError):
        extract_urls(None)


def test_analyze_url():
    result = analyze_url(
        "https://example.com/login?user=test"
    )

    assert result["url"] == "https://example.com/login?user=test"
    assert result["domain"] == "example.com"
    assert result["scheme"] == "https"
    assert result["uses_https"] is True
    assert result["has_path"] is True
    assert result["has_query"] is True


def test_shortened_url_detection():
    result = analyze_url(
        "https://bit.ly/verify-account"
    )

    assert result["domain"] == "bit.ly"
    assert result["shortened"] is True


def test_normal_url_is_not_shortened():
    result = analyze_url(
        "https://example.com/login"
    )

    assert result["shortened"] is False


def test_subdomain_shortener_detection():
    result = analyze_url(
        "https://sub.bit.ly/test"
    )

    assert result["shortened"] is True


def test_empty_url():
    with pytest.raises(ValueError):
        analyze_url("")


def test_complete_url_analysis():
    result = analyze_urls(
        """
        Visit https://example.com/login
        Backup: https://bit.ly/verify
        Also visit http://example.org
        """
    )

    assert result["url_count"] == 3
    assert result["domain_count"] == 3
    assert result["shortened_url_count"] == 1
    assert result["shortened_urls_present"] is True
    assert result["https_count"] == 2
    assert result["http_count"] == 1


def test_same_domain_multiple_urls():
    result = analyze_urls(
        """
        https://example.com/login
        https://example.com/reset
        """
    )

    assert result["url_count"] == 2
    assert result["domain_count"] == 1
    assert result["domains"] == ["example.com"]


def test_no_urls():
    result = analyze_urls(
        "This is a normal email without any links."
    )

    assert result["url_count"] == 0
    assert result["domain_count"] == 0
    assert result["shortened_url_count"] == 0
    assert result["shortened_urls_present"] is False