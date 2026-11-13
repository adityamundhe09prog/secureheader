import pytest
from secureheader.scanner import normalize_url

def test_adds_https_when_scheme_missing():
    assert normalize_url("example.com") == "https://example.com"

def test_accepts_http_and_https():
    assert normalize_url("http://example.com").startswith("http://")
    assert normalize_url("https://example.com").startswith("https://")

@pytest.mark.parametrize("value", ["", "ftp://example.com", "https://"])
def test_rejects_invalid_urls(value):
    with pytest.raises(ValueError):
        normalize_url(value)

def test_rejects_embedded_credentials():
    with pytest.raises(ValueError):
        normalize_url("https://user:pass@example.com")
