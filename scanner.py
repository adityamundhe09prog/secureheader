from urllib.parse import urlparse
import requests

DEFAULT_TIMEOUT = 10
USER_AGENT = "SecureHeader/1.0 (+https://github.com/yourusername/secureheader)"

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported")
    return value

def fetch_headers(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    normalized = normalize_url(url)
    response = requests.get(
        normalized,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        stream=True,
    )
    try:
        return {
            "requested_url": normalized,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
        }
    finally:
        response.close()
