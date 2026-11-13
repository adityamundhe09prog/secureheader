from secureheader.headers import analyze_headers

def test_all_headers_present_scores_100():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    }
    result = analyze_headers(headers)
    assert result["score"] == 100
    assert result["present_count"] == 6

def test_missing_headers_are_reported():
    result = analyze_headers({})
    assert result["score"] == 0
    assert result["present_count"] == 0
    assert all(not item["present"] for item in result["checks"])

def test_header_matching_is_case_insensitive():
    result = analyze_headers({"content-security-policy": "default-src 'self'"})
    csp = next(item for item in result["checks"] if item["header"] == "Content-Security-Policy")
    assert csp["present"] is True
