"""Security header checks and plain-language recommendations."""

HEADER_RULES = {
    "Content-Security-Policy": {
        "description": "Helps restrict the sources from which a page can load content.",
        "recommendation": "Define a restrictive Content-Security-Policy suited to the application.",
        "severity": "high",
    },
    "Strict-Transport-Security": {
        "description": "Tells browsers to use HTTPS for future connections.",
        "recommendation": "Enable HSTS after confirming the entire site works over HTTPS.",
        "severity": "high",
    },
    "X-Content-Type-Options": {
        "description": "Helps prevent MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options: nosniff.",
        "severity": "medium",
    },
    "X-Frame-Options": {
        "description": "Provides legacy protection against clickjacking in frames.",
        "recommendation": "Set DENY or SAMEORIGIN, or use CSP frame-ancestors.",
        "severity": "medium",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information browsers send.",
        "recommendation": "Choose a policy such as strict-origin-when-cross-origin.",
        "severity": "low",
    },
    "Permissions-Policy": {
        "description": "Controls access to browser features and APIs.",
        "recommendation": "Disable browser features that the application does not need.",
        "severity": "low",
    },
}

def analyze_headers(response_headers: dict) -> dict:
    normalized = {str(k).lower(): str(v) for k, v in response_headers.items()}
    results = []
    for name, rule in HEADER_RULES.items():
        value = normalized.get(name.lower())
        results.append({
            "header": name,
            "present": value is not None,
            "value": value,
            "severity": rule["severity"],
            "description": rule["description"],
            "recommendation": None if value is not None else rule["recommendation"],
        })
    total = len(results)
    present = sum(item["present"] for item in results)
    score = round((present / total) * 100) if total else 0
    return {
        "score": score,
        "present_count": present,
        "total_count": total,
        "checks": results,
    }
