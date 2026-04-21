from urllib.parse import urlencode, urlparse

import requests


TEST_PAYLOADS = [
    ("sqli_probe", "' OR '1'='1"),
    ("xss_probe", "<script>alert(1)</script>"),
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
]


def _normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def _validate_url(url):
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


def scan_url(url):
    target = _normalize_url(url)
    if not _validate_url(target):
        return {"ok": False, "target": url, "error": "Invalid URL format."}

    findings = []
    checked_headers = {}
    recommendations = []

    try:
        response = requests.get(target, timeout=5, allow_redirects=True)
    except requests.RequestException as exc:
        return {
            "ok": False,
            "target": target,
            "error": f"Request failed: {exc}",
            "summary": "The scanner could not reach the target.",
        }

    for header in SECURITY_HEADERS:
        checked_headers[header] = response.headers.get(header, "Missing")
        if header not in response.headers:
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Missing security header: {header}",
                    "evidence": "Header absent in base response.",
                }
            )

    body_lower = response.text.lower()
    if "<form" in body_lower and "csrf" not in body_lower:
        findings.append(
            {
                "severity": "medium",
                "title": "Potential CSRF protection gap",
                "evidence": "HTML form detected without an obvious csrf marker in the page body.",
            }
        )

    for probe_name, payload in TEST_PAYLOADS:
        query = urlencode({"input": payload})
        test_url = f"{target.rstrip('/')}/?{query}"

        try:
            test_response = requests.get(test_url, timeout=5)
        except requests.RequestException:
            continue

        if payload in test_response.text:
            findings.append(
                {
                    "severity": "high",
                    "title": f"Reflected input observed during {probe_name}",
                    "evidence": f"Probe payload was reflected by {test_url}.",
                }
            )

    risk_score = min(100, len(findings) * 20)

    if not findings:
        recommendations.append("No obvious reflected-input or header issues were found in this light scan.")
    else:
        recommendations.append("Review server-side input handling and ensure output encoding is consistently applied.")
        recommendations.append("Add or validate key browser security headers across the application.")

    return {
        "ok": True,
        "target": target,
        "status_code": response.status_code,
        "risk_score": risk_score,
        "summary": "Lightweight web exposure scan completed.",
        "findings": findings,
        "headers": checked_headers,
        "recommendations": recommendations,
    }
