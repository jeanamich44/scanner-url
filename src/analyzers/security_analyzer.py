from typing import Any, Dict, List

# --------------------------------------------------

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy"
]

# --------------------------------------------------

def analyze_security(headers: Dict[str, str], cookies: List[Dict[str, Any]], is_https: bool) -> Dict[str, Any]:
    norm_headers = {k.lower(): v for k, v in headers.items()}

    present_headers: Dict[str, str] = {}
    missing_headers: List[str] = []

    for h in SECURITY_HEADERS:
        if h in norm_headers:
            present_headers[h] = norm_headers[h]
        else:
            missing_headers.append(h)

    score = 100

    if not is_https:
        score -= 30

    for h in missing_headers:
        if h == "strict-transport-security" and is_https:
            score -= 15
        elif h == "content-security-policy":
            score -= 20
        elif h in ["x-frame-options", "x-content-type-options"]:
            score -= 10
        elif h in ["referrer-policy", "permissions-policy"]:
            score -= 5
        else:
            score -= 5

    cookie_analysis: List[Dict[str, Any]] = []
    for c in cookies:
        name = c.get("name", "")
        secure = c.get("secure", False)
        httponly = c.get("httponly", False)
        samesite = c.get("samesite", "")

        issues: List[str] = []
        if is_https and not secure:
            issues.append("Missing Secure flag")
            score -= 5
        if not httponly:
            issues.append("Missing HttpOnly flag")
            score -= 5
        if not samesite:
            issues.append("Missing SameSite attribute")
            score -= 3

        cookie_analysis.append({
            "name": name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "issues": issues
        })

    score = max(0, min(100, score))

    grade = "F"
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "is_https": is_https,
        "present_headers": present_headers,
        "missing_headers": missing_headers,
        "cookies_audit": cookie_analysis
    }
