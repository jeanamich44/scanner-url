import json
import random
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from curl_cffi.requests import AsyncSession
from src.core.browser_profiles import get_browser_profile

# --------------------------------------------------

ENDPOINTS_PATH = Path(__file__).resolve().parents[2] / "endpoints.json"
if not ENDPOINTS_PATH.exists():
    ENDPOINTS_PATH = Path(__file__).resolve().parents[3] / "endpoints.json"
if not ENDPOINTS_PATH.exists():
    ENDPOINTS_PATH = Path(r"C:\Users\cuba\Desktop\Pas Touche\Programmation\Creation\endpoints.json")

# --------------------------------------------------

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1", "X-Custom-IP-Authorization": "127.0.0.1", "X-Forwarded-Host": "localhost"},
    {"X-Forwarded-For": "::1", "X-Remote-IP": "127.0.0.1", "X-Host": "localhost"},
    {"Client-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1", "CF-Connecting-IP": "127.0.0.1"},
]

# --------------------------------------------------

PATH_MUTATIONS = [
    lambda p: p + "/",
    lambda p: p + "/.",
    lambda p: "/" + p.lstrip("/").replace("/", "//"),
    lambda p: p + "%20",
    lambda p: p + "?",
    lambda p: p + "%00",
    lambda p: p.upper(),
    lambda p: "/" + p.lstrip("/").replace("/", "/./"),
]

# --------------------------------------------------

SENSITIVE_PATTERNS = [
    re.compile(r"(password|passwd|pwd)\s*[:=]", re.IGNORECASE),
    re.compile(r"(api[_-]?key|apikey|secret[_-]?key)\s*[:=]", re.IGNORECASE),
    re.compile(r"(access[_-]?token|auth[_-]?token|bearer)\s*[:=]", re.IGNORECASE),
    re.compile(r"(aws_access_key_id|aws_secret_access_key)", re.IGNORECASE),
    re.compile(r"(database_url|db_password|db_host|mongodb)", re.IGNORECASE),
    re.compile(r"(private[_-]?key|ssh-rsa|BEGIN RSA)", re.IGNORECASE),
    re.compile(r"(smtp_password|mail_password|sendgrid)", re.IGNORECASE),
    re.compile(r"\[core\]\s*\n\s*repositoryformatversion", re.IGNORECASE),
    re.compile(r"(client_secret|client_id)\s*[:=]", re.IGNORECASE),
]

# --------------------------------------------------

def load_endpoints(path: Optional[Path] = None, top_n: Optional[int] = None) -> List[Dict[str, Any]]:
    p = path or ENDPOINTS_PATH
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    eps = data.get("endpoints", [])
    if top_n and top_n > 0:
        eps = eps[:top_n]
    return eps

# --------------------------------------------------

def _check_sensitive(body: str) -> List[str]:
    found = []
    for pat in SENSITIVE_PATTERNS:
        if pat.search(body):
            found.append(pat.pattern)
    return found

# --------------------------------------------------

def _classify(status: int, cl: int, sensitive: List[str], ct: str) -> str:
    if sensitive and status == 200:
        return "critical"
    if status == 200 and cl > 0:
        ct_l = ct.lower()
        if any(t in ct_l for t in ["json", "xml", "text/plain", "application/octet", "yaml"]):
            return "high"
        return "medium"
    if status in (301, 302, 307, 308):
        return "info"
    if status in (401, 403):
        return "low"
    if status == 405:
        return "info"
    if status >= 500:
        return "medium"
    return "info"

# --------------------------------------------------

def _analyze_resp(resp) -> Dict[str, Any]:
    status = resp.status_code
    ct = resp.headers.get("content-type", "")
    body = ""
    cl = 0
    try:
        body = resp.text
        cl = len(resp.content)
    except Exception:
        cl = int(resp.headers.get("content-length", 0))
    sens = _check_sensitive(body) if body else []
    sev = _classify(status, cl, sens, ct)
    return {
        "status": status,
        "content_length": cl,
        "content_type": ct,
        "severity": sev,
        "sensitive_data": sens,
        "accessible": status in (200, 201, 202, 204) and cl > 0,
    }

# --------------------------------------------------

async def probe_fast(
    session: AsyncSession,
    base_url: str,
    endpoint: str,
    score: int,
    timeout: float,
    use_bypass: bool,
    use_mutations: bool,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "endpoint": endpoint,
        "score": score,
        "status": None,
        "severity": "none",
        "accessible": False,
        "content_length": 0,
        "content_type": "",
        "response_time_ms": 0,
        "sensitive_data": [],
    }

    url = base_url.rstrip("/") + endpoint
    if headers:
        hdrs = dict(headers)
    else:
        _, hdrs = get_browser_profile("chrome")

    try:
        t0 = time.time()
        resp = await session.get(url, headers=hdrs, timeout=timeout, allow_redirects=False)
        result["response_time_ms"] = round((time.time() - t0) * 1000, 1)
        status = resp.status_code
        result["status"] = status

        if status == 404:
            return result

        if status in (200, 201, 202, 204):
            info = _analyze_resp(resp)
            result.update(info)
            return result

        if status in (301, 302, 307, 308):
            result["severity"] = "info"
            return result

        if status in (401, 403):
            result["severity"] = "low"

            if use_bypass:
                for bh in BYPASS_HEADERS:
                    try:
                        resp2 = await session.get(url, headers={**hdrs, **bh}, timeout=timeout, allow_redirects=False)
                        if resp2.status_code in (200, 201, 202):
                            result.update(_analyze_resp(resp2))
                            return result
                    except Exception:
                        pass

            if use_mutations:
                for mutate in PATH_MUTATIONS[:4]:
                    try:
                        mut_url = base_url.rstrip("/") + mutate(endpoint)
                        resp3 = await session.get(mut_url, headers=hdrs, timeout=timeout, allow_redirects=False)
                        if resp3.status_code in (200, 201, 202):
                            result.update(_analyze_resp(resp3))
                            return result
                    except Exception:
                        pass

            return result

        if status >= 500:
            result["severity"] = "medium"

        return result

    except Exception:
        return result
