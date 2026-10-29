import random
from typing import Dict, Optional, Tuple

# --------------------------------------------------

CHROME_IMPERSONATE = "chrome146"
FIREFOX_IMPERSONATE = "firefox147"
SAFARI_IMPERSONATE = "safari18_0"

# --------------------------------------------------

CHROME_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Sec-Ch-Ua": '"Chromium";v="146", "Google Chrome";v="146", "Not-A.Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "Priority": "u=0, i"
}

# --------------------------------------------------

FIREFOX_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Te": "trailers",
    "Priority": "u=0, i"
}

# --------------------------------------------------

SAFARI_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Priority": "u=0, i"
}

# --------------------------------------------------

PROFILES = {
    "chrome": (CHROME_IMPERSONATE, CHROME_HEADERS),
    "firefox": (FIREFOX_IMPERSONATE, FIREFOX_HEADERS),
    "safari": (SAFARI_IMPERSONATE, SAFARI_HEADERS)
}

# --------------------------------------------------

FORBIDDEN_NON_CHROMIUM = {
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version-list"
}

# --------------------------------------------------

def sanitize_headers(headers: Dict[str, str], browser_key: str) -> Dict[str, str]:
    b = browser_key.strip().lower()
    cleaned = dict(headers)
    if b in ["firefox", "safari"]:
        for k in list(cleaned.keys()):
            if k.lower() in FORBIDDEN_NON_CHROMIUM:
                del cleaned[k]
        if b == "safari" and "upgrade-insecure-requests" in {k.lower() for k in cleaned.keys()}:
            for k in list(cleaned.keys()):
                if k.lower() == "upgrade-insecure-requests":
                    del cleaned[k]
    return cleaned

# --------------------------------------------------

def get_browser_profile(browser_name: str = "chrome") -> Tuple[str, Dict[str, str]]:
    key = browser_name.strip().lower()
    if key == "random":
        key = random.choice(["chrome", "firefox", "safari"])
    if key not in PROFILES:
        key = "chrome"
    impersonate_val, headers_template = PROFILES[key]
    return impersonate_val, sanitize_headers(dict(headers_template), key)

# --------------------------------------------------

def build_request_headers(base_headers: Dict[str, str], extra_headers: Optional[Dict[str, str]] = None, browser: str = "chrome") -> Dict[str, str]:
    merged = dict(base_headers)
    if extra_headers:
        merged.update(extra_headers)
    return sanitize_headers(merged, browser)
