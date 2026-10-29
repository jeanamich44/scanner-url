import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from curl_cffi import requests
from src.analyzers import inspect_dns, inspect_ssl, analyze_security, detect_technologies
from src.core.browser_profiles import get_browser_profile
from src.core.proxy_manager import format_proxy_line

# --------------------------------------------------

class UrlScanner:
    def __init__(self, timeout: float = 12.0, max_redirects: int = 10, browser: str = "chrome", proxy: Optional[str] = None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.browser = browser
        self.proxy = format_proxy_line(proxy) if proxy else None

    # --------------------------------------------------

    def _normalize_url(self, raw_url: str) -> str:
        trimmed = raw_url.strip()
        if not re.match(r"^https?://", trimmed, re.IGNORECASE):
            trimmed = "https://" + trimmed
        return trimmed

    # --------------------------------------------------

    def _parse_cookie_header(self, raw_cookie: str) -> Dict[str, Any]:
        parts = [p.strip() for p in raw_cookie.split(";")]
        name_val = parts[0] if parts else ""
        name = name_val.split("=")[0] if "=" in name_val else name_val
        lower_raw = raw_cookie.lower()

        secure = "secure" in lower_raw
        httponly = "httponly" in lower_raw
        samesite = ""
        m = re.search(r"samesite=([a-zA-Z]+)", lower_raw)
        if m:
            samesite = m.group(1)

        return {
            "name": name,
            "raw": raw_cookie,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite
        }

    # --------------------------------------------------

    def _extract_page_content(self, html_text: str, current_url: str) -> Dict[str, Any]:
        soup = BeautifulSoup(html_text, "html.parser")
        parsed_current = urlparse(current_url)
        current_domain = parsed_current.netloc.lower()

        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else ""

        meta_data: Dict[str, str] = {}
        og_data: Dict[str, str] = {}
        twitter_data: Dict[str, str] = {}

        for meta in soup.find_all("meta"):
            name = meta.get("name", "").lower()
            prop = meta.get("property", "").lower()
            content = meta.get("content", "")

            if name in ["description", "keywords", "robots", "author", "viewport"]:
                meta_data[name] = content
            elif prop.startswith("og:"):
                og_data[prop] = content
            elif name.startswith("twitter:"):
                twitter_data[name] = content

        canonical_link = ""
        canonical_tag = soup.find("link", rel=lambda x: x and "canonical" in x)
        if canonical_tag and canonical_tag.get("href"):
            canonical_link = urljoin(current_url, canonical_tag.get("href"))

        favicon_link = ""
        favicon_tag = soup.find("link", rel=lambda x: x and any(i in x for i in ["icon", "shortcut icon"]))
        if favicon_tag and favicon_tag.get("href"):
            favicon_link = urljoin(current_url, favicon_tag.get("href"))

        h1_tags = [h.get_text(strip=True) for h in soup.find_all("h1")]
        h2_count = len(soup.find_all("h2"))
        h3_count = len(soup.find_all("h3"))

        all_links = soup.find_all("a", href=True)
        internal_links: List[str] = []
        external_links: List[str] = []

        for a in all_links:
            href = a.get("href", "").strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full_link = urljoin(current_url, href)
            p = urlparse(full_link)
            if p.netloc.lower() == current_domain or not p.netloc:
                internal_links.append(full_link)
            else:
                external_links.append(full_link)

        images = soup.find_all("img")
        scripts = soup.find_all("script")
        stylesheets = soup.find_all("link", rel=lambda x: x and "stylesheet" in x)
        iframes = soup.find_all("iframe")
        forms = soup.find_all("form")
        inputs = soup.find_all("input")

        mixed_content: List[str] = []
        if current_url.lower().startswith("https://"):
            for tag in scripts + images + stylesheets + iframes:
                src = tag.get("src") or tag.get("href")
                if src and src.strip().lower().startswith("http://"):
                    mixed_content.append(src.strip())

        return {
            "title": title,
            "meta": meta_data,
            "open_graph": og_data,
            "twitter_card": twitter_data,
            "canonical": canonical_link,
            "favicon": favicon_link,
            "headings": {
                "h1": h1_tags,
                "h2_count": h2_count,
                "h3_count": h3_count
            },
            "links": {
                "total": len(all_links),
                "internal_count": len(internal_links),
                "external_count": len(external_links),
                "sample_internal": internal_links[:10],
                "sample_external": external_links[:10]
            },
            "assets": {
                "images_count": len(images),
                "scripts_count": len(scripts),
                "stylesheets_count": len(stylesheets),
                "iframes_count": len(iframes),
                "forms_count": len(forms),
                "inputs_count": len(inputs)
            },
            "mixed_content": mixed_content
        }

    # --------------------------------------------------

    def scan(self, raw_url: str) -> Dict[str, Any]:
        start_time = time.time()
        initial_url = self._normalize_url(raw_url)
        parsed_initial = urlparse(initial_url)
        initial_hostname = parsed_initial.hostname or ""

        redirect_chain: List[Dict[str, Any]] = []
        current_url = initial_url
        final_response = None
        error_msg = None

        impersonate_val, base_headers = get_browser_profile(self.browser)
        proxy_arg = {"proxy": self.proxy} if self.proxy else {}
        session = requests.Session(impersonate=impersonate_val, **proxy_arg)

        for _ in range(self.max_redirects):
            try:
                res = session.get(
                    current_url,
                    headers=base_headers,
                    allow_redirects=False,
                    timeout=self.timeout
                )
                status = res.status_code
                loc = res.headers.get("location")

                hop = {
                    "url": current_url,
                    "status_code": status,
                    "headers": dict(res.headers)
                }
                redirect_chain.append(hop)

                if status in (301, 302, 303, 307, 308) and loc:
                    next_url = urljoin(current_url, loc)
                    current_url = next_url
                    continue
                else:
                    final_response = res
                    break
            except Exception as e:
                error_msg = str(e)
                break

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        final_url = current_url
        parsed_final = urlparse(final_url)
        final_hostname = parsed_final.hostname or initial_hostname
        is_https = parsed_final.scheme.lower() == "https"

        dns_data = inspect_dns(final_hostname)
        ssl_data = inspect_ssl(final_hostname) if is_https else {"enabled": False, "valid": False}

        headers_dict: Dict[str, str] = {}
        cookies_list: List[Dict[str, Any]] = []
        html_analysis: Dict[str, Any] = {}
        tech_list: List[str] = []
        status_code = None
        content_type = ""
        content_length = 0

        if final_response is not None:
            status_code = final_response.status_code
            headers_dict = dict(final_response.headers)
            content_type = headers_dict.get("content-type", "")
            content_length = len(final_response.content)

            raw_cookies = final_response.headers.get_list("set-cookie") if hasattr(final_response.headers, "get_list") else []
            for c_str in raw_cookies:
                cookies_list.append(self._parse_cookie_header(c_str))

            body_str = final_response.text
            tech_list = detect_technologies(headers_dict, body_str)
            html_analysis = self._extract_page_content(body_str, final_url)

        security_data = analyze_security(headers_dict, cookies_list, is_https)

        ip_regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        is_ip_host = bool(re.match(ip_regex, final_hostname))

        risk_indicators: List[str] = []
        if not is_https:
            risk_indicators.append("Connexion non sécurisée (HTTP clair)")
        if is_ip_host:
            risk_indicators.append("Nom d'hôte résolu directement en IP (suspect)")
        if ssl_data.get("enabled") and not ssl_data.get("valid"):
            risk_indicators.append(f"Certificat SSL invalide : {ssl_data.get('error')}")
        if html_analysis.get("mixed_content"):
            risk_indicators.append(f"Contenu mixte détecté ({len(html_analysis['mixed_content'])} ressources)")
        if status_code and status_code >= 400:
            risk_indicators.append(f"Code HTTP d'erreur : {status_code}")

        return {
            "initial_url": initial_url,
            "final_url": final_url,
            "status_code": status_code,
            "is_reachable": final_response is not None and error_msg is None,
            "error": error_msg,
            "response_time_ms": elapsed_ms,
            "redirect_count": max(0, len(redirect_chain) - 1),
            "redirect_chain": redirect_chain,
            "headers": headers_dict,
            "content_info": {
                "content_type": content_type,
                "content_length_bytes": content_length
            },
            "security": security_data,
            "technologies": tech_list,
            "page_details": html_analysis,
            "ssl": ssl_data,
            "dns": dns_data,
            "risk_indicators": risk_indicators
        }
