import re
from typing import Any, Dict, List

# --------------------------------------------------

def detect_technologies(headers: Dict[str, str], body_text: str) -> List[str]:
    techs: List[str] = []
    norm_headers = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body_text.lower()

    server = norm_headers.get("server", "")
    if "nginx" in server:
        techs.append("Nginx")
    if "apache" in server:
        techs.append("Apache")
    if "cloudflare" in server or "cf-ray" in norm_headers:
        techs.append("Cloudflare")
    if "caddy" in server:
        techs.append("Caddy")
    if "litespeed" in server:
        techs.append("LiteSpeed")
    if "microsoft-iis" in server:
        techs.append("Microsoft-IIS")
    if "gws" in server or "esf" in server:
        techs.append("Google Web Server")

    x_powered = norm_headers.get("x-powered-by", "")
    if "php" in x_powered or "phpsessid" in norm_headers.get("set-cookie", ""):
        techs.append("PHP")
    if "express" in x_powered:
        techs.append("Express.js")
    if "asp.net" in x_powered:
        techs.append("ASP.NET")
    if "next.js" in x_powered or "__next" in body_lower or "/_next/static/" in body_lower:
        techs.append("Next.js")
    if "nuxt" in x_powered or "__nuxt" in body_lower or "/_nuxt/" in body_lower:
        techs.append("Nuxt.js")

    if "wp-content/" in body_lower or "wp-includes/" in body_lower:
        techs.append("WordPress")
    if "cdn.shopify.com" in body_lower or "shopify.theme" in body_lower:
        techs.append("Shopify")
    if 'content="drupal' in body_lower or "drupal.settings" in body_lower:
        techs.append("Drupal")
    if 'content="joomla' in body_lower:
        techs.append("Joomla")
    if 'content="ghost' in body_lower or "ghost-portal" in body_lower:
        techs.append("Ghost")

    if "data-reactroot" in body_lower or "_reactrootcontainer" in body_lower or "react.production.min.js" in body_lower:
        techs.append("React")
    if "data-v-" in body_lower or "vue.min.js" in body_lower or "window.__vue__" in body_lower:
        techs.append("Vue.js")
    if "ng-version=" in body_lower or "<app-root" in body_lower or "ng-app=" in body_lower:
        techs.append("Angular")
    if "jquery.min.js" in body_lower or "jquery.js" in body_lower or "jquery-" in body_lower:
        techs.append("jQuery")
    if "bootstrap.min.css" in body_lower or "bootstrap.min.js" in body_lower or "bootstrap.bundle" in body_lower:
        techs.append("Bootstrap")
    if "tailwindcss" in body_lower:
        techs.append("Tailwind CSS")

    if "google-analytics.com" in body_lower or "googletagmanager.com" in body_lower or "gtag(" in body_lower:
        techs.append("Google Analytics / GTM")
    if "hotjar.com" in body_lower or "_hjsettings" in body_lower:
        techs.append("Hotjar")
    if "clarity.ms/tag" in body_lower:
        techs.append("Microsoft Clarity")

    return sorted(list(set(techs)))
