import argparse
import json
import os
import sys
from typing import Any, Dict, List
from src.core import UrlScanner, ProxyManager

# --------------------------------------------------

def print_scan_summary(data: Dict[str, Any]) -> None:
    print("=" * 60)
    print(f"URL Initiale : {data.get('initial_url')}")
    print(f"URL Finale   : {data.get('final_url')}")
    print(f"Status Code  : {data.get('status_code')}")
    print(f"Temps        : {data.get('response_time_ms')} ms")
    print(f"Redirections : {data.get('redirect_count')}")

    if data.get("error"):
        print(f"Erreur       : {data.get('error')}")

    print("-" * 60)
    sec = data.get("security", {})
    print(f"Sécurité     : Note {sec.get('grade')} ({sec.get('score')}/100)")

    missing_h = sec.get("missing_headers", [])
    if missing_h:
        print(f"En-têtes manquants : {', '.join(missing_h)}")

    risks = data.get("risk_indicators", [])
    if risks:
        print("Risques détectés :")
        for r in risks:
            print(f"  [!] {r}")

    print("-" * 60)
    ssl_info = data.get("ssl", {})
    if ssl_info.get("enabled"):
        print(f"SSL Valide   : {'Oui' if ssl_info.get('valid') else 'Non'}")
        print(f"Version SSL  : {ssl_info.get('version')}")
        print(f"Jours restants : {ssl_info.get('days_remaining')}")
        issuer = ssl_info.get("issuer", {}).get("organizationName", "Inconnu")
        print(f"Émetteur SSL : {issuer}")
    else:
        print("SSL          : Non actif / Inaccessible")

    print("-" * 60)
    dns_info = data.get("dns", {})
    ips = dns_info.get("a", [])
    if ips:
        print(f"Adresses IP (A) : {', '.join(ips)}")
    mx = [m.get("exchange", "") for m in dns_info.get("mx", [])]
    if mx:
        print(f"Serveurs MX     : {', '.join(mx)}")

    print("-" * 60)
    techs = data.get("technologies", [])
    print(f"Technologies : {', '.join(techs) if techs else 'Aucune détectée'}")

    page = data.get("page_details", {})
    if page:
        print(f"Titre Page   : {page.get('title')}")
        links = page.get("links", {})
        print(f"Liens        : Total {links.get('total')} (Internes: {links.get('internal_count')}, Externes: {links.get('external_count')})")
        assets = page.get("assets", {})
        print(f"Éléments     : Images: {assets.get('images_count')}, Scripts: {assets.get('scripts_count')}, CSS: {assets.get('stylesheets_count')}, Formulaires: {assets.get('forms_count')}")
    print("=" * 60)

# --------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Scanner d'URL complet")
    parser.add_argument("--url", "-u", type=str, help="URL cible à scanner")
    parser.add_argument("--file", "-f", type=str, help="Fichier contenant une liste d'URLs (une par ligne)")
    parser.add_argument("--output", "-o", type=str, help="Chemin du fichier JSON de sortie")
    parser.add_argument("--json", action="store_true", help="Afficher directement la sortie JSON dans la console")
    parser.add_argument("--timeout", type=float, default=12.0, help="Délai d'attente réseau par requête")
    parser.add_argument("--browser", "-b", type=str, default="chrome", choices=["chrome", "firefox", "safari", "random"], help="Profil navigateur TLS et headers (chrome, firefox, safari, random)")
    parser.add_argument("--proxy", "-p", type=str, default=None, help="Proxy unique (ex: http://user:pass@ip:port ou ip:port:user:pass)")
    parser.add_argument("--proxy-file", type=str, default=None, help="Fichier contenant une liste de proxys")

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    proxy_mgr = ProxyManager()
    if args.proxy_file and os.path.exists(args.proxy_file):
        proxy_mgr.load_file(args.proxy_file)

    results: List[Dict[str, Any]] = []

    urls_to_scan: List[str] = []
    if args.url:
        urls_to_scan.append(args.url)
    if args.file:
        if os.path.exists(args.file):
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    u = line.strip()
                    if u and not u.startswith("#"):
                        urls_to_scan.append(u)

    for target in urls_to_scan:
        chosen_proxy = args.proxy
        if not chosen_proxy and proxy_mgr.has_proxies():
            chosen_proxy = proxy_mgr.get_proxy()

        scanner = UrlScanner(
            timeout=args.timeout,
            browser=args.browser,
            proxy=chosen_proxy
        )
        res = scanner.scan(target)
        results.append(res)
        if not args.json:
            print_scan_summary(res)

    if args.json:
        if len(results) == 1:
            print(json.dumps(results[0], indent=2, ensure_ascii=False))
        else:
            print(json.dumps(results, indent=2, ensure_ascii=False))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            if len(results) == 1:
                json.dump(results[0], f, indent=2, ensure_ascii=False)
            else:
                json.dump(results, f, indent=2, ensure_ascii=False)

# --------------------------------------------------

if __name__ == "__main__":
    main()
