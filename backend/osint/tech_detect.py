"""
Détection légère des technologies utilisées par un site web,
à partir des headers HTTP et d'empreintes simples dans le HTML.

Ce n'est pas un remplacement de Wappalyzer (empreintes limitées),
mais un point de départ suffisant pour un rapport de reconnaissance.

Usage:
    python tech_detect.py https://exemple.com
"""

import sys
import re
import requests

# Empreintes (regex) -> nom de la techno détectée
HTML_SIGNATURES = {
    r"wp-content|wp-includes": "WordPress",
    r"Drupal.settings": "Drupal",
    r"__NEXT_DATA__": "Next.js",
    r"data-reactroot|react-dom": "React",
    r"ng-version": "Angular",
    r"cdn.shopify.com": "Shopify",
    r"laravel_session": "Laravel (PHP)",
    r"django": "Django (Python)",
}

HEADER_SIGNATURES = {
    "Server": {
        r"nginx": "Nginx",
        r"apache": "Apache HTTP Server",
        r"cloudflare": "Cloudflare (CDN/WAF)",
        r"Microsoft-IIS": "Microsoft IIS",
    },
    "X-Powered-By": {
        r"PHP": "PHP",
        r"Express": "Express.js (Node.js)",
        r"ASP.NET": "ASP.NET",
    },
}


def detect_technologies(url: str, timeout: int = 10) -> dict:
    result = {"url": url, "technologies": set(), "headers": {}, "security_headers": {}}

    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Sentinel-OSINT/1.0"})
    except requests.RequestException as e:
        result["error"] = str(e)
        return result

    result["status_code"] = resp.status_code
    result["headers"] = dict(resp.headers)

    # Empreintes headers
    for header_name, sigs in HEADER_SIGNATURES.items():
        value = resp.headers.get(header_name, "")
        for pattern, tech in sigs.items():
            if re.search(pattern, value, re.IGNORECASE):
                result["technologies"].add(tech)

    # Empreintes HTML
    body = resp.text[:200_000]  # limite raisonnable
    for pattern, tech in HTML_SIGNATURES.items():
        if re.search(pattern, body, re.IGNORECASE):
            result["technologies"].add(tech)

    # Headers de sécurité présents / absents (utile pour le scoring de risque)
    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    for h in security_headers:
        result["security_headers"][h] = h in resp.headers

    result["technologies"] = sorted(result["technologies"])
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tech_detect.py <url>")
        sys.exit(1)

    data = detect_technologies(sys.argv[1])
    print(f"[*] Analyse de {data['url']}")
    print(f"[+] Technologies détectées: {', '.join(data['technologies']) or 'aucune'}\n")
    print("[+] Headers de sécurité:")
    for h, present in data.get("security_headers", {}).items():
        mark = "✓" if present else "✗ MANQUANT"
        print(f"    {h}: {mark}")
