"""
Module de reconnaissance passive - énumération de sous-domaines.

Utilise crt.sh (base publique des certificats TLS / Certificate Transparency),
une méthode 100% passive : aucune requête n'est envoyée à la cible elle-même,
seulement à l'API publique crt.sh. Légal et sans danger pour la cible.

Usage:
    python subdomains.py exemple.com
"""

import sys
import json
import requests
from typing import Set

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def get_subdomains(domain: str, timeout: int = 15) -> Set[str]:
    """Récupère les sous-domaines connus d'un domaine via crt.sh."""
    url = CRTSH_URL.format(domain=domain)
    subdomains: Set[str] = set()

    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Sentinel-OSINT/1.0"})
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[!] Erreur lors de la requête crt.sh: {e}", file=sys.stderr)
        return subdomains

    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*.") and domain in name:
                subdomains.add(name)
            elif name.startswith("*."):
                subdomains.add(name.replace("*.", ""))

    return subdomains


def check_alive(subdomains: Set[str], timeout: int = 5) -> dict:
    """Vérifie rapidement lesquels de ces sous-domaines répondent en HTTP/HTTPS."""
    results = {}
    for sub in subdomains:
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{sub}", timeout=timeout, allow_redirects=True)
                results[sub] = {
                    "status_code": r.status_code,
                    "scheme": scheme,
                    "server": r.headers.get("Server", "unknown"),
                    "final_url": r.url,
                }
                break
            except requests.RequestException:
                continue
        else:
            results[sub] = {"status_code": None, "scheme": None}
    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python subdomains.py <domaine>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[*] Recherche de sous-domaines pour: {target}")
    subs = get_subdomains(target)
    print(f"[+] {len(subs)} sous-domaine(s) trouvé(s)\n")
    for s in sorted(subs):
        print(f"  - {s}")
