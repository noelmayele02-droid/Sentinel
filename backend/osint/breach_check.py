"""
Vérification de compromissions connues via l'API HaveIBeenPwned (HIBP).

IMPORTANT : depuis 2024, l'API HIBP nécessite une clé payante (~4$/mois)
pour la recherche par email. Ce module est écrit pour fonctionner dès que
vous ajoutez votre clé dans HIBP_API_KEY (variable d'environnement).

Sans clé, le module utilise l'API "Pwned Passwords" (gratuite, anonyme,
k-anonymity) pour au moins vérifier si un mot de passe a fuité - utile
pour la partie sensibilisation du dashboard.

Usage:
    python breach_check.py email@exemple.com
    python breach_check.py --password "motdepasse123"
"""

import sys
import os
import hashlib
import requests

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
HIBP_PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_email_breaches(email: str) -> dict:
    """Nécessite une clé API HIBP (variable d'env HIBP_API_KEY)."""
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        return {
            "email": email,
            "error": "HIBP_API_KEY non configurée. Voir https://haveibeenpwned.com/API/Key",
        }

    headers = {"hibp-api-key": api_key, "User-Agent": "Sentinel-OSINT/1.0"}
    url = HIBP_BREACH_URL.format(account=email)

    resp = requests.get(url, headers=headers, timeout=10)
    if resp.status_code == 200:
        return {"email": email, "breaches": resp.json()}
    elif resp.status_code == 404:
        return {"email": email, "breaches": []}
    else:
        return {"email": email, "error": f"HTTP {resp.status_code}"}


def check_password_pwned(password: str) -> dict:
    """
    Vérifie un mot de passe via k-anonymity : seuls les 5 premiers
    caractères du hash SHA-1 sont envoyés, jamais le mot de passe en clair.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    resp = requests.get(HIBP_PWNED_PASSWORDS_URL.format(prefix=prefix), timeout=10)
    resp.raise_for_status()

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return {"pwned": True, "times_seen": int(count)}

    return {"pwned": False, "times_seen": 0}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python breach_check.py <email> | --password <mdp>")
        sys.exit(1)

    if sys.argv[1] == "--password":
        result = check_password_pwned(sys.argv[2])
        if result["pwned"]:
            print(f"[!] Ce mot de passe a été vu {result['times_seen']} fois dans des fuites connues.")
        else:
            print("[+] Ce mot de passe n'apparaît pas dans les fuites connues (Pwned Passwords).")
    else:
        result = check_email_breaches(sys.argv[1])
        print(result)
