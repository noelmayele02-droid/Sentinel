"""
Module de recherche de CVE (Common Vulnerabilities and Exposures) à partir
des produits/versions détectés par osint/tech_detect.py.

Source de données : NVD (National Vulnerability Database), l'API officielle
du NIST — gratuite, publique, aucune clé requise (mais rate-limitée à
5 requêtes / 30s sans clé — https://nvd.nist.gov/developers/request-an-api-key
si vous voulez augmenter cette limite).

⚠️ Ce module fait uniquement de la RECHERCHE et de la LECTURE d'informations
publiques sur des vulnérabilités déjà documentées. Il ne génère, ne teste et
n'exploite aucune vulnérabilité.

Usage CLI:
    python cve_search.py nginx 1.18.0
    python cve_search.py wordpress 6.4.2 --max 5
"""

import sys
import time
import argparse
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Respect du rate-limit public NVD (5 req / 30s sans clé API)
_MIN_DELAY_SECONDS = 6.5
_last_call_ts = 0.0


def _throttle():
    """Espace les appels pour rester sous la limite publique de l'API NVD."""
    global _last_call_ts
    elapsed = time.time() - _last_call_ts
    if elapsed < _MIN_DELAY_SECONDS:
        time.sleep(_MIN_DELAY_SECONDS - elapsed)
    _last_call_ts = time.time()


def _extract_cvss(metrics: dict) -> dict:
    """Récupère le meilleur score CVSS disponible (v3.1 > v3.0 > v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return {
                "version": data.get("version"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity", entries[0].get("baseSeverity", "N/A")),
                "vector": data.get("vectorString"),
            }
    return {"version": None, "score": None, "severity": "N/A", "vector": None}


def search_cves(product: str, version: str = None, max_results: int = 10, timeout: int = 15) -> dict:
    """Recherche les CVE connues pour un produit (et éventuellement une version précise).

    Retourne un dict {product, version, total_results, cves: [...], error?}.
    Chaque entrée de `cves` contient : id, description, severity, score, vector,
    published, url (lien direct vers la fiche NVD).
    """
    keyword = f"{product} {version}".strip() if version else product
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    _throttle()
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=timeout,
                             headers={"User-Agent": "Sentinel-CVE-Lookup/1.0"})
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return {"product": product, "version": version, "total_results": 0, "cves": [], "error": str(e)}

    vulnerabilities = data.get("vulnerabilities", [])
    cves = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        desc_fr = next((d["value"] for d in descriptions if d.get("lang") == "fr"), None)
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
        cvss = _extract_cvss(cve.get("metrics", {}))

        cves.append({
            "id": cve_id,
            "description": desc_fr or desc_en or "Description non disponible",
            "severity": cvss["severity"],
            "cvss_score": cvss["score"],
            "cvss_vector": cvss["vector"],
            "published": cve.get("published"),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
        })

    # Les plus critiques et les plus récentes en premier
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "N/A": 4}
    cves.sort(key=lambda c: (severity_order.get(c["severity"], 4), c["published"] or ""), reverse=False)

    return {
        "product": product,
        "version": version,
        "total_results": data.get("totalResults", len(cves)),
        "cves": cves,
    }


def search_cves_for_technologies(versioned_products: list, max_results_per_product: int = 5) -> list:
    """Prend la liste `versioned_products` renvoyée par tech_detect.detect_versions()
    et retourne les résultats CVE pour chacun. Respecte le rate-limit NVD entre
    chaque produit (peut donc être lent si plusieurs produits sont détectés).
    """
    results = []
    for p in versioned_products:
        result = search_cves(p["product"], p.get("version"), max_results=max_results_per_product)
        results.append(result)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recherche de CVE par produit/version (API NVD)")
    parser.add_argument("product", help="Nom du produit, ex: nginx, wordpress, apache http server")
    parser.add_argument("version", nargs="?", default=None, help="Version exacte (optionnel)")
    parser.add_argument("--max", type=int, default=10, help="Nombre max de résultats (défaut: 10)")
    args = parser.parse_args()

    print(f"[*] Recherche CVE pour: {args.product} {args.version or ''}".strip())
    result = search_cves(args.product, args.version, max_results=args.max)

    if result.get("error"):
        print(f"[!] Erreur: {result['error']}")
        sys.exit(1)

    print(f"[+] {result['total_results']} résultat(s) trouvé(s), affichage de {len(result['cves'])}:\n")
    for cve in result["cves"]:
        print(f"  {cve['id']}  [{cve['severity']}]  score={cve['cvss_score']}")
        print(f"    {cve['description'][:160]}{'...' if len(cve['description']) > 160 else ''}")
        print(f"    {cve['url']}\n")
