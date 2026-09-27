"""
Résolution DNS + géolocalisation IP des sous-domaines/serveurs trouvés,
pour alimenter la carte interactive du dashboard.

Utilise ip-api.com (gratuit, 45 req/min, pas de clé nécessaire pour usage
non-commercial). Pour un usage commercial/haut volume, remplacer par
ipinfo.io ou MaxMind GeoLite2 (base locale, pas de limite de requêtes).

Usage:
    python geolocate.py exemple.com www.exemple.com api.exemple.com
"""

import sys
import socket
import time
import requests
from typing import Optional

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org,as,query"


def resolve_ip(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def geolocate_ip(ip: str) -> dict:
    try:
        resp = requests.get(IP_API_URL.format(ip=ip), timeout=8)
        data = resp.json()
        if data.get("status") == "success":
            return data
        return {"error": data.get("message", "échec géolocalisation")}
    except requests.RequestException as e:
        return {"error": str(e)}


def map_hosts(hostnames: list) -> list:
    """Retourne une liste de points géo prêts pour le frontend (Leaflet)."""
    points = []
    for host in hostnames:
        ip = resolve_ip(host)
        if not ip:
            points.append({"hostname": host, "ip": None, "error": "résolution DNS échouée"})
            continue

        geo = geolocate_ip(ip)
        time.sleep(1.5)  # respecter la limite de 45 req/min de ip-api.com (gratuit)

        if "error" in geo:
            points.append({"hostname": host, "ip": ip, "error": geo["error"]})
            continue

        points.append({
            "hostname": host,
            "ip": ip,
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "city": geo.get("city"),
            "country": geo.get("country"),
            "isp": geo.get("isp"),
            "org": geo.get("org"),
            "asn": geo.get("as"),
        })

    return points


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python geolocate.py <host1> [host2] [host3] ...")
        sys.exit(1)

    result = map_hosts(sys.argv[1:])
    for point in result:
        if "error" in point:
            print(f"[!] {point['hostname']}: {point['error']}")
        else:
            print(f"[+] {point['hostname']} ({point['ip']}) -> {point['city']}, {point['country']} "
                  f"[{point['org']}]")
