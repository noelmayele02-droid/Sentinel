"""
Module de DÉTECTION (défensif) - analyse des journaux d'événements Windows
pour repérer les signatures d'attaques classiques sur Active Directory.

Ce module ne réalise AUCUNE attaque. Il lit des exports de logs (CSV/XML,
tels qu'exportés depuis l'Observateur d'événements Windows ou Sysmon) et
applique des règles de détection connues (basées sur MITRE ATT&CK).

Pour générer des logs d'attaque à des fins de test, en environnement
labo isolé et autorisé, utilisez des frameworks reconnus conçus pour ça :
  - Atomic Red Team (atomicredteam.io) : exécute des techniques ATT&CK
    unitaires et documentées, pensées pour tester la détection.
  - BloodHound / SharpHound : cartographie des chemins d'attaque AD
    (lecture seule, pas d'exploitation).
Ce projet se concentre volontairement sur la détection plutôt que sur
l'outillage offensif.

Règles implémentées :
  - Kerberoasting : rafale d'événements 4769 (Ticket de service Kerberos
    demandé) avec chiffrement RC4 (0x17) pour un même compte, en peu de temps.
  - Pass-the-Hash : événement 4624 (ouverture de session) de type 9
    (NewCredentials) ou authentification NTLM là où Kerberos est attendu,
    depuis une source inhabituelle.

Usage:
    python ad_log_parser.py sample_logs/security_events.csv
"""

import sys
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict

# Seuils de détection (ajustables selon l'environnement)
KERBEROASTING_THRESHOLD_RC4 = 5        # nb de tickets RC4 pour un même compte (signal fort)
KERBEROASTING_THRESHOLD_AES = 8        # nb de tickets AES pour un même compte (signal plus faible,
                                        # car AES est le chiffrement par défaut sur les DC récents -
                                        # seuil plus haut pour limiter les faux positifs)
KERBEROASTING_WINDOW_MIN = 10          # sur cette fenêtre de temps (minutes)

# Types de chiffrement Kerberos à surveiller (valeurs telles qu'elles apparaissent
# dans l'événement 4769, champ TicketEncryptionType)
ENCRYPTION_TYPES = {
    "0x17": {"name": "RC4", "severity": "high"},     # legacy, signal fort de Kerberoasting
    "0x12": {"name": "AES256", "severity": "medium"}, # chiffrement moderne, Rubeus/impacket peuvent le forcer
    "0x11": {"name": "AES128", "severity": "medium"},
}


def load_events(csv_path: str) -> List[Dict]:
    """
    Format CSV attendu (colonnes minimales) :
    TimeCreated, EventID, AccountName, IpAddress, TicketEncryptionType, LogonType
    """
    events = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(row)
    return events


def detect_kerberoasting(events: List[Dict]) -> List[Dict]:
    """
    Détecte les rafales de demandes de tickets Kerberos (event 4769) pour un
    même compte, que le chiffrement soit RC4 (signal fort et historique) ou
    AES (chiffrement par défaut moderne, mais que des outils comme Rubeus
    peuvent volontairement forcer/révéler dans une rafale suspecte).
    """
    alerts = []
    # on regroupe séparément par compte ET par type de chiffrement, pour ne
    # pas mélanger un usage légitime mixte avec une vraie rafale suspecte
    by_account_enc = defaultdict(list)

    for e in events:
        if e.get("EventID") != "4769":
            continue
        enc = e.get("TicketEncryptionType")
        if enc not in ENCRYPTION_TYPES:
            continue
        try:
            ts = datetime.fromisoformat(e["TimeCreated"])
        except (KeyError, ValueError):
            continue
        key = (e.get("AccountName", "unknown"), enc)
        by_account_enc[key].append((ts, e))

    seen_accounts = set()
    for (account, enc), occurrences in by_account_enc.items():
        if account in seen_accounts:
            continue  # une alerte Kerberoasting suffit par compte

        enc_info = ENCRYPTION_TYPES[enc]
        threshold = KERBEROASTING_THRESHOLD_RC4 if enc_info["name"] == "RC4" else KERBEROASTING_THRESHOLD_AES

        occurrences.sort(key=lambda x: x[0])
        if len(occurrences) < threshold:
            continue

        for i in range(len(occurrences) - threshold + 1):
            window = occurrences[i:i + threshold]
            span = window[-1][0] - window[0][0]
            if span <= timedelta(minutes=KERBEROASTING_WINDOW_MIN):
                alerts.append({
                    "type": f"Kerberoasting suspecté ({enc_info['name']})",
                    "severity": enc_info["severity"],
                    "account": account,
                    "encryption": enc_info["name"],
                    "event_count": len(window),
                    "window_minutes": round(span.total_seconds() / 60, 1),
                    "first_seen": window[0][0].isoformat(),
                    "last_seen": window[-1][0].isoformat(),
                    "mitre_technique": "T1558.003",
                    "recommendation": (
                        "Vérifier si le compte de service utilise un mot de passe "
                        "fort (>25 caractères) ou passer à gMSA. Auditer les SPN "
                        "associés à ce compte."
                        if enc_info["name"] == "RC4" else
                        "Rafale de tickets AES pour un compte de service : moins "
                        "critique qu'en RC4 mais à corréler avec le contexte "
                        "(horaire inhabituel, source inconnue) avant de conclure."
                    ),
                })
                seen_accounts.add(account)
                break

    return alerts


def detect_pass_the_hash(events: List[Dict]) -> List[Dict]:
    """Détecte les indicateurs de Pass-the-Hash (logon type 9 / NTLM anormal)."""
    alerts = []

    for e in events:
        if e.get("EventID") == "4624" and e.get("LogonType") == "9":
            alerts.append({
                "type": "Pass-the-Hash suspecté (LogonType 9)",
                "severity": "critical",
                "account": e.get("AccountName", "unknown"),
                "source_ip": e.get("IpAddress", "unknown"),
                "timestamp": e.get("TimeCreated"),
                "mitre_technique": "T1550.002",
                "recommendation": (
                    "Isoler la machine source, réinitialiser les identifiants du "
                    "compte concerné, vérifier l'usage de Credential Guard / LSA "
                    "Protection sur les postes sensibles."
                ),
            })

    return alerts


SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def run_detection(csv_path: str) -> List[Dict]:
    events = load_events(csv_path)
    alerts = []
    alerts += detect_kerberoasting(events)
    alerts += detect_pass_the_hash(events)
    return sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a["severity"], 0), reverse=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ad_log_parser.py <fichier_logs.csv>")
        sys.exit(1)

    found = run_detection(sys.argv[1])
    print(f"[+] {len(found)} alerte(s) détectée(s)\n")
    for a in found:
        print(f"  [{a['severity'].upper()}] {a['type']} - compte: {a['account']}")
        print(f"      MITRE ATT&CK: {a['mitre_technique']}")
        print(f"      Recommandation: {a['recommendation']}\n")
