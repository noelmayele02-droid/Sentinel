# 🛡️ SENTINEL — Plateforme unifiée de cyber-intelligence

**Auteur :** Albert Isaac Noël Mayele — Bachelor Cybersécurité, YNOV Campus Lille

Sentinel réunit dans un seul dashboard ce qu'un pentester et un analyste SOC font
séparément : reconnaissance OSINT, cartographie géospatiale de la surface
d'attaque, détection d'attaques Active Directory à partir de logs, et scoring
IA des vulnérabilités trouvées.

## Modules

| Module | Rôle | Statut |
|---|---|---|
| `backend/osint/` | Sous-domaines (crt.sh), détection techno, headers de sécurité, vérif fuites | ✅ Fonctionnel |
| `backend/geomap/` | Résolution DNS + géolocalisation IP pour la carte | ✅ Fonctionnel |
| `backend/detection/` | Analyse de logs Windows Event → alertes Kerberoasting / Pass-the-Hash | ✅ Fonctionnel (règles MITRE ATT&CK) |
| `backend/ai_scoring/` | Priorisation et explication des findings via l'API Claude | ✅ Fonctionnel (clé API requise) |
| `frontend/index.html` | Dashboard (carte interactive + résultats) | ✅ Fonctionnel |

## ⚠️ Périmètre volontaire du projet

Ce projet contient uniquement des outils de **reconnaissance passive** et de
**détection défensive**. Il ne contient volontairement **aucun code
d'exploitation** (pas de génération de Golden Ticket, pas d'extraction de
hash, pas de mouvement latéral automatisé).

Pour **générer** des événements d'attaque à des fins de test de détection,
dans un **labo isolé et autorisé**, utilisez des frameworks reconnus et
documentés par la communauté sécurité :
- [Atomic Red Team](https://atomicredteam.io/) — techniques ATT&CK unitaires, faites pour tester la détection
- [BloodHound / SharpHound](https://github.com/BloodHoundAD/BloodHound) — cartographie des chemins d'attaque AD (lecture seule)

Le module `ad_log_parser.py` de Sentinel est justement conçu pour **détecter**
les traces que ces outils génèrent dans les logs Windows.

## Installation

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY="votre_clé"   # optionnel, pour le scoring IA
export HIBP_API_KEY="votre_clé"        # optionnel, pour la vérif de fuites email

cd backend
uvicorn app:app --reload --port 8000
```

Puis ouvrez `frontend/index.html` dans un navigateur.

## Export des logs depuis un vrai labo AD

Le script `scripts/export_ad_logs.ps1` (PowerShell, à exécuter en
administrateur) lit le journal Sécurité Windows et génère directement un CSV
au format attendu par `ad_log_parser.py`. Il peut collecter **en local** (sur
la machine où il s'exécute) ou **à distance sur plusieurs machines**, y
compris situées sur un **autre sous-réseau ou domaine** (utile en contexte
professionnel réel : supervision du SI d'un site distant ou d'un partenaire
dans le cadre d'un mandat de sécurité).

```powershell
# Collecte locale (sur le DC où vous exécutez le script)
.\scripts\export_ad_logs.ps1 -OutputPath .\logs_export.csv -HoursBack 2

# Collecte à distance sur plusieurs machines/réseaux via WinRM
$cred = Get-Credential
.\scripts\export_ad_logs.ps1 -ComputerNames "dc01.labo.local","10.20.0.5" -Credential $cred -HoursBack 4
```

⚠️ **La collecte à distance nécessite une autorisation explicite** sur les
machines cibles (mandat, contrat de service, convention d'audit) — WinRM et
des identifiants valides ne remplacent pas une autorisation. Le script
affiche un rappel à l'écran avant toute collecte multi-machines.

Puis, quelle que soit l'origine des logs, analysez-les de la même façon :

```bash
python backend/detection/ad_log_parser.py logs_export.csv
```

Le détecteur alerte désormais sur les tickets Kerberos **en RC4** (signal
fort, sévérité `high`) **et en AES128/256** (signal plus faible car c'est le
chiffrement par défaut moderne, sévérité `medium`) — la démo fonctionne donc
même si le labo/l'environnement cible utilise un chiffrement moderne par
défaut.

## Test rapide du module de détection AD (sans backend)

```bash
cd backend/detection
python ad_log_parser.py ../../sample_logs/security_events.csv
```

## Utilisation des modules OSINT en CLI

```bash
cd backend/osint
python subdomains.py exemple.com
python tech_detect.py https://exemple.com
python ../geomap/geolocate.py exemple.com
```

## Stack technique

- **Backend** : Python, FastAPI, Requests
- **Frontend** : HTML/CSS/JS, Leaflet.js (carte interactive)
- **IA** : API Anthropic (Claude) pour l'explication et la priorisation
- **Sources de données** : crt.sh (Certificate Transparency), ip-api.com, HaveIBeenPwned

## Roadmap

- [ ] Authentification et gestion multi-utilisateurs
- [ ] Export PDF automatique du rapport de scan
- [ ] Intégration Sysmon pour une détection AD plus fine
- [ ] Historique des scans et suivi de l'évolution du risque dans le temps
- [ ] Dockerisation complète (docker-compose backend + frontend)

## Usage éthique

Cet outil est destiné à un usage sur des domaines/systèmes que vous
possédez ou pour lesquels vous avez une autorisation écrite explicite
(pentest, bug bounty scope, environnement de lab). Scanner un tiers sans
autorisation est illégal dans la plupart des juridictions.
