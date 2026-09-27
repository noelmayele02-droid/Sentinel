"""
Sentinel - API principale (FastAPI)

Orchestre les modules OSINT, géolocalisation, détection AD et scoring IA,
et expose des endpoints REST consommés par le dashboard (frontend/index.html).

Lancement:
    uvicorn app:app --reload --port 8000

Puis ouvrir frontend/index.html dans un navigateur (ou servir en statique).
"""

import os
import sys
import tempfile

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(os.path.join(os.path.dirname(__file__)))

from osint.subdomains import get_subdomains, check_alive
from osint.tech_detect import detect_technologies
from geomap.geolocate import map_hosts
from detection.ad_log_parser import run_detection
from ai_scoring.scorer import score_finding

app = FastAPI(title="Sentinel API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # à restreindre en production
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    domain: str
    use_ai_scoring: bool = False


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def scan_domain(req: ScanRequest):
    """Lance une reconnaissance OSINT complète sur un domaine."""
    domain = req.domain.strip().lower()
    if not domain:
        raise HTTPException(400, "Domaine requis")

    subs = get_subdomains(domain)
    subs_list = sorted(subs)[:20]  # limite pour rester raisonnable en démo

    tech = detect_technologies(f"https://{domain}")
    geo_points = map_hosts([domain] + subs_list[:5])  # limite requêtes géoloc

    findings = []
    for h, present in tech.get("security_headers", {}).items():
        if not present:
            findings.append({
                "type": "header_manquant",
                "detail": f"Le header de sécurité '{h}' est absent",
                "target": domain,
            })

    result = {
        "domain": domain,
        "subdomains": subs_list,
        "subdomains_total_found": len(subs),
        "technologies": tech.get("technologies", []),
        "security_headers": tech.get("security_headers", {}),
        "geo_points": geo_points,
        "findings": findings,
    }

    if req.use_ai_scoring and findings:
        result["ai_analysis"] = [
            {"finding": f, "analysis": score_finding(f)} for f in findings[:5]
        ]

    return result


@app.post("/api/detect-ad")
async def detect_ad(file: UploadFile = File(...)):
    """Analyse un export CSV de logs Windows Event pour détecter Kerberoasting / Pass-the-Hash."""
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "Fichier CSV attendu")

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".csv", delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        alerts = run_detection(tmp_path)
    finally:
        os.unlink(tmp_path)

    return {"alerts": alerts, "alert_count": len(alerts)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
