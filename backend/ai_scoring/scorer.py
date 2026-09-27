"""
Module de scoring assisté par IA.

Prend les findings bruts (OSINT + détection AD) et demande à un LLM de :
  - évaluer la gravité (critique/haute/moyenne/basse)
  - expliquer le risque en langage clair, sans jargon
  - proposer un plan de remédiation en 3 étapes concrètes

Nécessite une clé API Anthropic dans la variable d'environnement
ANTHROPIC_API_KEY. Voir https://docs.claude.com/en/api pour l'obtenir.

Usage:
    python scorer.py findings.json
"""

import sys
import os
import json
import requests

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """Tu es un analyste en cybersécurité senior qui aide un junior
à comprendre et prioriser des findings de sécurité. Pour chaque finding reçu,
réponds UNIQUEMENT en JSON avec ce format, sans aucun texte autour :

{
  "severity": "critical|high|medium|low",
  "explanation": "explication en langage simple, 2-3 phrases",
  "remediation_steps": ["étape 1", "étape 2", "étape 3"]
}
"""


def score_finding(finding: dict) -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"error": "ANTHROPIC_API_KEY non configurée dans l'environnement."}

    payload = {
        "model": MODEL,
        "max_tokens": 500,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": f"Finding à analyser:\n{json.dumps(finding, ensure_ascii=False)}"}
        ],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    resp = requests.post(ANTHROPIC_API_URL, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": "Réponse IA non parsable", "raw": text}


def score_all(findings: list) -> list:
    return [{"finding": f, "analysis": score_finding(f)} for f in findings]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scorer.py <findings.json>")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        findings = json.load(f)

    results = score_all(findings)
    print(json.dumps(results, indent=2, ensure_ascii=False))
