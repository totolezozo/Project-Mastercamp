#!/usr/bin/env python3
# src/enrich_cve.py

import os
import json
import requests
import certifi

# Fichiers d'entrée et de sortie
IN_FILE  = os.path.join(os.path.dirname(__file__), '..', 'data', 'cve_entries.json')
OUT_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'enriched_cve.json')

# Endpoints API
MITRE_API = "https://cveawg.mitre.org/api/cve/{cve}"
EPSS_API  = "https://api.first.org/data/v1/epss?cve={cve}"

def load_cve_entries(path=IN_FILE):
    with open(path, encoding='utf-8') as f:
        return json.load(f)

def fetch_json(url):
    """GET JSON avec vérification SSL via certifi."""
    try:
        r = requests.get(url, timeout=10, verify=certifi.where())
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        print(f"[ERROR] échec requête {url} : {e}")
        return None

def get_mitre_info(cve_id):
    """Récupère description, CVSS, CWE et systèmes affectés depuis MITRE."""
    data = fetch_json(MITRE_API.format(cve=cve_id))
    if not data or "containers" not in data:
        return None

    cna = data["containers"]["cna"]

    # Description
    descriptions = cna.get("descriptions", [])
    desc = descriptions[0]["value"] if descriptions else ""

    # CVSS (baseScore) – on tente v3.1 puis v3.0
    base_score = None
    for m in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV3_0"):
            if key in m:
                base_score = m[key].get("baseScore")
                break
        if base_score is not None:
            break

    # Catégorie de gravité
    if base_score is None:
        severity = None
    elif base_score <= 3:
        severity = "Faible"
    elif base_score <= 6:
        severity = "Moyenne"
    elif base_score <= 8:
        severity = "Élevée"
    else:
        severity = "Critique"

    # CWE
    cwe_id   = "Non disponible"
    cwe_desc = "Non disponible"
    prob = cna.get("problemTypes", [])
    if prob and "descriptions" in prob[0]:
        pd = prob[0]["descriptions"][0]
        cwe_id   = pd.get("cweId", cwe_id)
        cwe_desc = pd.get("description", cwe_desc)

    # Produits affectés
    affected = []
    for prod in cna.get("affected", []):
        vendor = prod.get("vendor", "")
        name   = prod.get("product", "")
        versions = [
            v.get("version")
            for v in prod.get("versions", [])
            if v.get("status") == "affected" and v.get("version")
        ]
        affected.append({
            "vendor": vendor,
            "product": name,
            "versions": versions
        })

    return {
        "description": desc,
        "cvss_score": base_score,
        "base_severity": severity,
        "cwe_id": cwe_id,
        "cwe_description": cwe_desc,
        "affected_systems": affected
    }

def get_epss_score(cve_id):
    """Récupère le score EPSS (0–1) depuis FIRST."""
    data = fetch_json(EPSS_API.format(cve=cve_id))
    if not data:
        return None
    epss_list = data.get("data", [])
    if epss_list:
        return epss_list[0].get("epss")
    return None

def main():
    entries = load_cve_entries()
    enriched = []

    for ent in entries:
        for cve in ent.get("cves", []):
            print(f"[INFO] Enrichissement {cve} ({ent['reference']})")

            m_info = get_mitre_info(cve)
            if not m_info:
                print(f"[WARN] pas d'info MITRE pour {cve}")
                continue

            e_score = get_epss_score(cve)

            record = {
                # Conserver les métadonnées du bulletin
                "reference": ent["reference"],
                "type":      ent["type"],
                "title":     ent["title"],
                "published": ent["published"],
                "link":      ent["link"],
                "json_url":  ent["json_url"],
                # CVE enrichi
                "cve_id":           cve,
                "description":      m_info["description"],
                "cvss_score":       m_info["cvss_score"],
                "base_severity":    m_info["base_severity"],
                "cwe_id":           m_info["cwe_id"],
                "cwe_description":  m_info["cwe_description"],
                "epss_score":       e_score,
                "affected_systems": m_info["affected_systems"]
            }
            enriched.append(record)

    # Sauvegarde du JSON enrichi
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)

    print(f"[OK] {len(enriched)} enregistrements enrichis -> {OUT_FILE}")

if __name__ == "__main__":
    main()
