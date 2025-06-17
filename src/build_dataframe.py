#!/usr/bin/env python3
# src/build_dataframe.py

import os
import json
import pandas as pd

# Chemins d'entrée et de sortie
IN_FILE  = os.path.join(os.path.dirname(__file__), '..', 'data', 'enriched_cve.json')
OUT_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'consolidated.csv')

def flatten_affected_systems(affected):
    """
    Retourne trois chaînes :
     - tous les vendors séparés par ;
     - tous les produits séparés par ;
     - toutes les versions (uniques) séparées par ;
    """
    vendors = []
    products = []
    versions = []
    for sys in affected:
        vendors.append(sys.get("vendor", ""))
        products.append(sys.get("product", ""))
        versions.extend(sys.get("versions", []))
    # Déduplication versions
    unique_versions = sorted(set(versions))
    return (
        "; ".join(dict.fromkeys(vendors)),    # préserve l'ordre d'apparition
        "; ".join(dict.fromkeys(products)),
        "; ".join(unique_versions),
    )

def main():
    # 1) Charger les données enrichies
    with open(IN_FILE, encoding='utf-8') as f:
        enriched = json.load(f)

    # 2) Construire la liste de dicts pour pandas
    rows = []
    for ent in enriched:
        vend, prod, vers = flatten_affected_systems(ent.get("affected_systems", []))
        rows.append({
            "id_ansi":       ent["reference"],
            "titre":         ent["title"],
            "type_bulletin": ent["type"],
            "date_pub":      ent["published"],
            "cve_id":        ent["cve_id"],
            "cvss_score":    ent["cvss_score"],
            "base_severity": ent["base_severity"],
            "cwe_id":        ent["cwe_id"],
            "epss_score":    ent["epss_score"],
            "lien_bulletin": ent["link"],
            "description":   ent["description"],
            "vendor":        vend,
            "produit":       prod,
            "versions":      vers,
        })

    # 3) Créer le DataFrame
    df = pd.DataFrame(rows)

    # 4) Écrire en CSV
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    df.to_csv(OUT_FILE, index=False, encoding='utf-8')
    print(f"[OK] DataFrame enregistré → {OUT_FILE}")

if __name__ == "__main__":
    main()
