#!/usr/bin/env python3
# src/parse_json.py

import os
import json
import re
import requests
import certifi
from urllib.parse import urlparse

# Fichiers d'entrée et de sortie
IN_FILE  = os.path.join(os.path.dirname(__file__), '..', 'data', 'rss_entries.json')
OUT_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'cve_entries.json')

# Regex pour attraper tout identifiant CVE dans le JSON
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}')

def load_rss_entries(path=IN_FILE):
    """Charge la liste des bulletins extraits à l'étape 1."""
    with open(path, encoding='utf-8') as f:
        return json.load(f)

def derive_reference(link):
    """Extrait l'ID ANSSI (ex. CERTFR-2025-ALE-008) depuis l'URL."""
    path = urlparse(link).path.rstrip('/')
    return path.split('/')[-1]

def fetch_json(url):
    """Récupère et retourne le JSON d'un bulletin."""
    try:
        resp = requests.get(url, timeout=10, verify=certifi.where())
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[ERROR] impossible de récupérer {url} : {e}")
        return None

def extract_cves(data):
    """Depuis le dict JSON brut, retourne la liste unique de CVE."""
    # 1) CVE déclarés dans la clé "cves"
    key_cves = [c.get('name') for c in data.get('cves', []) if c.get('name')]
    # 2) CVE trouvés via regex dans tout le JSON
    text = json.dumps(data)
    regex_cves = CVE_PATTERN.findall(text)
    # Unifier et trier
    return sorted(set(key_cves + regex_cves))

def main():
    entries = load_rss_entries()
    output = []

    for ent in entries:
        link = ent['link'].rstrip('/')
        json_url = f"{link}/json/"

        print(f"[INFO] Traitement de {ent['type']} → {json_url}")
        data = fetch_json(json_url)
        if not data:
            continue

        ref = derive_reference(link)
        cves = extract_cves(data)

        output.append({
            'reference': ref,
            'type':      ent['type'],
            'title':     ent['title'],
            'published': ent['published'],
            'link':      link,
            'json_url':  json_url,
            'cves':      cves,
        })

    # Sauvegarde
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[OK] {len(output)} bulletins traités. Fichier généré → {OUT_FILE}")

if __name__ == '__main__':
    main()
