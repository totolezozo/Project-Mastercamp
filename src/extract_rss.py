#!/usr/bin/env python3
# src/extract_rss.py


#Étape 1 : Extraction des Flux RSS
#La première partie du projet consiste à extraire les avis et alertes de l'ANSSI.
#Cela permet d'obtenir le Titre, Description, Date de publication et Lien vers le bulletin détaillé.

import os
import requests
import feedparser
import csv
import json
import certifi

# Flux à traiter
FEEDS = [
    ('avis',   'https://www.cert.ssi.gouv.fr/avis/feed'),
    ('alerte', 'https://www.cert.ssi.gouv.fr/alerte/feed'),
]

# Répertoire de sortie
OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')

def fetch_feed(url):
    """Récupère en HTTPS le contenu du flux RSS via requests+certifi."""
    try:
        resp = requests.get(url, timeout=10, verify=certifi.where())
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"[ERROR] impossible de récupérer {url} : {e}")
        return None

def fetch_entries():
    """Parse tous les flux et retourne la liste normalisée."""
    all_entries = []
    for feed_type, url in FEEDS:
        print(f"[INFO] Parsing {feed_type} → {url}")
        text = fetch_feed(url)
        if not text:
            continue
        feed = feedparser.parse(text)
        if feed.bozo:
            print(f"[WARN] problème de parsing {url} : {feed.bozo_exception}")
        for e in feed.entries:
            all_entries.append({
                'type':        feed_type,
                'title':       e.get('title', '').strip(),
                'description': e.get('description', e.get('summary', '')).strip(),
                'published':   e.get('published', '').strip(),
                'link':        e.get('link', '').strip(),
            })
    return all_entries

def save_csv(entries, fname='rss_entries.csv'):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, fname)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        cols = ['type','title','description','published','link']
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(entries)
    print(f"[OK] CSV → {path}")

def save_json(entries, fname='rss_entries.json'):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, fname)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    print(f"[OK] JSON → {path}")

if __name__ == '__main__':
    entries = fetch_entries()
    if not entries:
        print("[ERROR] Aucune entrée trouvée, vérifiez les URLs des flux.")
        exit(1)
    save_csv(entries)
    save_json(entries)
