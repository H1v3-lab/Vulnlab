# VulnLab 🔓

Lab de sécurité web volontairement vulnérable — usage **local et éducatif uniquement**.

## Prérequis

- Docker >= 24
- Docker Compose v2
- Make (optionnel mais recommandé)

## Démarrage rapide

```bash
# Cloner / placer le projet
cd vulnlab

# Construire et démarrer tous les containers
make build
make up

# Ouvrir le dashboard
open http://localhost
```

## Structure du projet

```
vulnlab/
├── docker-compose.yml       ← Orchestration principale
├── Makefile                 ← Commandes raccourcies
├── proxy/
│   ├── nginx.conf           ← Config NGINX globale
│   └── conf.d/
│       └── vulnlab.conf     ← Routes vers les challenges
├── dashboard/
│   └── index.html           ← Interface principale (http://localhost)
│
├── c01-sqli/                ← PHP + MySQL  · SQLi
├── c02-xss/                 ← Node.js      · XSS stored/reflected
├── c03-ssti/                ← Python Flask · SSTI Jinja2
├── c04-broken-auth/         ← PHP          · Broken Auth / Sessions
├── c05-brute/               ← Node.js      · Brute Force
├── c06-idor-auth/           ← Python Flask · IDOR profils
├── c07-upload/              ← PHP          · File Upload
├── c08-lfi/                 ← PHP          · LFI / Path Traversal
├── c09-crypto/              ← Python       · Weak Crypto MD5
├── c10-jwt/                 ← Node.js      · JWT Forgery
├── c11-ssrf/                ← Python Flask · SSRF
├── c12-xxe/                 ← Python lxml  · XXE
├── c13-idor/                ← Node.js+Mongo· IDOR API REST
├── c14-csrf/                ← PHP          · CSRF
└── c15-cmdi/                ← Python Flask · Command Injection
```

## URLs des challenges

| # | Vuln | URL |
|---|------|-----|
| C01 | SQL Injection | http://localhost/c01/ |
| C02 | XSS | http://localhost/c02/ |
| C03 | SSTI | http://localhost/c03/ |
| C04 | Broken Auth | http://localhost/c04/ |
| C05 | Brute Force | http://localhost/c05/ |
| C06 | IDOR Auth | http://localhost/c06/ |
| C07 | File Upload | http://localhost/c07/ |
| C08 | LFI/RFI | http://localhost/c08/ |
| C09 | Weak Crypto | http://localhost/c09/ |
| C10 | JWT Forgery | http://localhost/c10/ |
| C11 | SSRF | http://localhost/c11/ |
| C12 | XXE | http://localhost/c12/ |
| C13 | IDOR API | http://localhost/c13/ |
| C14 | CSRF | http://localhost/c14/ |
| C15 | Cmd Injection | http://localhost/c15/ |

## Commandes utiles

```bash
make up        # Démarrer tout
make down      # Arrêter
make reset     # Tout supprimer (volumes inclus)
make logs      # Logs en temps réel
make c01       # Démarrer uniquement C01 + proxy
```

## ⚠️ Avertissement

Ce lab contient des vulnérabilités **intentionnelles**.  
Ne **jamais** l'exposer sur internet ou un réseau non contrôlé.  
Usage strictement local pour l'apprentissage de la sécurité offensive.
