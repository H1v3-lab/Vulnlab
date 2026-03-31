.PHONY: up down build reset logs ps help

# ─────────────────────────────────────────────
# VulnLab — Makefile
# ─────────────────────────────────────────────

help:
	@echo ""
	@echo "  VulnLab — commandes disponibles"
	@echo "  ────────────────────────────────"
	@echo "  make up       — Démarre tous les containers"
	@echo "  make down     — Arrête et supprime les containers"
	@echo "  make build    — (Re)construit toutes les images"
	@echo "  make reset    — Supprime tout (containers + volumes)"
	@echo "  make logs     — Affiche les logs en temps réel"
	@echo "  make ps       — Liste les containers actifs"
	@echo "  make c01      — Lance uniquement le challenge 01"
	@echo ""

up:
	docker compose up -d
	@echo ""
	@echo "  ✓ VulnLab démarré → http://localhost"
	@echo ""

down:
	docker compose down

build:
	docker compose build --no-cache

reset:
	docker compose down -v --remove-orphans

logs:
	docker compose logs -f

ps:
	docker compose ps

# Cibles individuelles pour développement
c01:
	docker compose up -d mysql c01-sqli proxy

c02:
	docker compose up -d c02-xss proxy

c03:
	docker compose up -d c03-ssti proxy

c04:
	docker compose up -d c04-broken-auth proxy

c05:
	docker compose up -d c05-brute proxy

c06:
	docker compose up -d c06-idor-auth proxy

c07:
	docker compose up -d c07-upload proxy

c08:
	docker compose up -d c08-lfi proxy

c09:
	docker compose up -d c09-crypto proxy

c10:
	docker compose up -d c10-jwt proxy

c11:
	docker compose up -d c11-ssrf proxy

c12:
	docker compose up -d c12-xxe proxy

c13:
	docker compose up -d mongo c13-idor proxy

c14:
	docker compose up -d c14-csrf proxy

c15:
	docker compose up -d c15-cmdi proxy
