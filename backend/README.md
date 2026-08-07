# NeuroBots Zero-Trust API Security Gateway

Fast, deterministic detection of BOLA, BFLA, JWT attacks, and rate abuse.

## Quick Start

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Gateway runs on 0.0.0.0:8080

## Core Features

- JWT validation (signature, expiry, issuer, audience, alg=none defense)
- BOLA detection (object ownership tracking, provisionable ahead of traffic)
- BFLA detection (role-based access control)
- Rate limiting (per-identity, true sliding window, sustained + burst)
- Risk scoring (hard signals + soft signal corroboration)
- Async multi-agent anomaly detection (control plane: profile, sequence, graph, Guardian narrative)
- Autonomous escalation (repeat-offender identities/IPs get an automatic, self-expiring cooldown)
- Durable audit log (PostgreSQL when reachable, in-memory fallback otherwise)
- Admin API (metrics, alerts, incidents, entities, ownership provisioning), key-protected

## Request Flow

1. JWT validation
2. Rate limit check (sliding window, sustained + burst)
3. Route matching + feature extraction
4. BOLA/BFLA/enumeration checks
5. Async anomaly score read (soft signal only)
6. Signal fusion + policy decision
7. Forward to upstream, or deny
8. Alert + (if escalation-eligible) incident logged, both fire-and-forget

## Admin APIs

All require header `X-Admin-Key` matching `ADMIN_API_KEY`.

- GET /health - Gateway status (no key required)
- GET /admin/metrics - Request counts, policy thresholds
- GET /admin/alerts - Recent decisions (Postgres-backed when configured, else last 500 in memory)
- GET /admin/incidents - Autonomous escalation events
- GET /admin/entities - Per-entity profiles
- POST /admin/ownership - Provision real object ownership ahead of traffic

## Configuration

Environment variables in .env:

- JWT_SECRET: HMAC secret for HS256
- UPSTREAM_URL: Target API (default: http://127.0.0.1:9000)
- REDIS_URL: Redis connection (default: redis://127.0.0.1:6379) — optional, falls back to in-memory
- DATABASE_URL: PostgreSQL connection — optional, falls back to in-memory
- ADMIN_API_KEY: key required on all /admin/* routes (default changeme-admin-key, rotate before demoing)

## Team

- Gouri: JWT validation, BOLA/BFLA detection, reverse proxy
- Jeevan: Rate limiting, risk scoring, policy decisions
