# How To Run NeuroBots — Live Demo Guide

Every command below was run, in this exact order, from a genuine clean slate
(no containers, no processes) on 2026-08-08 before this file was written —
nothing here is untested. Run each numbered step in its own terminal so the
logs stay visible during a live demo; that's deliberate, not an oversight
(`start_all.sh` backgrounds steps 3–5 for convenience when you don't need to
watch them, but for a presentation, separate terminals read better).

## Prerequisites (one-time)

```bash
# Python deps
cd backend && pip install -r requirements.txt && cd ..
cd ml && pip install -r requirements.txt && cd ..

# Frontend deps
cd frontend && npm install && cd ..

# TLS dev cert (only needed if you plan to demo TLS_ENABLED=true)
cd backend && ./generate_dev_cert.sh && cd ..
```

Docker is required for real Redis/Postgres (recommended for a real demo —
see "Running without Docker" below if you don't have it).

## The 7 steps, one terminal each

### Terminal 1 — Redis

```bash
docker run -d --name neurobots-redis -p 6379:6379 redis:7-alpine
docker exec neurobots-redis redis-cli PING
```

Expect `PONG`. This is what makes BOLA ownership, rate limits, and
escalation state real and shared instead of single-process in-memory.

### Terminal 2 — PostgreSQL

```bash
docker run -d --name neurobots-postgres -p 5432:5432 \
  -e POSTGRES_USER=user -e POSTGRES_PASSWORD=password -e POSTGRES_DB=neurobots \
  postgres:15-alpine
docker exec neurobots-postgres pg_isready -U user
```

Expect `accepting connections`. Give it 3–5 seconds after `docker run`
before checking — first boot needs a moment.

### Terminal 3 — Demo upstream API

```bash
cd backend
python3 -u demo_upstream.py
```

Expect `Demo upstream API starting on 0.0.0.0:9000`. Verify from another
terminal: `curl http://127.0.0.1:9000/api/accounts/1001` → real JSON with
alice's account (including `ssn`, which the gateway masks later — that's the
point).

### Terminal 4 — Gateway

```bash
cd backend
python3 -u main.py
```

Expect, in order: `Route config: loaded 5 routes...`, `Shared Store: Redis
connected`, `Audit Log: PostgreSQL connected, schema ensured`, `Ownership
seed loaded: 4 grants...`, `Config audit: 5 warning(s)` (expected — these are
the demo-mode default secrets, see `DEPLOYMENT.md`), then `Uvicorn running on
http://0.0.0.0:8080`.

**If you see "Redis unavailable" or "PostgreSQL unavailable" instead**:
Terminal 1/2 aren't ready yet or aren't reachable. The gateway still starts
and works correctly on in-memory fallback — nothing breaks — but you won't
get durable audit history or the ML risk signal. Stop the gateway
(`Ctrl-C`), confirm Terminal 1/2's health checks above pass, then restart it.

Verify: `curl http://127.0.0.1:8080/health` → `200`.

### Terminal 5 — ML worker

```bash
cd ml
python3 -u worker.py
```

**Use `-u` (unbuffered) for every service here, not just this one** —
verified directly: without it, Python's stdout buffering delay is
inconsistent (the gateway's own startup lines were delayed by a few seconds
in one test run, and the ML worker's didn't appear at all for 5+ seconds in
another), and during a live demo a delayed "Redis connected" line reads as
"broken" when it's actually just buffered. All three commands in this guide
already include `-u` for that reason.

Expect immediately: `ML worker: Redis connected` then `ML worker: polling
http://127.0.0.1:8080 every 2.0s`.

**If Redis isn't reachable, don't bother starting this one** — it'll retry
forever and add nothing. Detection works completely without it; it's a
second, independent signal, never a dependency.

### Terminal 6 — Frontend dashboard

```bash
cd frontend
npm run dev
```

Expect `VITE ... ready` and `Local: http://localhost:3000/`. Open that URL.

### Terminal 7 — Generate real demo traffic

```bash
cd backend
python3 attack_sim/simulate.py
```

This is a real attack simulator firing real HTTP requests at the real
gateway — not a fake data generator. Expect a scorecard ending in something
close to:

```
Attack classes detected : 14/14   (100%)
Legitimate requests     : 18/18 correctly allowed
False positives         : 0
```

Refresh the dashboard — it now shows this real traffic: live threat feed,
risk gauge, MITRE matrix, entity table, all reading real gateway data.

**Run this exactly once per gateway start for a clean scorecard.** A second
run within about a minute will show the gateway's own autonomous mitigation
correctly (and confusingly, if you don't know this) locking out the test
traffic's own source IP — that's the product working as designed, not a
bug, but it makes for a confusing live demo. Restart Terminal 4 between
runs if you need to re-run it. Full explanation in `backend/MEMORY.md`.

## Proving specific things during the demo

```bash
# Real ML risk scoring, live
curl -H "X-Admin-Key: changeme-admin-key" http://127.0.0.1:8080/admin/ml-status

# Real executive report, generated on demand
curl -H "X-Admin-Key: changeme-admin-key" http://127.0.0.1:8080/admin/executive-report

# Real config-audit / secure-deployment gate
curl -H "X-Admin-Key: changeme-admin-key" http://127.0.0.1:8080/admin/config-audit

# A real BOLA block, live
curl http://127.0.0.1:8080/api/accounts/1002 \
  -H "Authorization: Bearer $(cd backend && python3 -c "
import time, jwt
from config import settings
now = int(time.time())
print(jwt.encode({'sub':'not_bob','roles':['user'],'iat':now,'nbf':now-10,'exp':now+3600,
  'iss':settings.issuer,'aud':settings.audience}, settings.jwt_secret, algorithm='HS256'))
")"
# -> 403, X-ZT-Decision: block, real BOLA violation against bob's account
# (a stderr "InsecureKeyLengthWarning" about the JWT secret is expected here -
#  it's the same demo-mode default secret config-audit already flags, harmless)
```

## Stopping everything

```bash
# Ctrl-C in terminals 3, 4, 5, 6 (or: pkill -f "demo_upstream.py|main.py|worker.py|vite")
docker stop neurobots-redis neurobots-postgres
docker rm neurobots-redis neurobots-postgres
```

## The one-command alternative

For local dev (not presenting), `./start_all.sh` runs terminals 3–5 for you
with real health checks between each step, and `./stop_all.sh` cleans them
up. It deliberately does not start the frontend (see its own comment) or
Redis/Postgres (bring those up yourself, or it falls back to in-memory —
still fully functional, just without durability or the ML signal).

## Running without Docker

Everything still works with zero Redis/Postgres — skip terminals 1, 2, and
5 entirely. The gateway logs "using in-memory fallback" for both and every
detection still works exactly the same for a single process. What you lose:
durable audit history across restarts, the ML risk signal, and correctness
under `WORKERS > 1` (see `DEPLOYMENT.md` — multi-worker mode specifically
requires Redis).

## Known caveat, disclosed not hidden

Under the full real-stack configuration above (real Redis + a live ML
worker), gateway decision latency is measurably higher than the
in-memory-only numbers elsewhere in this repo — real round-trips to Redis
add up across the several sequential calls one request makes (rate limit,
BOLA, ML risk lookup). Measured p50 ~3ms, p99 ~13ms, occasionally touching
the 15ms budget at the max. Still functionally correct and still fast in
absolute terms; the honest, current numbers (not the best-case ones) are in
`backend/PERFORMANCE.md`, along with root cause and a scoped fix.
