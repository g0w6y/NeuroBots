# Deploying NeuroBots

## Local / demo

```bash
cp .env.example .env
docker compose up --build
```

| Service | URL | Published |
|---|---|---|
| Dashboard | http://127.0.0.1:3000 | yes |
| Gateway | http://127.0.0.1:8080 | yes |
| Redis | 127.0.0.1:6379 | yes (dev convenience) |
| PostgreSQL | 127.0.0.1:5432 | yes (dev convenience) |
| Demo upstream API | — | **no, deliberately** |

The demo upstream is not published to the host. It has no authorization checks
at all — that is its purpose — so exposing it would let anyone read every
account while bypassing the gateway entirely. Uncomment the `ports:` block in
`docker-compose.yml` only if you specifically want to demonstrate that.

Without Docker, use `start_all.sh` (macOS/Linux) or `start_all.ps1` (Windows),
then run the dashboard with `cd frontend && npm run dev`.

## Before this goes anywhere real

Six things, in order of how badly they bite:

1. **`JWT_SECRET`.** Anyone holding it can mint a token for any subject with any
   role, which defeats the entire product. Generate one:
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
2. **`ADMIN_API_KEY`.** The only access control on `/admin/*` — metrics, alerts,
   incidents, entities and ownership provisioning. Not CORS. This header.
3. **`CORS_ALLOWED_ORIGINS`.** Defaults to `*`. Set it to your dashboard's exact
   origin.
4. **`POSTGRES_PASSWORD`.** Defaults to `neurobots`.
5. **`TRUSTED_PROXIES`.** Empty by default, which is the safe setting — the
   socket peer is used as the client address. If you deploy behind a load
   balancer you *must* set this to the balancer's address or every client will
   appear to come from the balancer and share one rate-limit bucket. Set it to
   the wrong thing and callers can spoof `X-Forwarded-For` to control their own
   identity, rate-limit bucket and IP cooldown key.
6. **TLS.** Nothing here terminates it. Put the gateway behind a load balancer
   or ingress that does. Bearer tokens over plaintext are not a security
   product.

## Scaling

**The gateway is CPU-bound and single-process as shipped.** `main.py` runs one
uvicorn worker. The measured *decision overhead* is sub-millisecond (see
`BENCHMARK.md`), but single-process throughput is bounded well below what that
overhead implies — the local benchmark measures a few hundred req/s end to end,
not thousands. To scale, run multiple replicas behind a load balancer:

```yaml
gateway:
  deploy:
    replicas: 4
```

Two things must be true before horizontal scaling is correct, and both are why
the in-memory fallbacks are a development convenience only:

- **Redis must be real.** Rate-limit windows, ownership grants and escalation
  cooldowns live there. With the in-memory fallback each replica keeps its own
  copy, so a 120/60s limit becomes 480/60s across four replicas, and an identity
  blocked by one replica is unblocked on the next.
- **PostgreSQL must be real.** Otherwise each replica has a private 500-entry
  audit deque and the dashboard shows whichever one the load balancer happened
  to route to.

Check both at runtime — `/health` reports the true state:

```json
{"shared_store_redis": "connected", "audit_log_postgres": "connected"}
```

If either says `in-memory fallback active` in production, the deployment is
misconfigured regardless of whether requests are succeeding.

Redis and Postgres should be managed services (ElastiCache/MemoryStore, RDS/Cloud
SQL) rather than the compose containers, which have no backup, failover or
resource limits.

## Known gaps

These are real and unresolved. None of them break the demo; all of them matter
before production.

- **Two ML implementations.** `ml/` is wired into every script and the compose
  file. `ml-worker/` is a later, larger implementation (commit `905f401`) that
  nothing starts. One of them should win. Until that is decided, `ml-worker/` is
  dead weight that will drift out of sync with the gateway's alert schema.
- **No CI.** Nothing runs `simulate.py`, `contract-check.mjs` or `benchmark.py`
  automatically. All three are scriptable and exit non-zero on failure, so this
  is a short GitHub Actions workflow away — and without it, a regression in
  detection is found by a human or not at all.
- **No resource limits in compose.** No `mem_limit`/`cpus`. A runaway ML worker
  can starve the gateway on the same host.
- **The frontend bundle is 631 kB** (184 kB gzipped) in one chunk. Fine for a
  LAN demo, worth code-splitting for anything internet-facing.
- **`npm audit` reports 2 vulnerabilities** (1 moderate, 1 high) in dev
  dependencies. They affect the build toolchain, not the served bundle, but they
  should be triaged before release.
- **`PRODUCT.md` claims 8,000+ req/s.** The measured figure on a developer
  laptop with one uvicorn worker is far lower. The sub-millisecond *decision
  overhead* is real and reproducible; the throughput headline is not supported
  by anything in this repo. Either produce a multi-replica benchmark that backs
  it or change the claim.

## Operational checks

```bash
# is it healthy, and is it actually using the real backing services?
curl http://127.0.0.1:8080/health

# lifetime counters and active policy thresholds
curl -H "X-Admin-Key: $ADMIN_API_KEY" http://127.0.0.1:8080/admin/metrics

# is the ML worker's signal actually landing?
curl -H "X-Admin-Key: $ADMIN_API_KEY" http://127.0.0.1:8080/admin/ml-status

# autonomous escalation events
curl -H "X-Admin-Key: $ADMIN_API_KEY" http://127.0.0.1:8080/admin/incidents

docker compose logs -f gateway
docker compose down        # add -v to wipe the Redis/Postgres volumes
```
