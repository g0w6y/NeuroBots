# Deployment Hardening Guide

For anyone taking this past the demo. Every claim below was verified
2026-08-08 against the actual running gateway, not written from assumption —
see the specific commands to reproduce each check yourself.

## 1. Rotate every default secret, then prove it

Five things ship with demo defaults specifically so the hackathon setup
needs zero configuration. None of them are safe past that:

| Setting | Demo default | Rotate to |
|---|---|---|
| `JWT_SECRET` | `demo-hs256-secret-change-me` | A real ≥32-byte random secret, or switch to `JWT_RSA_PUB_PEM` for asymmetric verification |
| `ADMIN_API_KEY` | `changeme-admin-key` | A real random key — this is the only thing gating every `/admin/*` route |
| `DATABASE_URL` | `postgresql://user:password@localhost/neurobots` | Real credentials, least-privilege (this account only needs `INSERT`/`SELECT` on `alerts` and `incidents`) |
| `CORS_ALLOWED_ORIGINS` | `*` | The dashboard's actual origin(s), comma-separated |
| `TLS_ENABLED` | `false` | `true`, with a real CA-issued cert — `generate_dev_cert.sh`'s self-signed one is for local dev only |

**Don't trust a checklist alone — prove it.** Set `REQUIRE_PRODUCTION_SECRETS=true`
and the gateway will refuse to start (exit code 3, not a silent warning) if
any of the five are still at their demo default:

```
FATAL: REQUIRE_PRODUCTION_SECRETS=true but insecure defaults are still in place:
  - JWT_SECRET is still the default demo value - rotate before any real deployment
  ...
Refusing to start.
```

Verified both directions on 2026-08-08: refuses to start with any default in
place, starts clean over real HTTPS once all five are rotated (confirmed via
`GET /admin/config-audit` returning `"clean": true, "warning_count": 0`).
Also runnable any time without the fail-closed behavior — `GET
/admin/config-audit` reports the same five checks as warnings, for a
dashboard or CI step that wants to know without stopping the process.

### Secrets manager integration

No code changes needed for this part — every setting above is a
`pydantic_settings.BaseSettings` field, which already reads from environment
variables (`config.py`). Any secrets manager that can inject environment
variables into the process works out of the box:

- **AWS**: ECS task definition `secrets` block pulling from Secrets Manager
  or Parameter Store, or the Secrets Manager CSI driver on EKS.
- **HashiCorp Vault**: the Vault Agent Injector sidecar pattern, templating
  secrets to a file the container sources before launch, or `vault agent`
  writing directly to the process environment.
- **Kubernetes**: native `Secret` objects mounted as environment variables
  via `envFrom`.

This repo doesn't integrate against any of these directly — there's no real
cloud infrastructure to test that against — but the settings layer was
already built to make that integration a deployment-config problem, not a
code problem, and that boundary is now verified: `config.py` never reads a
value except via `os.environ` (through pydantic), so nothing here can
accidentally read a secret from a file, a hardcoded fallback, or anywhere
that a real secrets manager's env-injection wouldn't reach.

## 2. Horizontal scaling — verified, with one real, disclosed limitation

`WORKERS=N` (new) makes the gateway run N real OS-level worker processes
instead of one (`main.py`'s `uvicorn.run("main:app", workers=N, ...)`).
**Only correct with Redis reachable.** Verified both ways on 2026-08-08,
with real Docker Redis/Postgres and `WORKERS=3`:

- **Methodology note, because it matters**: an `httpx.Client` reuses one
  persistent TCP connection by default, which pins every request to
  whichever single worker process happened to accept that connection first —
  a test built that way "passes" even with completely broken cross-worker
  state, because it never actually exercises more than one worker. Every
  result below used a fresh connection (`Connection: close`) per request
  specifically to force real distribution across all 3 processes; a first
  pass using a reused connection produced a false pass and was caught and
  redone before being trusted.
- **Rate limiting, with Redis**: a single identity's burst limit (configured
  at 25/3s) was correctly enforced at exactly request #26, matching a
  single-process result precisely — proof the 3 processes share one counter,
  not three independent ones.
- **Rate limiting, without Redis** (forced via an unreachable `REDIS_URL`):
  the same test didn't trip until request #45 — diverged, as expected, since
  each worker's in-memory fallback is process-local and has no way to see
  the others' counts.
- **BOLA ownership, with Redis**: one identity's first-touch ownership of an
  object correctly blocked a different identity's access to it, regardless
  of which of the 3 processes served either request.
- **Autonomous escalation, with Redis**: a real `auto_block_escalation`
  incident fired and was durably recorded via Postgres after the 3rd hostile
  block, exactly matching the configured threshold, regardless of which
  worker handled which of the individual requests.

**The one real limitation found and not yet fixed: live WebSocket push
(`/ws/events`) does not fan out across workers.** `EventHub`'s subscriber
set is in-process Python state (`main.py`) — a dashboard's WebSocket
connection is pinned to whichever single worker accepted it, and only sees
events that same worker happens to process. The REST polling endpoints
(`/admin/alerts`, `/admin/metrics`, etc.) are unaffected — they read from
Postgres, which every worker writes to identically — so a dashboard relying
on the polling fallback (already built for exactly this kind of degradation)
sees complete data regardless of worker count. Fixing WebSocket fan-out
properly needs a shared pub/sub backplane (Redis pub/sub is the natural
choice, already in the stack) — scoped as a real follow-up, not attempted
here this close to the deadline given the polling fallback already covers
the same data correctly.

## 3. Network exposure

- `/admin/*` is gated by `X-Admin-Key` (constant-time comparison,
  `hmac.compare_digest`), but the stronger posture is not relying on that
  alone — put it behind a network boundary (VPC-internal, or a reverse-proxy
  rule) so it's never reachable from the public internet at all, key or not.
- FastAPI's auto-docs (`/docs`, `/redoc`, `/openapi.json`) are disabled
  entirely (`docs_url=None` etc. in `main.py`) — this was a real bug found
  and fixed during the team's reconciliation, not a default FastAPI gives
  you; don't re-enable it in a fork without re-adding auth in front of it.
- `TRUSTED_PROXIES` must list your actual load balancer/reverse proxy
  address(es), comma-separated. Left empty (the default), `X-Forwarded-For`
  is never trusted and the raw socket peer is used for rate limiting, BOLA
  ownership keys, and IP-level escalation — correct for a direct-exposed
  deployment, but means a real deployment behind a real LB needs this set,
  or every request will appear to originate from the LB's own IP and share
  rate-limit/escalation state across all real clients.

## 4. What's still genuinely open after this pass

- WebSocket fan-out across workers (see §2) — polling still works correctly
  as a fallback, this only affects the live-push dashboard experience under
  `WORKERS > 1`.
- No secrets-manager integration has been run against real infrastructure —
  the boundary is verified correct (§1), the actual integration hasn't been.
- Sustained multi-worker load over minutes/hours (memory growth, connection
  leak checks) — the verification above is correctness under a short,
  targeted test, not a soak test.
