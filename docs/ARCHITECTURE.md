# NeuroBots Architecture

## The shape of it

NeuroBots is a reverse proxy that sits in front of an API and decides, per
request, whether the caller is allowed to do what they are asking. Everything
else in the repo exists to support, observe or prove that one decision.

```
                    ┌──────────────────────────────────────────┐
   browser ────────▶│  Dashboard (React/Vite, nginx :3000)     │
                    └───────────────────┬──────────────────────┘
                                        │ polls /admin/* every 2s
                                        │ (X-Admin-Key)
                                        ▼
   API client ─────▶┌──────────────────────────────────────────┐
   (Authorization:  │  GATEWAY  (FastAPI, :8080)               │
    Bearer <jwt>)   │                                          │
                    │   1. JWT validation                      │
                    │   2. rate limit (sliding window)         │
                    │   3. route match + feature extraction    │
                    │   4. BOLA / BFLA / enumeration checks    │
                    │   5. read ML anomaly score  (soft)       │
                    │   6. signal fusion → allow/challenge/    │
                    │      block                               │
                    │   7. forward, or deny                    │
                    │   8. write alert + incident (async)      │
                    └────┬────────────┬──────────────┬─────────┘
                         │            │              │
              allow only │            │ state        │ audit
                         ▼            ▼              ▼
              ┌────────────────┐  ┌────────┐  ┌────────────┐
              │ Upstream API   │  │ Redis  │  │ PostgreSQL │
              │ (demo_upstream │  │ :6379  │  │   :5432    │
              │  :9000)        │  └───┬────┘  └────────────┘
              │ NO auth checks │      │
              └────────────────┘      │ ml_risk:{subject}
                                      ▲
                    ┌─────────────────┴────────────────────────┐
                    │  ML WORKER (separate process)            │
                    │   polls /admin/alerts                    │
                    │   per-entity IsolationForest             │
                    │   Markov sequence model                  │
                    │   NetworkX access graph                  │
                    └──────────────────────────────────────────┘
```

## Why the pieces are separated this way

**The upstream API has no security code in it.** `backend/demo_upstream.py` is
deliberately vulnerable — no auth, no ownership checks. That is the entire
demonstration: the gateway protects an API that does nothing to protect itself,
without that API being modified. If detection logic leaked into the upstream,
the demo would prove nothing.

**The ML worker is never on the request path.** It is a separate process that
reads the gateway's alert history and writes scores into Redis. The gateway
reads those scores as one *soft* signal among several. Kill the worker and the
gateway behaves exactly as it did before the worker existed — detection does not
degrade, it just loses a corroborating input. This is why the ML worker cannot
cause an outage, and why it does not need to be fast.

**Hard signals decide; soft signals corroborate.** A failed JWT signature or an
ownership mismatch is dispositive on its own. A behavioural anomaly is not — it
can only push a request that already looks suspicious over a threshold. This is
the whole reason the false-positive rate stays at zero: no request is ever
blocked purely because a model found it unusual.

**Redis and PostgreSQL are optional.** Both have in-memory fallbacks, chosen at
startup and reported in `/health`. Losing Redis costs cross-restart persistence
and multi-instance sharing; losing Postgres costs durable audit history. Neither
stops the gateway from making correct decisions. The one thing that genuinely
needs real Redis is the ML worker, because Redis is the only channel between two
separate processes.

## The decision pipeline

Order matters, and it is cheapest-and-most-decisive first:

| # | Stage | Kind | Notes |
|---|---|---|---|
| 1 | JWT validation **+ revocation** | hard | signature, `exp`, `nbf`, `iss`, `aud`, `alg=none` defence, then `jti` denylist |
| 2 | Rate limiting | hard | per identity; sustained (120/60s) **and** burst (25/3s) |
| 3 | Route match / feature extraction | — | from `routes.json`, read at startup |
| 4 | BOLA | hard | does this subject own this object? |
| 5 | BFLA | hard | does this subject hold the required role? |
| 6 | Enumeration | hard | 8 distinct objects inside 10s |
| 7 | ML anomaly | **soft** | read from Redis, never blocks alone |
| 8 | Fusion + policy decision | — | score ≥ 70 block, ≥ 45 challenge |
| 9 | Enforce | — | forward upstream, or 401 challenge / 403 block |
| 10 | **Response inspection (API3)** | **soft** | over-serving, cross-tenant and bulk exposure |
| 11 | Emit event (async) | — | alert + incident, fire-and-forget |
| 12 | Escalation | hard | 3 blocks in 60s → self-expiring cooldown |

Thresholds live in `backend/routes.json` under `policy` and in `config.py`.

### Revocation (step 1)

The `jti` denylist is checked **after** the signature verifies, never before.
Order is a security property here: the `jti` is attacker-controlled input until
the signature proves otherwise, so checking it first would let anyone probe the
denylist for valid token ids, and would let a forged token with a guessed `jti`
reach the store. A token that fails validation is already rejected on its own
merits, so nothing is lost by checking later.

Entries self-expire at the revoked token's own `exp`. A revoked token that has
expired naturally is already rejected by the expiry check, so keeping its `jti`
past that point grows the denylist forever without adding protection.

A revoked token scores 90 — the same as a forgery. It is cryptographically
perfect, which is exactly why: presenting one means the credential was stolen
after revocation, or a killed session is being replayed. Neither deserves a
step-up challenge.

### Response inspection (step 10)

Every other check runs on the request and asks *"should this caller reach this
endpoint?"*. This one runs on the response and asks what no request-side check
can: *"did the upstream hand back more than this caller should see?"*

That covers OWASP **API3:2023**, the one category the gateway previously missed.
It matters because the request can be entirely legitimate — your own account,
your own token — and the response still leaks a password hash, a national id or
another tenant's record, because the upstream returns its whole row and trusts
the client to hide the rest.

Three findings, all **soft**:

| Detector | Fires when |
|---|---|
| `excessive_data_exposure` | response contains a field on the sensitive-name list |
| `cross_tenant_data_exposure` | response names an owner, and none of them is the caller (skipped for admins) |
| `bulk_data_exposure` | more than 50 records returned to a non-admin |

They are soft, and the decision is deliberately **not** recomputed after they
fire. By the time the gateway can see the body the upstream has already produced
it; re-scoring into a block would report a block that never happened. What this
buys is the audit record and the corroboration it lends to that entity's *next*
request — which is where the signal can actually act.

Detection is conservative on purpose, because this fires on traffic that already
passed authorization: sensitive fields match exact key names rather than
substrings, cross-tenant is reported only when an owner field genuinely
disagrees with the caller, and inspection is skipped above 512KB. A false
positive here means blocking a real user on a legitimate read — the exact
failure this gateway is measured on.

## Configuration surface

`backend/routes.json` is the piece worth understanding. It is the route table,
read at startup, and adding an entry there is what gives a path object-level and
role-level rules — no code change, no redeploy. Anything under a protected
prefix that is *not* listed still requires a valid token; listing it is what adds
authorization on top of authentication.

Everything else is environment variables, read by `config.py` through
pydantic-settings. See `.env.example`.

## Two ML implementations

The repo currently contains two:

- **`ml/`** — the one that is wired in. Referenced by `README.md`,
  `start_all.sh`, `start_all.ps1`, `docker-compose.yml` and `DEVOPS.md`. Five
  dependencies. This is what runs.
- **`ml-worker/`** — a later, larger, more structured implementation (config /
  core / events / features / anomaly / markov / graph / profiling packages, its
  own test suite, 19 dependencies). Added in commit `905f401`.

Nothing currently starts `ml-worker/`. This duplication is unresolved and is the
one genuine architectural loose end in the repo — see `docs/DEPLOYMENT.md`.

## Trust boundaries

| Boundary | Enforced by | Notes |
|---|---|---|
| API caller → gateway | JWT signature | `JWT_SECRET`; anyone holding it can mint any identity |
| Dashboard → `/admin/*` | `X-Admin-Key` header | the real boundary — **not** CORS |
| Browser origin | CORS | defaults to `*` for demo convenience; tighten in production |
| Client IP | socket peer | `X-Forwarded-For` is only believed from `TRUSTED_PROXIES` |

That last row is subtler than it looks. The client address decides the anonymous
identity, the rate-limit bucket and the IP cooldown key. Believing an
unvalidated header hands an attacker all three, so by default no proxy is
trusted and uvicorn's own `proxy_headers` is configured to match.
