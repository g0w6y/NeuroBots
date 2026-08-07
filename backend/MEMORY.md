# Project Memory — NeuroBots Zero-Trust API Security Gateway

Status doc for team continuity. Last updated 2026-08-08. Read this before making changes so you don't redo or undo work that's already been fixed and verified.

## Reconciliation with Nirmal's parallel rewrite (2026-08-08)

Nirmal (working with Claude Opus 5) independently rewrote large parts of this
same codebase in parallel with the 5-feature build below, and pushed first.
Rather than force-push over his work or attempt a blind git merge, his branch
was taken as the new base and every addition below was replayed on top of it,
then re-verified against *his* code, not re-assumed from earlier testing
against mine. His changes fixed real bugs mine had not caught:

- `auth.py`: a JWT with no `exp` claim was previously treated as valid
  forever; now a hard `jwt_no_expiry` signal (weight 85). `aud` is compared
  correctly whether the claim is a string or an array (RFC 7519). `roles` is
  coerced from string/null instead of crashing or iterating it character by
  character.
- `store.py`: ownership writes were Redis-*or*-memory — a live Redis failure
  mid-session silently zeroed out BOLA protection for every object touched
  after that point. Now written through to both simultaneously. Added a
  `_keeper_loop()` background task that redials Redis every 5s and sweeps
  entities idle >15min, so an outage self-heals without a process restart —
  see High Availability below.
- `main.py`: FastAPI's auto-docs (`/docs`, `/redoc`, `/openapi.json`) were
  reachable without auth — an admin-surface exposure. Now disabled entirely.
  Response passthrough was re-wrapping upstream bytes in `JSONResponse`,
  which corrupts non-JSON bodies and drops headers — now relayed raw.
  `X-Forwarded-For` was trusted unconditionally, meaning any caller could
  spoof their source IP and dodge both the rate limiter and the IP-level
  autonomous-escalation threshold — now only trusted from configured
  `trusted_proxies`. Route table externalized to `routes.json`; an unmatched
  path under a protected prefix now fails *closed* (`UNLISTED_PROTECTED_ROUTE`)
  instead of silently skipping authorization.
- `seed_ownership.json`: pre-provisions real ownership of the three demo
  accounts (1001→alice, 1002→bob, 1003→carol) at startup, closing the
  BOLA "first-touch" ground-truth gap for the demo dataset specifically.
  **If you write a test against these accounts with a throwaway identity,
  you will get a real BOLA block — that's correct behavior, not a bug.**
  Authenticate as the actual seeded owner instead.
- `audit_log.py` did not yet have the reconnect-loop pattern `store.py`
  gained — ported the same `_keeper_loop()` shape into it (15s interval,
  `SELECT 1` liveness check, redial on failure). See High Availability below.

## Five features built to close real gaps found in a requirements cross-check (2026-08-08)

Cross-checked against the official hackathon problem statement and the
reference architecture artifact; five items came back explicitly not done.
All five are now real and individually verified end to end against Nirmal's
(reconciled, harder-to-fool) codebase, not just against the earlier version.

**OWASP API Top 10 coverage, API3/API7/API8/API9 (`security_checks.py`, new file)**
- API3 (excessive data exposure): `SENSITIVE_FIELDS` policy masks `ssn`/
  `tax_id` in response bodies for any non-admin caller. Wired into
  `check_and_forward()` right after the upstream response comes back;
  `main.py`'s `gateway()` handler now returns the *redacted* body, not the
  raw upstream one, when a violation is found. Verified: alice (a real
  seeded owner, non-admin role) reading her own account gets a 200 with
  `ssn` masked to `*******6789` and `balance` untouched — allowed *and*
  redacted, not blocked, because BOLA and API3 are separate axes.
- API7 (SSRF): recursively scans JSON request bodies for URL-shaped strings
  targeting RFC1918/link-local/loopback addresses, including
  `169.254.169.254` (cloud metadata). Hard signal, weight 90. Verified with
  a `webhook_url` pointed at the metadata IAM credentials path — blocked.
- API8 (security misconfiguration): `audit_config(settings)` runs at
  startup and is exposed at `GET /admin/executive-report`'s sibling
  `GET /admin/config-audit` — flags default JWT secret, default admin key,
  wildcard CORS, TLS disabled, default DATABASE_URL. Also added a
  `security_headers_middleware` (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `X-Permitted-Cross-Domain-Policies`, plus HSTS when
  TLS is on) applied to every response.
- API9 (improper inventory management / shadow endpoints): any request that
  matches `UNLISTED_PROTECTED_ROUTE` (an `/api/` path not in `routes.json`)
  now also emits a soft `shadow_endpoint_signal` (weight 30) in addition to
  the existing fail-closed authorization block — makes shadow-API traffic
  visible in alerts, not just rejected silently.
- API10 (unsafe consumption of third-party APIs) deliberately NOT attempted
  — this gateway is an inbound reverse proxy; it doesn't consume other
  APIs on the tenant's behalf, so API10 isn't a meaningful axis here.

**Executive reporting (`executive_report.py`, new file)**
`generate_executive_report(alerts, incidents)` — deterministic aggregation
over real audit-log data: block rate, OWASP breakdown, MITRE breakdown, top
risky entities, most-blocked entities, autonomous mitigation events, and a
template-generated narrative. Deliberately **not a live LLM call** — same
principle as the Guardian narrative in agents.py: a verdict-adjacent report
must never be hallucinated. Exposed at `GET /admin/executive-report`.
Verified against real accumulated data from the attack_sim suite's own run.

**High availability (`store.py` + `audit_log.py` `_keeper_loop()`)**
Both Redis and Postgres now self-heal: a background task redials every
5s/15s respectively and flips `connected` back on reconnect, with no
process restart required and no request ever blocked waiting on it — every
call already degrades to the in-memory/deque fallback when disconnected.
`store.py`'s loop is Nirmal's; `audit_log.py`'s was ported to match it
during reconciliation. HA was re-verified for `audit_log.py` specifically
(kill Postgres mid-session, confirm fallback, bring it back, confirm
reconnect within one interval) but **not yet re-run against the fully
reconciled tree in this specific pass** — worth a final confirmation before
the demo if there's time.

**End-to-end encryption in transit (`generate_dev_cert.sh` + `config.py` + `main.py`)**
`tls_enabled` (default off, so local dev needs no setup) wires
`ssl_certfile`/`ssl_keyfile` into uvicorn. `generate_dev_cert.sh` makes a
local self-signed cert for demo/dev; use a real CA-issued cert in
production. Verified: plain HTTP refused when enabled, HTTPS with the dev
cert succeeds. Encryption at rest is explicitly out of scope here — no raw
credentials or unredacted PII are stored (see API3 above for the latter);
disk/RDS-level encryption is an infrastructure responsibility, not
something meaningfully added by application code.

**Attack Simulation Suite (`attack_sim/simulate.py`)**
This is Nirmal's file (9 numbered cases: BOLA, BFLA, missing token, alg=none,
wrong-key signature, expired JWT, bad issuer/audience/malformed token,
enumeration, burst abuse), extended during reconciliation with two more
cases exercising the two detectors above that his suite didn't cover yet:
- Case 11 — SSRF via a `webhook_url` field pointed at the metadata endpoint.
- Case 12 — API3 exposure: alice reads her own seeded account, asserts the
  response is *both* allowed (real owner) *and* has `ssn` masked in the body
  — the one case in the suite that inspects response-body content instead
  of just the `X-ZT-Decision` header.
Also has a `phase_behavioural` low-and-slow case already numbered 10 — the
new cases were numbered 11/12 to avoid colliding with it.

Latest clean run (fresh gateway process, single pass): 14/14 attack classes
detected, 18/18 legitimate requests correctly allowed, 0 false positives,
p50 0.05-0.08ms / p99 0.5-0.6ms decision overhead, all inside the 15ms budget.

**Important, verified operational limit:** run this suite exactly once per
gateway process. `phase_attacks` alone produces ~9-10 hard, hostile-classified
blocks from one real source IP, right at `auto_block_ip_threshold` (10/60s).
Confirmed by running it twice back to back against the same live gateway:
the second run's case 6 (expects "challenge") comes back "block", and a
third run produced a genuine collateral false positive (bob's own benign
request blocked) — both traced via `/admin/incidents` to real
`auto_block_escalation` events against `ip:127.0.0.1` and identity `bob`.
This is the autonomous-mitigation system working correctly, not a detection
bug — the suite's own repeated traffic genuinely looks like a coordinated
attack from one IP. It does mean `--loop` (documented in the file, "repeat
forever, for a live demo") is **not safe to use as shipped** against a
gateway with real auto-mitigation enabled — every pass past the first will
show worsening spurious failures and can lock the demo machine's own IP out
for 5-10 minutes. Full caution note is in `attack_sim/simulate.py`'s module
docstring. Deliberately not "fixed" by isolating each attack behind its own
spoofed IP — that would defeat phase 4's actual purpose (proving a barrage
from your own machine doesn't collaterally block your own legitimate
traffic), and retuning the auto-mitigation threshold this close to the
deadline is a real policy call the team should make together, not something
to change unilaterally.

## What this is

A gateway that sits in front of an API and blocks authorization attacks in real time: BOLA, BFLA, JWT tampering, rate abuse. Two-plane design — fast deterministic checks inline (data plane), async behavioral anomaly detection in the background (control plane / multi-agent layer), plus an autonomous escalation layer that remembers proven attackers across requests instead of re-deciding from scratch every time.

## Real ML worker (new, closes a real plan-vs-reality gap)

`ML.md` planned a real machine-learning system: per-entity IsolationForest
(scikit-learn), Markov chain sequence modeling, NetworkX graph analysis. What
existed before this was `agents.py` - genuinely useful, genuinely tested, but
hand-written threshold rules, not ML. That gap is now closed for real: `ml/`
(sibling to `backend/` in the NeuroBots repo, deliberately NOT nested inside
`backend/` - `ML.md`'s own docker-compose treats it as a separate top-level
service, and nesting it would also create an import collision with
`backend/config.py`) is a standalone async worker doing exactly what was
planned - see `ml/README.md` for the full detail.

Gateway-side change: `store.get_ml_risk()` (new) reads `ml_risk:{subject}` from
the same shared Redis, and `main.py` adds it as a second, genuinely independent
soft signal (`ml_anomaly`) alongside the existing `control_plane_anomaly`. This
is what makes `fuse_signals()`'s "2+ soft signals required to block" rule
reachable for the first time - with only one soft-signal source, that path was
structurally dead code no matter how the code looked.

Verified end to end against a real running stack (real gateway, real disposable
Redis via Docker, the ML worker as an actual separate process) - not unit-tested
in isolation. Confirmed: the worker ignores its own startup backlog correctly, a
genuine BOLA attack (attacker targeting a victim's already-owned object)
produces zero training data and zero graph edges for the attacker, legitimate
traffic produces a real trained model and gets written to Redis, and the
gateway correctly reads a real score back and adds the signal (confirmed via a
manually-seeded high score triggering a real challenge decision).

Found and documented a real calibration caveat while testing: an
IsolationForest trained on ~15 samples of pure repetitive legitimate traffic
scored 0.767 (moderately "anomalous" for traffic that should look boring) -
small-sample IsolationForest scores are inherently noisy. Raised the minimum
sample floor, but the real protection is structural: `ml_anomaly` is always a
soft signal, never blocks alone. See `ml/README.md` for the full reasoning -
don't rely on threshold-tuning alone to fix this class of noise.

## Frontend connection + demo upstream

Connected to the real dashboard (neurobots-frontend / NeuroBots repo's frontend/) this
session, not just built alongside it. Found and fixed three real bugs that only show up
when something outside this process actually consumes the responses: no CORS (browsers
can't call a cross-origin API without it), a naive-timestamp bug (datetime.utcnow().isoformat()
has no timezone marker, so a browser's `new Date(...)` reads it as local time - verified
5.5 hours off in IST, silently broke the dashboard's timeseries chart), and the frontend
was defaulting to a port that hasn't existed since an earlier cleanup. All fixed, verified
against real captured traffic through the real running app, not assumed.

Also added `demo_upstream.py` - a small, real, working sample API (in-memory accounts,
transactions, transfers, users) for the gateway to forward "allow" decisions to. Before
this, every legitimate request correctly got forwarded and then 502'd, because nothing
was listening at UPSTREAM_URL. The gateway's decisions were never fake - there was just
nothing real behind it to complete the round trip, which looks broken in a demo even
though it's correct. Not part of detection logic at all; skipping it changes nothing
about what the gateway blocks or allows, only what a legitimate request gets back.

## Reference design this follows

An artifact defined the canonical 9-step flow and the multi-agent layer. Ground truth, not guessed:

**9 steps:** validate JWT + revocation → rate limit (early) → extract features → authorize (BOLA/BFLA) → risk score (cached ML) → policy decision → enforce → inspect response (API3) → emit event (async).

**4 agents (async, never block a request):** profile, sequence, graph, LLM (Guardian narrative).

## Status against that flow

| Step | Status |
|---|---|
| JWT validation | Done. Revocation not implemented (no real IDP to source revocation events from). |
| Rate limit (early) | Done. True sliding window, sustained + burst, Redis-backed with in-memory fallback. |
| Extract features | Done. Route matching does real pattern extraction now (was broken — see Fixed Bugs). |
| Authorize BOLA/BFLA | Done, with a disclosed gap — see BOLA ground truth below. |
| Risk score (cached ML) | Done, and now actually reachable — see "Control plane was inert" below. Soft signal only; corroboration is enforced in `fuse_signals()` as of this session, it previously was not. |
| Policy decision | Done. Hard signal → block. 2+ corroborating soft → block. Single soft → challenge. |
| Enforce | Done. Was double-forwarding to upstream on every allowed request — fixed. |
| Inspect response (API3) | Done (2026-08-08). `security_checks.py` masks sensitive fields (`ssn`, `tax_id`) in response bodies for non-admin callers. See "Five features" above. |
| Emit event (async) | Done. Fire-and-forget, never blocks the response. Now durably persisted too — see audit_log.py in Architecture notes. |

**Multi-agent layer:** profile, sequence, graph all done (agents.py) — and, as of
2026-08-08, actually consumed by the request path rather than computed and
discarded. Do not read the old "done" as "working"; it was implemented and inert. Guardian is done but deliberately **not a live LLM call** — deterministic narrative template over the Signal list, so a security verdict can never be hallucinated. That was a conscious choice, not a shortcut — an LLM writing security verdicts is exactly the wrong place to introduce hallucination risk.

**Autonomous mitigation:** built on top of the reference flow, not in it originally. The system had no memory of a proven attacker between requests until this was added — entity.blocked existed as a field but nothing ever set it. Now: 3 confirmed *hostile* violations from a verified identity within 60s → cooldown (self-expiring, progressive on repeat offenses). Source IP escalates too, but at a much higher threshold (10, not 3) specifically to avoid punishing users sharing a NAT/proxy with an attacker.

## Control plane was inert, and fixing it exposed a second bug (2026-08-08)

Both found by running the real app and reading the alerts it produced, not by inspection.

**1. The whole multi-agent layer never reached a decision.** `get_enriched_risk()`
returned `None` outright whenever Redis was unreachable — which is the *documented
default* configuration, since Redis is optional everywhere else. So the profile,
sequence and graph agents computed anomaly scores once a second and nothing ever
read them. Step 6 of the 9-step flow was a no-op in every demo anyone has run.
Evidence: `control_plane_anomaly` fired **0 times across 69 alerts**, in a run that
included an 8-object enumeration and a 30-request burst — traffic the sequence and
volume detectors both score 75–85. The deterministic checks caught all of it
anyway, which is exactly why this never surfaced as a missed detection; it surfaced
as a headline feature contributing nothing. Fixed with a local cache mirroring the
Redis one, the same degrade-to-memory pattern `store.py` and `audit_log.py` use.

**2. A single heuristic could block a real user.** This only became reachable once
(1) was fixed. The documented policy is "hard → block; 2+ corroborating soft →
block; single soft → challenge", but `fuse_signals()` never encoded the
corroboration rule — it compared the fused score against the block threshold, and
both live soft detectors peak above it (sequence 80, volume 75). Verified against
the running gateway: a legitimate subject that merely sped up (22 req/10s against
its usual 5 — under the 25/3s burst limit *and* the 120/60s sustained limit,
nothing forged, nothing it did not own) produced a bare `control_plane_anomaly`
and 11 challenged requests. Had the anomaly scored 5 points higher it would have
been 11 blocks. `fuse_signals()` now requires either a hard signal or 2+ soft
signals before `block` is reachable; a lone inference caps at `challenge`.

Note that `attack_sim/simulate.py` reports 0 false positives either way — its
legitimate phases never vary their pace, so they never exercise the behavioural
layer at all. A clean scorecard from that suite is not evidence about this class
of bug.

## Two real false positives found in autonomous mitigation, both fixed

1. Escalation originally counted *every* block reason, including routine non-malicious friction: an expired token retried a couple of times, a missing-auth-header request, a frontend bug calling an endpoint the wrong role. Fixed — only signals that require deliberately forged/scripted input count now (bola_cross_user, bola_enumeration, jwt_alg_none, jwt_alg_confusion, jwt_bad_signature, jwt_malformed, rate_limit_burst).
2. Unauthenticated/invalid-token traffic (anon:{ip}) was going through the *low* identity threshold (3) instead of the *high* IP threshold (10) — silently reintroducing the exact NAT/shared-IP collateral risk the higher threshold was raised to prevent. Fixed — identity-level escalation now only applies to a cryptographically verified subject.

Both found by actually running requests through the app and checking the result, not by reasoning in the abstract. If you touch the escalation logic in main.py, re-run that kind of test before trusting a change — this class of bug does not show up by inspection.

Important scope note for anyone worried these fixes weakened detection: they only ever touched what feeds the escalation counter, never `fuse_signals()` itself. The per-request block/challenge/allow decision is exactly as strict as before — an expired token, a BFLA violation, a rate-limit hit still blocks that individual request every time. Only "should this also lock the identity out for 5+ minutes" changed.

## Fixed bugs, in case you're wondering why something looks different than you remember

- Route matching was a literal dict-key lookup against strings like `/api/accounts/{id}` compared to a real path like `/api/accounts/1001` — never matched. BOLA/BFLA/enumeration never ran on any real request until this was fixed. Now `match_route()` does real segment-pattern matching.
- BOLA was dead code even where routes did match — ownership was recorded *before* the check ran, so the check always read back what it had just written.
- Enumeration counted lifetime history with no time window — a legit user touching 8 accounts over a whole day got permanently blocked forever after.
- Rate limiting counted "requests ever, capped at 300" — not a real sliding window. Any user crossing 120 cumulative requests got rate-limited forever regardless of actual pace.
- Admin API (`/admin/*`, `/health`) was completely unreachable — the catch-all gateway route was registered before them, so Starlette matched the catch-all first every time and silently proxied admin requests to a nonexistent upstream. These endpoints never worked, full stop, until route order was fixed.
- Admin API was also unauthenticated once reachable — added `X-Admin-Key` header check.
- Double-forward bug: an allowed request got forwarded to upstream twice (once in check_and_forward, again in the route handler). For `POST /api/transfers` that meant every allowed transfer executed twice against upstream. Fixed — response object is reused, not re-fetched.
- `datetime.utcnow()` was silently broken in this environment for JWT nbf/exp comparison — replaced with `time.time()`.

## BOLA ground truth — known limitation, not fully closeable

Ownership is inferred from "who the gateway saw touch this object first," not from a real backend's ownership records. An attacker who guesses an object ID before its real owner's first request through this gateway becomes the recorded "owner." Mitigated, not solved:
- `seed_ownership.json` at repo root, loaded at startup, to pre-provision known ownership.
- `POST /admin/ownership` to provision ownership as resources are created (call this from wherever your real backend creates a resource).
- `bola_strict_mode` config (default off) — when on, denies by default on any unprovisioned object instead of granting first-touch ownership.

Full fix needs a real backend's ownership data behind this gateway. Don't invent a workaround without checking with the team first — the wrong access-control policy here (e.g. a blanket admin-role bypass) can open a worse hole than the one it closes.

## Architecture notes

- `store.py` — shared state (BOLA ownership, rate-limit windows, enumeration windows, escalation state). Real Redis when reachable (SADD/SISMEMBER/SCARD for ownership, ZADD/ZCOUNT sliding windows), equivalent in-memory fallback when not. Verified both paths independently — the fallback with the actual disconnected Redis in this environment, the Redis path with `fakeredis` standing in for a real server. A uniqueness-key bug (`id(now)` collisions) was caught during that verification and fixed with a proper monotonic counter — worth remembering if you add new Redis-backed counters here, don't reach for `id()` as a uniqueness source.
- `agents.py` — the async control plane / multi-agent layer. Shares one Redis connection with `store.py` via `control_plane.use_client()`, doesn't dial twice.
- Single-process only. Multi-worker (`uvicorn --workers N`) deployment is now *safe* with Redis reachable (state is shared), but has never actually been tested running that way — only single-process, verified.
- `audit_log.py` — durable persistence for alerts and incidents. Real PostgreSQL when reachable (schema auto-created on startup, indexed on subject/timestamp/decision), in-memory deque fallback (500/200 cap) when not — same pattern as store.py's Redis handling. Writes are fire-and-forget, never add latency to the response. Verified against a real disposable Postgres in Docker (rows confirmed durable by querying the database directly, independent of the app's own connection, after the app had shut down), and separately verified the fallback path with a deliberately unreachable DSN. `/admin/metrics` now runs a real SQL aggregate when Postgres is connected, not a Python sum() over a capped deque — accurate lifetime counts, not "count of whatever's still in the last 500."
- Default secrets (`demo-hs256-secret-change-me`, `changeme-admin-key`) and the default `database_url` are demo placeholders — rotate via `.env` before anything beyond the hackathon demo. Without a real Postgres configured, the gateway runs exactly as before (in-memory only) — nothing about persistence being unreachable degrades detection or blocks a single request.

## Team status

- Gouri: JWT, reverse proxy, BOLA/BFLA/enumeration — done and tested. Task detail in GOURI.md.
- Jeevan: rate limiting, feature extraction, policy engine, logging — done and tested, but built by Claude in this session, not by Jeevan. As of last check, Jeevan has **zero commits** to this repo and was not even successfully added as a collaborator until a second invite was sent (`j33v4nz`, write access) — unclear if accepted yet. Task detail in JEEVAN.md.

## What's genuinely still open

1. BOLA ground truth — mitigated, not solved (see above).
2. Jeevan's actual participation — invite is out, unconfirmed whether accepted.
3. Multi-worker deployment — safe in theory now, untested in practice.
4. `attack_sim/simulate.py` is real and lives in the repo (that objection from
   earlier is closed), but it's still the only test coverage — no separate
   unit-test suite. Fine for a hackathon demo; would want more before real use.
5. Elasticsearch / time-series analysis — deliberately skipped, not forgotten. Postgres persistence (now done) gives a real substrate to build either on top of later, but standing up a whole separate ES service wasn't worth the operational complexity for a hackathon demo.
6. HA reconnect for `audit_log.py` specifically (as opposed to `store.py`,
   which Nirmal verified) was not re-run against the final reconciled tree
   in this pass — quick kill/revive test worth doing before the demo if time allows.
7. API10 (unsafe consumption of third-party APIs) intentionally not
   attempted — see "Five features" above for why it doesn't apply here.

## If you're picking this up cold

Read GOURI.md and JEEVAN.md for the per-person task breakdown and the reasoning behind each fix in that person's area. Read this file for the big picture. Don't trust your memory of "what the code does" over actually reading main.py, detect.py, store.py, agents.py — several serious bugs in this project were the kind that look correct on a skim and are provably wrong when you actually run a request through them.
