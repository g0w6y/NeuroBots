# Project Memory — NeuroBots Zero-Trust API Security Gateway

Status doc for team continuity. Last updated 2026-08-07. Read this before making changes so you don't redo or undo work that's already been fixed and verified.

## What this is

A gateway that sits in front of an API and blocks authorization attacks in real time: BOLA, BFLA, JWT tampering, rate abuse. Two-plane design — fast deterministic checks inline (data plane), async behavioral anomaly detection in the background (control plane / multi-agent layer), plus an autonomous escalation layer that remembers proven attackers across requests instead of re-deciding from scratch every time.

## Frontend connection + demo upstream (new)

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
| Inspect response (API3) | **Not built.** No response-body inspection exists. Flagged, not faked. |
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

1. Step 8 — API3 response inspection (excessive data exposure). Zero implementation.
2. BOLA ground truth — mitigated, not solved (see above).
3. Jeevan's actual participation — invite is out, unconfirmed whether accepted.
4. Multi-worker deployment — safe in theory now, untested in practice.
5. No automated tests committed to the repo. Verified each session via throwaway scripts, nothing lives in the repo as proof for a judge to re-run. This was a deliberate choice at the team's request earlier ("remove demo bluff") — revisit if judging weight is on demonstrable test coverage.
6. Elasticsearch / time-series analysis — deliberately skipped, not forgotten. Postgres persistence (now done) gives a real substrate to build either on top of later, but standing up a whole separate ES service wasn't worth the operational complexity for a hackathon demo.

## If you're picking this up cold

Read GOURI.md and JEEVAN.md for the per-person task breakdown and the reasoning behind each fix in that person's area. Read this file for the big picture. Don't trust your memory of "what the code does" over actually reading main.py, detect.py, store.py, agents.py — several serious bugs in this project were the kind that look correct on a skim and are provably wrong when you actually run a request through them.
