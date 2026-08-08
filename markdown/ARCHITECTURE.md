# Project0 Architecture

Diagram-based companion to `backend/MEMORY.md` (the full reasoning behind
every design decision, in prose) and `ml/README.md`. This file is the
picture; those files are the "why." All diagrams below reflect the actual
code as of 2026-08-08 — every component, file, and endpoint named here
exists and was verified running, not aspirational.

## 1. System components

```mermaid
graph TB
    Client["Client<br/>(browser / API caller)"]
    Dashboard["Frontend Dashboard<br/>(React, frontend/)"]

    subgraph Gateway["Gateway — backend/main.py — :8080"]
        CF["check_and_forward()<br/>9-step decision pipeline"]
        Hub["EventHub<br/>WebSocket fan-out"]
    end

    Upstream["Demo Upstream API<br/>backend/demo_upstream.py — :9000<br/>(sample data, not part of detection logic)"]
    Redis[("Redis<br/>BOLA ownership, rate windows,<br/>escalation state, ml_risk cache")]
    Postgres[("PostgreSQL<br/>durable alerts + incidents<br/>backend/audit_log.py")]
    ML["ML Worker — ml/worker.py<br/>IsolationForest + Markov + NetworkX"]
    Agents["Rule-based agents<br/>backend/agents.py<br/>profile / sequence / graph"]

    Client -->|HTTPS/HTTP request| CF
    CF -->|allow| Upstream
    Upstream -->|response| CF
    CF <-->|ownership, rate, escalation| Redis
    CF -->|write alerts/incidents| Postgres
    CF -->|record event, async, fire-and-forget| Agents
    Agents <-->|shared connection| Redis
    ML -->|polls GET /admin/alerts| CF
    ML -->|writes ml_risk:subject, profile:subject| Redis
    CF -->|reads ml_risk:subject| Redis
    CF -->|publish alert/incident| Hub
    Hub -->|WebSocket /ws/events| Dashboard
    Dashboard -->|poll /admin/* with X-Admin-Key| CF

    style Gateway fill:transparent,stroke-width:2px
```

Every arrow here is a real call in the code, not a planned one:
`store.py`/`agents.py` share one Redis client (`control_plane.use_client()`);
the ML worker is a fully separate process that only talks to the gateway
through its own public `/admin/alerts` endpoint and Redis, never imported
directly — if it isn't running, the gateway degrades to exactly what it was
before it existed, nothing in the request path depends on it.

## 2. The 9-step request flow

This is the same flow the reference architecture artifact diagrams
interactively; this version is the static, in-repo record of it, kept in
sync with `check_and_forward()` in `main.py`.

```mermaid
flowchart TD
    Start(["Request arrives"]) --> S1["1. Validate JWT<br/>(sig, exp, nbf, iss, aud,<br/>alg=none, alg-confusion)"]
    S1 -->|invalid / missing| Block403["403 Block<br/>(jwt_* hard signal)"]
    S1 -->|valid, or anon:ip| S2["2. Rate limit, early<br/>(sliding window,<br/>sustained + burst)"]
    S2 -->|over limit| Block403
    S2 -->|ok| S3["3. Extract features<br/>(route match, resource,<br/>object id, path params)"]
    S3 --> S4["4. Authorize: BOLA / BFLA<br/>(Redis ownership check,<br/>role check)"]
    S4 -->|not owner / wrong role| Block403
    S4 -->|owns it| S5["5. Risk score<br/>(cached ML risk +<br/>control-plane anomaly)"]
    S5 --> S6["6. Policy decision<br/>fuse_signals():<br/>hard→block, 2+soft→block,<br/>1 soft→challenge"]
    S6 -->|block| Block403
    S6 -->|challenge| Step401["401<br/>WWW-Authenticate: step_up_required"]
    S6 -->|allow| S7["7. Enforce: forward<br/>to upstream"]
    S7 --> S8["8. Inspect response<br/>(API3 — mask sensitive<br/>fields for non-admin roles)"]
    S8 --> S9["9. Emit event, async<br/>(never blocks the response)"]
    S9 --> Respond(["Response to client"])
    Block403 --> S9b["Emit event, async"] --> Respond
    Step401 --> S9c["Emit event, async"] --> Respond

    S9 -.->|fire-and-forget| Async["Async: agents.py +<br/>ml worker update baselines"]
```

Steps 1–7 run inline, on the request's own critical path — this is what the
`<15ms` budget is measuring (see `backend/PERFORMANCE.md`: p50 0.05–0.08ms,
p99 0.3–0.6ms, measured, not estimated). Step 9's async emission is the only
thing that ever touches the intelligence layer; a slow or unreachable ML
worker or Redis never adds latency to a live request, by construction.

## 3. Autonomous mitigation escalation

The system remembers a proven attacker across requests instead of
re-deciding from scratch every time — this is the part of the flow that
isn't in the reference architecture's per-request diagram, because it spans
multiple requests over time.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant G as Gateway
    participant R as Redis

    A->>G: Request #1 (forged JWT)
    G->>G: fuse_signals() → block (hard signal)
    G->>R: record_block_event(subject/ip)
    Note over G: only "hostile" detectors count<br/>(bola_cross_user, jwt_alg_none, jwt_bad_signature,<br/>jwt_malformed, jwt_no_expiry, bola_enumeration —<br/>NOT rate_limit_burst, NOT routine auth friction)
    G-->>A: 403

    A->>G: Request #2 (forged JWT)
    G->>R: record_block_event → count=2
    G-->>A: 403

    A->>G: Request #3 (forged JWT)
    G->>R: record_block_event → count=3
    Note over G: count >= auto_block_threshold (3)
    G->>G: escalate(subject, reason, now)
    G->>R: set_blocked(subject, cooldown)
    Note over G,R: cooldown = base × min(escalation_count, max_multiplier)<br/>— progressive: worse on repeat offenses
    G-->>A: 403 (auto-blocked)

    A->>G: Request #4 (even a valid token now)
    G->>R: is_blocked(subject)?
    R-->>G: yes, until T+cooldown
    G-->>A: 403, short-circuited before JWT/BOLA even runs

    Note over G,R: Same mechanism runs independently for source IP,<br/>at a much higher threshold (10 not 3) specifically to<br/>avoid punishing users sharing a NAT/proxy with an attacker.<br/>Identity-level escalation only ever applies to a<br/>cryptographically verified subject — anon:ip traffic<br/>only ever escalates via the IP path.
```

Verified against real traffic, not just read off the code: `/admin/incidents`
after a real attack-sim run shows genuine `auto_block_escalation` events for
both an identity (`scanner`, after repeated enumeration) and a source IP
(`ip:127.0.0.1`, after the suite's own aggregate hostile traffic crossed the
threshold) — see `backend/MEMORY.md` for the exact incident records and what
they revealed about safely re-running the attack suite.

## 4. OWASP API Top 10 coverage

| # | Category | Status | Detector |
|---|---|---|---|
| API1 | Broken Object Level Authorization | Covered | `bola_cross_user`, `bola_enumeration` — `backend/detect.py` |
| API2 | Broken Authentication | Covered | `jwt_*` family — `backend/auth.py` |
| API3 | Broken Object Property Level Authorization (excessive data exposure) | Covered | `excessive_data_exposure_prevented` — `backend/security_checks.py`, response-body redaction |
| API4 | Unrestricted Resource Consumption | Covered | rate limiting, sustained + burst — `backend/detect.py` |
| API5 | Broken Function Level Authorization | Covered | `bfla_role_violation` — `backend/detect.py` |
| API6 | Unrestricted Access to Sensitive Business Flows | Covered | `control_plane_anomaly`, `ml_anomaly` soft signals — `backend/agents.py`, `ml/` |
| API7 | Server-Side Request Forgery | Covered | `ssrf_internal_target` — `backend/security_checks.py`, scans request bodies for RFC1918/link-local/cloud-metadata targets |
| API8 | Security Misconfiguration | Covered | `GET /admin/config-audit` + security-headers middleware — `backend/security_checks.py` |
| API9 | Improper Inventory Management | Covered | `shadow_endpoint_access` for unlisted routes under a protected prefix — `backend/security_checks.py` |
| API10 | Unsafe Consumption of APIs | Not attempted, by design | This gateway is an inbound reverse proxy — it doesn't consume third-party APIs on the tenant's behalf, so API10 isn't a meaningful axis for it |

## 5. Horizontal scaling (`WORKERS=N`)

```mermaid
graph LR
    LB["Load balancer /<br/>reverse proxy"]
    W1["Gateway worker 1"]
    W2["Gateway worker 2"]
    W3["Gateway worker 3"]
    Redis[("Redis<br/>ownership · rate windows ·<br/>escalation state")]
    PG[("PostgreSQL<br/>alerts + incidents")]

    LB --> W1
    LB --> W2
    LB --> W3
    W1 <-->|shared state| Redis
    W2 <-->|shared state| Redis
    W3 <-->|shared state| Redis
    W1 -->|writes| PG
    W2 -->|writes| PG
    W3 -->|writes| PG

    subgraph Limitation["Known limitation"]
        WS["/ws/events push<br/>does NOT fan out —<br/>a socket only sees<br/>its own worker's events.<br/>Polling endpoints unaffected."]
    end
```

Verified with real `WORKERS=3` against real Docker Redis + Postgres on
2026-08-08: rate limiting, BOLA ownership, and identity-level auto-escalation
all confirmed correctly shared across all 3 independent processes — and
confirmed to genuinely diverge when Redis is unreachable, proving the shared
state actually matters rather than assuming it. See `DEPLOYMENT.md` for the
full methodology (including a real test-methodology bug caught and fixed
along the way) and `backend/MEMORY.md` for the incident-level detail.

## 6. Where the diagrams above are proven, not just drawn

- Flow diagram (§2): every step corresponds 1:1 to a numbered comment in
  `check_and_forward()` in `backend/main.py`.
- Escalation sequence (§3): every message corresponds to a real function call
  (`store.record_block_event`, `escalate`, `store.set_blocked`,
  `store.is_blocked`) in the same file, and was re-confirmed against real
  `/admin/incidents` output on 2026-08-08 (see `backend/MEMORY.md`).
- Component diagram (§1): every edge is a real network call or shared
  connection in the running system — reachable and testable via the commands
  in `backend/PERFORMANCE.md` and `../backend/attack_sim/simulate.py`.

For the reasoning behind each design decision (why hard/soft signal
separation, why BOLA ownership is first-touch, why the ML risk signal is
always soft, why escalation thresholds differ for identity vs. IP) see
`backend/MEMORY.md` — this file is deliberately just the shape of the
system, not the argument for it.
