# NeuroBots — Round 2 Presentation Source

Source material for the team to build the actual PPT from. Every technical
claim below is something that was actually built and verified this build —
not a plan, not an estimate. Where something isn't known to me (team name,
college), it's marked `[FILL IN]` rather than guessed. Numbers throughout
are the real, latest verified results as of 2026-08-08, not best-case ones
from earlier in the build.

---

## Slide 1 — Team Introduction

- **Team Name:** `[FILL IN]`
- **Domain:** Cybersecurity / AI-Powered API Security
- **Team Members:**
  - Gouri Sankar A — Backend (repo owner)
  - Jeevan George — Backend
  - Melwin Santhosh — ML
  - Nirmal Josekutty — Backend / DevOps / Frontend
  - Aleena Shaji — Frontend
  - Mariya Liss — Frontend
- **College Name:** `[FILL IN]`
- **Repo:** github.com/g0w6y/NeuroBots

---

## Slide 2 — Problem Statement

**What problem are you solving?**
API traffic is the largest attack surface in modern software, and most API
gateways only enforce static rules (rate limits, schema checks). They can't
see *behavior* — a valid, correctly-signed request from a real logged-in
user reaching for data that isn't theirs (BOLA), or a slow, distributed
attack that never trips any single fixed threshold.

**Why is it important?**
Broken Object Level Authorization is OWASP's #1 API risk and behind real,
large breaches (the pattern behind incidents like T-Mobile and Optus:
a valid credential, an object ID that isn't yours). Signature-based WAFs
see a technically valid request and let it through — the danger is in the
*context*, not the request shape.

**Who are the target users?**
Engineering and security teams at any API-first company — fintech,
healthcare, SaaS — that need real-time authorization enforcement in front
of their APIs without rewriting the APIs themselves.

---

## Slide 3 — Proposed Solution

**The solution:** NeuroBots is a Zero-Trust API Security Gateway — every
request is inspected before it reaches the real API, decided in real time
using both deterministic rules and real trained ML behavioral models.

**Key features:**
- Full request pipeline: JWT validation → rate limiting → BOLA/BFLA
  authorization → ML + rule-based risk scoring → policy decision →
  response inspection (masks sensitive fields before they leave) → async
  learning loop
- Two *independent* anomaly-detection engines (a deterministic rule engine
  and a real IsolationForest/Markov/graph model) that must **corroborate**
  before a soft signal alone can block a request — one inference can never
  slam the door on a real user by itself
- **Autonomous mitigation**: repeat-offender identities/IPs get an
  automatic, self-expiring cooldown, no human in the loop
- **Autonomous API hardening** (our own addition, distinct from mitigation):
  when a *resource* — not a single attacker — comes under sustained attack
  from multiple distinct sources, the system raises that resource's own
  security posture on its own, safely (never punishes an innocent user of
  that resource alone)
- Executive reporting, generated on demand from real audit data
- Real-time decisions: **p50 ~4ms** measured under real load, inside the
  15ms budget

**What makes it unique / innovation over existing solutions:**
- Most "AI security" demos fake the AI. Ours is real, trained, and *proven
  independent* — verified end to end including its anti-poisoning rule
  (a confirmed attacker's traffic is recorded but never used to retrain
  the baseline).
- Autonomous hardening is not a standard feature of API gateways — it's a
  genuinely novel defense layer, with anti-gaming built in from day one
  (a forged token can't manufacture "distinct attackers" to weaponize it).
- Full transparency by design: every block carries the OWASP category, the
  MITRE ATT&CK technique, and a plain-language explanation — never a bare
  "denied."

---

## Slide 4 — Technical Architecture

**Architecture diagram:** see `ARCHITECTURE.md` in the repo (component
graph, 9-step request flow, autonomous mitigation sequence, horizontal
scaling diagram — all Mermaid, render directly on GitHub).

**Technology stack:**
- Backend gateway: Python, FastAPI, uvicorn
- Frontend dashboard: React, Vite
- Shared state: Redis (BOLA ownership, rate limits, escalation, hardening)
- Durable audit log: PostgreSQL
- Deployment: Docker / docker-compose

**AI models:**
- Per-entity **IsolationForest** (scikit-learn) — anomaly scoring on
  real behavioral features
- **Markov chain** sequence modeling — flags unusual call-sequence
  transitions
- **NetworkX** bipartite user↔object access graph — fan-in/fan-out
  novelty scoring
- Deliberately **not** using a live LLM to decide any verdict — narrative
  and executive-report generation are deterministic templates, so a
  security decision can never be hallucinated

**APIs:**
- The gateway itself: fully API-first, every capability (detection, admin,
  provisioning, reporting) is an HTTP endpoint
- 15+ admin endpoints: `/admin/alerts`, `/admin/metrics`,
  `/admin/executive-report`, `/admin/hardening`, `/admin/ml-status`,
  `/admin/config-audit`, `/admin/incidents`, and more
- A demo upstream API the gateway protects, standing in for a real
  customer API

**Database:**
- PostgreSQL — durable alerts and incidents, auto-schema on startup
- Redis — fast shared state across gateway instances, self-healing
  reconnect on outage

**Hardware components:** None — pure software product, no hardware
dependency.

---

## Slide 5 — Current Progress

**GitHub Repository:** github.com/g0w6y/NeuroBots — actively developed,
every claim below is committed and pushed, not local-only.

**What's actually built and verified (not just planned):**
- Full backend gateway: JWT validation, BOLA/BFLA, rate limiting, adaptive
  step-up authentication, risk scoring, autonomous mitigation, autonomous
  hardening
- Full OWASP API Top 10 coverage where applicable (**9 of 10** — API10
  doesn't apply, this gateway doesn't consume third-party APIs)
- Real ML pipeline: trained models, live risk scores, verified consumed by
  real gateway decisions
- Frontend dashboard: live threat feed, risk gauge, MITRE matrix, entity
  table, API inventory, access control view, threat-hunting view — all
  reading real gateway data, no mock data
- TLS-in-transit, high availability (self-healing Redis/Postgres
  reconnect), horizontal scaling (actually run with 3 worker processes and
  verified, not just designed to be safe)
- Executive reporting generated on demand from real audit data

**Automated proof, checked into the repo, runnable by a judge directly:**
- `attack_sim/simulate.py` — real attack simulator: **16/16 attack classes
  detected, 18/18 legitimate requests correctly allowed, 0 false
  positives**
- `backend/tests/` + `ml/tests/` — **46 unit tests, all passing**
- `frontend/contract-check.mjs` — **44/44 checks**, verifying the dashboard
  renders real gateway data correctly, field by field
- `backend/benchmark.py` — real concurrent throughput measurement

**Documentation (all real, all in the repo):** `ARCHITECTURE.md`,
`DEPLOYMENT.md`, `PERFORMANCE.md`, `DEMO.md`, `backend/MEMORY.md` —
covering design decisions, deployment hardening, real performance numbers,
and exact commands to run the whole system.

---

## Slide 6 — Live Demo

**Exact, tested run sequence — see `DEMO.md` in the repo for copy-paste
commands, verified from a clean slate before being written down:**

1. Start Redis + PostgreSQL (Docker)
2. Start the demo upstream API, the gateway, and the ML worker
3. Start the frontend dashboard
4. Run the real attack simulator — fires real HTTP requests, no fake data
5. Watch the dashboard update live with real detections

**What to show live:**
- A real BOLA attack (one user reaching for another's data) blocked
  instantly, with the exact reason shown
- The dashboard's live threat feed populating in real time
- `GET /admin/executive-report` — a real generated summary
- `GET /admin/hardening` — proof the autonomous hardening feature is live
- The attack simulator's own scorecard: 16/16 detected, 0 false positives

Even the parts not shown live are independently provable via the commands
in `DEMO.md` — nothing here needs to be taken on faith.

---

## Slide 7 — Challenges & Next Plan

**Current challenges (real ones, faced and solved during the build):**
- Balancing detection strictness against false positives — required
  building a real corroboration rule (2+ independent signals needed before
  a soft signal alone can block) after finding a real near-miss
- Making a *new* autonomous defense (resource hardening) safe against being
  weaponized against real users — required a genuine anti-gaming design,
  not just a feature that "works" in the demo
- Coordinating parallel work from multiple team members on the same
  codebase without losing anyone's real contributions

**Remaining work:**
- Throughput/load testing beyond the current verified scale
- Secrets-manager integration tested against real cloud infrastructure
  (the integration point is built and verified, the live integration isn't)
- Live dashboard push across multiple gateway workers (currently falls
  back to polling, which still works correctly)

**Plan before the Final Round:**
- Load-test at production-representative scale
- Expand OAuth flow support if the next round's scope calls for it
- Explore the remaining bonus directions (LLM-assisted threat hunting with
  strict guardrails, graph neural networks) if time allows — both
  currently and deliberately not built, to avoid overclaiming

---

## Slide 8 — Impact

**Expected users:** Any team running an API-first product that needs
real-time authorization enforcement — fintech, healthcare, SaaS platforms,
internal enterprise APIs.

**Scalability:** Verified horizontally scalable — state (BOLA ownership,
rate limits, escalation, hardening) lives in Redis specifically so
multiple gateway instances share one consistent view; actually run with
multiple worker processes and confirmed correct, not just designed to be.

**Business impact:** Reduces breach risk and cost from the exact class of
attack behind real, large incidents (BOLA against valid credentials) —
and reduces security-team triage load with autonomous mitigation and
hardening that act before a human has to.

**Social impact:** Protects end-user data — the same BOLA pattern behind
real consumer data breaches — without adding friction for legitimate
users, verified as **0 false positives** across the full test suite.

**Future scope:** LLM-assisted threat hunting (with the same "never let it
decide a verdict" safety principle already applied elsewhere in the
system), graph neural networks for deeper relationship anomaly detection,
AI-directed penetration testing to continuously validate the gateway
itself.
