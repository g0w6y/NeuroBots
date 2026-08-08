# Project0: Round 2 Presentation Source

Source material for the team to build the actual PPT from. Every technical
claim below is something that was actually built and verified in this
build, not a plan and not an estimate. Where something isn't known to me
(team name, college), it's marked `[FILL IN]` rather than guessed. Numbers
throughout are the real, latest verified results as of 2026-08-08, not
best-case ones from earlier in the build.

## Slide 1: Team Introduction

- **Team Name:** `[FILL IN]`
- **Domain:** Cybersecurity / AI-Powered API Security
- **Team Members:**
  - Gouri Sankar A: Backend (repo owner)
  - Jeevan George: Backend
  - Melwin Santhosh: ML
  - Nirmal Josekutty: Backend / DevOps / Frontend
  - Aleena Shaji: Frontend
  - Mariya Liss: Frontend
- **College Name:** `[FILL IN]`
- **Repo:** github.com/g0w6y/Project0

## Slide 2: Problem Statement

**What problem are you solving?**
API traffic is the largest attack surface in modern software, and most API
gateways only enforce static rules such as rate limits and schema checks.
They can't see behavior: a valid, correctly signed request from a real
logged-in user reaching for data that isn't theirs (BOLA), or a slow,
distributed attack that never trips any single fixed threshold.

**Why is it important?**
Broken Object Level Authorization is OWASP's number one API risk, and it's
the pattern behind real, large breaches such as T-Mobile and Optus: a
valid credential paired with an object ID that isn't yours. Signature-based
WAFs see a technically valid request and let it through. The danger is in
the context, not the request shape.

**Who are the target users?**
Engineering and security teams at any API-first company, including
fintech, healthcare, and SaaS, that need real-time authorization
enforcement in front of their APIs without rewriting the APIs themselves.

## Slide 3: Proposed Solution

**The solution:** Project0 is a Zero-Trust API Security Gateway. Every
request is inspected before it reaches the real API, and decided in real
time using both deterministic rules and real trained ML behavioral models.

**Key features:**
- Full request pipeline: JWT validation, rate limiting, BOLA/BFLA
  authorization, ML and rule-based risk scoring, policy decision, response
  inspection that masks sensitive fields before they leave, then an async
  learning loop
- Two independent anomaly-detection engines, a deterministic rule engine
  and a real IsolationForest/Markov/graph model, that must corroborate
  before a soft signal alone can block a request. One inference can never
  slam the door on a real user by itself
- Autonomous mitigation: repeat-offender identities and IPs get an
  automatic, self-expiring cooldown, no human in the loop
- Autonomous API hardening, a new addition distinct from mitigation: when a
  resource, not a single attacker, comes under sustained attack from
  multiple distinct sources, the system raises that resource's own
  security posture on its own, safely, without ever punishing an innocent
  user of that resource alone
- Executive reporting, generated on demand from real audit data
- Real-time decisions: p50 around 4ms measured under real load, inside the
  15ms budget
- Intelligence Console: kill-chain reconstruction (correlates an identity's
  alerts into MITRE ATT&CK phases), predictive threat forecasting (Shannon
  entropy + exponential smoothing over the live alert stream), adaptive
  per-entity trust scoring, and autonomous hardening recommendations,
  all rule-based and statistical over real audit data, not a live model
- A from-scratch Graph Attention Network + Graph Convolutional Network
  (pure numpy, no PyTorch/DGL) scores structural anomalies on the access
  graph. Genuinely trained: the GCN layer and edge classifier update via
  real backpropagation and Adam, verified by watching loss decrease across
  real training runs; the GAT attention layer computes real multi-head
  attention over real edges

**What makes it unique, and innovation over existing solutions:**
- Most "AI security" demos fake the AI. Ours is real, trained, and proven
  independent, verified end to end including its anti-poisoning rule where
  a confirmed attacker's traffic is recorded but never used to retrain the
  baseline
- Autonomous hardening is not a standard feature of API gateways. It's a
  genuinely novel defense layer, with anti-gaming built in from day one so
  a forged token can't manufacture "distinct attackers" to weaponize it
- Full transparency by design: every block carries the OWASP category, the
  MITRE ATT&CK technique, and a plain-language explanation, never a bare
  "denied"

## Slide 4: Technical Architecture

**Architecture diagram:** see `ARCHITECTURE.md` in the repo for the
component graph, the 9-step request flow, the autonomous mitigation
sequence, and the horizontal scaling diagram. All Mermaid, rendering
directly on GitHub.

**Technology stack:**
- Backend gateway: Python, FastAPI, uvicorn
- Frontend dashboard: React, Vite
- Shared state: Redis (BOLA ownership, rate limits, escalation, hardening)
- Durable audit log: PostgreSQL
- Deployment: Docker / docker-compose

**AI models:**
- Per-entity IsolationForest (scikit-learn): anomaly scoring on real
  behavioral features
- Markov chain sequence modeling: flags unusual call-sequence transitions
- NetworkX bipartite user-object access graph: fan-in / fan-out novelty
  scoring
- A from-scratch Graph Attention Network + Graph Convolutional Network
  (pure numpy): real self-supervised link-prediction training via
  backpropagation and Adam, fused into the same ml_risk score as the three
  models above
- Deliberately not using a live LLM to decide any verdict. Narrative and
  executive-report generation are deterministic templates, so a security
  decision can never be hallucinated

**APIs:**
- The gateway itself is fully API-first: every capability, including
  detection, admin, provisioning, and reporting, is an HTTP endpoint
- 22 admin endpoints, including `/admin/alerts`, `/admin/metrics`,
  `/admin/executive-report`, `/admin/hardening`, `/admin/ml-status`,
  `/admin/config-audit`, `/admin/incidents`, and the Intelligence Console's
  `/admin/kill-chains`, `/admin/threat-forecast`, `/admin/threat-intel`,
  `/admin/trust-scores`, and `/admin/auto-harden`
- A demo upstream API the gateway protects, standing in for a real
  customer API

**Database:**
- PostgreSQL: durable alerts and incidents, auto-schema on startup
- Redis: fast shared state across gateway instances, self-healing
  reconnect on outage

**Hardware components:** None. Pure software product, no hardware
dependency.

## Slide 5: Current Progress

**GitHub Repository:** github.com/g0w6y/Project0, actively developed.
Every claim below is committed and pushed, not local-only.

**What's actually built and verified, not just planned:**
- Full backend gateway: JWT validation, BOLA/BFLA, rate limiting, adaptive
  step-up authentication, risk scoring, autonomous mitigation, autonomous
  hardening
- Full OWASP API Top 10 coverage where applicable, 9 of 10 (API10 doesn't
  apply since this gateway doesn't consume third-party APIs)
- Real ML pipeline: trained models, live risk scores, verified as actually
  consumed by real gateway decisions
- Frontend dashboard: live threat feed, risk gauge, MITRE matrix, entity
  table, API inventory, access control view, threat-hunting view, an
  Intelligence Console (kill chains, threat forecast, trust scores,
  auto-harden recommendations), and a real-time attack heatmap, all
  reading real gateway data with no mock data
- TLS in transit, high availability via self-healing Redis/Postgres
  reconnect, and horizontal scaling actually run with 3 worker processes
  and verified, not just designed to be safe
- Executive reporting generated on demand from real audit data

**Automated proof, checked into the repo and runnable by a judge directly:**
- `attack_sim/simulate.py`: a real attack simulator. 18 of 18 attack
  classes detected, 18 of 18 legitimate requests correctly allowed, 0
  false positives, plus a real attack-chain scenario (one identity: recon,
  BOLA, BFLA, pivot, evade) reconstructed live on the Threat Hunt dashboard
- `backend/tests/` and `ml/tests/`: 46 unit tests, all passing
- `frontend/contract-check.mjs`: 44 of 44 checks, verifying the dashboard
  renders real gateway data correctly, field by field
- `backend/benchmark.py`: real concurrent throughput measurement

**Documentation, all real and all in the repo:** `ARCHITECTURE.md`,
`DEPLOYMENT.md`, `PERFORMANCE.md`, `TESTING.md`, `DEMO.md`, `backend/MEMORY.md`.
Covers design decisions, deployment hardening, real performance numbers
(including a real, disclosed latency gap under concurrent load with real
Redis attached — reported honestly rather than left out), and exact
commands to run the whole system.

## Slide 6: Live Demo

**Exact, tested run sequence.** See `DEMO.md` in the repo for copy-paste
commands, verified from a clean slate before being written down.

1. Start Redis and PostgreSQL (Docker)
2. Start the demo upstream API, the gateway, and the ML worker
3. Start the frontend dashboard
4. Run the real attack simulator, which fires real HTTP requests with no
   fake data
5. Watch the dashboard update live with real detections

**What to show live:**
- A real BOLA attack, one user reaching for another's data, blocked
  instantly with the exact reason shown
- The dashboard's live threat feed populating in real time
- `GET /admin/executive-report`, a real generated summary
- `GET /admin/hardening`, proof the autonomous hardening feature is live
- The attack simulator's own scorecard: 18 of 18 detected, 0 false
  positives
- The Threat Hunt page's "Recon then exploit" saved hunt, showing the
  chain scenario's identity reconstructed step by step from real alerts
- The Intelligence Console: a real kill-chain reconstruction and threat
  forecast generated from that same attack traffic, not canned

Even the parts not shown live are independently provable via the commands
in `DEMO.md`. Nothing here needs to be taken on faith.

## Slide 7: Challenges and Next Plan

**Current challenges, real ones faced and solved during the build:**
- Balancing detection strictness against false positives, which required
  building a real corroboration rule (2+ independent signals needed before
  a soft signal alone can block) after finding a real near-miss
- Making a new autonomous defense, resource hardening, safe against being
  weaponized against real users. This required a genuine anti-gaming
  design, not just a feature that "works" in the demo
- Coordinating parallel work from multiple team members on the same
  codebase without losing anyone's real contributions, and without merging
  anything blind: every teammate's branch was reviewed line by line before
  merging, and real issues were caught and fixed this way, including
  detector names that didn't match the real code, a wrong port in a doc
  example, and a fake "AI-generated" report that never called any model

**Remaining work:**
- A real, disclosed latency gap: gateway decision overhead stays inside
  budget under real load with the in-memory fallback, but measures well
  outside it under real concurrent load with real Redis attached (found,
  reproduced three times, not yet root-caused - see `PERFORMANCE.md`)
- Secrets-manager integration tested against real cloud infrastructure
  (the integration point is built and verified, the live integration isn't)
- Live dashboard push across multiple gateway workers, which currently
  falls back to polling and still works correctly

**Plan before the Final Round:**
- Root-cause and fix the real-Redis concurrency latency gap above
- Load-test at production-representative scale
- Expand OAuth flow support if the next round's scope calls for it
- LLM-assisted threat hunting, with the same "never let it decide a
  verdict" guardrail already applied everywhere else, if time allows -
  still deliberately not built, to avoid overclaiming

## Slide 8: Impact

**Expected users:** Any team running an API-first product that needs
real-time authorization enforcement, including fintech, healthcare, and
SaaS platforms, and internal enterprise APIs.

**Scalability:** Verified horizontally scalable. State such as BOLA
ownership, rate limits, escalation, and hardening lives in Redis
specifically so multiple gateway instances share one consistent view.
Actually run with multiple worker processes and confirmed correct, not
just designed to be.

**Business impact:** Reduces breach risk and cost from the exact class of
attack behind real, large incidents, BOLA against valid credentials, and
reduces security-team triage load with autonomous mitigation and hardening
that act before a human has to.

**Social impact:** Protects end-user data, the same BOLA pattern behind
real consumer data breaches, without adding friction for legitimate users.
Verified as 0 false positives across the full test suite.

**Future scope:** LLM-assisted threat hunting, using the same "never let
it decide a verdict" safety principle already applied elsewhere in the
system; extending the graph neural network already live in `ml/` with full
backpropagation through its attention layer, not just its GCN and edge
classifier; and AI-directed penetration testing to continuously validate
the gateway itself.
