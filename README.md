# NeuroBots

Zero Trust API Security Intelligence and Autonomous Authorization Protection Platform

## Repository layout

```
backend/    FastAPI gateway: JWT validation, BOLA/BFLA detection, rate limiting,
            deterministic anomaly rules, autonomous escalation, audit log
  routes.json       the protected route table (see below), edit, don't recompile
  seed_ownership.json  pre-provisioned object ownership, loaded at startup
ml/         Real ML worker: per-entity IsolationForest, Markov sequence model,
            NetworkX access graph (scikit-learn/networkx, not a rename of backend/)
frontend/   React/Vite dashboard, reads real gateway state, no simulated data
markdown/   Every doc in the repo except this README, see the Documentation
            section below for what's where
run.py      python3 run.py starts everything (Redis, Postgres, upstream,
            gateway, ML worker, dashboard) from one command, see below
start_all.sh / stop_all.sh   the same idea without Docker/frontend, see below
```

### Protecting a new endpoint

`backend/routes.json` is the route table, read at startup. Adding an entry there
is what gives a path object-level (BOLA) and role-level (BFLA) rules, with no
code change and no redeploy. Anything under a protected prefix that is *not*
listed still requires a valid token; listing it is what adds authorization on
top of authentication. Point `ROUTE_CONFIG_FILE` at a different file to override.

## Fastest way to run it: one command

```bash
python3 run.py
```

Starts Redis and PostgreSQL (Docker, if available, otherwise the gateway
falls back to in-memory state automatically), installs backend/frontend
dependencies on first run if they're missing, then starts the demo
upstream API, the gateway, the ML worker, and the dashboard, all from this
one process, in one terminal. Real health checks between each step, not
fixed sleeps. Press Ctrl-C to stop everything it started, cleanly.

```bash
cd backend && python3 attack_sim/simulate.py    # in a second terminal, once run.py is up
```

## Docker Compose (equivalent, containerised)

```bash
cp .env.example .env
docker compose up --build
```

Brings up Redis, PostgreSQL, the vulnerable demo API, the gateway, the ML worker,
and the dashboard. Dashboard on http://127.0.0.1:3000, gateway on
http://127.0.0.1:8080. Run `docker compose down` to stop it (`-v` also wipes the
volumes).

```bash
./scripts/demo.sh
```

Does everything above plus health-waits, runs the attack suite and the
benchmark, and opens the dashboard.

See `markdown/docs/DEPLOYMENT.md` before running this anywhere that is not your
laptop. The default `JWT_SECRET` and `ADMIN_API_KEY` are demo values.

## Without Docker: one command

```bash
REDIS_URL=redis://127.0.0.1:6379 ./start_all.sh
cd frontend && npm run dev
./stop_all.sh
```

The first line starts the demo upstream, the gateway, and the ML worker. The
second line starts the dashboard in its own terminal. The third stops
everything the first line started.

On Windows use the PowerShell equivalents, which also create the venv and
install backend requirements on first run:

```powershell
.\start_all.ps1
cd frontend
npm run dev
.\stop_all.ps1
```

`.\start_all.ps1` also accepts `-GatewayPort 18080 -UpstreamPort 19000` to run
on different ports.

`REDIS_URL` is optional. Omit it and everything still works, just without the
ML worker's signal (the gateway falls back to in-memory state either way). Logs
for each service land in `.demo-logs/` if something needs checking.

## Run it end to end, manually

This is what the scripts above automate. Five terminals:

**Terminal 1: sample protected API** (real working demo data, not a mock of the gateway)

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python demo_upstream.py
```

Listens on `0.0.0.0:9000`.

**Terminal 2: the gateway**

```bash
cd backend
source venv/bin/activate
python main.py
```

Listens on `0.0.0.0:8080`.

**Terminal 3: ML worker** (needs a real Redis reachable by both this and the gateway)

```bash
cd ml
pip install -r requirements.txt
REDIS_URL=redis://127.0.0.1:6379 GATEWAY_URL=http://127.0.0.1:8080 ADMIN_API_KEY=changeme-admin-key python3 worker.py
```

**Terminal 4: dashboard**

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open http://localhost:3000. Make sure `VITE_GATEWAY_URL` and `VITE_ADMIN_KEY`
in `.env` match the gateway.

**Terminal 5: attack simulation suite** (this is what puts data on the dashboard)

```bash
cd backend
source venv/bin/activate
python attack_sim/simulate.py
```

Runs one full pass and prints a scorecard. For a live demo that keeps firing:

```bash
python attack_sim/simulate.py --loop
```

**Score a run against a freshly started gateway.** The suite reuses a small
cast of identities, and several forgery cases share one subject, so on a
second back-to-back run that subject is still inside the autonomous cooldown
it earned the first time, and returns `auto_escalated_block` where the suite
expects `challenge`. That is the product working correctly, a proven forger
is supposed to stay blocked, but it makes the scorecard read fewer than the
full count. A clean run reports 16/16 attack classes detected, 18/18
legitimate requests correctly allowed, 0 false positives. Restart `main.py`
between scored runs for a clean number. `POST /admin/reset` clears alerts and
escalation state but deliberately preserves ownership grants, so it is not a
substitute for a restart.

`simulate.py` drives real traffic at the gateway and scores it against the
success criteria: it runs legitimate traffic, then all attack classes, then
legitimate traffic again. That last phase is the one that matters, because a
gateway that blocks real users after an attack has just traded a false
negative for a false positive. It prints the detection rate, the false
positive count, and the measured p50/p99 gateway overhead.

Verify the dashboard is reading the gateway correctly at any point with:

```bash
cd frontend
node contract-check.mjs
```

This runs the dashboard's own transform functions over live gateway responses
and asserts every field each panel renders is actually present.

Skipping `demo_upstream.py` doesn't break detection. Every gateway decision
(JWT, BOLA, BFLA, rate limiting, autonomous mitigation) is identical either
way. It only means legitimate, allowed requests correctly forward and then
502, since there's nothing listening at `UPSTREAM_URL` to receive them.

Skipping `ml/worker.py` doesn't break detection either. It only adds a
second, independent anomaly signal on top of the gateway's own rule engine.
Without it running, the gateway behaves exactly as if it never existed. It
does need a real Redis (not the gateway's in-memory fallback) to actually
produce that signal, since it's a genuinely separate process sharing state
through Redis, not through memory.

Redis and PostgreSQL are optional. The gateway falls back to in-memory state
for both when they're unreachable (rate limits, BOLA ownership, and the
audit log all work either way; only cross-restart persistence and
multi-instance sharing need the real services). CORS defaults to permissive
for local demo convenience. The actual access boundary on every `/admin/*`
route is the `X-Admin-Key` header, not CORS. Lock `CORS_ALLOWED_ORIGINS`
down before any real deployment.

## Documentation

All documentation lives in `markdown/`, one folder for every doc in the repo.

| Doc | What it covers |
|---|---|
| `markdown/ARCHITECTURE.md` | diagram-based: component graph, the 9-step decision pipeline, autonomous mitigation and hardening, horizontal scaling |
| `markdown/docs/ARCHITECTURE.md` | how the pieces fit, the decision pipeline, trust boundaries |
| `markdown/docs/TESTING.md` | running the attack suite, contract check and benchmark, and reading a bad result |
| `markdown/docs/DEPLOYMENT.md` | production checklist, scaling, known gaps |
| `markdown/DEPLOYMENT.md` | secret rotation, the fail-closed production gate, secrets-manager integration boundary |
| `markdown/PERFORMANCE.md` | real measured latency numbers and how they were found |
| `markdown/BENCHMARK.md` | latest measured latency and throughput (regenerate with `scripts/benchmark.py`) |
| `markdown/DEMO.md` | exact, tested commands to run the full stack for a live demo |
| `markdown/PRESENTATION.md` | Round 2 presentation slide source material |

See `markdown/backend/README.md` and `markdown/backend/MEMORY.md` for the
gateway's full status, every bug found and fixed with why it mattered, and
what's genuinely still open. See `markdown/frontend/README.md` for what the
dashboard shows and how it derives display metrics from the gateway's real
responses. See `markdown/ml/README.md` for the ML worker.

## Problem Statement

Almost every app today talks to other software through APIs. An API is just
the doorway a website or mobile app uses to ask a server for data, such as
your bank balance, your medical record, or your order history. Because
these doorways carry valuable data, attackers now go straight for them.

The most dangerous API attacks are authorization attacks, where a real,
logged in user asks for data that belongs to someone else. A simple
example: you open a banking app and it loads your account at an address
like `/api/accounts/1001`. If you change that number to 1002 and the server
forgets to check who owns account 1002, it hands you a stranger's account
details. That single missing check is called Broken Object Level
Authorization, or BOLA, and it is the number one risk in the OWASP API
Security Top 10.

The hard part is that these requests look completely normal. The user is
logged in, the request is well formed, and nothing is technically broken,
so traditional firewalls that look for known bad patterns see nothing
wrong and let it through.

This is not just theory. In January 2023, T-Mobile disclosed that an
attacker abused a single API to pull the personal data of about 37 million
customers. In 2022, the Australian telecom Optus exposed the personal
details of millions of customers through an API that was not properly
protected. Neither breach needed advanced hacking, just a valid session and
an API that failed to check whether the user was actually allowed to access
the data being requested.

The problem we are addressing is exactly this: API attacks that look like
legitimate traffic, abuse weak or missing authorization, and slip past
normal security tools, putting large amounts of sensitive personal and
financial data at risk.

## Technology Stack

Frontend: React, Vite.

Backend and API gateway: Python, FastAPI, httpx, PyJWT, WebSockets.

Machine learning: scikit-learn (IsolationForest), NetworkX, a Markov chain
sequence model.

Reporting and narrative generation: deterministic templates over real
audit data, not a live LLM call. A security verdict must never be
hallucinated, so nothing that decides or explains a block is generated by
a language model.

Databases: Redis and PostgreSQL.

Deployment: Docker and Docker Compose.

Standards: OWASP API Security Top 10 and MITRE ATT&CK.

## Business Impact

Authorization attacks such as BOLA and BFLA are among the top causes of
API breaches, and a single incident can cost a company heavily in fines,
downtime, lost customers, and damage to its reputation. Our platform
detects and blocks these attacks in real time, protects customer data, and
keeps APIs fast and reliable thanks to low latency and a low false
positive rate that avoids blocking real users. It applies across banking,
healthcare, fintech, SaaS, government, telecom, and online retail, and it
reduces the cost and effort of meeting security and compliance
requirements.

## Social Impact

It helps protect people's most sensitive data, such as bank details,
medical records, and government identity information, from being accessed
by the wrong person. Because every block is explained and mapped to known
security standards, it builds public trust and makes audits easier. A
lightweight and affordable design means smaller organisations and public
services can protect their users too, not only large enterprises.
