# NeuroBots

Zero Trust API Security Intelligence and Autonomous Authorization Protection Platform

## Repository layout

```
backend/    FastAPI gateway - JWT validation, BOLA/BFLA detection, rate limiting,
            deterministic anomaly rules, autonomous escalation, audit log
ml/         Real ML worker - per-entity IsolationForest, Markov sequence model,
            NetworkX access graph (scikit-learn/networkx, not a rename of backend/)
frontend/   React/Vite dashboard - reads real gateway state, no simulated data
start_all.sh / stop_all.sh   one-command demo startup/shutdown, with real health
                              checks between each step - see below
```

## Fastest way to run it: one command

```bash
REDIS_URL=redis://127.0.0.1:6379 ./start_all.sh    # demo upstream + gateway + ML worker
cd frontend && npm run dev                          # dashboard, in its own terminal
./stop_all.sh                                        # when done
```

`REDIS_URL` is optional — omit it and everything still works, just without the ML
worker's signal (the gateway falls back to in-memory state either way). Logs for
each service land in `.demo-logs/` if something needs checking.

## Run it end to end, manually (what the script above actually automates)

```bash
# terminal 1 - sample protected API (real working demo data, not a mock of the gateway)
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python demo_upstream.py              # listens on 0.0.0.0:9000

# terminal 2 - gateway
cd backend && source venv/bin/activate
python main.py                       # listens on 0.0.0.0:8080

# terminal 3 - ML worker (needs a real Redis reachable by both this and the gateway)
cd ml
pip install -r requirements.txt
REDIS_URL=redis://127.0.0.1:6379 GATEWAY_URL=http://127.0.0.1:8080 \
  ADMIN_API_KEY=changeme-admin-key python3 worker.py

# terminal 4 - dashboard
cd frontend
npm install
cp .env.example .env                 # VITE_GATEWAY_URL / VITE_ADMIN_KEY must match the gateway
npm run dev                          # http://localhost:5173
```

Skipping `demo_upstream.py` doesn't break detection — every gateway decision (JWT,
BOLA, BFLA, rate limiting, autonomous mitigation) is identical either way. It only
means legitimate, allowed requests correctly forward and then 502, since there's
nothing listening at `UPSTREAM_URL` to receive them.

Skipping `ml/worker.py` doesn't break detection either — it only adds a second,
independent anomaly signal on top of the gateway's own rule engine. Without it
running, the gateway behaves exactly as if it never existed. It does need a real
Redis (not the gateway's in-memory fallback) to actually produce that signal, since
it's a genuinely separate process sharing state through Redis, not through memory.

Redis and PostgreSQL are optional — the gateway falls back to in-memory state for
both when they're unreachable (rate limits, BOLA ownership, and the audit log all
work either way; only cross-restart persistence and multi-instance sharing need
the real services). CORS defaults to permissive for local demo convenience — the
actual access boundary on every `/admin/*` route is the `X-Admin-Key` header, not
CORS; lock `CORS_ALLOWED_ORIGINS` down before any real deployment.

See `backend/README.md` and `backend/MEMORY.md` for the gateway's full status,
every bug found and fixed with why it mattered, and what's genuinely still open.
See `frontend/README.md` for what the dashboard shows and how it derives display
metrics from the gateway's real responses.

## Problem Statement Understanding..


Almost every app today talks to other software through APIs. An API is just the doorway a website or mobile app uses to ask a server for data, such as your bank balance, your medical record or your order history. Because these doorways carry valuable data, attackers now go straight for them.

The most dangerous API attacks are authorization attacks, where a real, logged in user asks for data that belongs to someone else. A simple example: you open a banking app and it loads your account at an address like /api/accounts/1001. If you change that number to 1002 and the server forgets to check who owns account 1002, it hands you a stranger's account details. That single missing check is called Broken Object Level Authorization, or BOLA, and it is the number one risk in the OWASP API Security Top 10.

The hard part is that these requests look completely normal. The user is logged in, the request is well formed, and nothing is technically broken, so traditional firewalls that look for known bad patterns see nothing wrong and let it through.

This is not just theory. In January 2023, T Mobile disclosed that an attacker abused a single API to pull the personal data of about 37 million customers. In 2022, the Australian telecom Optus exposed the personal details of millions of customers through an API that was not properly protected. These breaches did not need advanced hacking, just a valid session and an API that failed to check whether the user was actually allowed to access the data being requested.

The problem we are addressing is exactly this: API attacks that look like legitimate traffic, abuse weak or missing authorization, and slip past normal security tools, putting large amounts of sensitive personal and financial data at risk.

## Proposed Technology Stack

Frontend: React, Tailwind CSS, Recharts.

Backend and API gateway: Python, FastAPI, httpx, PyJWT, WebSockets.

Machine learning: scikit learn, NetworkX, Markov model.

LLM: LangChain for threat hunting summaries and executive reports.

Databases: Redis and PostgreSQL.

Deployment: Docker and Docker Compose.

Standards: OWASP API Top 10 and MITRE ATT&CK..

## Business Impact

Authorization attacks such as BOLA and BFLA are among the top causes of API breaches, and a single incident can cost a company heavily in fines, downtime, lost customers and damage to its reputation. Our platform detects and blocks these attacks in real time, protects customer data, and keeps APIs fast and reliable thanks to low latency and a low false positive rate that avoids blocking real users. It applies across banking, healthcare, fintech, SaaS, government, telecom and online retail, and it reduces the cost and effort of meeting security and compliance requirements.

## Social Impact

It helps protect people's most sensitive data, such as bank details, medical records and government identity information, from being accessed by the wrong person. Because every block is explained and mapped to known security standards, it builds public trust and makes audits easier. A lightweight and affordable design means smaller organisations and public services can protect their users too, not only large enterprises.
