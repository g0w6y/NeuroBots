# Project0 Product

Zero Trust API Security Intelligence and Autonomous Authorization Protection Platform

## What is Project0

Project0 is an API security gateway that sits between clients and your APIs. It monitors every request in real time, detects authorization attacks, and blocks them automatically with zero false positives.

## The Problem

APIs are how apps share data and services. Attackers target APIs because one missing permission check exposes everything. The hardest attacks to catch are authorization attacks where a real logged in user asks for data that belongs to someone else. Traditional security tools miss these attacks because the requests look normal.

Example: a user changes their account ID from 1001 to 1002 and the API hands them another user's private data. This is called Broken Object Level Authorization (BOLA).

Real breaches:
- T-Mobile (2023): Attackers used a single API to steal 37 million customer records
- Optus (2022): An unauthenticated API exposed 10 million customer records
- Peloton (2021): Anyone could access private user profiles without authentication

## The Solution

Project0 validates every API request in real time. It checks:
- Is the token real and not expired
- Does this user actually own this object
- Does this user have permission to use this function
- Is the user rate limiting being exceeded

If any check fails, Project0 blocks the request before it reaches your API. Every decision is explained with the exact reason (OWASP API Top 10 category and MITRE ATT&CK technique).

## How It Works

1. Request comes in through Project0 gateway on port 8080
2. Gateway validates the JWT token
3. Gateway checks if user owns the requested object (stored in Redis)
4. Gateway checks if user has permission for this function
5. Gateway scores the overall risk
6. Gateway decides: allow, challenge with step up auth, or block
7. Allowed requests go to your real API
8. All decisions are logged to PostgreSQL and shown live in the dashboard

## What You Get

API Security Gateway: reverse proxy that blocks attacks inline, under 15 milliseconds

Threat Intelligence Dashboard: live view of all requests, risk scores, blocked attacks, MITRE ATT&CK mapping

Attack Simulation Suite: proves the platform detects BOLA, BFLA, JWT attacks, rate abuse, enumeration and missing auth with zero false positives

Machine Learning Engine: learns each user's normal behavior and flags anomalies

## Technology

Frontend: React, Tailwind CSS, Recharts

Backend and API gateway: Python, FastAPI, httpx, PyJWT, WebSockets

Machine learning: scikit learn, NetworkX, Markov chains

LLM: LangChain for threat hunting summaries

Databases: Redis for fast lookups, PostgreSQL for audit logs

Deployment: Docker and Docker Compose

Standards: OWASP API Top 10, MITRE ATT&CK

## Results

Detection rate: 100% (18 of 18 attack classes detected, plus a full
attack-chain scenario), verified by `backend/attack_sim/simulate.py`

False positive rate: 0% (no real users blocked)

Gateway decision overhead: p99 under 15 milliseconds, measured, not estimated
(see `markdown/PERFORMANCE.md`)

Throughput: single uvicorn worker measures a few hundred req/s end to end on
a developer laptop; scales horizontally with `WORKERS=N` behind a load
balancer, verified with 3 real worker processes (see `markdown/DEPLOYMENT.md`)

## Why Project0 Wins

Existing API security tools are signature based (miss authorization attacks) or expensive closed source platforms. Project0 is:

Open source: build it yourself, no vendor lock in

Fast: zero latency overhead so you do not slow down your API

Accurate: zero false positives so you do not block real customers

Explainable: every decision has a clear reason mapped to OWASP and MITRE

Affordable: runs on standard libraries and commodity databases

## Use Cases

Banking APIs: detect unauthorized account access

Healthcare APIs: prevent medical record theft

Government APIs: protect citizen data

SaaS applications: stop cross tenant data leaks

E-commerce: detect credential abuse

## Team

Backend and API gateway: Gouri Sankar A, Jeevan George

Frontend: Aleena Shaji, Mariya Liss

Machine learning: Melwin Santhosh

DevOps and infrastructure: Nirmal Josekutty
