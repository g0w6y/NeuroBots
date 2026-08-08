# Testing Project0

Four things need proving, and there is a script for each:

| What | Script | Passes when |
|---|---|---|
| Detection is correct | `backend/attack_sim/simulate.py` | 12/12 attacks caught, 0 false positives |
| Revocation and API3 work | `scripts/verify_flow.py` | all checks pass |
| The dashboard shows real data | `frontend/contract-check.mjs` | 44/44 contract checks |
| It stays fast under load | `scripts/benchmark.py` | p99 gateway overhead < 15ms |

## Before you run anything

Bring the stack up and note which port the gateway is on. Every script below
takes the gateway URL, and the single most common failure is pointing a script
at a *different* gateway than the one you just started.

```powershell
# Windows
.\start_all.ps1
```
```bash
# macOS / Linux
./start_all.sh
```
```bash
# or the full containerised stack
docker compose up -d --build
```

Confirm before proceeding:

```bash
curl http://127.0.0.1:8080/health
```

## 1. Attack simulation

```bash
# Windows
.\backend\venv\Scripts\python.exe backend\attack_sim\simulate.py --gateway http://127.0.0.1:8080

# macOS / Linux
backend/venv/bin/python backend/attack_sim/simulate.py

# repeat forever, for a live demo
python attack_sim/simulate.py --loop
```

The suite runs four phases: legitimate traffic, then every attack class, then a
behavioural-drift case that needs ~25s to build a baseline, then **legitimate
traffic again**. That last phase is the one that matters. A gateway which blocks
real users after an attack has traded a false negative for a false positive,
which is not an improvement.

Twelve attack classes are covered: BOLA cross-user, BFLA privilege escalation,
missing token, `alg=none` forgery, wrong-key signature, expired token, untrusted
issuer, wrong audience, malformed token, object enumeration, rate/burst abuse,
and a low-and-slow scrape that stays under every hard limit.

Every verdict is read off the gateway's own `X-ZT-Decision` response header. The
simulator has no privileged view into the gateway and shares no state with it.

### Score it against a freshly started gateway

The suite reuses a small cast of identities, and several forgery cases share one
subject. On a second back-to-back run that subject is still inside the
autonomous cooldown it earned the first time, so it returns
`auto_escalated_block` where the suite expects `challenge` — and the scorecard
reads 11/12.

That is the product working correctly; a proven forger is supposed to stay
blocked. But it makes the number look wrong. **Restart the gateway between
scored runs.** `POST /admin/reset` clears alerts and escalation state but
deliberately preserves ownership grants, so it is not a substitute.

## 2. Revocation and response inspection

```bash
python scripts/verify_flow.py --gateway http://127.0.0.1:8000
```

Covers the two flow steps the attack simulator structurally cannot reach:

- **Step 1 revocation** — mints a token with a `jti`, confirms it is allowed,
  revokes it, and confirms the *same* token is now blocked while a *new* token
  for the same subject still works. That last assertion is the important one: a
  revocation that kills the subject rather than the credential would pass a
  naive test and be badly wrong.
- **Step 10 response inspection** — confirms an authorized read that over-serves
  is flagged with OWASP API3 and MITRE mapping and named evidence, **and that the
  caller still receives the response**. Also asserts a clean endpoint does not
  trip the detector, which is the false-positive guard.

Exits non-zero on any failure, so it can gate CI next to `simulate.py`.

## 3. Dashboard contract check

```bash
cd frontend
VITE_GATEWAY_URL=http://127.0.0.1:8080 VITE_ADMIN_KEY=changeme-admin-key node contract-check.mjs
```
```powershell
# Windows
cd frontend
$env:VITE_GATEWAY_URL="http://127.0.0.1:8080"; $env:VITE_ADMIN_KEY="changeme-admin-key"; node contract-check.mjs
```

This runs the dashboard's own transform functions (`src/api/normalize.js` and
`src/api/analysis.js`) over live gateway responses and asserts that every field
each panel renders is actually present and sane. It catches the class of bug
where the backend renames a field and the UI silently renders `undefined`.

All five sections are covered: Overview, plus the route-table join behind API
Inventory, the ownership grants behind Access Control, and the hunt predicates
behind Threat Hunt. That last group matters most — the hunts key off signal
*names*, so if the gateway renames a detector the page would quietly show zero
results forever. The check asserts that at least one hunt fires whenever blocked
traffic is in the window, which turns that silent drift into a failure.

This is why the derived logic lives in `src/api/analysis.js` rather than inside
the components: `contract-check.mjs` runs under plain node and cannot import
JSX, so anything buried in a `.jsx` file is logic that can never be verified
against a real gateway.

**The variable names must be `VITE_`-prefixed.** Setting `GATEWAY_URL` instead of
`VITE_GATEWAY_URL` does not error — the script silently falls back to
`http://127.0.0.1:8080` and checks whatever is there, which may be a stale
gateway from an earlier session. That produces confusing failures (empty
timeseries, zero entities, alerts thousands of seconds old) that look like
product bugs and are not.

Run it *after* the attack simulation. Against a gateway with no traffic, the
checks for populated charts and non-empty entity tables legitimately fail
because there is genuinely nothing to show.

## 4. Performance benchmark

```bash
python scripts/benchmark.py --gateway http://127.0.0.1:8080 --out BENCHMARK.md
python scripts/benchmark.py --users 800 --requests 20 --concurrency 200
```

Reports two different latency figures, and the difference between them is the
point:

- **Gateway decision overhead** — from the gateway's own audit log. This is what
  protecting your API costs, and the figure the 15ms budget applies to.
- **End-to-end latency** — client-observed, so it includes the harness's own
  async scheduling, the loopback hop and the upstream API's response time. It
  will always be much larger, and a slow upstream does not mean a slow gateway.

### Why it does not just spawn 1000 threads

The gateway is a security device. Point a naive load generator at it and the
rate limiter, the enumeration detector and autonomous escalation all fire, so
you measure how fast it *rejects* traffic. So the harness generates legitimate
load: one distinct signed identity per virtual user (its own rate-limit bucket),
each staying under the 25-per-3s burst ceiling, against `POST /api/transfers` —
authenticated and fully scored, but with no object param, so no ownership lookup
and no enumeration signal.

The run then asserts nothing was blocked or challenged, prints a warning if
anything was, and exits non-zero. A benchmark that quietly averages over a pile
of 403s is worse than no benchmark.

Keep `--requests` under 25. At or above the burst limit the script warns you up
front.

## Interpreting a bad result

| Symptom | Usual cause |
|---|---|
| 11/12 instead of 12/12 | gateway not restarted between scored runs — see above |
| Contract check: 0 entities, stale alerts | pointed at the wrong gateway; use `VITE_`-prefixed vars |
| Contract check fails on empty charts | no traffic yet; run the attack sim first |
| Benchmark reports contamination | `--requests` at/above 25, or a gateway with prior escalation state |
| Throughput far below expectation | single uvicorn worker; see `docs/DEPLOYMENT.md` |
| `502` on allowed requests | upstream not running — correct gateway behaviour, nothing to fix |
