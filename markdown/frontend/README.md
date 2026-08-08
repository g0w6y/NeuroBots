# Project0 Threat Console

Live dashboard for the Project0 Zero-Trust API Security Gateway. Reads real gateway
state over HTTP — no simulated or mock data anywhere in this app.

## Run it

```bash
npm install
cp .env.example .env   # point VITE_GATEWAY_URL / VITE_ADMIN_KEY at your running gateway
npm run dev
```

The gateway must be running first (see the `backend` project) and reachable at
`VITE_GATEWAY_URL` (default `http://127.0.0.1:8080`). `VITE_ADMIN_KEY` must match the
gateway's `ADMIN_API_KEY` — every `/admin/*` route requires it.

## What it shows

- **Threat feed** — live decisions (allow/challenge/block) with the exact signals and
  MITRE/OWASP tags the gateway attached to each one.
- **Risk gauge + stat row** — overall risk, block rate, average latency, entity count.
- **Allowed vs. blocked chart** — last hour, bucketed from real alert timestamps.
- **MITRE ATT&CK matrix** — only the techniques the gateway actually detects (T1078,
  T1119, T1548, T1499, T1550, T1087). Deliberately not a generic reference list — showing
  a technique here the gateway can't detect would be a real, dashboard-level false claim.
- **Autonomous mitigation panel** — escalation events from `/admin/incidents`: which
  identity or source IP got auto-blocked, why, and for how long. This is the gateway
  acting without a human in the loop, not a simulated feature.
- **Entities by risk** — per-subject request volume, risk score, distinct endpoints
  touched, and status (active / flagged / blocked).

## Data flow

`src/api/gateway.js` calls the gateway's `/admin/*` endpoints directly. `src/api/normalize.js`
transforms the gateway's actual response shapes (field names like `time`, `risk`, `explain`,
`signals[].detector` — not the display names the components use) into what the UI reads.
Every value in `normalize.js` is derived from a real response; nothing is generated. If a
poll fails, `useLiveData.js` shows the last known real data with an honest "gateway
unreachable" banner and keeps retrying — it never substitutes fake data.

## CORS note

The gateway's CORS default is permissive (`*`) for demo convenience — the actual access
boundary on every admin route is `X-Admin-Key`, not CORS. If the gateway is configured
with a locked-down origin list, add this app's dev origin to `CORS_ALLOWED_ORIGINS` on
the gateway side.
