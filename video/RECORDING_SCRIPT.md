# Project0 Demo Recording Script

I could not record an actual video file - I have no screen-recording or
video-capture capability in this environment. What's here instead is a
precise, timed script, built only from commands and flows already verified
working this session, for you or a teammate to record for real.

**How to record on a Mac:** press Cmd+Shift+5, choose "Record Entire Screen"
or "Record Selected Portion," click Record. Stop with Cmd+Shift+5 again or
the menu-bar stop button. Takes one try if you follow this script.

**Save the result here:** `video/project0_demo.mp4` (or `.mov`), then:
```bash
cd /Users/gourisankara/project0-main
git add video/project0_demo.mp4
git commit -m "Add demo recording"
git push origin main
```

## Before you hit record

Get everything running first so the recording itself has zero dead air
waiting for services to start:

```bash
cd /Users/gourisankara/project0-main
python3 run.py
```

Wait for `dashboard : http://localhost:3000` in the output. Open that URL
in a browser tab now, before recording, so the tab is already loaded.

## The recording, ~3-4 minutes total

**0:00 - 0:20 | Cold open**
Show the terminal with `run.py`'s output on screen for a few seconds -
Redis, Postgres, upstream, gateway, ML worker, dashboard all coming up
with real health checks. Say: "This is Project0, a Zero-Trust API
Security Gateway. One command starts the whole stack - no mocks, no
canned data."

**0:20 - 0:45 | The dashboard, empty**
Switch to the browser tab. Point out the left nav: Overview, Threat
Hunt, API Inventory, Access Control, Executive Report, Logs. Say:
"Nothing here is invented - every panel reads live data from the
gateway. Right now there's no traffic yet, so let's generate some real
attacks."

**0:45 - 1:30 | Fire the attack suite**
Switch to a second terminal:
```bash
cd /Users/gourisankara/project0-main/backend
python3 attack_sim/simulate.py
```
Let it run on screen - real HTTP requests hitting the real gateway. Say
while it runs: "This fires real attacks: BOLA, BFLA, JWT forgery, SSRF,
enumeration, rate abuse - sixteen attack classes - plus real legitimate
traffic, before and after. Nothing here is scripted to succeed; the
gateway either catches it or it doesn't." Let the final scorecard show on
screen for a few seconds: 16/16 detected, 18/18 legitimate allowed, 0
false positives, and the real p50/p99 latency numbers.

**1:30 - 2:15 | Back to the dashboard, now alive**
Switch back to the browser, refresh or let it live-update. Show:
- Overview: the risk gauge, live threat feed populated with the real
  attacks just fired, MITRE matrix lit up
- Threat Hunt: click into one BOLA case, show the reconstructed
  attack-chain timeline for that identity

**2:15 - 2:45 | Access Control, the network graph**
Click Access Control. Show the Interactive Access Graph tab (D3.js) -
real users, endpoints, and resources as nodes, drawn from real ownership
grants and ML profiles. Say: "This is a live map of who can touch what,
built from the same data BOLA decisions are made against, not a separate
mock."

**2:45 - 3:15 | Executive Report**
Click Executive Report, click "Generate report." Show the real narrative
and breakdown appearing. Say: "This is a deterministic summary over real
audit data, not a live language model - a security report should never
be something an LLM could hallucinate."

**3:15 - 3:40 | Prove one attack directly**
Back to a terminal:
```bash
curl -s http://127.0.0.1:8080/api/accounts/1002 -H "Authorization: Bearer $(cd /Users/gourisankara/project0-main/backend && python3 -c "
import time, jwt
from config import settings
now = int(time.time())
print(jwt.encode({'sub':'not_bob','roles':['user'],'iat':now,'nbf':now-10,'exp':now+3600,
  'iss':settings.issuer,'aud':settings.audience}, settings.jwt_secret, algorithm='HS256'))
")" -i
```
Point out the response: `403`, `X-ZT-Decision: block`, a real BOLA
violation against bob's account, blocked in real time.

**3:40 - 4:00 | Close**
Cut back to the dashboard Overview for a final wide shot. Say: "Every
number on this screen came from this run, right now - nothing here is
canned." End recording.

## If something doesn't look right while recording

- Attack suite showing false positives on a second run: expected if you
  re-run it within the same gateway session (documented, real limitation
  - see `markdown/backend/MEMORY.md`). Restart `run.py` (Ctrl-C, then
  `python3 run.py` again) for a clean second take.
- Dashboard showing stale data: hard-refresh the browser tab.
- Anything else: `python3 run.py` again from a clean terminal is always a
  safe reset - it tears down nothing you didn't start, and Ctrl-C stops
  everything cleanly.
