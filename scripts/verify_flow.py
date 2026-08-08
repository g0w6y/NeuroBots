"""
Verifies the two response-path and credential-path steps of the gateway flow
that the attack simulator cannot reach:

  step 1  JWT validation + REVOCATION - a cryptographically perfect token that
          an operator has killed must stop working on its very next request,
          without affecting any other token held by the same subject.
  step 8  RESPONSE INSPECTION (OWASP API3) - an ALLOWED, correctly authorized
          read whose response over-serves must be flagged and explained,
          without the response being withheld from the caller.

    python scripts/verify_flow.py
    python scripts/verify_flow.py --gateway http://127.0.0.1:8080

Exits non-zero on any failure, so it can gate CI alongside simulate.py.

CAUTION, same family as simulate.py's own: this file mints "alice" and hits
/api/accounts/1001 from whatever IP it runs on. Run it (or simulate.py)
enough times in a row against the same never-restarted gateway and the
source IP eventually crosses auto_block_ip_threshold on its own accumulated
history - at that point "SAME token is now rejected" can still correctly
read block/403, but for the wrong reason (auto_escalated_block short-
circuiting before the JWT layer even runs, not jwt_revoked), which would
make "jwt_revoked signal recorded" fail even though revocation itself is
working. Verified this is genuinely a repeated-run artifact, not a flaw in
a single pass: on a freshly started gateway this file passes cleanly and
specifically every time. Restart the gateway (or wait out the cooldown)
if this file has been run several times back to back and starts failing.
"""
import argparse
import json
import os
import sys
import time
import uuid

import httpx
import jwt as pyjwt

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))
from config import settings

_p = argparse.ArgumentParser()
_p.add_argument("--gateway", default=os.getenv("GATEWAY_URL", "http://127.0.0.1:8080"))
GW = _p.parse_args().gateway.rstrip("/")
ADMIN = {"X-Admin-Key": settings.admin_api_key}


def mint(sub, roles=None, jti=None, ttl=3600):
    now = int(time.time())
    payload = {
        "sub": sub, "roles": roles or ["user"], "iat": now, "nbf": now,
        "exp": now + ttl, "iss": settings.issuer, "aud": settings.audience,
    }
    if jti:
        payload["jti"] = jti
    return pyjwt.encode(payload, settings.jwt_secret, algorithm="HS256"), payload["exp"]


def hdr(tok):
    return {"Authorization": f"Bearer {tok}"}


ok = True


def check(label, cond, detail=""):
    global ok
    if not cond:
        ok = False
    print(f"{'PASS' if cond else 'FAIL'}  {label}  {detail}")


# "observe" counts alongside "allow" throughout this file for the same
# reason attack_sim.py's phase_benign accepts it: if this runs against a
# gateway where the "account" resource is still inside its autonomous
# hardening window (e.g. attack_sim.py's own phase 4 ran against this same
# process recently - a natural thing to do back to back, since TESTING.md
# lists these scripts in sequence), a real, correctly-authorized read comes
# back "observe" instead of "allow" for up to resource_hardening_cooldown_sec
# (180s default) - still 200, still real data, never interrupted. Found by
# actually hitting this: running verify_flow.py right after simulate.py
# produced 4 false failures here before this was accounted for.
_OK_DECISIONS = ("allow", "observe")

with httpx.Client(timeout=10.0) as c:
    print("\n=== STEP 1: JWT validation + revocation ===")
    jti = f"sess-{uuid.uuid4().hex[:8]}"
    tok, exp = mint("alice", jti=jti)

    r1 = c.get(f"{GW}/api/accounts/1001", headers=hdr(tok))
    check("valid token with a jti is allowed",
          r1.headers.get("X-ZT-Decision") in _OK_DECISIONS,
          f"decision={r1.headers.get('X-ZT-Decision')} status={r1.status_code}")

    rev = c.post(f"{GW}/admin/revoke", headers=ADMIN,
                 json={"jti": jti, "exp": exp, "reason": "verification run"})
    check("revoke accepted", rev.status_code == 200, rev.text[:120])

    r2 = c.get(f"{GW}/api/accounts/1001", headers=hdr(tok))
    check("SAME token is now rejected",
          r2.headers.get("X-ZT-Decision") == "block" and r2.status_code == 403,
          f"decision={r2.headers.get('X-ZT-Decision')} status={r2.status_code}")

    # emit_alert()'s audit write is fire-and-forget by design (main.py) - the
    # response for r2 above can and does return before that write lands. With
    # the in-memory fallback the write is effectively instant so this never
    # showed up; with real Postgres attached it's a genuine race - caught by
    # actually running this against a real docker-compose Postgres, not the
    # fallback this file mostly gets tested against. Same wait STEP 8 already
    # uses below for the same reason.
    time.sleep(0.4)
    alerts = c.get(f"{GW}/admin/alerts", headers=ADMIN).json()
    revoked_alert = [a for a in alerts
                     if any(s.get("detector") == "jwt_revoked" for s in a.get("signals", []))]
    check("jwt_revoked signal recorded with OWASP/MITRE", bool(revoked_alert),
          json.dumps(revoked_alert[-1]["signals"][0], indent=None) if revoked_alert else "none")

    fresh, _ = mint("alice", jti=f"sess-{uuid.uuid4().hex[:8]}")
    r3 = c.get(f"{GW}/api/accounts/1001", headers=hdr(fresh))
    check("a NEW token for the same subject still works",
          r3.headers.get("X-ZT-Decision") in _OK_DECISIONS,
          f"decision={r3.headers.get('X-ZT-Decision')}")

    listed = c.get(f"{GW}/admin/revocations", headers=ADMIN).json()
    check("revocation is listed", listed["count"] >= 1,
          f"count={listed['count']} source={listed['source']}")

    print("\n=== STEP 8: response inspection (API3) ===")
    tok2, _ = mint("alice", jti=f"sess-{uuid.uuid4().hex[:8]}")
    r4 = c.get(f"{GW}/api/accounts/1001", headers=hdr(tok2))
    check("authorized read is still allowed (not blocked by API3)",
          r4.headers.get("X-ZT-Decision") in _OK_DECISIONS and r4.status_code == 200,
          f"decision={r4.headers.get('X-ZT-Decision')}")

    time.sleep(0.4)
    alerts = c.get(f"{GW}/admin/alerts", headers=ADMIN).json()
    mine = [a for a in alerts if a["path"] == "/api/accounts/1001" and a["subject"] == "alice"]
    latest = mine[-1] if mine else {}
    dets = [s["detector"] for s in latest.get("signals", [])]
    check("excessive_data_exposure detected on an ALLOWED request",
          "excessive_data_exposure" in dets, f"signals={dets}")

    exposure = [s for s in latest.get("signals", []) if s["detector"] == "excessive_data_exposure"]
    if exposure:
        s = exposure[0]
        check("finding carries OWASP API3 + MITRE + evidence",
              s["owasp"].startswith("API3") and s["mitre"] and s["evidence"],
              f"{s['owasp']} / {s['mitre']}")
        check("evidence names the leaked fields",
              "password_hash" in s["evidence"] and "ssn" in s["evidence"],
              s["evidence"])
    check("narrative mentions the response finding",
          "Response inspection" in (latest.get("narrative") or ""),
          (latest.get("narrative") or "")[:110])

    print("\n=== regression: clean endpoint must NOT trip API3 ===")
    tok3, _ = mint("alice", jti=f"sess-{uuid.uuid4().hex[:8]}")
    c.get(f"{GW}/api/accounts/1001/transactions", headers=hdr(tok3))
    time.sleep(0.4)
    alerts = c.get(f"{GW}/admin/alerts", headers=ADMIN).json()
    tx = [a for a in alerts if a["path"].endswith("/transactions")]
    tx_dets = [s["detector"] for s in (tx[-1].get("signals", []) if tx else [])]
    check("transactions response (no sensitive fields) is clean",
          "excessive_data_exposure" not in tx_dets, f"signals={tx_dets}")

print(f"\n{'ALL CHECKS PASSED' if ok else 'FAILURES PRESENT'}")
sys.exit(0 if ok else 1)
