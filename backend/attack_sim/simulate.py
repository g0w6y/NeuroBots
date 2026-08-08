"""
Project0 attack simulation suite.

Drives real HTTP traffic at a running gateway and scores it against the success
criteria in BACKEND.md: 8/8 attack classes detected, 0 false positives on
legitimate traffic, gateway decision overhead under 15ms.

Nothing here is mocked. Every request is a real request over the wire; every
verdict below is read off the gateway's own X-ZT-Decision response header. The
simulator has no privileged view into the gateway and shares no state with it.

CAUTION about --loop / repeated runs: phase_attacks deliberately fires every
attack class from one real source IP, on purpose - phase 4 exists specifically
to prove a barrage from your own machine doesn't collaterally block your own
legitimate traffic, and that only holds if everything genuinely comes from one
IP. A single pass already produces close to a dozen hard, hostile-classified
blocks (BOLA, alg=none, bad signature, malformed JWT, continued enumeration,
the chain phase's two BOLA hits), against auto_block_ip_threshold (10 in 60s,
config.py) — verified against a live run, still 0 false positives on a clean
Redis, but with less headroom than before. Verified by
running this file twice in a row against the same live gateway: the second
run's own case 6 (expects "challenge") comes back "block" and an unrelated
benign case (bob reading his own account) genuinely fails - not a detection
bug, the gateway is correctly treating the *suite's own* repeated traffic as a
coordinated attack from that IP and locking it out for 5-10 minutes. Run this
suite exactly once per gateway process for a certification pass. Restart the
gateway (or wait out the cooldown) before running it again. Don't use --loop
against a gateway with real auto-mitigation enabled unless you've confirmed
the interval is long enough, and the threshold high enough, to outlast its own
traffic - as shipped, it isn't.

CAUTION about the "Gateway decision overhead" line specifically, with real
Postgres attached: found by running this suite against a genuinely fresh
clone with real docker-compose Redis/Postgres (not the in-memory fallback
this file mostly gets tested against), then a second time after restarting
the gateway process. p99 read "OVER the 15ms budget" on both runs. Root
cause verified, not assumed: `/admin/reset`'s `audit_log.reset()` correctly
and deliberately never touches Postgres rows ("an audit log that can be
erased through the API is not an audit log" - see audit_log.py), and killing
the gateway process doesn't touch them either - only a fresh Postgres
database does. The p50/p99 line is the one part of this scorecard that reads
*historical* alert rows (`GET /admin/alerts`) rather than judging live
per-request headers, so with real Postgres it silently mixes in every prior
run's samples, including ones recorded during unrelated CPU contention (a
concurrent `npm install`, in the run that surfaced this). The pass/fail
scorecard above that line is unaffected - each case is judged against its
own live X-ZT-Decision header, not against history. Verified the fix: with
Postgres tables genuinely truncated first (`TRUNCATE alerts, incidents;`),
a clean run reads p99 comfortably inside budget. If this line ever reads
over budget against a real Postgres deployment, truncate those two tables
(or point at a fresh database) before concluding the gateway itself is slow.

Usage:
    python attack_sim/simulate.py              # one full pass, prints a scorecard
    python attack_sim/simulate.py --loop       # NOT safe as-is, see CAUTION above
    python attack_sim/simulate.py --gateway http://127.0.0.1:8080
"""

import argparse
import base64
import json
import os
import sys
import time

import httpx
import jwt as pyjwt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings  # noqa: E402


# ---------------------------------------------------------------- token minting

def mint(sub, roles=None, ttl=3600, iss=None, aud=None, secret=None):
    """A normal, correctly signed token — what a real logged-in user carries."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "roles": roles if roles is not None else ["user"],
        "iat": now,
        "nbf": now - 10,
        "exp": now + ttl,
        "iss": settings.issuer if iss is None else iss,
        "aud": settings.audience if aud is None else aud,
    }
    return pyjwt.encode(payload, secret or settings.jwt_secret, algorithm="HS256")


def mint_alg_none(sub="mallory"):
    """The classic CVE-2015-9235 attack: strip the signature, set alg to none,
    and hand yourself the admin role."""
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": sub, "roles": ["admin"], "iat": now, "exp": now + 3600,
               "iss": settings.issuer, "aud": settings.audience}

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=")

    return (seg(header) + b"." + seg(payload) + b".").decode()


# ---------------------------------------------------------------------- harness

class Sim:
    def __init__(self, gateway):
        self.gateway = gateway.rstrip("/")
        self.client = httpx.Client(timeout=15)
        self.rows = []          # (phase, name, expected, actual, risk, latency_ms, ok)

    def send(self, method, path, token=None, body=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        t0 = time.perf_counter()
        try:
            r = self.client.request(method, self.gateway + path, headers=headers, json=body)
        except Exception as exc:                      # gateway down / connection refused
            return None, "unreachable", "-", (time.perf_counter() - t0) * 1000, str(exc)
        wall_ms = (time.perf_counter() - t0) * 1000
        return (r,
                r.headers.get("X-ZT-Decision", "none"),
                r.headers.get("X-ZT-Risk", "-"),
                wall_ms,
                None)

    def case(self, phase, name, expected, method, path, token=None, body=None, also_ok=()):
        r, decision, risk, wall_ms, err = self.send(method, path, token, body)
        if err:
            self.rows.append((phase, name, expected, "UNREACHABLE", "-", wall_ms, False))
            return None
        ok = (decision == expected) or (decision in also_ok)
        self.rows.append((phase, name, expected, decision, risk, wall_ms, ok))
        return r


# ------------------------------------------------------------------- the phases

def phase_benign(sim, tag="", account_also_ok=()):
    """Legitimate users doing legitimate things. Every one of these MUST be
    allowed — each unexpected block here is a false positive, and the platform's
    headline claim is that there are none.

    account_also_ok: extra acceptable decisions for the account-resource
    checks specifically, not the whole phase - used post-hardening (phase 5)
    to accept "observe" alongside "allow". This is NOT relaxing the false
    positive bar: "observe" still means the request succeeded (200, real
    data, no interruption) - see resource_hardening_signal's docstring for
    why that decision can happen without ever meaning a real user was
    punished. A "block" or "challenge" here would still, correctly, fail
    this check regardless of account_also_ok."""
    alice = mint("alice")
    bob = mint("bob")
    root = mint("root", ["admin"])
    p = f"benign{tag}"

    sim.case(p, "alice reads her own account", "allow", "GET", "/api/accounts/1001", alice, also_ok=account_also_ok)
    sim.case(p, "alice reads her own transactions", "allow", "GET", "/api/accounts/1001/transactions", alice, also_ok=account_also_ok)
    sim.case(p, "bob reads his own account", "allow", "GET", "/api/accounts/1002", bob, also_ok=account_also_ok)
    sim.case(p, "admin reads the admin user list", "allow", "GET", "/api/admin/users", root)
    sim.case(p, "alice posts a legitimate transfer", "allow", "POST", "/api/transfers", alice,
             body={"from_account": "1001", "to_account": "1002", "amount": 25.00})
    for i in range(4):
        sim.case(p, f"alice re-reads her account ({i + 1})", "allow", "GET", "/api/accounts/1001", alice, also_ok=account_also_ok)


def phase_attacks(sim):
    """The 8 attack classes from PRODUCT.md. Each must be blocked."""
    alice = mint("alice")

    # 1. BOLA — a real, logged-in user reaching for someone else's object.
    #    This is the headline attack: OWASP API1, and the T-Mobile / Optus pattern.
    sim.case("attack", "1. BOLA — bob reads alice's account", "block",
             "GET", "/api/accounts/1001", mint("bob"))

    # 2. BFLA — a valid user calling an admin-only function.
    sim.case("attack", "2. BFLA — plain user hits /api/admin/users", "block",
             "GET", "/api/admin/users", alice)

    # 3. Missing credential on a protected route.
    sim.case("attack", "3. Missing token on a protected route", "block",
             "GET", "/api/accounts/1001", None)

    # 4. alg=none signature stripping, self-granted admin role.
    sim.case("attack", "4. JWT alg=none with forged admin role", "block",
             "GET", "/api/admin/users", mint_alg_none())

    # 5. Forged signature — right shape, wrong key.
    sim.case("attack", "5. JWT signed with the wrong key", "block",
             "GET", "/api/accounts/1001", mint("eve", secret="attacker-guessed-secret"))

    # 6. Expired credential replayed after its lifetime. Expected verdict here is
    #    "challenge", not "block": an expired session is a hard fact but a benign
    #    one, so policy asks for step-up re-authentication. The request still
    #    never reaches the upstream API, so nothing leaks either way.
    #    Subject is unique per run, same reasoning as phase_behavioural's
    #    analyst id below: this is the one case in the suite expecting
    #    "challenge" rather than "block", so it's the one case a second
    #    run's accumulated control-plane profile on a *reused* fixed identity
    #    can silently push over the block threshold - not a wrong verdict,
    #    just a misleading one for a single-purpose deterministic test.
    #    Caught by running the suite twice in a row without restarting the
    #    gateway; --loop does exactly that every --interval seconds.
    sim.case("attack", "6. Expired JWT replayed", "challenge",
             "GET", "/api/accounts/1001", mint(f"carol_expired_{int(time.time())}", ttl=-3600))

    # 7. Token minted for a different issuer/audience — cross-environment replay.
    sim.case("attack", "7a. JWT from an untrusted issuer", "block",
             "GET", "/api/accounts/1001", mint("dave", iss="evil-idp"))
    sim.case("attack", "7b. JWT scoped to a different audience", "block",
             "GET", "/api/accounts/1001", mint("dave", aud="some-other-api"))
    sim.case("attack", "7c. Structurally malformed token", "block",
             "GET", "/api/accounts/1001", "this.is.not-a-real-jwt")

    # 8. Enumeration — walking object IDs to scrape the dataset. The gateway
    #    should tolerate the first few (could be a legitimate list view) and then
    #    recognise the pattern.
    scanner = mint("scanner")
    caught_at = None
    for n, oid in enumerate(range(4000, 4000 + settings.enum_threshold + 4), start=1):
        r, decision, risk, _, err = sim.send("GET", f"/api/accounts/{oid}", scanner)
        if err:
            break
        if decision == "block" and caught_at is None:
            caught_at = n
    sim.rows.append(("attack", f"8. Object enumeration (caught at request #{caught_at})",
                     "block", "block" if caught_at else "allow", "-", 0.0, bool(caught_at)))

    # 9. Volumetric abuse — burst past the per-user limit.
    flooder = mint("flooder")
    burst_caught = None
    for n in range(1, settings.rate_limit_burst_requests + 6):
        r, decision, risk, _, err = sim.send("GET", "/api/accounts/5000", flooder)
        if err:
            break
        if decision == "block" and burst_caught is None:
            burst_caught = n
    sim.rows.append(("attack", f"9. Rate/burst abuse (caught at request #{burst_caught})",
                     "block", "block" if burst_caught else "allow", "-", 0.0, bool(burst_caught)))

    # 11. SSRF — a webhook/callback field pointed at the cloud metadata
    #     endpoint instead of a real external host. OWASP API7.
    ssrf_actor = mint("ssrf_actor")
    sim.case("attack", "11. SSRF via webhook_url to cloud metadata endpoint (API7)", "block",
             "POST", "/api/transfers", ssrf_actor,
             body={"from_account": "1001", "to_account": "1002", "amount": 10,
                   "webhook_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})

    # 12. Excessive data exposure — alice (a real, seeded, non-admin owner)
    #     reads her own account. The request is correctly allowed (she owns
    #     it), but the response body must still have its ssn field masked
    #     before it leaves the gateway. OWASP API3. This is the one case in
    #     the suite that isn't just a decision check - it inspects the
    #     actual response body security_checks.py redacted.
    alice_plain = mint("alice", roles=["user"])
    r, decision, risk, _, err = sim.send("GET", "/api/accounts/1001", alice_plain)
    ssn_masked = False
    detail = f"unreachable: {err}" if err else f"http {r.status_code if r else '?'}"
    if r is not None and r.status_code == 200:
        try:
            ssn = r.json().get("ssn", "")
            ssn_masked = "*" in ssn
            detail = f"ssn={ssn!r}"
        except Exception as exc:
            detail = f"response not JSON ({exc})"
    ok = (decision == "allow") and ssn_masked
    sim.rows.append(("attack", f"12. Excessive data exposure — ssn masked for owner ({detail}) (API3)",
                     "allow+masked", f"{decision}+{'masked' if ssn_masked else 'UNMASKED'}", risk, 0.0, ok))

    # 15. Shadow endpoint — a real-world pattern: an old API version, a debug
    #     route, or a field the docs forgot, still live behind the gateway but
    #     never added to routes.json. The detector for this (API9, improper
    #     inventory management) has existed since security_checks.py's four-
    #     detector expansion, but until now nothing in this suite ever proved
    #     it fires — the OWASP coverage table listed API9 "Covered" on the
    #     strength of code review, not a live case. It's deliberately a soft,
    #     informational-only signal (weight 30, well under both thresholds)
    #     so an unlisted path a real integration legitimately needs is
    #     visible, not broken — the expected verdict is "observe", not block.
    shadow_actor = mint("shadow_probe")
    sim.case("attack", "15. Shadow endpoint — unlisted /api/ path (API9)", "observe",
             "GET", "/api/accounts/1001/export", shadow_actor)

    # 16. Security misconfiguration self-audit — same story as case 15: API8's
    #     detector (audit_config, /admin/config-audit) has existed since the
    #     same expansion and was never actually called by the suite that
    #     certifies coverage. This isn't attack traffic — an operator or CI
    #     job calls this endpoint directly — so it's checked structurally
    #     rather than by decision header: the endpoint must be live, return
    #     200, and report a real, structured verdict.
    admin_hdr = {"X-Admin-Key": settings.admin_api_key}
    try:
        r16 = httpx.get(f"{sim.gateway}/admin/config-audit", headers=admin_hdr, timeout=5)
        body16 = r16.json()
        audit_ok = (
            r16.status_code == 200
            and isinstance(body16.get("clean"), bool)
            and isinstance(body16.get("warnings"), list)
        )
        detail16 = f"clean={body16.get('clean')}, {body16.get('warning_count')} warning(s)"
    except Exception as exc:
        audit_ok = False
        detail16 = f"unreachable: {exc}"
    sim.rows.append(("attack", f"16. Security misconfiguration audit is live ({detail16}) (API8)",
                     "200+structured", "200+structured" if audit_ok else "FAIL", "-", 0.0, audit_ok))


def phase_attack_chain(sim):
    """One attacker identity, one session, in order — recon, exploit, escalate,
    pivot, evade. Every other case in phase_attacks proves a single request
    gets the right verdict in isolation; nothing in the suite before this
    proved those verdicts hold together as an actual attacker's session, which
    is the more convincing and more realistic shape a real incident takes.

    Every step reuses an existing, already-proven detector — no new detection
    logic is introduced here. What's new is the sequencing and two assertions
    that only make sense across multiple requests from the same identity:
    that response-masking and precise, request-scoped blocking keep working
    correctly mid-attack, and that being caught twice doesn't get this
    identity's own legitimate traffic collaterally punished (auto-escalation
    needs 3 hostile hits in the window; this chain deliberately produces
    exactly 2 — bola_cross_user twice — bfla_role_violation is intentionally
    excluded from that count, see HOSTILE_ESCALATION_DETECTORS in main.py —
    so step 5 is a real test of "under the threshold", not a lucky pass).

    This is also, quietly, the first case in the suite that ever exercises
    the dashboard's "Recon then exploit" saved hunt (frontend/src/api/
    analysis.js) with traffic actually shaped like what it looks for: at
    least two clean requests from an identity before its first hostile one.
    Every other case's identity is hostile from request one, which is why
    that hunt has been real, built, and reachable in the UI, but never once
    populated by anything in this suite until this phase.
    """
    chain_id = f"chain_attacker_{int(time.time())}"
    token = mint(chain_id)

    # 1. Recon — probe a couple of ID slots nobody has touched yet. Ownership
    #    is first-touch, so these reads are genuinely unremarkable: exactly
    #    what a first-time legitimate caller looks like too. This is why a
    #    fixed-threshold detector can't catch this step, and doesn't need to.
    recon_obj = f"93{int(time.time())}"
    sim.case("chain", "recon 1 — probe an untouched object id", "allow",
             "GET", f"/api/accounts/{recon_obj}", token)
    sim.case("chain", "recon 2 — probe a second untouched id", "allow",
             "GET", f"/api/accounts/{recon_obj}1", token)

    # 2. Exploit — recon over, go straight for a real, seeded, owned object
    #    (alice's account). This is the BOLA moment: OWASP API1, the exact
    #    T-Mobile/Optus pattern, now happening as the third request of a
    #    session that looked clean for the first two.
    sim.case("chain", "exploit — BOLA on a real victim account (API1)", "block",
             "GET", "/api/accounts/1001", token)

    # 3. Escalate — horizontal failed, try vertical: the same identity reaches
    #    for an admin-only function next, the real behaviour of an attacker
    #    who still has a live session and is looking for any way in.
    sim.case("chain", "escalate — same identity tries an admin route (API5)", "block",
             "GET", "/api/admin/users", token)

    # 4. Pivot — a real, common gap in other systems: object-level auth
    #    enforced on the primary endpoint but forgotten on a nested
    #    sub-resource of the same object. Proves this gateway doesn't have
    #    that gap — object_param resolution is shared, so the sibling
    #    endpoint is exactly as protected as the one already blocked.
    sim.case("chain", "pivot — same victim, sibling endpoint (API1)", "block",
             "GET", "/api/accounts/1001/transactions", token)

    # 5. Evade — slow down and go back to touching only what this identity
    #    actually owns. The safety property: two real, confirmed hostile
    #    hits from this identity (step 2 and step 4) is proportionate
    #    evidence, not a life sentence — auto-escalation needs 3 in the
    #    window, so this identity is never blocked outright here. A bare
    #    "block" would mean the gateway is over-punishing, exactly the
    #    failure mode this platform is measured against.
    #
    #    also_ok=("observe",): by this point in a full suite run, the
    #    "account" resource has usually already crossed autonomous hardening's
    #    OWN independent bar — bob's case 1 and scanner's case 8 are two more
    #    real, distinct attackers against the same resource, landed earlier
    #    in phase_attacks, and this chain's own step 2 makes three. That's a
    #    second, genuinely correct mechanism doing its job, not a false
    #    positive: "observe" still means 200, real data, no interruption —
    #    see resource_hardening_signal's docstring and phase_benign's
    #    identical account_also_ok pattern for why. What must never happen
    #    here is "challenge" or "block" — verified separately by case 14.
    time.sleep(1.0)
    sim.case("chain", "evade — same identity reads its own object again", "allow",
             "GET", f"/api/accounts/{recon_obj}", token, also_ok=("observe",))


def phase_behavioural(sim):
    """The attack no fixed threshold catches.

    Every detector above fires on a rule: a bad signature, an object the subject
    doesn't own, a request count over a line. An attacker who knows the limits
    just stays under them. This subject does exactly that — it never forges a
    token, never touches an object it doesn't own, and never crosses any rate
    limit. It simply starts behaving unlike itself.

    Catching it needs a learned per-subject baseline, which is what the control
    plane is for. The expected verdict is `challenge`, not `block`: a behavioural
    deviation is inference rather than proof, so the right answer is to make the
    user re-authenticate, not to cut off someone who might just be having a busy
    morning. That distinction is what lets the platform run this detector at all
    without putting its zero-false-positive claim at risk.

    Takes ~25s, since a baseline has to exist before it can be departed from.
    """
    subject = f"analyst_{int(time.time())}"
    token = mint(subject)
    # Unique per run, exactly like the subject. A fixed id made this phase
    # self-poisoning: ownership is first-touch, so run 1's throwaway analyst
    # permanently became the owner of the object, and every later run's analyst
    # was a textbook bola_cross_user against it - three hostile blocks, identity
    # escalated, and the phase then reported the behavioural detector as broken
    # when what it had actually done was catch a real BOLA violation the suite
    # manufactured itself. `/admin/reset` cannot rescue this either: it preserves
    # ownership grants on purpose, so only a full process restart cleared it.
    obj = f"97{int(time.time()) % 100000}"

    for _ in range(7):                       # ~14s of ordinary, quiet activity
        sim.send("GET", f"/api/accounts/{obj}", token)
        time.sleep(2)

    for _ in range(30):                      # ~3 req/s: far off its own baseline,
        sim.send("GET", f"/api/accounts/{obj}", token)   # but inside 120/60s and 25/3s
        time.sleep(0.33)

    # The control plane recomputes on a ~1s tick and the data plane reads the
    # cached result, so a single probe fired at a fixed delay is racing that tick
    # - it was measured failing roughly one run in two. Poll instead: the verdict
    # we care about is "does the behavioural layer reach a decision at all",
    # not "does it happen to have ticked within 2.5 seconds". Each probe is
    # itself in-window traffic, so the deviation stays live while we look.
    decision, risk = None, 0
    for _ in range(8):
        time.sleep(1.0)
        _, decision, risk, _, _ = sim.send("GET", f"/api/accounts/{obj}", token)
        if decision == "challenge":
            break

    sim.rows.append(("attack", "10. Low-and-slow scrape (under every hard limit)",
                     "challenge", decision, risk, 0.0, decision == "challenge"))


def phase_hardening(sim):
    """Autonomous API hardening (bonus): distinct from every other case here,
    which each prove a single request gets a correct verdict. This proves a
    multi-request, multi-attacker CONSEQUENCE: enough distinct attackers
    against one resource and the gateway raises that resource's own bar on
    its own, with nobody telling it to - and does so without ever punishing
    a real, unrelated user of that resource, which is the actual hard part.

    Needs 3 DISTINCT attacker identities (not one identity three times -
    that's what identity-level auto-escalation already owns, see case 1-9
    above) genuinely blocked against the SAME resource type, run with real
    spacing so the gateway's fire-and-forget recording (deliberately kept
    off the request's own response path - see main.py's maybe_harden_resource)
    has time to land before we check. A tight loop with no spacing was
    measured under-triggering for exactly this reason during development;
    this phase's pacing is not cosmetic.
    """
    account1, account2, account3 = f"96{int(time.time())}1", f"96{int(time.time())}2", f"96{int(time.time())}3"
    owner1, owner2, owner3 = mint(f"hard_owner1_{int(time.time())}"), mint(f"hard_owner2_{int(time.time())}"), mint(f"hard_owner3_{int(time.time())}")
    # first-touch each owner onto their own object so the subsequent attacker
    # requests are genuine bola_cross_user violations, not first-touch grants
    for obj, owner in ((account1, owner1), (account2, owner2), (account3, owner3)):
        sim.send("GET", f"/api/accounts/{obj}", owner)

    attacker1 = mint(f"hard_attacker1_{int(time.time())}")
    attacker2_bad_sig = mint(f"hard_attacker2_{int(time.time())}", secret="wrong-secret-for-hardening-test")
    attacker3 = mint(f"hard_attacker3_{int(time.time())}")

    sim.send("GET", f"/api/accounts/{account1}", attacker1)          # bola_cross_user, distinct subject
    time.sleep(1.0)
    sim.send("GET", f"/api/accounts/{account2}", attacker2_bad_sig)  # jwt_bad_signature, collapses to this IP
    time.sleep(1.0)
    sim.send("GET", f"/api/accounts/{account3}", attacker3)          # bola_cross_user, distinct subject
    time.sleep(1.0)

    admin = {"X-Admin-Key": settings.admin_api_key}
    hardened = False
    for _ in range(6):
        time.sleep(1.0)
        try:
            r = httpx.get(f"{sim.gateway}/admin/hardening", headers=admin, timeout=5)
            resources = [h["resource"] for h in r.json().get("hardened_resources", [])]
            if "account" in resources:
                hardened = True
                break
        except Exception:
            pass
    sim.rows.append(("attack", "13. Autonomous hardening triggers after 3 distinct attackers on one resource",
                     "hardened", "hardened" if hardened else "not hardened", "-", 0.0, hardened))

    # The safety property that matters more than the trigger itself: a real,
    # unrelated owner of a DIFFERENT object of the now-hardened resource must
    # never be challenged or blocked by this alone - only observed. If this
    # fails, the feature is a self-inflicted DoS vector, not a defense.
    innocent = mint(f"hard_innocent_{int(time.time())}")
    innocent_obj = f"96{int(time.time())}9"
    sim.send("GET", f"/api/accounts/{innocent_obj}", innocent)  # first-touch, establishes ownership
    r, decision, risk, _, err = sim.send("GET", f"/api/accounts/{innocent_obj}", innocent)  # real second read
    safe = (not err) and decision in ("allow", "observe")
    sim.rows.append(("attack", f"14. Innocent owner of hardened resource not collaterally punished (decision={decision})",
                     "allow/observe", decision if not err else "UNREACHABLE", risk, 0.0, safe))


# ------------------------------------------------------------------- scorecard

def report(sim, gateway):
    admin = {"X-Admin-Key": settings.admin_api_key}

    print()
    print("=" * 96)
    print(f"{'PHASE':<14}{'CASE':<52}{'EXPECT':<10}{'GOT':<10}{'RISK':<6}")
    print("=" * 96)
    for phase, name, expected, actual, risk, ms, ok in sim.rows:
        mark = "PASS" if ok else "FAIL"
        print(f"{mark:<5}{phase:<9}{name[:51]:<52}{expected:<10}{str(actual):<10}{str(risk):<6}")

    attacks = [r for r in sim.rows if r[0] == "attack"]
    benign = [r for r in sim.rows if r[0].startswith("benign")]
    chain = [r for r in sim.rows if r[0] == "chain"]
    detected = sum(1 for r in attacks if r[6])
    false_pos = [r for r in benign if not r[6]]
    chain_ok = sum(1 for r in chain if r[6])

    print("=" * 96)
    print(f"Attack classes detected : {detected}/{len(attacks)}"
          f"   ({100 * detected // max(len(attacks), 1)}%)")
    print(f"Legitimate requests     : {len(benign) - len(false_pos)}/{len(benign)} correctly allowed")
    print(f"False positives         : {len(false_pos)}"
          + ("" if not false_pos else "   <-- " + "; ".join(r[1] for r in false_pos)))
    if chain:
        print(f"Attack chain scenario   : {chain_ok}/{len(chain)} steps correct"
              f"   (recon -> BOLA -> BFLA -> pivot -> evade, one identity)")

    # Gateway decision overhead, measured by the gateway itself and read back
    # from the audit log. This is the number BACKEND.md's <15ms budget refers to:
    # time spent deciding, not the upstream API's own response time.
    try:
        alerts = httpx.get(f"{gateway}/admin/alerts", headers=admin, timeout=15).json()
        lat = sorted(a["latency_ms"] for a in alerts if isinstance(a.get("latency_ms"), (int, float)))
        if lat:
            p50 = lat[len(lat) // 2]
            p99 = lat[min(len(lat) - 1, int(len(lat) * 0.99))]
            budget = "within" if p99 < 15 else "OVER"
            print(f"Gateway decision overhead: p50 {p50:.2f}ms   p99 {p99:.2f}ms   max {lat[-1]:.2f}ms"
                  f"   ({budget} the 15ms budget)")
        m = httpx.get(f"{gateway}/admin/metrics", headers=admin, timeout=15).json()
        print(f"Gateway counters        : {m['requests']} requests, {m['allowed']} allowed, "
              f"{m['challenged']} challenged, {m['blocked']} blocked, {m['incidents']} incidents")
    except Exception as exc:
        print(f"(admin API not readable for latency/counters: {exc})")
    print("=" * 96)

    return len(false_pos) == 0 and detected == len(attacks) and chain_ok == len(chain)


def run_once(gateway):
    sim = Sim(gateway)
    print("\n-- phase 1: legitimate traffic (baseline) ------------------------------")
    phase_benign(sim)
    print("-- phase 2: the attack suite ------------------------------------------")
    phase_attacks(sim)
    print("-- phase 2b: one attacker, one session (recon -> exploit -> evade) ----")
    phase_attack_chain(sim)
    # This phase was written but never called, so the one detector that needs a
    # learned baseline went untested by the suite that certifies the product.
    # It is also the only phase that exercises the control plane at all: every
    # other case here trips a fixed threshold, and the legitimate phases never
    # vary their pace, which is why a clean scorecard used to say nothing about
    # whether the behavioural layer worked. It did not - see backend/MEMORY.md.
    print("-- phase 3: behavioural drift (needs a baseline, takes ~25s) -----------")
    phase_behavioural(sim)
    print("-- phase 4: autonomous api hardening (needs spacing, takes ~10s) ------")
    phase_hardening(sim)
    # The critical test: after a full attack barrage from this same machine, do
    # real users still get served? A gateway that blocks them has traded a false
    # negative for a false positive, which is the failure mode this product
    # exists to avoid.
    print("-- phase 5: legitimate traffic again, post-attack ----------------------")
    # account_also_ok=("observe",): phase 4 may have left the "account"
    # resource hardened for up to resource_hardening_cooldown_sec (180s
    # default) - real, correct, and time-bounded, not a bug. See
    # phase_benign's docstring for why "observe" here isn't a false positive.
    phase_benign(sim, tag="-post", account_also_ok=("observe",))
    return report(sim, gateway.rstrip("/"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default=f"http://127.0.0.1:{settings.listen_port}")
    ap.add_argument("--loop", action="store_true", help="repeat forever, for a live demo")
    ap.add_argument("--interval", type=float, default=20.0)
    args = ap.parse_args()

    try:
        httpx.get(f"{args.gateway}/health", timeout=5)
    except Exception:
        print(f"Gateway not reachable at {args.gateway} — start it with `python main.py` first.")
        sys.exit(2)

    if not args.loop:
        sys.exit(0 if run_once(args.gateway) else 1)

    while True:
        run_once(args.gateway)
        print(f"\n(sleeping {args.interval}s — Ctrl-C to stop)\n")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
