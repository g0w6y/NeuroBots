"""
NeuroBots attack simulation suite.

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
IP. But a single pass already produces ~9-10 hard, hostile-classified blocks
(BOLA, alg=none, bad signature, malformed JWT, continued enumeration), which
sits right at auto_block_ip_threshold (10 in 60s, config.py). Verified by
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

    def case(self, phase, name, expected, method, path, token=None, body=None):
        r, decision, risk, wall_ms, err = self.send(method, path, token, body)
        if err:
            self.rows.append((phase, name, expected, "UNREACHABLE", "-", wall_ms, False))
            return None
        ok = (decision == expected)
        self.rows.append((phase, name, expected, decision, risk, wall_ms, ok))
        return r


# ------------------------------------------------------------------- the phases

def phase_benign(sim, tag=""):
    """Legitimate users doing legitimate things. Every one of these MUST be
    allowed — each unexpected block here is a false positive, and the platform's
    headline claim is that there are none."""
    alice = mint("alice")
    bob = mint("bob")
    root = mint("root", ["admin"])
    p = f"benign{tag}"

    sim.case(p, "alice reads her own account", "allow", "GET", "/api/accounts/1001", alice)
    sim.case(p, "alice reads her own transactions", "allow", "GET", "/api/accounts/1001/transactions", alice)
    sim.case(p, "bob reads his own account", "allow", "GET", "/api/accounts/1002", bob)
    sim.case(p, "admin reads the admin user list", "allow", "GET", "/api/admin/users", root)
    sim.case(p, "alice posts a legitimate transfer", "allow", "POST", "/api/transfers", alice,
             body={"from_account": "1001", "to_account": "1002", "amount": 25.00})
    for i in range(4):
        sim.case(p, f"alice re-reads her account ({i + 1})", "allow", "GET", "/api/accounts/1001", alice)


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
    detected = sum(1 for r in attacks if r[6])
    false_pos = [r for r in benign if not r[6]]

    print("=" * 96)
    print(f"Attack classes detected : {detected}/{len(attacks)}"
          f"   ({100 * detected // max(len(attacks), 1)}%)")
    print(f"Legitimate requests     : {len(benign) - len(false_pos)}/{len(benign)} correctly allowed")
    print(f"False positives         : {len(false_pos)}"
          + ("" if not false_pos else "   <-- " + "; ".join(r[1] for r in false_pos)))

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

    return len(false_pos) == 0 and detected == len(attacks)


def run_once(gateway):
    sim = Sim(gateway)
    print("\n-- phase 1: legitimate traffic (baseline) ------------------------------")
    phase_benign(sim)
    print("-- phase 2: the attack suite ------------------------------------------")
    phase_attacks(sim)
    # This phase was written but never called, so the one detector that needs a
    # learned baseline went untested by the suite that certifies the product.
    # It is also the only phase that exercises the control plane at all: every
    # other case here trips a fixed threshold, and the legitimate phases never
    # vary their pace, which is why a clean scorecard used to say nothing about
    # whether the behavioural layer worked. It did not - see backend/MEMORY.md.
    print("-- phase 3: behavioural drift (needs a baseline, takes ~25s) -----------")
    phase_behavioural(sim)
    # The critical test: after a full attack barrage from this same machine, do
    # real users still get served? A gateway that blocks them has traded a false
    # negative for a false positive, which is the failure mode this product
    # exists to avoid.
    print("-- phase 4: legitimate traffic again, post-attack ----------------------")
    phase_benign(sim, tag="-post")
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
