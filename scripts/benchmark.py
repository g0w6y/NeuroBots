"""
NeuroBots performance benchmark (DEVOPS.md Part 5).

Measures what the gateway costs you: end-to-end latency percentiles as a client
experiences them, the gateway's own decision overhead as recorded in its audit
log, and sustained throughput.

    python scripts/benchmark.py                          # default 400x20 = 8000 requests
    python scripts/benchmark.py --users 800 --requests 20
    python scripts/benchmark.py --gateway http://127.0.0.1:8080 --out BENCHMARK.md

Why this is not the naive "1000 threads hammering one endpoint" loop
--------------------------------------------------------------------
The gateway is a security device with per-identity rate limiting (120 req/60s
sustained, 25 req/3s burst), an enumeration detector (8 distinct objects in 10s)
and autonomous escalation (3 blocks in 60s earns a cooldown). Point a naive load
generator at it and every one of those fires, so you end up measuring how fast it
rejects traffic - which is not the number anyone wants from a benchmark.

So this harness deliberately generates load that is *legitimate*:

  - every virtual user is a distinct subject with its own correctly signed JWT,
    so each gets its own rate-limit bucket rather than sharing one
  - each user sends at most `--requests` calls, kept under the 25-per-3s burst
    ceiling by default
  - the target is POST /api/transfers: authenticated and fully scored, but with
    no object_param, so there is no ownership lookup to provision and no
    enumeration signal to trip

The run then ASSERTS that nothing was blocked or challenged. If anything was, the
latency numbers are not comparable and the script says so rather than printing a
flattering average over a pile of 403s.
"""

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone

import httpx
import jwt as pyjwt

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))
from config import settings  # noqa: E402


def mint(sub: str, ttl: int = 3600) -> str:
    now = int(time.time())
    return pyjwt.encode(
        {
            "sub": sub,
            "roles": ["user"],
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "iss": settings.issuer,
            "aud": settings.audience,
        },
        settings.jwt_secret,
        algorithm="HS256",
    )


def pct(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int((p / 100.0) * len(sorted_vals)))
    return sorted_vals[idx]


async def virtual_user(client, gateway, user_id, n_requests, results, sem):
    """One distinct identity making n_requests legitimate calls."""
    token = mint(f"bench_u{user_id}")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"from_account": "1001", "to_account": "1002", "amount": 1}

    async with sem:
        for _ in range(n_requests):
            start = time.perf_counter()
            try:
                r = await client.post(
                    f"{gateway}/api/transfers", headers=headers, json=payload
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                results.append(
                    (elapsed_ms, r.status_code, r.headers.get("X-ZT-Decision", "?"))
                )
            except Exception as e:  # a transport error is a result too - record it
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                results.append((elapsed_ms, 0, f"error:{type(e).__name__}"))


async def run(args):
    gateway = args.gateway.rstrip("/")
    admin_headers = {"X-Admin-Key": args.admin_key}

    async with httpx.AsyncClient(timeout=30.0) as probe:
        try:
            health = (await probe.get(f"{gateway}/health")).json()
        except Exception as e:
            print(f"ERROR: gateway not reachable at {gateway} ({e})")
            return 1
        try:
            before = (await probe.get(f"{gateway}/admin/metrics", headers=admin_headers)).json()
        except Exception:
            before = {}

    total = args.users * args.requests
    print(f"Gateway   : {gateway}")
    print(f"Redis     : {health.get('shared_store_redis')}")
    print(f"Postgres  : {health.get('audit_log_postgres')}")
    print(f"Load      : {args.users} identities x {args.requests} requests = {total}")
    print(f"Concurrency: {args.concurrency}\n")
    print("running...", flush=True)

    results = []
    sem = asyncio.Semaphore(args.concurrency)
    limits = httpx.Limits(
        max_connections=args.concurrency * 2, max_keepalive_connections=args.concurrency
    )

    wall_start = time.perf_counter()
    async with httpx.AsyncClient(timeout=30.0, limits=limits) as client:
        await asyncio.gather(
            *[
                virtual_user(client, gateway, uid, args.requests, results, sem)
                for uid in range(args.users)
            ]
        )
    elapsed = time.perf_counter() - wall_start

    # ---------------------------------------------------------------- analysis
    latencies = sorted(r[0] for r in results)
    decisions = {}
    statuses = {}
    for _, status, decision in results:
        decisions[decision] = decisions.get(decision, 0) + 1
        statuses[status] = statuses.get(status, 0) + 1

    clean = decisions.get("allow", 0)
    contaminated = len(results) - clean

    # The gateway's own view of its decision cost, straight out of the audit log.
    # This is the honest "overhead" figure: end-to-end latency below also carries
    # the client's own asyncio scheduling and the upstream hop.
    gw_latencies = []
    async with httpx.AsyncClient(timeout=30.0) as probe:
        try:
            alerts = (await probe.get(f"{gateway}/admin/alerts", headers=admin_headers)).json()
            gw_latencies = sorted(
                a["latency_ms"] for a in alerts if isinstance(a.get("latency_ms"), (int, float))
            )
        except Exception:
            pass
        try:
            after = (await probe.get(f"{gateway}/admin/metrics", headers=admin_headers)).json()
        except Exception:
            after = {}

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "gateway": gateway,
        "redis": health.get("shared_store_redis"),
        "postgres": health.get("audit_log_postgres"),
        "identities": args.users,
        "requests_per_identity": args.requests,
        "total_requests": len(results),
        "duration_sec": elapsed,
        "throughput_rps": len(results) / elapsed if elapsed else 0,
        "e2e": {
            "p50": pct(latencies, 50),
            "p95": pct(latencies, 95),
            "p99": pct(latencies, 99),
            "max": latencies[-1] if latencies else 0,
            "mean": statistics.fmean(latencies) if latencies else 0,
        },
        "gateway_decision": {
            "p50": pct(gw_latencies, 50),
            "p95": pct(gw_latencies, 95),
            "p99": pct(gw_latencies, 99),
            "max": gw_latencies[-1] if gw_latencies else 0,
            "samples": len(gw_latencies),
        },
        "decisions": decisions,
        "statuses": statuses,
        "clean": clean,
        "contaminated": contaminated,
        "metrics_before": before,
        "metrics_after": after,
    }

    # ------------------------------------------------------------------ output
    e = report["e2e"]
    g = report["gateway_decision"]
    print(f"\n{'=' * 68}")
    print("NeuroBots Performance Benchmark")
    print("=" * 68)
    print(f"Total requests      : {report['total_requests']}")
    print(f"Duration            : {elapsed:.2f}s")
    print(f"Throughput          : {report['throughput_rps']:.0f} req/s")
    print()
    print("End-to-end latency (client-observed, includes upstream hop)")
    print(f"  p50 {e['p50']:.2f}ms   p95 {e['p95']:.2f}ms   p99 {e['p99']:.2f}ms   max {e['max']:.2f}ms")
    print()
    print(f"Gateway decision overhead (audit log, n={g['samples']})")
    print(f"  p50 {g['p50']:.3f}ms   p95 {g['p95']:.3f}ms   p99 {g['p99']:.3f}ms   max {g['max']:.3f}ms")
    print()
    print(f"Decisions           : {json.dumps(decisions)}")
    print(f"HTTP statuses       : {json.dumps(statuses)}")

    budget_ok = g["p99"] < 15.0
    print()
    if contaminated:
        print(f"WARNING: {contaminated}/{len(results)} requests were not plain allows.")
        print("         Rate limiting or escalation fired, so these latency numbers mix")
        print("         allow-path and deny-path work and are NOT a clean measurement.")
        print("         Restart the gateway and lower --requests below the 25-per-3s burst.")
    else:
        print(f"CLEAN: all {clean} requests were allowed - no rate limiting, no escalation.")
    print(f"p99 gateway overhead under the 15ms budget: {'YES' if budget_ok else 'NO'}")
    print("=" * 68)

    if args.out:
        write_markdown(args.out, report)
        print(f"\nwrote {args.out}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"wrote {args.json}")

    return 0 if (budget_ok and not contaminated) else 1


def write_markdown(path, r):
    e, g = r["e2e"], r["gateway_decision"]
    status = "PASS" if g["p99"] < 15 and not r["contaminated"] else "FAIL"
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"""# NeuroBots Benchmark

Generated by `scripts/benchmark.py` on {r['timestamp']}.
Regenerate with `python scripts/benchmark.py --out BENCHMARK.md`.

## Run

| | |
|---|---|
| Gateway | `{r['gateway']}` |
| Redis | {r['redis']} |
| PostgreSQL | {r['postgres']} |
| Identities | {r['identities']} |
| Requests per identity | {r['requests_per_identity']} |
| Total requests | {r['total_requests']} |
| Duration | {r['duration_sec']:.2f}s |
| **Throughput** | **{r['throughput_rps']:.0f} req/s** |

Load is generated as legitimate traffic: one distinct signed identity per
virtual user, each staying under the per-identity burst ceiling, against
`POST /api/transfers` (authenticated and fully scored, but with no object
param, so no ownership lookup and no enumeration signal). All
{r['clean']} requests were allowed{'' if not r['contaminated'] else f" except {r['contaminated']}, which means the numbers below are contaminated"}.

## Gateway decision overhead

The cost the gateway itself adds, read from its own audit log
(n={g['samples']}). This is the figure the 15ms budget applies to.

| p50 | p95 | p99 | max |
|---|---|---|---|
| {g['p50']:.3f}ms | {g['p95']:.3f}ms | {g['p99']:.3f}ms | {g['max']:.3f}ms |

**p99 under the 15ms budget: {status}**

## End-to-end latency

Client-observed, so this includes the client's own async scheduling, the
loopback hop and the upstream API's response time - not just the gateway.

| p50 | p95 | p99 | max | mean |
|---|---|---|---|---|
| {e['p50']:.2f}ms | {e['p95']:.2f}ms | {e['p99']:.2f}ms | {e['max']:.2f}ms | {e['mean']:.2f}ms |

## Decisions

```json
{json.dumps(r['decisions'], indent=2)}
```

## How to read this

- **Gateway decision overhead** is what protecting an API costs you. It is the
  number to quote and the one the budget is set against.
- **End-to-end latency** will always be larger and is dominated by whatever the
  upstream API does. A slow upstream does not mean a slow gateway.
- **Throughput** is bounded by this harness and the loopback interface as much
  as by the gateway. Treat it as a floor, not a ceiling.
- Any non-`allow` decision means a security control fired during the run, and
  the latency mix is then meaningless. The script exits non-zero in that case.
""")


def main():
    p = argparse.ArgumentParser(description="NeuroBots performance benchmark")
    p.add_argument("--gateway", default=os.getenv("GATEWAY_URL", "http://127.0.0.1:8080"))
    p.add_argument("--admin-key", default=os.getenv("ADMIN_API_KEY", settings.admin_api_key))
    p.add_argument("--users", type=int, default=400, help="distinct identities")
    p.add_argument(
        "--requests",
        type=int,
        default=20,
        help="requests per identity (keep under the 25-per-3s burst limit)",
    )
    p.add_argument("--concurrency", type=int, default=100)
    p.add_argument("--out", default=None, help="write a Markdown report here")
    p.add_argument("--json", default=None, help="write the raw report JSON here")
    args = p.parse_args()

    if args.requests >= 25:
        print(
            f"NOTE: --requests {args.requests} is at or above the 25-per-3s burst limit;\n"
            "      expect rate-limit blocks to contaminate the measurement.\n"
        )
    sys.exit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
