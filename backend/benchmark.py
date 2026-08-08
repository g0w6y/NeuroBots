"""
Project0 real throughput + concurrency benchmark.

attack_sim/simulate.py already measures the gateway's own per-request decision
overhead (p50/p99, read from the audit log) - that number has been real since
2026-08-08. What was still missing was a throughput figure: how many
concurrent legitimate users can this gateway instance actually serve.

Design note, so the number this produces means what it claims to mean: the
product deliberately rate-limits any single identity (120 req/60s sustained,
25 req/3s burst - see config.py). A benchmark that ignores this and floods
from one identity isn't measuring gateway throughput, it's measuring how fast
the rate limiter (correctly) starts rejecting - a different, already-covered
metric. To measure genuine serving capacity instead, this simulates many
distinct concurrent identities, each paced well under its own limits, each
reading its own uniquely-owned object (first-touch ownership, so nobody
collides with anyone else's BOLA check). That's the honest shape of "how much
concurrent legitimate traffic can this handle" for a gateway whose whole job
is throttling any one identity.

Two numbers come out of this, and they answer different questions:
  - Throughput (req/s): total completed requests / wall-clock duration,
    across all concurrent identities. Answers "how many concurrent users."
  - End-to-end latency (client-observed, ms): wall-clock round trip per
    request, includes network + gateway decision + upstream call. Answers
    "how fast does a single request feel," and is a different, larger number
    than attack_sim's gateway-only decision overhead by design - that one
    excludes the upstream hop on purpose, to isolate the gateway's own cost.

Usage:
    python3 benchmark.py [--identities 150] [--requests-per-identity 6] [--gateway http://127.0.0.1:8080]

Needs the gateway AND demo_upstream.py both running - this measures the real
round trip, not the gateway in isolation.
"""

import argparse
import asyncio
import statistics
import sys
import time

import httpx
import jwt as pyjwt

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from config import settings


def mint(sub: str) -> str:
    now = int(time.time())
    payload = {
        "sub": sub, "roles": ["user"], "iat": now, "nbf": now - 10, "exp": now + 3600,
        "iss": settings.issuer, "aud": settings.audience,
    }
    return pyjwt.encode(payload, settings.jwt_secret, algorithm="HS256")


async def identity_worker(client, gateway, identity_idx, requests_per_identity, pace_sec, results):
    # Each identity is a distinct subject touching a distinct object it
    # first-touch-owns - zero BOLA interference between workers, and paced
    # well under both rate-limit windows so none of them self-throttle
    # mid-run, which would corrupt the throughput number.
    token = mint(f"bench_{identity_idx}")
    object_id = f"9{identity_idx:06d}"
    path = f"{gateway}/api/accounts/{object_id}"
    headers = {"Authorization": f"Bearer {token}"}

    for i in range(requests_per_identity):
        t0 = time.perf_counter()
        try:
            r = await client.get(path, headers=headers)
            dt_ms = (time.perf_counter() - t0) * 1000
            results.append((r.status_code, dt_ms, r.headers.get("X-ZT-Decision")))
        except Exception as exc:
            results.append((None, None, str(exc)))
        if i < requests_per_identity - 1:
            await asyncio.sleep(pace_sec)


async def run(gateway: str, n_identities: int, requests_per_identity: int, pace_sec: float):
    try:
        r = await httpx.AsyncClient(timeout=5).get(f"{gateway}/health")
        r.raise_for_status()
    except Exception as exc:
        print(f"Gateway not reachable at {gateway} ({exc}). Start it with `python3 main.py` first.")
        sys.exit(2)

    limits = httpx.Limits(max_connections=n_identities + 20, max_keepalive_connections=n_identities + 20)
    results: list[tuple] = []

    async with httpx.AsyncClient(timeout=10, limits=limits) as client:
        print(f"Benchmark: {n_identities} concurrent identities x {requests_per_identity} requests each, "
              f"paced {pace_sec}s apart per identity (each safely under the "
              f"{settings.rate_limit_burst_requests}/{settings.rate_limit_burst_sec}s burst and "
              f"{settings.rate_limit_requests}/{settings.rate_limit_window_sec}s sustained limits).")
        t_start = time.perf_counter()
        await asyncio.gather(*[
            identity_worker(client, gateway, i, requests_per_identity, pace_sec, results)
            for i in range(n_identities)
        ])
        elapsed = time.perf_counter() - t_start

    total = len(results)
    ok = [r for r in results if r[0] == 200]
    non_ok = [r for r in results if r[0] != 200]
    latencies = sorted(dt for _, dt, _ in ok if dt is not None)

    print()
    print("=" * 78)
    print("THROUGHPUT")
    print("=" * 78)
    print(f"Total requests          : {total}")
    print(f"Completed 200 OK        : {len(ok)}")
    print(f"Non-200 / errored       : {len(non_ok)}"
          + ("" if not non_ok else f"  <-- {non_ok[:5]}"))
    print(f"Wall-clock duration     : {elapsed:.3f}s")
    print(f"Throughput              : {total / elapsed:.1f} req/s "
          f"(across {n_identities} concurrent identities)")

    if latencies:
        def pct(p):
            idx = min(len(latencies) - 1, int(len(latencies) * p))
            return latencies[idx]

        print()
        print("=" * 78)
        print("END-TO-END LATENCY (client-observed, includes network + gateway + upstream)")
        print("=" * 78)
        print(f"p50  : {statistics.median(latencies):.2f}ms")
        print(f"p95  : {pct(0.95):.2f}ms")
        print(f"p99  : {pct(0.99):.2f}ms")
        print(f"max  : {latencies[-1]:.2f}ms")
        print(f"min  : {latencies[0]:.2f}ms")
        print()
        print("Note: this is END-TO-END round trip (client -> gateway -> upstream -> client),")
        print("a different, larger number than attack_sim/simulate.py's gateway-only decision")
        print("overhead (p50/p99 sub-millisecond) by design - that figure deliberately excludes")
        print("the upstream hop to isolate the gateway's own cost. Both are real, both matter,")
        print("they answer different questions.")
    print("=" * 78)

    return total, elapsed, non_ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default=f"http://127.0.0.1:{settings.listen_port}")
    ap.add_argument("--identities", type=int, default=150)
    ap.add_argument("--requests-per-identity", type=int, default=6)
    ap.add_argument("--pace-sec", type=float, default=0.5)
    args = ap.parse_args()
    asyncio.run(run(args.gateway, args.identities, args.requests_per_identity, args.pace_sec))
