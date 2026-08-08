# Project0 Performance Benchmark Report

Real numbers, measured 2026-08-08 against the actual running gateway on a
single developer laptop — not estimated, not carried over from an earlier
"should be fine" claim. Two separate tools produced this data:

- `attack_sim/simulate.py` — gateway-only decision overhead, single-threaded,
  read from the audit log's own `latency_ms` field (recorded server-side,
  before any upstream call).
- `benchmark.py` (new) — real concurrent throughput and end-to-end latency,
  many distinct identities hitting the gateway simultaneously.

Regenerate either at any time: `python3 attack_sim/simulate.py` or
`python3 benchmark.py`. Both need the gateway and `demo_upstream.py` running.

## Headline numbers

**Important, found late and worth stating up front: every number below,
including the ones already published elsewhere (README, PRESENTATION.md),
was measured with Redis and PostgreSQL both disconnected (in-memory
fallback) — not disclosed in this table until now.** With both actually
connected, the picture is materially different; see "With real Redis
attached" below, added 2026-08-08 after re-running this exact benchmark
against a genuinely fresh clone with real docker-compose Redis/Postgres.

| Metric | Value | Source | Backing stores |
|---|---|---|---|
| Gateway decision overhead, single request | p50 0.05–0.08ms, p99 0.3–0.6ms | `attack_sim/simulate.py` | in-memory fallback |
| Gateway decision overhead, under 50-concurrent load | p50 0.05ms, p99 0.42ms, max 0.86ms | `benchmark.py` + audit log | in-memory fallback |
| End-to-end round trip (client → gateway → upstream → client), 50 concurrent identities | p50 15.6ms, p99 190ms, max 212ms | `benchmark.py` | in-memory fallback |
| Throughput, 50 concurrent identities, 0 errors | 101.4 req/s | `benchmark.py` | in-memory fallback |

The `<15ms` target in the problem statement is the **gateway's own decision
overhead** — that's the thing this product actually adds to a request. On
the in-memory-fallback numbers above, this isn't close, it's roughly
**25–300× inside the target**. That claim does NOT currently hold with real
Redis attached under real concurrent load — see below.

## With real Redis attached (found 2026-08-08, unresolved)

Re-ran the identical `benchmark.py` command, same target route
(`POST /api/transfers`, no BOLA lookup - same route the in-memory numbers
above used), against a genuinely fresh clone with real docker-compose Redis
and PostgreSQL, both confirmed `connected` via `/health` before each run:

| Concurrency | Gateway decision overhead (p50 / p95 / p99 / max) | Backing stores |
|---|---|---|
| 1 | 3.1ms / 5.0ms / 9.4ms / 11.9ms | real Redis + real Postgres |
| 50 | 65.8ms / 83.5ms / 95.4ms / 98.1ms | real Redis + real Postgres |

Reproduced three times, consistent each time, ruling out one-off noise.
Also ruled out, specifically:

- **Postgres connection state** - disconnecting it entirely (true in-memory
  audit-log fallback, Redis still real) made no measurable difference
  (p99 stayed ~88ms), so Postgres write latency is not the cause -
  consistent with `emit_alert()`'s write being fire-and-forget.
- **Accumulated entity count** - a gateway with 100 `control_plane_baselines`
  from prior traffic measured the SAME low p99 (~9ms) as a 0-baseline one at
  concurrency 1, so the `agents.py` control-plane tick (which does iterate
  every known entity once a second) was a reasonable first suspect and isn't
  confirmed as the cause.
- **Redis itself being slow under this concurrency** - benchmarked 5
  sequential Redis round trips per simulated request (roughly what one real
  request's rate-limit + ownership + hardening + ml_risk checks cost) at the
  same concurrency=50, directly against Redis, bypassing the gateway
  entirely: p99 14.6ms. Real, but nowhere near enough to explain a 95ms
  gateway p99 on its own.

What's confirmed: this is real (reproduces cleanly), it's specific to real
concurrent load against real Redis (concurrency=1 is fine even with both
real), and it is not fully root-caused yet - the Redis round-trip cost
measured in isolation only accounts for a fraction of the gap. Whatever
else is contributing (event-loop scheduling under real concurrency,
something CPU-bound in the request path, or a combination) hasn't been
isolated with the same rigor as the httpx pool-size fix below. Don't
repeat the in-memory-fallback numbers above as if they describe the
Redis-connected, more production-realistic deployment - they don't, and
this file said otherwise until this pass caught it.

## Why there are two different latency numbers, not one

A request's total time has two parts: what the gateway itself costs (JWT
validation, rate limiting, BOLA/BFLA checks, risk fusion, policy decision —
everything `check_and_forward()` does before deciding to forward), and what
the *upstream API* costs once the gateway has decided to let the request
through. Only the first part is the gateway's own contribution, and it's the
part the `<15ms` requirement is actually about — a zero-trust gateway isn't
responsible for how fast the backend behind it happens to be.

`attack_sim/simulate.py` and the audit log's `latency_ms` field measure only
that first part. `benchmark.py`'s end-to-end number necessarily includes the
second part too, because it's testing the real request path a client
actually experiences.

## A real bottleneck found and fixed, and one found and correctly left alone

Benchmarking at 150 concurrent identities first produced an alarming result:
p99 end-to-end latency over 4 seconds. Before writing that number down
anywhere, it was diagnosed properly rather than assumed:

1. **Checked the gateway's own server-side `latency_ms` for those same
   requests.** It stayed sub-millisecond (p99 0.28ms) throughout — proof the
   zero-trust decision logic itself was not the bottleneck, whatever was
   slow, it wasn't this.
2. **Found the gateway's upstream `httpx.AsyncClient` had no explicit
   connection pool limits**, meaning it fell back to httpx's defaults
   (`max_connections=100`), undersized for 150 concurrent forwards. Raised to
   500/100 in `main.py`. This measurably helped (p50 dropped 256ms → 107ms)
   but didn't fix the tail — proving it wasn't the whole story either.
3. **Isolated the real cause by bypassing the gateway entirely** and hitting
   `demo_upstream.py` directly with the same concurrency profile: it
   reproduced the *same* multi-second tail on its own. `demo_upstream.py` is
   a small, single-process, synchronous-handler FastAPI dev server —
   documented everywhere in this repo as a stand-in so the gateway has
   something real to forward "allow" decisions to, never built or claimed to
   be a load-tested backend. That's the actual bottleneck, and it's outside
   the product being evaluated.
4. **Confirmed the ceiling is concurrency-level-dependent**, not something
   more fundamentally broken: 20 concurrent → p99 54ms, 50 → p99 127ms,
   100 → p99 2006ms. Both the gateway and the demo upstream run as
   single-process dev servers (`uvicorn.run()`, no `--workers`) in this
   setup — a real, disclosed limitation of the demo deployment, not the
   zero-trust logic. It's the same gap already named honestly elsewhere as
   "horizontal scalability: partial, never run with multiple workers."

The connection-pool fix (item 2) was a genuine, worthwhile improvement and
is now in `main.py`. Rewriting `demo_upstream.py` into a production-grade,
load-tested service was deliberately **not** attempted — it would be solving
a problem the actual deliverable doesn't have, at the cost of time this
close to the deadline. The reported throughput number (101.4 req/s) is
therefore a real, honest measurement of *this specific demo topology* on one
laptop, not a claim about the gateway's own ceiling, which the sub-millisecond
decision-overhead numbers show is far higher than the request path around it
can currently exercise.

## Methodology

`benchmark.py` avoids two ways a concurrency test can lie to itself:

- **Single-identity flooding isn't throughput, it's rate-limit testing.**
  The gateway deliberately caps any one identity at 25 req/3s burst and
  120 req/60s sustained (`config.py`) — flooding from one identity mostly
  measures how fast it gets (correctly) rejected, a different metric already
  covered by the attack simulation suite's own burst-abuse case. Instead,
  each of N concurrent identities is distinct and paced well under both
  limits (0.5s apart), modeling N simultaneous real users rather than one
  attacker.
- **Object collisions would trigger real BOLA blocks, not slowness.** Each
  identity reads only its own uniquely-numbered object (first-touch
  ownership), so no worker's traffic can trip another's authorization check
  and silently turn a performance test into a security test.

Re-run methodology used to produce the diagnosis above is preserved as plain
Python one-liners in the shell history of the session that produced this
report — nothing here was hand-waved; every number was regenerated at least
once before being written down.

## What's still not measured

- Throughput at concurrency beyond this demo topology's ceiling (would need
  `--workers N` on both the gateway and a real upstream, or horizontal
  scaling across instances — see the open "horizontal scalability" item).
- Sustained load over minutes/hours (memory growth, connection leak checks).
- Multi-instance / load-balanced throughput.

These are genuinely open, not silently assumed fine.
