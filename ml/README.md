# NeuroBots ML Worker

**This is the one ML implementation in this repo.** A second, independently-built
one (`ml-worker/`, Melwin's) briefly existed alongside this folder and was removed
2026-08-08 after a real comparison, not a coin flip: it wrote `ml_risk:{subject}` to
Redis as a JSON blob, but `backend/store.py`'s `get_ml_risk()` does `int(val)` on
that key — a format mismatch that would have made the signal silently go dark on
every request (caught by the bare `except Exception: return None`), the same class
of bug as the "control plane was inert" issue found and fixed earlier this session.
It also defaulted to gateway port 8081, not this repo's actual 8080. This folder is
the one `backend/main.py` and `backend/store.py` actually read from, and the one
verified end to end against a real running stack. `ml-worker/` did have one genuine
asset this folder lacked — a real 34-test pytest suite — ported below as
`tests/test_ml.py`, rewritten against this module's actual API rather than the
removed one's.

Real machine learning, not a rename of the rule-based detector. Per `ML.md`'s original
plan: a standalone async worker that trains a real `scikit-learn` `IsolationForest`
per entity, builds a real Markov transition table for call sequences, and maintains a
real `NetworkX` user↔object access graph. Writes `ml_risk:{subject}` to Redis; the
gateway reads it as an independent second anomaly signal alongside its own
deterministic rule engine (`backend/agents.py`).

## Why a second, independent signal matters

`fuse_signals()` in the gateway has always had a rule: 2+ independent soft signals
agreeing is required before a soft signal can escalate to a block. Until this worker
existed, there was only ever one soft-signal source in the whole system
(`control_plane_anomaly`), so that corroboration path was structurally unreachable —
dead code. This worker is what makes it real: the rule engine and the trained models
are genuinely independent detectors that can now actually agree or disagree.

## Run it

```bash
pip install -r requirements.txt
REDIS_URL=redis://127.0.0.1:6379 GATEWAY_URL=http://127.0.0.1:8080 \
  ADMIN_API_KEY=changeme-admin-key python3 worker.py
```

Needs the gateway running and Redis reachable — both by the gateway and by this
worker (same Redis instance, real one; this doesn't work against the gateway's
in-memory fallback). If either is unavailable, the worker retries rather than
crashing, and the gateway runs exactly as it does without this process at all —
this only ever adds a signal, it's never a dependency of the request path.

## What it actually does (ML.md Parts 1-7)

1. Polls `GET /admin/alerts` every `ML_POLL_INTERVAL_SECONDS` (default 2s), tracking
   a watermark timestamp so it only processes genuinely new events, never reprocesses
   history from before it started.
2. Builds a per-subject `EntityProfile`: endpoints seen, objects touched per resource,
   request timestamps, endpoint-transition counts.
3. **IsolationForest** (`profiling.py`): trains one model per entity on that entity's
   own allowed-request feature vectors (hour of day, day of week, smoothed request
   rate, object/endpoint hash, days since first seen, distinct objects/endpoints
   touched today). Retrains every `ML_RETRAIN_EVERY_N` new samples, not on every
   event — real cost control for scaling to many entities.
4. **Markov chain** (`profiling.py`): tracks `endpoint_A -> endpoint_B` transition
   counts per entity, scores the current transition's negative log probability.
5. **NetworkX graph** (`graph.py`): a real bipartite user↔object graph. Novelty score
   for a request considers whether this is a genuinely new edge, how many *other* new
   edges this user has created very recently (burst = reconnaissance-like), and the
   object's fan-in (a shared/public object is far less suspicious to touch for the
   first time than a private one with one owner).
6. **Fusion** (`risk.py`): `ml_risk = 100 * (0.4*isolation + 0.3*sequence + 0.3*graph)`,
   exactly the weights in `ML.md`. Two separate writes, deliberately not gated the
   same way: `profile:{subject}` is written for *any* tracked entity, even with just
   1 sample — pure visibility (`GET /admin/ml-status` on the gateway), proving the
   worker is alive and watching traffic without waiting for enough data to matter.
   `ml_risk:{subject}` — the actual signal the gateway acts on — is only written
   once `ML_MIN_SAMPLES` is crossed; a model trained on a handful of samples is
   noise, not signal, and shouldn't be treated as a real anomaly claim.
7. **Anti-poisoning**: a `block` decision marks that entity `known_attacker` and is
   never folded into its training data — not that one request, and not any later
   "allowed" request from the same identity either, since a proven attacker's
   later traffic isn't retroactively trustworthy. Verified: a genuine BOLA attack
   (attacker targeting a victim's already-owned object) produced zero new graph
   edges and never appears in that identity's `profile:{subject}`.

## Verified for real, not assumed

Every claim above was checked against a real running stack, not unit-tested in
isolation: a real gateway, a real disposable Redis (Docker), and this worker as an
actual separate OS process talking to both. Confirmed: a genuine BOLA attack
produces zero training data and zero graph edges for the attacker; legitimate
traffic produces a real IsolationForest score, a real graph, and gets
written to Redis; the gateway correctly reads a real `ml_risk` value back and adds
`ml_anomaly` as a signal (confirmed via a manually-seeded high score triggering a
real challenge decision end to end).

## Two more real bugs found while testing the full startup flow

1. **First-poll data loss.** The original design skipped whatever was already in
   `/admin/alerts` on the worker's very first poll, meant to avoid reprocessing a
   stale previous session's history on restart. In the much more common case — this
   worker starting fresh alongside a fresh gateway, exactly the demo scenario — it
   silently discarded the opening traffic if it landed before that first poll
   completed. Confirmed with a real test: sent traffic immediately after startup, 0
   events processed. Fixed: the worker now processes everything visible on its first
   poll. `/admin/alerts` is already a bounded recent window, not unbounded history,
   so the "avoid reprocessing a huge backlog" concern doesn't really apply — losing
   real events on startup was worse than occasionally reprocessing a few.
2. **`pgrep` pattern bug in `start_all.sh`**, not in this worker's own code, but
   found while testing this worker end to end as part of the startup script: on
   macOS, the Python interpreter's actual path (`Python.app/.../Python`) doesn't
   contain the literal string "python3", so `pgrep -f "python3 <script>"` silently
   matches nothing. `stop_all.sh` would have done nothing at all. Fixed by matching
   on the script filename alone, verified against real `ps aux` output before
   trusting the pattern a second time.

## A real calibration caveat, found by that same testing

With only ~15 samples of pure, uniform, repetitive legitimate traffic (same user,
same endpoint, same object, over and over), the IsolationForest scored 0.767 —
moderately "anomalous" for traffic that should look completely boring. This is a
known property of training a model on very little data, not a bug in the fusion
logic. `min_samples_to_score` is set conservatively (25) to reduce it, but the real
protection is structural: `ml_anomaly` is always a soft signal. Alone, it can trigger
a step-up challenge, never a block — blocking requires a second, independent signal
to agree first. Don't rely on threshold-tuning alone to fully solve small-sample
noise; the corroboration requirement is the actual safety net, by design.

## Testing

```bash
pip install -r requirements.txt   # includes pytest
python3 -m pytest tests/ -v
```

32 real unit tests against this module's actual classes (`EntityProfile`,
`AccessGraph`, `compute_ml_risk`, `MLWorker`) — not the removed `ml-worker/`'s
parallel schema. Covers path parsing, profile accumulation, IsolationForest
training gating, Markov transition scoring, graph novelty (including the
shared-vs-private fan-in dampening from `ML.md` Part 5), risk fusion bounds,
and — the property this whole worker exists to protect — the anti-poisoning
guarantee: a confirmed hostile block stops that entity's later "allowed"
traffic from ever being folded into training data again. All 32 pass as of
2026-08-08 against a real run, not assumed.

## Config

All in `config.py`, overridable via environment variables — see the file for exact
names. Key ones: `ML_MIN_SAMPLES` (25), `ML_RETRAIN_EVERY_N` (5),
`ML_ISOLATION_THRESHOLD` (0.7, currently informational — the raw isolation score
feeds the weighted fusion rather than being hard-thresholded on its own),
`ML_MARKOV_THRESHOLD` (0.1).

## What's simplified from the original ML.md wording, deliberately

- "Object ID as one hot encoding (numeric hash)" — one-hot encoding of a field with
  unbounded cardinality (object IDs) isn't practical; implemented as a stable hash
  mod a fixed range instead, which is what's actually usable as a numeric feature.
- Endpoint/resource inference from the raw request path is done with a lightweight
  heuristic (`profiling.parse_path`) rather than importing the gateway's full route
  table, keeping this worker genuinely decoupled from the gateway's internals — it
  only depends on the gateway's public `/admin/alerts` shape.
