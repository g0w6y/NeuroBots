# Jeevan's Tasks

**Steps:** 3 (rate limit), 4 (features), 8-9 (policy + logging)

## Your Code Sections

### detect.py - Rate Limiting

Function: check_rate_limit(request_count, limit, window_sec, detector_name)

The counting itself moved out of main.py's local deque and into store.py (store.record_request_time / store.count_requests_in_window). It uses a Redis ZSET per subject (score=timestamp) when Redis is reachable, ZCOUNT for the windowed count, and falls back to an equivalent in-memory deque filtered by timestamp when Redis is down. This is what makes rate limiting safe across multiple gateway workers/processes now (previously it was pure in-process state, so two workers behind a load balancer would each have their own counters and the limit would effectively double per worker). check_rate_limit() itself is unchanged — still a pure function, just fed real windowed counts now.

Both sustained (120/60s) and burst (25/3s) checked independently, either can produce a hard signal.

### detect.py - Signal Fusion

Function: fuse_signals()

Currently implemented:
- If any hard signal → block (403)
- If 2+ soft signals AND score >= 70 → block
- If score >= 45 → challenge (401)
- If score > 0 → observe (log, forward)
- Else → allow (forward)

False positive prevention:
- Learning window (first 8s): no soft signal blocks
- Corroboration rule: 2+ soft signals required to block
- Hard signals: only on cryptographic facts or definite violations

### main.py - Risk Scoring

In check_and_forward():

Currently implemented:
- Sum weights from all signals, cap at 100
- Store in entity.risk_score
- Include in alert

Logic:
- Hard signals: 60-90 weight each (deterministic)
- Soft signals: 40-80 weight (behavioral, need corroboration)
- Score = sum of weights, max 100

To improve:
- Time decay: older signals lose weight
- Entity lifecycle: higher thresholds for new entities
- Baseline comparison: flag deviations from user's normal behavior

### audit_log.py - Logging + Admin APIs (new module)

PostgreSQL persistence is done. Alerts and incidents used to live only in an in-memory deque (500/200 cap, wiped on every restart) — that's now audit_log.py's AuditLog class: real Postgres tables (schema auto-created on startup) when reachable, with the exact same graceful in-memory fallback pattern as store.py's Redis handling when it isn't. Verified for real, not assumed — spun up a disposable Postgres in Docker, ran the full attack scenario suite through it, confirmed the rows persisted by querying the database directly (outside the app's own connection) after the app's TestClient context had already exited, then separately verified the fallback path with a deliberately bad DSN to confirm the gateway still works with zero degradation when Postgres is down.

Writes are fire-and-forget (asyncio.create_task), same principle as the control-plane event emission — a slow or dead audit DB must never add latency to the response path. One subtlety worth knowing if you touch this: the alert dict's status_code field is only finalized after the upstream call completes (or fails), so the write is deliberately placed after that point in each of the three return branches (block/challenge/forward), not once up front — writing earlier would race with the later mutation and sometimes persist a null status_code for forwarded requests.

/admin/metrics now runs a real SQL aggregate (COUNT ... GROUP BY decision) against Postgres when connected, not a Python sum() over a capped 500-item deque — so it's now an accurate lifetime count, not "count of whatever's still in the last 500."

Elasticsearch / time-series analysis: not built. Postgres now provides a real substrate this could be built on top of later (ts_vector for full-text search, a GROUP BY date_trunc for time-series buckets), but standing up a whole separate ES service for a hackathon demo is more moving parts to operate and demo than the time budget justifies. Skipped deliberately, not forgotten.

Time decay / entity lifecycle (from the original "to improve" list): reconsidered rather than built as originally framed. Time decay is already achieved structurally — every check here (rate limits, enumeration, escalation) reads from a time-windowed query, so old activity falls out of relevance automatically without needing a separate decay function; the escalation counter specifically has a 24h Redis TTL, which is itself a form of decaying reputation. "Entity lifecycle / higher thresholds for new entities" was reconsidered too: the data-plane deterministic checks (BOLA/BFLA/rate limits) are facts, not heuristics, and should NOT get relaxed thresholds just because an entity is new — that would mean a brand-new attacker identity gets a grace period to attack more freely, which is backwards. The learning window that does exist (agents.py, 8s) is correctly scoped to the heuristic control-plane layer only, not the deterministic layer, and that's already the case.

## Testing

Your rate limiting:
```bash
# Generate 125 requests to same endpoint (should be blocked)
for i in {1..125}; do 
  curl -H "Authorization: Bearer TOKEN" http://localhost:8080/api/accounts/1
done
```

Check /admin/metrics for request counts.

## False Positive Prevention

- Rate limiting: true sliding window, only counts requests actually inside the window (see fix above)
- Risk scoring: Soft signals need independent agreement (2+ detectors)
- Learning window: First 8s of user activity = no soft blocks
- Policy: Block only on certainty (hard signals or strong corroboration)

Keep it logical, deterministic, and fact-based. No probabilistic guessing.

## Multi-Agent Reference

Per the reference design, the async intelligence layer has 4 agents: profile, sequence, graph, and a Guardian narrative agent. agents.py has all 4: EntityBaseline/compute_baseline_stats (profile), detect_sequence_anomaly, detect_graph_anomaly, and generate_narrative (Guardian — deterministic template over the Signal list, not a live LLM call, so it can never hallucinate a verdict). The control plane never blocks a request; it only writes an enriched risk score to Redis that the next request reads as a soft signal. Your policy engine (fuse_signals) is what decides if that soft signal matters — it always needs corroboration from something else to actually block.

## Autonomous mitigation (new)

This is the direct answer to "does the AI actually act autonomously, or just re-evaluate per request." Previously entity.blocked existed as a field but nothing ever set it — the system had no memory of a proven attacker between requests. Now, in main.py's check_and_forward:

- Not every "block" counts toward escalation, only ones caused by a genuinely hostile signal (see HOSTILE_ESCALATION_DETECTORS in main.py). This was a real false positive found by testing: expired tokens retried a few times, a missing-token request, and a BFLA violation from a plausible frontend bug were all originally counted, and 3 of any of them in 60s would lock out a completely innocent user for 5+ minutes. Only signals that require deliberately forged/scripted input now count: bola_cross_user, bola_enumeration, jwt_alg_none, jwt_alg_confusion, jwt_bad_signature, jwt_malformed, rate_limit_burst. Everything else still blocks the individual request, it just doesn't compound into a lockout.
- Identity-level escalation (auto_block_threshold, 3 in 60s) only applies to a verified subject (jwt_result.valid True) — anon:{ip} pseudo-identities (unauthenticated/invalid-token traffic) are excluded from this path entirely and only go through the ip_key path. This was also a real gap found by testing: anon:{ip} was silently getting the low identity threshold even though it's fundamentally the same NAT/shared-IP collateral risk the higher IP threshold exists to prevent.
- IP-level escalation uses a separate, much higher threshold (auto_block_ip_threshold, 10) for the same reason — IP-level blocking risks catching innocent users behind the same NAT/proxy as an attacker, so it needs much stronger evidence (many distinct hostile identities from one source) before it fires.
- Every escalation is logged as a structured incident (not mixed into raw alerts) and exposed via GET /admin/incidents.
- Cooldowns self-expire via Redis TTL (or timestamp comparison in the fallback) — no permanent lockout risk from a stale block.

This is still fully deterministic, no LLM decides anything here — the "AI" in "autonomous AI mitigation" is the multi-agent anomaly layer (profile/sequence/graph) feeding signals in, plus this escalation logic acting on confirmed outcomes without waiting for a human. If you want to tune aggressiveness, the five config knobs are all in config.py: auto_block_threshold, auto_block_ip_threshold, auto_block_window_sec, auto_block_cooldown_sec, auto_block_max_multiplier.

Worth being explicit about scope: the false-positive fixes above only ever touched what feeds the ESCALATION counter (`if action == "block" and is_hostile_block(signals):`). They never touched `action = fuse_signals(signals)` itself — the per-request block/challenge/allow decision is exactly as strict as it was before any of this. An expired token, a BFLA violation, a sustained-rate-limit hit still gets that individual request blocked every time, with the same weights and the same hard-signal rule. Nothing was weakened to fix the false positives — only the "should this also lock the identity out for 5+ minutes" question changed.

## Admin API auth

/admin/metrics, /admin/alerts, /admin/entities, /admin/incidents, and POST /admin/ownership all require header X-Admin-Key matching settings.admin_api_key. They used to be both unauthenticated and (separately) completely unreachable — the catch-all gateway route was registered before them in main.py, so Starlette matched the catch-all first for every admin/health request and silently proxied it to upstream. Fixed by moving the route registrations above the catch-all. If you add new admin routes, they must go above @app.api_route("/{path:path}", ...) or they'll never be reached.
