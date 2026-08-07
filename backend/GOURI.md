# Gouri's Tasks

**Steps:** 1 (extract), 2 (JWT), 5 (BOLA), 6 (BFLA/enum)

## Your Code Sections

### auth.py - JWT Validation

Currently implemented:
- HS256 signature verification
- Expiry check (exp claim)
- Not-before check (nbf claim)
- Issuer validation (iss claim)
- Audience validation (aud claim)
- alg=none detection
- Algorithm confusion detection
- Malformed token detection

To enhance:
- RSA/RS256 support (if needed)
- Token revocation check (optional)
- Custom scope validation (optional)

### detect.py - BOLA Detection

Function: check_bola(subject, resource, object_id, is_owner, fan_in, strict)

Current logic:
- is_owner True → allow
- fan_in == 0 (nobody has ever been granted this object) and strict=False → allow, caller grants ownership to this subject
- fan_in == 0 and strict=True (config bola_strict_mode) → hard block, deny-by-default until explicitly provisioned
- fan_in <= 5 (private object) and not owner → hard block
- fan_in > 5 (shared object) and not owner → allow

Ownership is no longer a plain in-process dict. It now lives behind store.py (store.is_owner / store.fan_in / store.grant_ownership), which uses real Redis SADD/SISMEMBER/SCARD against `authorized:{resource}:{object_id}` when Redis is reachable, and falls back to an equivalent in-memory dict when it isn't. Ownership is only granted in main.py AFTER check_bola returns no signal — never on a blocked attempt (no learning from attackers).

Known structural limitation, not fully fixed: ownership is still inferred from "who the gateway saw touch this object first," not from a real backend's ownership records, unless you provision it ahead of time. Two ways to provision real ownership before traffic arrives:
- seed_ownership.json in the repo root, loaded at startup: {"account": {"1001": ["alice"]}}
- POST /admin/ownership (needs X-Admin-Key) with {resource, object_id, subject} — call this whenever your real backend would create a resource, so the creator becomes the authoritative owner before any attacker can guess the ID first.

Route matching: match_route() in main.py does segment-by-segment pattern matching against the ROUTES list, extracting path params. Edit ROUTES in main.py to change route definitions, not a dict.

### detect.py - BFLA Detection

Function: check_bfla()

Current logic:
- Check if user has any required role → allow
- Missing required role → hard block

Enhancement: Add scope-based checks (read:accounts vs write:accounts)

### detect.py - Enumeration Detection

Function: check_enumeration(distinct_count, threshold)

Takes a precomputed count now, not a list. store.py tracks object hits in a Redis ZSET (member=object_id, score=timestamp) or in-memory deque fallback, windowed to settings.enum_window_sec (10s) via store.distinct_objects_in_window(). If 8+ distinct objects in that window → hard block.

### main.py - Reverse Proxy

Currently implemented:
- Forward requests to upstream via httpx
- Pass through headers and body
- Handle errors (502 if upstream unreachable)

To improve:
- Connection pooling
- Request/response logging

## Testing

Your checks are tested via the detection pipeline in main.py check_and_forward().

Run the gateway:
```bash
python main.py
```

Test with curl:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/api/accounts/123
```

## False Positive Prevention

- BOLA: Only flag when user lacks ownership AND object is private (fan_in <= 5)
- BFLA: Only flag when required roles specified in route AND user lacks all of them
- Enumeration: Only flag when distinct object count >= threshold (8) within the actual time window (10s), not lifetime history

All checks are deterministic facts, not probabilistic.

## Multi-Agent Reference

The intelligence layer (agents.py, Jeevan's area) implements 3 of the 4 agents shown in the reference design: profile, sequence, graph. The 4th (Guardian/LLM narrative agent) is deterministic templating, not a live LLM call, to avoid hallucination risk in a security verdict path. Your detectors (BOLA/BFLA/enumeration) feed the Signal objects that both the policy engine and the Guardian narrative consume — keep evidence strings factual and specific, they get quoted directly in the narrative.

## Admin API auth

/admin/metrics, /admin/alerts, /admin/entities, /admin/incidents, and POST /admin/ownership all require header X-Admin-Key matching settings.admin_api_key (default changeme-admin-key, override via .env before demoing). They used to be unauthenticated (and, separately, unreachable — see below).

## Route ordering bug (fixed)

The catch-all gateway route was registered before /health and /admin/*, so Starlette matched the catch-all first for every request and silently proxied all admin/health calls to upstream. These endpoints were completely dead until this was fixed — route order in main.py matters, admin/health routes must stay registered above the catch-all.

## Double-forward bug (fixed)

check_and_forward used to forward to upstream, then gateway() forwarded a second, separate copy of the same request. For GET this was just wasteful; for POST /api/transfers it meant every allowed transfer executed twice against upstream. check_and_forward now returns the httpx response object directly and gateway() reuses it instead of re-forwarding.
