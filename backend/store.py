import asyncio
import time
import json
import itertools
from collections import defaultdict, deque
from typing import Optional
import redis.asyncio as redis
from config import settings

_seq = itertools.count()


class SharedStore:
    """Shared gateway state, backed by Redis, mirrored in memory.

    Two properties matter more than speed here:

    1. A Redis failure must be *loud and recoverable*, not silent. `connected`
       was previously set only in connect() and never cleared, so once Redis
       died every call still attempted it, waited for the failure, and fell
       through - permanently, with no log line and no change to /health.

    2. The in-memory fallback must not be empty. Ownership used to be written to
       Redis *or* memory, never both. So when Redis died the local view had no
       owners at all: is_owner returned False, fan_in returned 0, and check_bola
       reads a zero fan-in as "nobody owns this yet" and allows the request. The
       failure mode of the database was therefore to silently switch BOLA
       detection off and report the resulting cross-user access as clean traffic
       - the single worst way for a security control to fail. Ownership is now
       written through to both, so losing Redis costs cross-process sharing and
       persistence, not detection.
    """

    RECONNECT_EVERY_SEC = 5.0
    SWEEP_EVERY_SEC = 120.0
    MAX_IDLE_SEC = 900.0

    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self.connected = False

        self._owned_objects = defaultdict(lambda: defaultdict(set))
        self._req_times = defaultdict(lambda: deque(maxlen=1000))
        self._obj_hits = defaultdict(lambda: defaultdict(lambda: deque(maxlen=500)))
        self._block_events = defaultdict(lambda: deque(maxlen=50))
        self._block_state = {}
        self._escalation_counts = defaultdict(int)
        self._last_touch = {}

        # autonomous resource hardening - see the block near record_resource_attack
        self._resource_attackers = defaultdict(dict)
        self._hardened_resources = {}

        # ML worker output, mirrored locally so the ML signal survives having no
        # Redis at all. subject -> (value, expires_at); the expiry mirrors the
        # TTL the worker would have set on the Redis key, so a score that stops
        # being refreshed decays out of existence here exactly as it would there.
        self._ml_risk: dict = {}
        self._ml_profiles: dict = {}
        # Which transport actually delivered the profiles served last. Reported
        # by /admin/ml-status, so it has to describe where the data came from
        # rather than merely whether Redis happens to be dialable - those two
        # answers differ exactly when the worker is publishing over HTTP while
        # the gateway holds an otherwise-empty Redis connection.
        self.last_ml_source = "none"

        # jti -> revocation record. Entries self-expire at the token's own `exp`,
        # so this cannot grow past the number of tokens live at any one moment.
        self._revoked = {}
        # Fallback TTL for a token whose exp we could not read. Deliberately
        # generous: erring long keeps a revoked credential dead, erring short
        # brings it back to life.
        self._default_revocation_ttl = 24 * 3600

        self._degraded_announced = False
        self._keeper: Optional[asyncio.Task] = None

    # ---------------------------------------------------------------- lifecycle

    async def _dial(self) -> bool:
        try:
            client = await redis.from_url(
                settings.redis_url,
                decode_responses=True,
                # Without these, a host that drops SYNs rather than refusing -
                # a suspended Docker VM, a stale LAN address - hangs startup for
                # the OS TCP timeout instead of falling back promptly.
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            await client.ping()
            self.redis_client = client
            self.connected = True
            self._degraded_announced = False
            return True
        except Exception:
            self.redis_client = None
            self.connected = False
            return False

    async def connect(self):
        ok = await self._dial()
        print(f"Shared Store: Redis {'connected' if ok else 'unavailable, using in-memory fallback'}")
        self._keeper = asyncio.create_task(self._keeper_loop())

    async def _keeper_loop(self):
        """Reconnect after a failure and sweep idle state. Both need to happen
        off the request path; doing reconnection inline would add the dial
        timeout to a user's request."""
        last_sweep = time.time()
        while True:
            try:
                await asyncio.sleep(self.RECONNECT_EVERY_SEC)

                if not self.connected:
                    if await self._dial():
                        print("Shared Store: Redis reconnected")

                now = time.time()
                if now - last_sweep >= self.SWEEP_EVERY_SEC:
                    last_sweep = now
                    self._sweep(now)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"Shared Store: keeper tick failed ({type(e).__name__}: {e})")

    def _sweep(self, now: float) -> None:
        """Drop per-subject state for subjects that have gone quiet.

        Every one of these maps is keyed by subject - and unauthenticated
        traffic produces one subject per source address - so without eviction
        they grow for the lifetime of the process. Ownership is deliberately not
        swept: it is authorization data, not traffic history.
        """
        stale = [s for s, t in self._last_touch.items() if now - t > self.MAX_IDLE_SEC]
        for s in stale:
            self._req_times.pop(s, None)
            self._obj_hits.pop(s, None)
            self._block_events.pop(s, None)
            self._last_touch.pop(s, None)
        for key, until in list(self._block_state.items()):
            if now >= until:
                del self._block_state[key]
        for bucket in (self._ml_risk, self._ml_profiles):
            for subject, (_, expires) in list(bucket.items()):
                if now >= expires:
                    del bucket[subject]
        if stale:
            print(f"Shared Store: swept {len(stale)} idle subjects")

    async def close(self):
        if self._keeper:
            self._keeper.cancel()
            try:
                await self._keeper
            except (asyncio.CancelledError, Exception):
                pass
            self._keeper = None
        if self.redis_client:
            try:
                await self.redis_client.close()
            except Exception:
                pass

    def _degrade(self, op: str, exc: Exception) -> None:
        """Mark the connection dead so subsequent calls stop paying the timeout,
        and say so exactly once per outage."""
        self.connected = False
        if not self._degraded_announced:
            self._degraded_announced = True
            print(f"Shared Store: Redis lost during {op} ({type(exc).__name__}: {exc}) — "
                  f"serving from in-memory mirror, retrying every {self.RECONNECT_EVERY_SEC}s")

    def _touch(self, subject: str) -> None:
        self._last_touch[subject] = time.time()

    def _local_owners(self, resource: str, object_id: str) -> set:
        # plain lookups: indexing the defaultdict would create the resource key
        # on every read, including misses
        return self._owned_objects.get(resource, {}).get(object_id, set())

    # ------------------------------------------------------------- ownership

    async def is_owner(self, resource: str, object_id: str, subject: str) -> bool:
        if self.connected:
            try:
                return bool(await self.redis_client.sismember(f"authorized:{resource}:{object_id}", subject))
            except Exception as e:
                self._degrade("is_owner", e)
        return subject in self._local_owners(resource, object_id)

    async def fan_in(self, resource: str, object_id: str) -> int:
        if self.connected:
            try:
                return await self.redis_client.scard(f"authorized:{resource}:{object_id}")
            except Exception as e:
                self._degrade("fan_in", e)
        return len(self._local_owners(resource, object_id))

    async def grant_ownership(self, resource: str, object_id: str, subject: str) -> None:
        # write through to memory first and unconditionally: this is what keeps
        # the fallback authoritative if Redis disappears later
        self._owned_objects[resource][object_id].add(subject)
        if self.connected:
            try:
                await self.redis_client.sadd(f"authorized:{resource}:{object_id}", subject)
            except Exception as e:
                self._degrade("grant_ownership", e)

    # ------------------------------------------------------------ rate limits

    async def record_request_time(self, subject: str, now: float) -> None:
        self._touch(subject)
        if self.connected:
            try:
                key = f"reqtimes:{subject}"
                # prune horizon follows config rather than a hard-coded 120s;
                # raising RATE_LIMIT_WINDOW_SEC past 120 silently truncated the
                # Redis window while the in-memory path kept the full one
                horizon = max(settings.rate_limit_window_sec, settings.rate_limit_burst_sec) * 2
                await self.redis_client.zadd(key, {f"{now}:{next(_seq)}": now})
                await self.redis_client.zremrangebyscore(key, 0, now - horizon)
                await self.redis_client.expire(key, horizon)
                return
            except Exception as e:
                self._degrade("record_request_time", e)
        self._req_times[subject].append(now)

    async def count_requests_in_window(self, subject: str, now: float, window_sec: int) -> int:
        if self.connected:
            try:
                return await self.redis_client.zcount(f"reqtimes:{subject}", now - window_sec, "+inf")
            except Exception as e:
                self._degrade("count_requests_in_window", e)
        return sum(1 for t in self._req_times[subject] if t >= now - window_sec)

    # ------------------------------------------------------------ enumeration

    async def record_object_hit(self, subject: str, resource: str, object_id: str, now: float) -> None:
        self._touch(subject)
        if self.connected:
            try:
                key = f"objhits:{subject}:{resource}"
                horizon = max(settings.enum_window_sec * 4, 120)
                await self.redis_client.zadd(key, {object_id: now})
                await self.redis_client.zremrangebyscore(key, 0, now - horizon)
                await self.redis_client.expire(key, horizon)
                return
            except Exception as e:
                self._degrade("record_object_hit", e)
        self._obj_hits[subject][resource].append((object_id, now))

    async def distinct_objects_in_window(self, subject: str, resource: str, now: float, window_sec: int) -> int:
        if self.connected:
            try:
                return await self.redis_client.zcount(f"objhits:{subject}:{resource}", now - window_sec, "+inf")
            except Exception as e:
                self._degrade("distinct_objects_in_window", e)
        return len(set(oid for oid, t in self._obj_hits[subject][resource] if t >= now - window_sec))

    # -------------------------------------------------------- auto-mitigation

    async def record_block_event(self, key: str, now: float, window_sec: int) -> int:
        self._touch(key)
        if self.connected:
            try:
                rkey = f"blockevents:{key}"
                await self.redis_client.zadd(rkey, {f"{now}:{next(_seq)}": now})
                await self.redis_client.zremrangebyscore(rkey, 0, now - window_sec)
                await self.redis_client.expire(rkey, window_sec)
                return await self.redis_client.zcard(rkey)
            except Exception as e:
                self._degrade("record_block_event", e)
        self._block_events[key].append(now)
        recent = [t for t in self._block_events[key] if now - t <= window_sec]
        self._block_events[key] = deque(recent, maxlen=50)
        return len(recent)

    async def set_blocked(self, key: str, blocked_until: float, cooldown_sec: int) -> None:
        if self.connected:
            try:
                await self.redis_client.set(f"blocked:{key}", str(blocked_until), ex=max(cooldown_sec, 1))
                return
            except Exception as e:
                self._degrade("set_blocked", e)
        self._block_state[key] = blocked_until

    async def get_blocked_until(self, key: str, now: float) -> float:
        if self.connected:
            try:
                val = await self.redis_client.get(f"blocked:{key}")
                return float(val) if val else 0.0
            except Exception as e:
                self._degrade("get_blocked_until", e)
        until = self._block_state.get(key, 0.0)
        if until and now >= until:
            del self._block_state[key]
            return 0.0
        return until

    async def increment_escalation_count(self, key: str) -> int:
        if self.connected:
            try:
                rkey = f"escalations:{key}"
                count = await self.redis_client.incr(rkey)
                await self.redis_client.expire(rkey, 86400)
                return count
            except Exception as e:
                self._degrade("increment_escalation_count", e)
        self._escalation_counts[key] += 1
        return self._escalation_counts[key]

    # ------------------------------------------------ autonomous resource hardening
    #
    # The auto-mitigation above punishes a proven *attacker* - one identity or
    # IP. It has nothing to say about a *resource* under sustained attack from
    # many different attackers, each of whom individually might never cross
    # their own identity/IP threshold. This tracks DISTINCT attacker keys
    # hitting one resource type (not raw event count - one identity blocked 20
    # times in a row is still the same attacker, and identity-level escalation
    # already handles them). Deliberately keyed on the exact same `attacker_key`
    # convention main.py already uses for identity/IP escalation (subject if
    # the JWT validated, else ip:{ip}) - a forged/invalid token never produces
    # a validated subject, so an attacker cannot cheaply manufacture "distinct
    # attackers" by putting a different `sub` claim in a new alg=none token
    # each time; every one of those still collapses to the same ip:{ip} key.
    # Genuinely reaching this bar needs either real distinct source IPs or
    # real, validly-signed tokens for different subjects - both substantially
    # more expensive than editing a JWT payload.

    async def record_resource_attack(self, resource: str, attacker_key: str, now: float, window_sec: int) -> int:
        self._touch(f"resource:{resource}")
        if self.connected:
            try:
                rkey = f"resattackers:{resource}"
                await self.redis_client.zadd(rkey, {attacker_key: now})
                await self.redis_client.zremrangebyscore(rkey, 0, now - window_sec)
                await self.redis_client.expire(rkey, window_sec)
                return await self.redis_client.zcard(rkey)
            except Exception as e:
                self._degrade("record_resource_attack", e)
        bucket = self._resource_attackers[resource]
        bucket[attacker_key] = now
        cutoff = now - window_sec
        self._resource_attackers[resource] = {k: t for k, t in bucket.items() if t >= cutoff}
        return len(self._resource_attackers[resource])

    async def set_resource_hardened(self, resource: str, hardened_until: float, cooldown_sec: int) -> None:
        if self.connected:
            try:
                await self.redis_client.set(f"hardened:{resource}", str(hardened_until), ex=max(cooldown_sec, 1))
                return
            except Exception as e:
                self._degrade("set_resource_hardened", e)
        self._hardened_resources[resource] = hardened_until

    async def get_resource_hardened_until(self, resource: str, now: float) -> float:
        if self.connected:
            try:
                val = await self.redis_client.get(f"hardened:{resource}")
                return float(val) if val else 0.0
            except Exception as e:
                self._degrade("get_resource_hardened_until", e)
        until = self._hardened_resources.get(resource, 0.0)
        if until and now >= until:
            del self._hardened_resources[resource]
            return 0.0
        return until

    async def list_hardened_resources(self, now: float) -> list:
        """Visibility for /admin/hardening - only currently-active entries."""
        results = []
        if self.connected:
            try:
                async for key in self.redis_client.scan_iter(match="hardened:*"):
                    val = await self.redis_client.get(key)
                    if val:
                        results.append({"resource": key.split(":", 1)[1], "hardened_until": float(val)})
                return results
            except Exception as e:
                self._degrade("list_hardened_resources", e)
        for resource, until in list(self._hardened_resources.items()):
            if until > now:
                results.append({"resource": resource, "hardened_until": until})
        return results

    # --------------------------------------------------------------------- ml

    async def publish_ml_signal(self, subject: str, ml_risk: Optional[int], profile: dict, ttl: int) -> None:
        """Record what ml/worker.py computed for one subject.

        Called two ways, and deliberately identical in effect either way:
        the worker writes to Redis directly when it has one, and POSTs to
        /admin/ml-signal when it does not. Redis was originally the *only*
        transport, which meant the entire ML component - IsolationForest,
        Markov sequences, the NetworkX access graph - silently produced nothing
        on any machine without a Redis to share. That is the common case for a
        laptop demo, so the headline ML feature was reliably invisible exactly
        when someone was watching. The models are real either way; only the
        transport between the two processes changed.

        Write-through to memory is unconditional, same rule as ownership: the
        local mirror has to stay authoritative if Redis disappears mid-run.
        `ml_risk` may be None - the worker publishes a profile for any tracked
        entity (visibility) but a score only once it has enough samples to mean
        anything, and that distinction has to survive the trip.
        """
        expires = time.time() + max(1, ttl)
        if ml_risk is not None:
            self._ml_risk[subject] = (int(ml_risk), expires)
        self._ml_profiles[subject] = (profile, expires)

        if self.connected:
            try:
                if ml_risk is not None:
                    await self.redis_client.setex(f"ml_risk:{subject}", ttl, str(int(ml_risk)))
                await self.redis_client.setex(f"profile:{subject}", ttl, json.dumps(profile))
            except Exception as e:
                self._degrade("publish_ml_signal", e)

    async def get_ml_risk(self, subject: str) -> Optional[int]:
        # Written by the separate ml/worker.py process (ML.md), never by this
        # one. Redis first when it is available, because that is the only path
        # that works across multiple gateway instances; the in-memory mirror
        # covers the single-process demo where no Redis exists.
        #
        # None means "no ML opinion available", which stays a completely normal
        # state: the gateway must decide correctly with zero ML signal, and
        # nothing here is ever allowed to become a dependency of the request
        # path.
        if self.connected:
            try:
                val = await self.redis_client.get(f"ml_risk:{subject}")
                if val is not None:
                    return int(val)
            except Exception as e:
                self._degrade("get_ml_risk", e)

        entry = self._ml_risk.get(subject)
        if not entry:
            return None
        score, expires = entry
        if time.time() >= expires:
            # expiry is enforced on read as well as in the sweep, so a stale
            # score can never outlive its TTL just because the sweep is due
            self._ml_risk.pop(subject, None)
            return None
        return score

    async def list_ml_profiles(self, limit: int = 200) -> list:
        # Read-only visibility into what the ML worker has actually built, for
        # /admin/ml-status. Merges both transports rather than picking one, for
        # the same reason list_ownership does: with Redis connected the worker
        # may have written through both, and reading one would under-report.
        # SCAN, never KEYS, so this cannot block Redis at any keyspace size.
        # An empty list is a true, expected state (worker never started), not
        # an error.
        now = time.time()
        merged: dict = {}
        redis_hits = 0

        for subject, (payload, expires) in list(self._ml_profiles.items()):
            if now >= expires:
                self._ml_profiles.pop(subject, None)
                continue
            merged[subject] = payload
        local_hits = len(merged)

        if self.connected:
            try:
                cursor = 0
                seen = 0
                while True:
                    cursor, keys = await self.redis_client.scan(cursor, match="profile:*", count=100)
                    for key in keys:
                        val = await self.redis_client.get(key)
                        if val:
                            try:
                                payload = json.loads(val)
                                merged[payload.get("subject", key)] = payload
                                redis_hits += 1
                            except Exception:
                                pass
                        seen += 1
                        if seen >= limit:
                            break
                    if seen >= limit or cursor == 0:
                        break
            except Exception as e:
                self._degrade("list_ml_profiles", e)

        if redis_hits:
            self.last_ml_source = "redis"
        elif local_hits:
            self.last_ml_source = "http (/admin/ml-signal)"
        else:
            self.last_ml_source = "none"

        return list(merged.values())[:limit]

    # ------------------------------------------------------------- revocation

    async def revoke_token(self, jti: str, exp: float, reason: str = "") -> dict:
        """Add a token id to the denylist until its own expiry.

        The TTL is the token's remaining lifetime, not a fixed window. A revoked
        token that has expired on its own is already rejected by the expiry
        check, so keeping its jti after that point grows the denylist forever
        without adding any protection - this is the difference between a
        denylist that stays small and one that becomes an operational problem.

        Written through to memory unconditionally, same as ownership, so the
        denylist stays authoritative if Redis disappears mid-flight. Revocation
        failing open is the one outcome that must never happen quietly.
        """
        now = time.time()
        ttl = max(1, int(exp - now)) if exp else self._default_revocation_ttl
        record = {"jti": jti, "revoked_at": now, "expires_at": exp or (now + ttl), "reason": reason}
        self._revoked[jti] = record

        if self.connected:
            try:
                await self.redis_client.setex(f"revoked:{jti}", ttl, json.dumps(record))
            except Exception as e:
                self._degrade("revoke_token", e)
        return record

    async def is_revoked(self, jti: str) -> bool:
        if not jti:
            return False

        # Memory first and always: it is a plain dict lookup, it cannot fail, and
        # checking it before Redis means a Redis outage cannot turn a revoked
        # token back into a valid one for anything revoked by this process.
        record = self._revoked.get(jti)
        if record:
            if record["expires_at"] > time.time():
                return True
            # self-expired; drop it so the local map does not grow unbounded
            self._revoked.pop(jti, None)

        if self.connected:
            try:
                return bool(await self.redis_client.exists(f"revoked:{jti}"))
            except Exception as e:
                self._degrade("is_revoked", e)
        return False

    async def list_revoked(self, limit: int = 500) -> list:
        now = time.time()
        live = {
            jti: r for jti, r in self._revoked.items() if r["expires_at"] > now
        }
        if self.connected:
            try:
                cursor = 0
                seen = 0
                while True:
                    cursor, keys = await self.redis_client.scan(cursor, match="revoked:*", count=100)
                    for key in keys:
                        val = await self.redis_client.get(key)
                        if val:
                            try:
                                r = json.loads(val)
                                live.setdefault(r.get("jti", key.split(":", 1)[-1]), r)
                            except Exception:
                                pass
                        seen += 1
                        if seen >= limit:
                            cursor = 0
                            break
                    if cursor == 0:
                        break
            except Exception as e:
                self._degrade("list_revoked", e)
        return sorted(live.values(), key=lambda r: r.get("revoked_at", 0), reverse=True)

    async def list_ownership(self, limit: int = 1000) -> list:
        """Every object-ownership grant currently in force, for /admin/ownership.

        Read-only visibility into the data BOLA decisions are actually made
        against - the Access Control page exists so that "who owns what" is
        inspectable rather than being an invisible set of Redis keys.

        The in-memory map is always merged in, not used only as a fallback:
        grant_ownership() writes through to memory unconditionally, so with
        Redis connected the two are both authoritative and reading only one of
        them would under-report. SCAN, never KEYS, for the same reason as
        list_ml_profiles.
        """
        merged: dict = {}

        for resource, objects in self._owned_objects.items():
            for object_id, subjects in objects.items():
                if subjects:
                    merged.setdefault((resource, object_id), set()).update(subjects)

        if self.connected:
            try:
                cursor = 0
                seen = 0
                while True:
                    cursor, keys = await self.redis_client.scan(
                        cursor, match="authorized:*", count=100
                    )
                    for key in keys:
                        # authorized:{resource}:{object_id} - split from the left
                        # twice only, since an object id may itself contain ':'
                        parts = key.split(":", 2)
                        if len(parts) != 3:
                            continue
                        _, resource, object_id = parts
                        members = await self.redis_client.smembers(key)
                        if members:
                            merged.setdefault((resource, object_id), set()).update(members)
                        seen += 1
                        if seen >= limit:
                            cursor = 0
                            break
                    if cursor == 0:
                        break
            except Exception as e:
                self._degrade("list_ownership", e)

        return sorted(
            (
                {
                    "resource": resource,
                    "object_id": object_id,
                    "owners": sorted(subjects),
                    "fan_in": len(subjects),
                }
                for (resource, object_id), subjects in merged.items()
            ),
            key=lambda g: (g["resource"], g["object_id"]),
        )

    # ------------------------------------------------------------------ admin

    def reset_runtime_state(self) -> dict:
        """Clear traffic history and mitigation state, keep ownership.

        Re-running a demo previously meant restarting the process: once an IP or
        identity cooldown fired there was no way to clear it. Ownership is
        preserved deliberately - it is provisioned authorization data, and
        wiping it would make the next BOLA demonstration silently pass.
        """
        counts = {
            "subjects": len(self._req_times),
            "block_states": len(self._block_state),
            "escalations": len(self._escalation_counts),
        }
        self._req_times.clear()
        self._obj_hits.clear()
        self._block_events.clear()
        self._block_state.clear()
        self._escalation_counts.clear()
        self._last_touch.clear()
        return counts

    async def reset_redis_runtime_state(self) -> int:
        if not self.connected:
            return 0
        removed = 0
        try:
            for pattern in ("reqtimes:*", "objhits:*", "blockevents:*", "blocked:*", "escalations:*"):
                async for key in self.redis_client.scan_iter(match=pattern, count=500):
                    await self.redis_client.delete(key)
                    removed += 1
        except Exception as e:
            self._degrade("reset_redis_runtime_state", e)
        return removed


store = SharedStore()
