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

    # --------------------------------------------------------------------- ml

    async def get_ml_risk(self, subject: str) -> Optional[int]:
        # written by the separate ml/worker.py process (ml.md), never by this
        # process. if it's unreachable, that just means no ML signal is
        # available this request - there's no in-memory fallback here, the
        # worker's whole design depends on shared Redis, and the gateway must
        # still work perfectly with zero ML signal if that process isn't running.
        if not self.connected:
            return None
        try:
            val = await self.redis_client.get(f"ml_risk:{subject}")
            return int(val) if val is not None else None
        except Exception:
            return None

    async def list_ml_profiles(self, limit: int = 200) -> list:
        # read-only visibility into what the ML worker has actually built -
        # for /admin/ml-status. Uses SCAN, not KEYS, so this never blocks
        # Redis regardless of keyspace size. Returns [] (not an error) if
        # Redis is unreachable or the worker has never run - both are valid,
        # expected states, not failures.
        if not self.connected:
            return []
        profiles = []
        try:
            cursor = 0
            seen = 0
            while True:
                cursor, keys = await self.redis_client.scan(cursor, match="profile:*", count=100)
                for key in keys:
                    val = await self.redis_client.get(key)
                    if val:
                        try:
                            profiles.append(json.loads(val))
                        except Exception:
                            pass
                    seen += 1
                    if seen >= limit:
                        return profiles
                if cursor == 0:
                    break
        except Exception:
            return profiles
        return profiles

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
