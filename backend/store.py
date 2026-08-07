import asyncio
import time
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
