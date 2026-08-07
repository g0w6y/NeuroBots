import time
import itertools
from collections import defaultdict, deque
from typing import Optional
import redis.asyncio as redis
from config import settings

_seq = itertools.count()


class SharedStore:
    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self.connected = False

        self._owned_objects = defaultdict(lambda: defaultdict(set))
        self._req_times = defaultdict(lambda: deque(maxlen=1000))
        self._obj_hits = defaultdict(lambda: defaultdict(lambda: deque(maxlen=500)))
        self._block_events = defaultdict(lambda: deque(maxlen=50))
        self._block_state = {}
        self._escalation_counts = defaultdict(int)

    async def connect(self):
        try:
            self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
            await self.redis_client.ping()
            self.connected = True
        except Exception:
            self.redis_client = None
            self.connected = False

    async def close(self):
        if self.redis_client:
            try:
                await self.redis_client.close()
            except Exception:
                pass

    async def is_owner(self, resource: str, object_id: str, subject: str) -> bool:
        if self.connected:
            try:
                return bool(await self.redis_client.sismember(f"authorized:{resource}:{object_id}", subject))
            except Exception:
                pass
        return subject in self._owned_objects[resource].get(object_id, set())

    async def fan_in(self, resource: str, object_id: str) -> int:
        if self.connected:
            try:
                return await self.redis_client.scard(f"authorized:{resource}:{object_id}")
            except Exception:
                pass
        return len(self._owned_objects[resource].get(object_id, set()))

    async def grant_ownership(self, resource: str, object_id: str, subject: str) -> None:
        if self.connected:
            try:
                await self.redis_client.sadd(f"authorized:{resource}:{object_id}", subject)
                return
            except Exception:
                pass
        self._owned_objects[resource][object_id].add(subject)

    async def record_request_time(self, subject: str, now: float) -> None:
        if self.connected:
            try:
                key = f"reqtimes:{subject}"
                await self.redis_client.zadd(key, {f"{now}:{next(_seq)}": now})
                await self.redis_client.zremrangebyscore(key, 0, now - 120)
                await self.redis_client.expire(key, 120)
                return
            except Exception:
                pass
        self._req_times[subject].append(now)

    async def count_requests_in_window(self, subject: str, now: float, window_sec: int) -> int:
        if self.connected:
            try:
                key = f"reqtimes:{subject}"
                return await self.redis_client.zcount(key, now - window_sec, "+inf")
            except Exception:
                pass
        return sum(1 for t in self._req_times[subject] if t >= now - window_sec)

    async def record_object_hit(self, subject: str, resource: str, object_id: str, now: float) -> None:
        if self.connected:
            try:
                key = f"objhits:{subject}:{resource}"
                await self.redis_client.zadd(key, {object_id: now})
                await self.redis_client.zremrangebyscore(key, 0, now - 120)
                await self.redis_client.expire(key, 120)
                return
            except Exception:
                pass
        self._obj_hits[subject][resource].append((object_id, now))

    async def distinct_objects_in_window(self, subject: str, resource: str, now: float, window_sec: int) -> int:
        if self.connected:
            try:
                key = f"objhits:{subject}:{resource}"
                return await self.redis_client.zcount(key, now - window_sec, "+inf")
            except Exception:
                pass
        return len(set(oid for oid, t in self._obj_hits[subject][resource] if t >= now - window_sec))

    async def record_block_event(self, key: str, now: float, window_sec: int) -> int:
        if self.connected:
            try:
                rkey = f"blockevents:{key}"
                await self.redis_client.zadd(rkey, {f"{now}:{next(_seq)}": now})
                await self.redis_client.zremrangebyscore(rkey, 0, now - window_sec)
                await self.redis_client.expire(rkey, window_sec)
                return await self.redis_client.zcard(rkey)
            except Exception:
                pass
        self._block_events[key].append(now)
        recent = [t for t in self._block_events[key] if now - t <= window_sec]
        self._block_events[key] = deque(recent, maxlen=50)
        return len(recent)

    async def set_blocked(self, key: str, blocked_until: float, cooldown_sec: int) -> None:
        if self.connected:
            try:
                await self.redis_client.set(f"blocked:{key}", str(blocked_until), ex=max(cooldown_sec, 1))
                return
            except Exception:
                pass
        self._block_state[key] = blocked_until

    async def get_blocked_until(self, key: str, now: float) -> float:
        if self.connected:
            try:
                val = await self.redis_client.get(f"blocked:{key}")
                return float(val) if val else 0.0
            except Exception:
                pass
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
            except Exception:
                pass
        self._escalation_counts[key] += 1
        return self._escalation_counts[key]

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


store = SharedStore()
