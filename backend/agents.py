"""
Behavioural control plane: learns each subject's own normal traffic shape and
flags deviations from it.

This layer produces *soft* signals only. Everything in detect.py is a
determination of fact - a signature that does not verify, an object the subject
demonstrably does not own - and blocks on its own. What lives here is inference:
"this subject is behaving unlike itself". Inference can be wrong, so it never
blocks by itself; it contributes score, and a sustained deviation is what lifts a
request into a step-up challenge. That division is the reason the gateway can
claim zero false positives and still catch a slow scraper that never trips a
hard threshold.
"""

import json
import time
import statistics
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional
import asyncio
import redis.asyncio as redis
from config import settings


class EntityBaseline:
    # An entity's endpoint set was previously unbounded, so a subject walking
    # distinct URLs held every one of them forever. These caps make a baseline's
    # footprint fixed regardless of how long the process runs or how adversarial
    # the traffic is.
    MAX_ENDPOINTS = 200
    MAX_OBJECTS_PER_RESOURCE = 500

    def __init__(self, subject_id: str):
        self.subject_id = subject_id
        self.created_at = datetime.utcnow()
        self.requests = deque(maxlen=1000)
        self.endpoints_accessed = set()
        self.resources_accessed = defaultdict(set)
        self.last_seen = time.time()

        # Rolling samples of "requests in the trailing RATE_WINDOW_SEC seconds",
        # appended once per control-plane tick. A spike is only meaningful
        # against history, so history has to be recorded separately rather than
        # recomputed from the same window being tested.
        self.rate_samples = deque(maxlen=120)

        self.avg_requests_per_min = 0.0
        self.peak_requests_per_min = 0.0

        # Frozen at the moment learning completes, never updated afterwards.
        # These were previously recomputed from the live accumulating sets on
        # every call, which meant "resources this subject normally touches"
        # always already contained whatever it had just touched - so nothing
        # could ever look novel.
        self.normal_endpoints = set()
        self.normal_resources = set()
        self.baseline_frozen = False

        self.object_access_graph = defaultdict(set)
        self.anomaly_score = 0.0
        self.anomaly_reason = ""
        self.last_updated = datetime.utcnow()
        self.is_learning = True

    def to_dict(self) -> dict:
        return {
            "subject_id": self.subject_id,
            "created_at": self.created_at.isoformat() + "Z",
            "endpoints_accessed": len(self.endpoints_accessed),
            "resources_accessed": {k: len(v) for k, v in self.resources_accessed.items()},
            "anomaly_score": self.anomaly_score,
            "anomaly_reason": self.anomaly_reason,
            "is_learning": self.is_learning,
            "avg_rpm": round(self.avg_requests_per_min, 2),
            "peak_rpm": round(self.peak_requests_per_min, 2),
            "normal_resources": sorted(self.normal_resources),
            "samples": len(self.rate_samples),
        }


class AnomalyDetector:
    RATE_WINDOW_SEC = 10          # width of one rate sample
    MIN_SAMPLES = 15              # need this much history before judging volume
    EXCLUDE_RECENT = 5            # newest samples withheld from the baseline
    VOLUME_SPIKE_RATIO = 4.0
    GRAPH_BREADTH = 3
    SEQUENCE_OBJECTS = 8
    MAX_BASELINES = 5000

    # Before "this subject has never used that resource" is allowed to mean
    # anything, the subject needs a working set large enough for the absence to
    # be evidence. The learning window closes after 5 requests / 8 seconds, which
    # is enough to start measuring *rate* but nowhere near enough to enumerate
    # what someone's job involves. Measured: a legitimate user who reads accounts
    # and then posts a transfer - every run, her normal work - had `transfer`
    # frozen out of her baseline because it fell a few seconds the wrong side of
    # that window, and was challenged for it on every subsequent transfer,
    # permanently. Novelty is only interesting once the baseline is credible.
    GRAPH_MIN_REQUESTS = 25
    GRAPH_MIN_AGE_SEC = 90.0

    def __init__(self):
        self.entity_baselines: Dict[str, EntityBaseline] = {}

    def get_or_create_baseline(self, subject_id: str) -> EntityBaseline:
        if subject_id not in self.entity_baselines:
            self.entity_baselines[subject_id] = EntityBaseline(subject_id)
        return self.entity_baselines[subject_id]

    def record_request(self, subject_id: str, method: str, path: str, resource: str, object_id: str = ""):
        baseline = self.get_or_create_baseline(subject_id)
        now = time.time()
        baseline.last_seen = now
        baseline.requests.append({
            "time": now,
            "method": method,
            "path": path,
            "resource": resource,
            "object_id": object_id
        })
        if len(baseline.endpoints_accessed) < EntityBaseline.MAX_ENDPOINTS:
            baseline.endpoints_accessed.add(path)
        if resource and object_id:
            if len(baseline.resources_accessed[resource]) < EntityBaseline.MAX_OBJECTS_PER_RESOURCE:
                baseline.resources_accessed[resource].add(object_id)
                baseline.object_access_graph[resource].add(object_id)

    def sample_rate(self, subject_id: str) -> None:
        """Record one point of traffic history. Called on the control-plane tick,
        which is what gives volume detection a past to compare against."""
        baseline = self.get_or_create_baseline(subject_id)
        now = time.time()
        window = [r for r in baseline.requests if (now - r["time"]) <= self.RATE_WINDOW_SEC]
        baseline.rate_samples.append(len(window))

    def evict_idle(self, max_idle_sec: float = 900.0) -> int:
        """Drop baselines for subjects that have gone quiet.

        Without this, every distinct subject ever seen - including one
        `anon:{ip}` per source address - retained a 1000-entry request deque
        plus its sets for the life of the process.
        """
        now = time.time()
        stale = [s for s, b in self.entity_baselines.items() if now - b.last_seen > max_idle_sec]
        for s in stale:
            del self.entity_baselines[s]

        # hard ceiling as a backstop against a flood of one-shot identities
        if len(self.entity_baselines) > self.MAX_BASELINES:
            ordered = sorted(self.entity_baselines.items(), key=lambda kv: kv[1].last_seen)
            for s, _ in ordered[: len(self.entity_baselines) - self.MAX_BASELINES]:
                del self.entity_baselines[s]
                stale.append(s)
        return len(stale)

    def compute_baseline_stats(self, subject_id: str) -> None:
        baseline = self.get_or_create_baseline(subject_id)

        if len(baseline.requests) < 5:
            baseline.is_learning = True
            return

        age_sec = (datetime.utcnow() - baseline.created_at).total_seconds()
        if age_sec < settings.learning_window_sec:
            baseline.is_learning = True
            return

        was_learning = baseline.is_learning
        baseline.is_learning = False

        now = time.time()
        recent_60s = [r for r in baseline.requests if (now - r["time"]) <= 60]
        baseline.avg_requests_per_min = len(recent_60s)

        recent_10s = [r for r in baseline.requests if (now - r["time"]) <= 10]
        if len(recent_10s) > baseline.peak_requests_per_min:
            baseline.peak_requests_per_min = len(recent_10s)

        # Snapshot "normal" exactly once, at the moment the learning window
        # closes. Everything observed afterwards is measured against this.
        if was_learning and not baseline.baseline_frozen:
            baseline.normal_endpoints = set(baseline.endpoints_accessed)
            baseline.normal_resources = set(baseline.resources_accessed.keys())
            baseline.baseline_frozen = True

    def detect_sequence_anomaly(self, subject_id: str) -> Optional[tuple[float, str]]:
        baseline = self.get_or_create_baseline(subject_id)

        if len(baseline.requests) < 5:
            return None

        now = time.time()
        recent_5s = [r for r in baseline.requests if (now - r["time"]) <= 5]

        if len(recent_5s) < 5:
            return None

        distinct_objects = len(set(r.get("object_id", "") for r in recent_5s if r.get("object_id")))

        if distinct_objects >= self.SEQUENCE_OBJECTS:
            return (min(80.0, distinct_objects * 10.0),
                    f"{distinct_objects} distinct objects touched in 5s")

        return None

    def detect_graph_anomaly(self, subject_id: str) -> Optional[tuple[float, str]]:
        """Flag a subject reaching into parts of the API it has never used.

        The previous rule required 4 or more distinct resource types in a 10s
        window. The route table defines exactly three (account, transfer,
        admin), so the condition was unsatisfiable and this detector could never
        fire. Absolute breadth was also the wrong question: what matters is not
        how many resource types a subject touches, but whether they are the ones
        it normally touches. A back-office job that always hits three is
        unremarkable; a retail user who has only ever read accounts suddenly
        reaching for admin is the signal.
        """
        baseline = self.get_or_create_baseline(subject_id)

        if not baseline.baseline_frozen or len(baseline.requests) < 3:
            return None

        now = time.time()
        recent = [r for r in baseline.requests if (now - r["time"]) <= 10]
        if len(recent) < 2:
            return None

        resources = {r["resource"] for r in recent if r["resource"]}
        if not resources:
            return None

        mature = (len(baseline.requests) >= self.GRAPH_MIN_REQUESTS
                  and (time.time() - baseline.created_at.timestamp()) >= self.GRAPH_MIN_AGE_SEC)

        novel = resources - baseline.normal_resources
        if novel and mature:
            # Admit it, then report it. Novelty is a property of the *first* time
            # a subject reaches somewhere new - that is the moment worth a step-up.
            # Leaving it out of the baseline forever meant the signal re-fired on
            # every later use, so a user whose ordinary job included a resource
            # they happened not to touch in their first 8 seconds was challenged
            # for doing that job, every single time, for the life of the process.
            # A detector that never stops firing on benign behaviour is not
            # detecting anything; it is just a tax on one unlucky user.
            baseline.normal_resources |= novel
            return (min(70.0, 35.0 + 20.0 * len(novel)),
                    f"reached {sorted(novel)}, never used by this subject during baselining")

        if len(resources) >= self.GRAPH_BREADTH:
            return (min(60.0, 20.0 * len(resources)),
                    f"touched {len(resources)} resource types in 10s")

        return None

    def detect_volume_anomaly(self, subject_id: str) -> Optional[tuple[float, str]]:
        """Flag a subject transacting far faster than it normally does.

        The previous implementation called compute_baseline_stats() - which set
        avg_requests_per_min to the count in the trailing 60 seconds - and then
        compared the count in the trailing 60 seconds against it. The ratio was
        therefore n/(n+1), always below 1, against a threshold of 5.0. It could
        not fire for any input. Detecting a spike requires history the spike is
        not part of, which is what rate_samples now provides.
        """
        baseline = self.get_or_create_baseline(subject_id)

        samples = list(baseline.rate_samples)
        if len(samples) < self.MIN_SAMPLES:
            return None

        current = samples[-1]
        history = samples[: -self.EXCLUDE_RECENT]
        if len(history) < 5:
            return None

        historical = statistics.median(history)
        if historical <= 0:
            # a subject that was previously idle is not "spiking" - it is simply
            # active, and volume alone says nothing about intent
            return None

        ratio = current / historical
        if ratio >= self.VOLUME_SPIKE_RATIO:
            return (min(75.0, 25.0 + ratio * 8.0),
                    f"{current} req/{self.RATE_WINDOW_SEC}s vs a usual {historical:.0f} "
                    f"({ratio:.1f}x this subject's own baseline)")

        return None

    def compute_anomaly_score(self, subject_id: str) -> tuple[float, str]:
        self.compute_baseline_stats(subject_id)
        baseline = self.entity_baselines.get(subject_id)

        if not baseline or baseline.is_learning:
            return (0.0, "learning")

        anomalies = [a for a in (
            self.detect_sequence_anomaly(subject_id),
            self.detect_graph_anomaly(subject_id),
            self.detect_volume_anomaly(subject_id),
        ) if a]

        if not anomalies:
            return (0.0, "normal")

        return (max(a[0] for a in anomalies), " + ".join(a[1] for a in anomalies))


def generate_narrative(subject: str, method: str, path: str, action: str, signals: list) -> str:
    if not signals:
        return f"{subject} called {method} {path}, no risk signals, clean."

    evidence = "; ".join(s.evidence for s in signals)
    owasp_tags = sorted(set(s.owasp for s in signals))

    if action == "block":
        lead = f"Blocked {subject} on {method} {path}"
    elif action == "challenge":
        lead = f"Step-up required for {subject} on {method} {path}"
    else:
        lead = f"Flagged {subject} on {method} {path}"

    return f"{lead}. {evidence}. Categories: {', '.join(owasp_tags)}."


class ControlPlaneAgent:
    TICK_SEC = 1.0

    def __init__(self):
        self.detector = AnomalyDetector()
        self.redis_client = None
        self.running = False
        self._owns_client = False
        self._task = None
        self._last_evict = 0.0

        # Enriched risk was cached in Redis only, and get_enriched_risk()
        # returned None outright when Redis was absent - so with the documented
        # default configuration (Redis optional, in-memory fallback) this whole
        # layer was inert and control_plane_anomaly could never reach a decision.
        # Every other subsystem degrades to memory; this one now does too.
        self._local_cache: Dict[str, dict] = {}

    async def connect_redis(self):
        try:
            self.redis_client = await redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            await self.redis_client.ping()
            self._owns_client = True
            print("Control Plane: Redis connected")
        except Exception as e:
            print(f"Control Plane: Redis unavailable, using in-process cache ({e})")
            self.redis_client = None
            self._owns_client = False

    def use_client(self, client) -> None:
        self.redis_client = client
        self._owns_client = False

    async def record_request_async(self, subject_id: str, method: str, path: str, resource: str, object_id: str = ""):
        self.detector.record_request(subject_id, method, path, resource, object_id)

    async def compute_and_store_risk(self, subject_id: str) -> dict:
        anomaly_score, reason = self.detector.compute_anomaly_score(subject_id)
        baseline = self.detector.get_or_create_baseline(subject_id)
        baseline.anomaly_score = anomaly_score
        baseline.anomaly_reason = reason
        baseline.last_updated = datetime.utcnow()

        enriched_risk = {
            "anomaly_score": anomaly_score,
            "anomaly_reason": reason,
            "baseline_stats": baseline.to_dict(),
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }

        self._local_cache[subject_id] = enriched_risk

        if self.redis_client:
            try:
                await self.redis_client.setex(
                    f"control_plane:{subject_id}", 300, json.dumps(enriched_risk)
                )
            except Exception:
                pass

        return enriched_risk

    async def get_enriched_risk(self, subject_id: str) -> Optional[dict]:
        if self.redis_client:
            try:
                data = await self.redis_client.get(f"control_plane:{subject_id}")
                if data:
                    return json.loads(data)
            except Exception:
                pass
        return self._local_cache.get(subject_id)

    async def control_plane_loop(self):
        self.running = True
        print("Control Plane: Agent started")

        while self.running:
            try:
                for subject_id in list(self.detector.entity_baselines.keys()):
                    self.detector.sample_rate(subject_id)
                    await self.compute_and_store_risk(subject_id)

                now = time.time()
                if now - self._last_evict > 60:
                    self._last_evict = now
                    dropped = self.detector.evict_idle()
                    for s in list(self._local_cache):
                        if s not in self.detector.entity_baselines:
                            del self._local_cache[s]
                    if dropped:
                        print(f"Control Plane: evicted {dropped} idle baselines")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # this used to swallow every error silently while /health kept
                # reporting the agent as "running", so a persistent fault in the
                # detector was invisible
                print(f"Control Plane: tick failed ({type(e).__name__}: {e})")

            await asyncio.sleep(self.TICK_SEC)

        print("Control Plane: Agent stopped")

    async def start(self):
        # Only dial if nobody handed us a client. start() previously called
        # connect_redis() unconditionally, which overwrote whatever use_client()
        # had just injected - so the "shares one Redis connection with store.py"
        # design dialled twice on every boot.
        if self.redis_client is None:
            await self.connect_redis()
        self._task = asyncio.create_task(self.control_plane_loop())

    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        # Only close a client we opened. Closing an injected one tore down the
        # store's connection underneath it during shutdown.
        if self.redis_client and self._owns_client:
            await self.redis_client.close()
        self.redis_client = None


control_plane = ControlPlaneAgent()
