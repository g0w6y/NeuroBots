"""
Project0 ML worker (ML.md).

Standalone async process. Polls the gateway's /admin/alerts for real request
events, builds real per-entity IsolationForest models (scikit-learn), a real
Markov transition table for call sequences, and a real NetworkX access graph.
Writes ml_risk:{subject} to Redis - the gateway reads it as an independent
second anomaly signal, alongside its own deterministic rule-engine one.

Never blocks anything. If this process isn't running, the gateway degrades
to exactly what it was before this existed - this only adds a signal, it
never becomes a dependency of the request path.

Anti-poisoning rule (ML.md Part 7): only allowed requests train the models.
A confirmed attacker's traffic is recorded (record_hostile) but never folded
into that entity's baseline - the same principle used everywhere else in
this project.

Run:
    python3 worker.py
"""

import asyncio
import json
import time
from datetime import datetime, timezone

import httpx
import redis.asyncio as redis

from config import settings
from profiling import EntityProfile, parse_path
from graph import AccessGraph
from risk import compute_ml_risk


def infer_resource(endpoint: str) -> str:
    if endpoint.startswith("/api/accounts"):
        return "account"
    if endpoint.startswith("/api/transfers"):
        return "transfer"
    if endpoint.startswith("/api/admin"):
        return "admin"
    return "other"


class MLWorker:
    def __init__(self):
        self.profiles: dict[str, EntityProfile] = {}
        self.graph = AccessGraph()
        self.redis_client = None
        self.redis_ready = False
        self.redis_announced = False
        self.last_processed_time = ""
        self.processed_count = 0

    def get_profile(self, subject: str) -> EntityProfile:
        if subject not in self.profiles:
            self.profiles[subject] = EntityProfile(subject)
        return self.profiles[subject]

    async def connect_redis(self) -> bool:
        """Try for Redis, but never wait for it forever.

        This used to be `while True: ... await asyncio.sleep(5)`, so with no
        Redis reachable the worker parked in this loop and never reached run()'s
        polling at all. On a machine with no Redis and no Docker - the ordinary
        laptop case - that meant the IsolationForest, the Markov model and the
        NetworkX graph never scored a single request, and start_all skipped
        launching this process entirely. The models were real and the demo never
        showed them.

        Redis is still preferred and still the only transport that works across
        multiple gateway instances; it is simply no longer a precondition for
        starting. If it appears later, publish() picks it up on the next tick.
        """
        try:
            client = await redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            await client.ping()
            self.redis_client = client
            if not self.redis_ready:
                print("ML worker: Redis connected")
            self.redis_ready = True
            return True
        except Exception as e:
            if self.redis_ready or not self.redis_announced:
                print(f"ML worker: Redis unavailable ({e}) - publishing to "
                      f"{settings.gateway_url}/admin/ml-signal instead")
                self.redis_announced = True
            self.redis_client = None
            self.redis_ready = False
            return False

    async def publish(self, client: httpx.AsyncClient, subject: str,
                      ml_risk: int | None, profile: dict, ttl: int) -> None:
        """One publish path, two transports, identical meaning.

        Redis when it is there, the gateway's admin endpoint when it is not. A
        failure on either is logged and dropped rather than raised: this worker
        only ever *adds* a signal, so losing one update must never take the
        process down or stall the poll loop.
        """
        if self.redis_ready and self.redis_client:
            try:
                if ml_risk is not None:
                    await self.redis_client.setex(f"ml_risk:{subject}", ttl, str(ml_risk))
                await self.redis_client.setex(f"profile:{subject}", ttl, json.dumps(profile))
                return
            except Exception as e:
                print(f"ML worker: Redis write failed for {subject} ({e}) - falling back to HTTP")
                self.redis_ready = False
                self.redis_client = None

        try:
            resp = await client.post(
                f"{settings.gateway_url}/admin/ml-signal",
                headers={"X-Admin-Key": settings.admin_api_key},
                json={"subject": subject, "ml_risk": ml_risk, "profile": profile, "ttl_sec": ttl},
                timeout=5,
            )
            if resp.status_code != 200:
                print(f"ML worker: gateway returned {resp.status_code} on /admin/ml-signal")
        except Exception as e:
            print(f"ML worker: could not publish {subject} ({e})")

    async def fetch_new_alerts(self, client: httpx.AsyncClient) -> list[dict]:
        try:
            resp = await client.get(
                f"{settings.gateway_url}/admin/alerts",
                headers={"X-Admin-Key": settings.admin_api_key},
                timeout=5,
            )
            if resp.status_code != 200:
                print(f"ML worker: gateway returned {resp.status_code} on /admin/alerts")
                return []
            alerts = resp.json()
        except Exception as e:
            print(f"ML worker: gateway unreachable ({e})")
            return []

        # Process everything visible on the very first poll, don't discard it
        # as "old history". A prior design skipped whatever was already in
        # /admin/alerts at startup, meant to avoid reprocessing a stale
        # previous session on restart - but /admin/alerts is already a bounded
        # recent window (not unbounded history), and in the much more common
        # case - this worker starting fresh alongside a fresh gateway - that
        # behavior silently discarded the demo's own opening traffic if it
        # landed before this first poll completed. Losing real events on
        # startup is worse than occasionally reprocessing a few.
        new_alerts = [a for a in alerts if a.get("time", "") > self.last_processed_time]
        if new_alerts:
            self.last_processed_time = max(a["time"] for a in new_alerts)
        return sorted(new_alerts, key=lambda a: a.get("time", ""))

    def process_alert(self, alert: dict, now: float) -> None:
        subject = alert.get("subject", "")
        path = alert.get("path", "")
        decision = alert.get("decision", "")
        if not subject or not path:
            return

        endpoint, object_id = parse_path(path)
        resource = infer_resource(endpoint)
        profile = self.get_profile(subject)

        if decision == "block":
            profile.record_hostile()
            self.graph.record_edge(subject, resource, object_id, now, is_blocked=True, risk_score=float(alert.get("risk", 85)))
            return
        if decision != "allow" and decision != "observe":
            return  # challenge: ambiguous, neither trains nor marks hostile

        if profile.known_attacker:
            # a confirmed attacker's later "allowed" requests still don't
            # retroactively become trustworthy training data
            return

        profile.record_allowed(endpoint, object_id, resource, now)
        self.graph.record_edge(subject, resource, object_id, now, is_blocked=False, risk_score=float(alert.get("risk", 0)))
        profile.maybe_retrain()

    async def score_and_publish(self, client: httpx.AsyncClient, subject: str, now: float) -> None:
        # Two separate concerns, deliberately not gated by the same condition:
        # - profile:{subject} is written for ANY tracked entity, even with just
        #   1 sample - pure visibility/debugging (/admin/ml-status), proving
        #   the worker is alive and actually watching traffic. Does not affect
        #   detection.
        # - ml_risk:{subject} - the actual signal the gateway reads and can act
        #   on - is only written once min_samples_to_score is crossed. A model
        #   trained on a handful of samples is noise, not signal; publishing it
        #   as a real risk score would feed exactly the kind of premature,
        #   under-informed anomaly claim the rest of this project has
        #   deliberately guarded against everywhere else.
        profile = self.profiles.get(subject)
        if not profile or not profile.requests:
            return

        has_enough_data = len(profile.requests) >= settings.min_samples_to_score
        profile_payload = {**profile.to_dict(), "updated_at": datetime.now(timezone.utc).isoformat() + "Z"}

        if not has_enough_data:
            await self.publish(client, subject, None, profile_payload, settings.profile_ttl_sec)
            return

        last = profile.requests[-1]
        isolation = profile.isolation_score(last["endpoint"], last["object_id"], now)
        markov = profile.markov_score(last["endpoint"])
        novelty = self.graph.novelty_score(subject, last["resource"], last["object_id"], now)
        gnn_score = self.graph.gnn_score(subject, last["resource"], last["object_id"])

        ml_risk, breakdown = compute_ml_risk(isolation, markov, novelty, gnn_score)
        profile_payload.update({"ml_risk": ml_risk, "breakdown": breakdown})

        await self.publish(client, subject, ml_risk, profile_payload, settings.ml_risk_ttl_sec)

    async def run(self):
        await self.connect_redis()
        transport = "redis" if self.redis_ready else "http"
        print(f"ML worker: polling {settings.gateway_url} every {settings.poll_interval_sec}s "
              f"(publishing over {transport})")

        # Retry Redis periodically instead of once at startup, so a Redis that
        # comes up later is picked up without restarting this process. Counted
        # in ticks rather than wall-clock so the dial cost stays off the hot path.
        ticks = 0
        retry_every = max(1, int(30 / max(0.1, settings.poll_interval_sec)))

        async with httpx.AsyncClient() as client:
            while True:
                ticks += 1
                if not self.redis_ready and ticks % retry_every == 0:
                    await self.connect_redis()

                new_alerts = await self.fetch_new_alerts(client)
                now = time.time()
                touched_subjects = set()

                for alert in new_alerts:
                    self.process_alert(alert, now)
                    touched_subjects.add(alert.get("subject", ""))
                    self.processed_count += 1

                for subject in touched_subjects:
                    if subject:
                        await self.score_and_publish(client, subject, now)

                if new_alerts:
                    print(f"ML worker: processed {len(new_alerts)} new event(s), "
                          f"{len(self.profiles)} profiled entities, graph {self.graph.stats()}")

                await asyncio.sleep(settings.poll_interval_sec)


if __name__ == "__main__":
    worker = MLWorker()
    asyncio.run(worker.run())
