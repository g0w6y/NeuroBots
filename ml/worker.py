"""
NeuroBots ML worker (ML.md).

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
        self.last_processed_time = ""
        self.processed_count = 0

    def get_profile(self, subject: str) -> EntityProfile:
        if subject not in self.profiles:
            self.profiles[subject] = EntityProfile(subject)
        return self.profiles[subject]

    async def connect_redis(self):
        while True:
            try:
                self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
                await self.redis_client.ping()
                print("ML worker: Redis connected")
                return
            except Exception as e:
                print(f"ML worker: Redis unavailable ({e}), retrying in 5s")
                await asyncio.sleep(5)

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

        if not self.last_processed_time:
            self.last_processed_time = alerts[-1]["time"] if alerts else ""
            return []

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
            return
        if decision != "allow" and decision != "observe":
            return  # challenge: ambiguous, neither trains nor marks hostile

        if profile.known_attacker:
            # a confirmed attacker's later "allowed" requests still don't
            # retroactively become trustworthy training data
            return

        profile.record_allowed(endpoint, object_id, resource, now)
        self.graph.record_edge(subject, resource, object_id, now)
        profile.maybe_retrain()

    async def score_and_publish(self, subject: str, now: float) -> None:
        profile = self.profiles.get(subject)
        if not profile or len(profile.requests) < settings.min_samples_to_score:
            return

        last = profile.requests[-1]
        isolation = profile.isolation_score(last["endpoint"], last["object_id"], now)
        markov = profile.markov_score(last["endpoint"])
        novelty = self.graph.novelty_score(subject, last["resource"], last["object_id"], now)

        ml_risk, breakdown = compute_ml_risk(isolation, markov, novelty)

        payload = {
            "ml_risk": ml_risk,
            "breakdown": breakdown,
            "sample_count": len(profile.requests),
            "updated_at": datetime.now(timezone.utc).isoformat() + "Z",
        }

        if self.redis_client:
            try:
                await self.redis_client.setex(f"ml_risk:{subject}", settings.ml_risk_ttl_sec, str(ml_risk))
                await self.redis_client.setex(
                    f"profile:{subject}", settings.profile_ttl_sec,
                    json.dumps({**profile.to_dict(), **payload})
                )
            except Exception as e:
                print(f"ML worker: Redis write failed for {subject} ({e})")

    async def run(self):
        await self.connect_redis()
        print(f"ML worker: polling {settings.gateway_url} every {settings.poll_interval_sec}s")

        async with httpx.AsyncClient() as client:
            while True:
                new_alerts = await self.fetch_new_alerts(client)
                now = time.time()
                touched_subjects = set()

                for alert in new_alerts:
                    self.process_alert(alert, now)
                    touched_subjects.add(alert.get("subject", ""))
                    self.processed_count += 1

                for subject in touched_subjects:
                    await self.score_and_publish(subject, now)

                if new_alerts:
                    print(f"ML worker: processed {len(new_alerts)} new event(s), "
                          f"{len(self.profiles)} profiled entities, graph {self.graph.stats()}")

                await asyncio.sleep(settings.poll_interval_sec)


if __name__ == "__main__":
    worker = MLWorker()
    asyncio.run(worker.run())
