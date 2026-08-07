import json
import time
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional
import asyncio
import redis.asyncio as redis
from config import settings


class EntityBaseline:
    def __init__(self, subject_id: str):
        self.subject_id = subject_id
        self.created_at = datetime.utcnow()
        self.requests = deque(maxlen=1000)
        self.endpoints_accessed = set()
        self.resources_accessed = defaultdict(set)
        self.avg_requests_per_min = 0.0
        self.peak_requests_per_min = 0.0
        self.normal_endpoints = set()
        self.normal_resources = set()
        self.object_access_graph = defaultdict(set)
        self.anomaly_score = 0.0
        self.anomaly_reason = ""
        self.last_updated = datetime.utcnow()
        self.is_learning = True

    def to_dict(self) -> dict:
        return {
            "subject_id": self.subject_id,
            "created_at": self.created_at.isoformat(),
            "endpoints_accessed": len(self.endpoints_accessed),
            "resources_accessed": {k: len(v) for k, v in self.resources_accessed.items()},
            "anomaly_score": self.anomaly_score,
            "anomaly_reason": self.anomaly_reason,
            "is_learning": self.is_learning,
            "avg_rpm": round(self.avg_requests_per_min, 2),
            "peak_rpm": round(self.peak_requests_per_min, 2),
        }


class AnomalyDetector:
    def __init__(self):
        self.entity_baselines: Dict[str, EntityBaseline] = {}

    def get_or_create_baseline(self, subject_id: str) -> EntityBaseline:
        if subject_id not in self.entity_baselines:
            self.entity_baselines[subject_id] = EntityBaseline(subject_id)
        return self.entity_baselines[subject_id]

    def record_request(self, subject_id: str, method: str, path: str, resource: str, object_id: str = ""):
        baseline = self.get_or_create_baseline(subject_id)
        now = time.time()
        baseline.requests.append({
            "time": now,
            "method": method,
            "path": path,
            "resource": resource,
            "object_id": object_id
        })
        baseline.endpoints_accessed.add(path)
        if resource and object_id:
            baseline.resources_accessed[resource].add(object_id)
            baseline.object_access_graph[resource].add(object_id)

    def compute_baseline_stats(self, subject_id: str) -> None:
        baseline = self.get_or_create_baseline(subject_id)

        if len(baseline.requests) < 5:
            baseline.is_learning = True
            return

        age_sec = (datetime.utcnow() - baseline.created_at).total_seconds()
        if age_sec < settings.learning_window_sec:
            baseline.is_learning = True
            return

        baseline.is_learning = False
        now = time.time()
        recent_60s = [r for r in baseline.requests if (now - r["time"]) <= 60]
        baseline.avg_requests_per_min = len(recent_60s) / 1.0

        recent_10s = [r for r in baseline.requests if (now - r["time"]) <= 10]
        if len(recent_10s) > baseline.peak_requests_per_min:
            baseline.peak_requests_per_min = len(recent_10s)

        if len(baseline.requests) > 10:
            baseline.normal_endpoints = set(list(baseline.endpoints_accessed)[:20])
            baseline.normal_resources = set(baseline.resources_accessed.keys())

    def detect_sequence_anomaly(self, subject_id: str) -> Optional[tuple[float, str]]:
        baseline = self.get_or_create_baseline(subject_id)

        if len(baseline.requests) < 5:
            return None

        now = time.time()
        recent_5s = [r for r in baseline.requests if (now - r["time"]) <= 5]

        if len(recent_5s) < 5:
            return None

        distinct_objects = len(set(r.get("object_id", "") for r in recent_5s if r.get("object_id")))

        if distinct_objects >= 8:
            anomaly_score = min(80.0, distinct_objects * 10)
            return (anomaly_score, f"rapid_object_access")

        return None

    def detect_graph_anomaly(self, subject_id: str) -> Optional[tuple[float, str]]:
        baseline = self.get_or_create_baseline(subject_id)

        if len(baseline.requests) < 3:
            return None

        now = time.time()
        recent_10s = [r for r in baseline.requests if (now - r["time"]) <= 10]

        if len(recent_10s) < 2:
            return None

        resources = set(r["resource"] for r in recent_10s if r["resource"])

        if len(resources) >= 4:
            anomaly_score = min(70.0, len(resources) * 15)
            return (anomaly_score, f"multi_resource_access")

        return None

    def detect_volume_anomaly(self, subject_id: str) -> Optional[tuple[float, str]]:
        baseline = self.get_or_create_baseline(subject_id)

        if len(baseline.requests) < 10:
            return None

        self.compute_baseline_stats(subject_id)

        now = time.time()
        recent_60s = [r for r in baseline.requests if (now - r["time"]) <= 60]
        current_rpm = len(recent_60s)

        if baseline.avg_requests_per_min > 0:
            spike_ratio = current_rpm / (baseline.avg_requests_per_min + 1)

            if spike_ratio >= 5.0:
                anomaly_score = min(75.0, spike_ratio * 10)
                return (anomaly_score, f"volume_spike")

        recent_3s = [r for r in baseline.requests if (now - r["time"]) <= 3]
        if len(recent_3s) >= 30:
            anomaly_score = 85.0
            return (anomaly_score, f"burst_detected")

        return None

    def compute_anomaly_score(self, subject_id: str) -> tuple[float, str]:
        self.compute_baseline_stats(subject_id)
        baseline = self.entity_baselines.get(subject_id)

        if not baseline or baseline.is_learning:
            return (0.0, "learning")

        seq_anomaly = self.detect_sequence_anomaly(subject_id)
        graph_anomaly = self.detect_graph_anomaly(subject_id)
        volume_anomaly = self.detect_volume_anomaly(subject_id)

        anomalies = [a for a in [seq_anomaly, graph_anomaly, volume_anomaly] if a]

        if not anomalies:
            return (0.0, "normal")

        max_score = max(a[0] for a in anomalies)
        reasons = [a[1] for a in anomalies]

        return (max_score, " + ".join(reasons))


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
    def __init__(self):
        self.detector = AnomalyDetector()
        self.redis_client = None
        self.running = False

    async def connect_redis(self):
        try:
            self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
            await self.redis_client.ping()
            print("Control Plane: Redis connected")
        except Exception as e:
            print(f"Control Plane: Redis unavailable ({e})")
            self.redis_client = None

    def use_client(self, client) -> None:
        self.redis_client = client

    async def record_request_async(self, subject_id: str, method: str, path: str, resource: str, object_id: str = ""):
        self.detector.record_request(subject_id, method, path, resource, object_id)

    async def compute_and_store_risk(self, subject_id: str) -> dict:
        anomaly_score, reason = self.detector.compute_anomaly_score(subject_id)
        baseline = self.detector.get_or_create_baseline(subject_id)

        enriched_risk = {
            "anomaly_score": anomaly_score,
            "anomaly_reason": reason,
            "baseline_stats": baseline.to_dict(),
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }

        if self.redis_client:
            try:
                await self.redis_client.setex(
                    f"control_plane:{subject_id}",
                    300,
                    json.dumps(enriched_risk)
                )
            except Exception:
                pass

        return enriched_risk

    async def get_enriched_risk(self, subject_id: str) -> Optional[dict]:
        if not self.redis_client:
            return None

        try:
            data = await self.redis_client.get(f"control_plane:{subject_id}")
            if data:
                return json.loads(data)
        except Exception:
            pass

        return None

    async def control_plane_loop(self):
        self.running = True
        print("Control Plane: Agent started")

        while self.running:
            try:
                for subject_id in list(self.detector.entity_baselines.keys()):
                    await self.compute_and_store_risk(subject_id)

                await asyncio.sleep(1)
            except Exception:
                await asyncio.sleep(1)

    async def start(self):
        await self.connect_redis()
        asyncio.create_task(self.control_plane_loop())

    async def stop(self):
        self.running = False
        if self.redis_client:
            await self.redis_client.close()


control_plane = ControlPlaneAgent()
