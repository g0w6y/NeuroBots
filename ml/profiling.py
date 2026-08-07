import re
import time
import zlib
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from config import settings


def parse_path(path: str) -> tuple[str, str]:
    """
    "/api/accounts/1001" -> ("/api/accounts/{id}", "1001")
    "/api/admin/users"   -> ("/api/admin/users", "")
    Heuristic: the last path segment is treated as an object id if it looks
    like an identifier (digits, or an alphanumeric token) rather than a fixed
    route word. Good enough for this route set without duplicating the
    gateway's own route table here.
    """
    segments = [s for s in path.split("/") if s]
    if not segments:
        return path, ""
    last = segments[-1]
    if re.fullmatch(r"[A-Za-z0-9_-]+", last) and (last.isdigit() or not last.isalpha()):
        endpoint = "/" + "/".join(segments[:-1] + ["{id}"])
        return endpoint, last
    return path, ""


def stable_hash(value: str, mod: int = 10_000) -> int:
    if not value:
        return 0
    return zlib.crc32(value.encode("utf-8")) % mod


class EntityProfile:
    def __init__(self, subject_id: str):
        self.subject_id = subject_id
        self.first_seen = datetime.now(timezone.utc)
        self.requests: list[dict] = []          # allowed requests only - training data
        self.endpoints_seen: set[str] = set()
        self.objects_by_resource: dict[str, set[str]] = {}
        self.request_times: deque = deque(maxlen=200)
        self.previous_endpoint: Optional[str] = None
        self.transitions: dict[tuple[str, str], int] = {}   # (from, to) -> count

        self.model: Optional[IsolationForest] = None
        self.samples_at_last_train = 0

        self.known_attacker = False   # ever had a hostile block - never let baseline learn from them again

    def record_allowed(self, endpoint: str, object_id: str, resource: str, ts: float):
        self.requests.append({"endpoint": endpoint, "object_id": object_id, "resource": resource, "ts": ts})
        if len(self.requests) > 500:
            self.requests = self.requests[-500:]
        self.endpoints_seen.add(endpoint)
        if resource:
            self.objects_by_resource.setdefault(resource, set())
            if object_id:
                self.objects_by_resource[resource].add(object_id)
        self.request_times.append(ts)

        if self.previous_endpoint is not None and self.previous_endpoint != endpoint:
            key = (self.previous_endpoint, endpoint)
            self.transitions[key] = self.transitions.get(key, 0) + 1
        self.previous_endpoint = endpoint

    def record_hostile(self):
        # a confirmed attacker's request is never folded into the training set -
        # same anti-poisoning rule the rest of this project already follows
        self.known_attacker = True

    def request_rate_last_minute(self, now: float) -> float:
        return sum(1 for t in self.request_times if now - t <= 60)

    def distinct_objects_today(self, now: float) -> int:
        day_start = now - 86400
        objs = set()
        for r in self.requests:
            if r["ts"] >= day_start and r["object_id"]:
                objs.add((r["resource"], r["object_id"]))
        return len(objs)

    def distinct_endpoints_today(self, now: float) -> int:
        day_start = now - 86400
        return len(set(r["endpoint"] for r in self.requests if r["ts"] >= day_start))

    def extract_features(self, endpoint: str, object_id: str, ts: float) -> np.ndarray:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        hour_of_day = dt.hour
        day_of_week = dt.weekday()
        request_rate = self.request_rate_last_minute(ts)
        object_hash = stable_hash(object_id)
        endpoint_hash = stable_hash(endpoint)
        days_since_first = (dt - self.first_seen).total_seconds() / 86400.0
        distinct_objects = self.distinct_objects_today(ts)
        distinct_endpoints = self.distinct_endpoints_today(ts)
        return np.array([[
            hour_of_day, day_of_week, request_rate, object_hash,
            endpoint_hash, days_since_first, distinct_objects, distinct_endpoints
        ]], dtype=float)

    def training_matrix(self) -> np.ndarray:
        rows = []
        for r in self.requests:
            rows.append(self.extract_features(r["endpoint"], r["object_id"], r["ts"])[0])
        return np.array(rows, dtype=float)

    def maybe_retrain(self) -> None:
        n = len(self.requests)
        if n < settings.min_samples_to_score:
            return
        if self.model is not None and (n - self.samples_at_last_train) < settings.retrain_every_n_samples:
            return
        X = self.training_matrix()
        if X.shape[0] < 2:
            return
        model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        model.fit(X)
        self.model = model
        self.samples_at_last_train = n

    def isolation_score(self, endpoint: str, object_id: str, ts: float) -> Optional[float]:
        """returns 0..1 anomaly score (1 = most anomalous), or None if not enough data yet"""
        if self.model is None or len(self.requests) < settings.min_samples_to_score:
            return None
        x = self.extract_features(endpoint, object_id, ts)
        # decision_function: higher = more normal. score_samples is similar.
        # convert to a 0..1 "anomaly-ness" via the sign/margin of decision_function.
        raw = self.model.decision_function(x)[0]
        # decision_function is roughly in [-0.5, 0.5]; negative = anomalous.
        # squash to 0..1 where 1 is most anomalous.
        anomaly = 1.0 / (1.0 + np.exp(raw * 8))
        return float(np.clip(anomaly, 0.0, 1.0))

    def markov_score(self, endpoint: str) -> Optional[float]:
        """negative log probability of transition previous -> endpoint. None if no prior endpoint or no data."""
        if self.previous_endpoint is None or self.previous_endpoint == endpoint:
            return None
        outgoing = {k: v for k, v in self.transitions.items() if k[0] == self.previous_endpoint}
        total = sum(outgoing.values())
        if total == 0:
            return None
        count = outgoing.get((self.previous_endpoint, endpoint), 0)
        prob = count / total if total else 0.0
        if prob == 0.0:
            prob = 1e-6
        return prob

    def to_dict(self) -> dict:
        return {
            "subject_id": self.subject_id,
            "first_seen": self.first_seen.isoformat(),
            "sample_count": len(self.requests),
            "endpoints_seen": len(self.endpoints_seen),
            "resources": {k: len(v) for k, v in self.objects_by_resource.items()},
            "has_model": self.model is not None,
            "known_attacker": self.known_attacker,
        }
