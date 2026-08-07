"""Pydantic models for gateway events and entity profiles."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Decision(str, Enum):
    """Gateway decision on a request."""

    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"


class GatewayEvent(BaseModel):
    """An event emitted by the NeuroBots gateway for each request processed."""

    subject: str = Field(..., description="User identity (sub claim from JWT)")
    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    path: str = Field(..., description="Request path (e.g. /api/accounts/123)")
    endpoint: str = Field(
        ..., description="Matched route pattern (e.g. /api/accounts/{id})"
    )
    resource: str = Field(..., description="Resource type (e.g. account, user)")
    object_id: str = Field(default="", description="Object ID extracted from path")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the request was processed",
    )
    decision: Decision = Field(..., description="Gateway decision: allow/block/challenge")
    risk_score: int = Field(default=0, ge=0, le=100, description="Gateway risk score (0-100)")
    latency_ms: float = Field(default=0.0, ge=0, description="Processing latency in ms")

    @field_validator("method")
    @classmethod
    def uppercase_method(cls, v: str) -> str:
        return v.upper()

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            raise ValueError(f"Cannot parse timestamp: {v}")
        return v

    @property
    def hour_of_day(self) -> int:
        return self.timestamp.hour

    @property
    def day_of_week(self) -> int:
        return self.timestamp.weekday()

    @property
    def is_allowed(self) -> bool:
        return self.decision == Decision.ALLOW


class EntityProfile(BaseModel):
    """Behavioral profile for a single user (subject)."""

    subject_id: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_requests: int = 0
    endpoints_seen: list[str] = Field(default_factory=list)
    objects_by_resource: dict[str, list[str]] = Field(default_factory=dict)
    request_timestamps: list[datetime] = Field(default_factory=list)
    recent_endpoints: list[str] = Field(default_factory=list)
    baseline_rate_per_minute: float = 0.0
    distinct_objects_today: int = 0
    distinct_endpoints_today: int = 0
    attack_count: int = 0
    allowed_count: int = 0
    blocked_count: int = 0
    challenged_count: int = 0
    is_trained: bool = False
    last_retrain: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for Redis storage."""
        return {
            "subject_id": self.subject_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "total_requests": self.total_requests,
            "endpoints_seen": self.endpoints_seen,
            "objects_by_resource": self.objects_by_resource,
            "request_timestamps": [t.isoformat() for t in self.request_timestamps[-100:]],
            "recent_endpoints": self.recent_endpoints[-20:],
            "baseline_rate_per_minute": self.baseline_rate_per_minute,
            "distinct_objects_today": self.distinct_objects_today,
            "distinct_endpoints_today": self.distinct_endpoints_today,
            "attack_count": self.attack_count,
            "allowed_count": self.allowed_count,
            "blocked_count": self.blocked_count,
            "challenged_count": self.challenged_count,
            "is_trained": self.is_trained,
            "last_retrain": self.last_retrain.isoformat() if self.last_retrain else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EntityProfile:
        """Deserialize from dict loaded from Redis."""
        return cls(
            subject_id=data["subject_id"],
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            total_requests=data.get("total_requests", 0),
            endpoints_seen=data.get("endpoints_seen", []),
            objects_by_resource=data.get("objects_by_resource", {}),
            request_timestamps=[
                datetime.fromisoformat(t) for t in data.get("request_timestamps", [])
            ],
            recent_endpoints=data.get("recent_endpoints", []),
            baseline_rate_per_minute=data.get("baseline_rate_per_minute", 0.0),
            distinct_objects_today=data.get("distinct_objects_today", 0),
            distinct_endpoints_today=data.get("distinct_endpoints_today", 0),
            attack_count=data.get("attack_count", 0),
            allowed_count=data.get("allowed_count", 0),
            blocked_count=data.get("blocked_count", 0),
            challenged_count=data.get("challenged_count", 0),
            is_trained=data.get("is_trained", False),
            last_retrain=(
                datetime.fromisoformat(data["last_retrain"])
                if data.get("last_retrain")
                else None
            ),
        )

    @property
    def endpoint_set(self) -> set[str]:
        return set(self.endpoints_seen)

    def get_object_set(self, resource: str) -> set[str]:
        return set(self.objects_by_resource.get(resource, []))


class MLRiskResult(BaseModel):
    """Result of ML risk computation for a user."""

    subject_id: str
    ml_risk: int = Field(ge=0, le=100, description="Combined ML risk score 0-100")
    anomaly_score: float = Field(ge=0.0, le=1.0, description="IsolationForest score")
    sequence_score: float = Field(ge=0.0, le=1.0, description="Markov sequence score")
    graph_score: float = Field(ge=0.0, le=1.0, description="Graph novelty score")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = Field(default_factory=dict)
