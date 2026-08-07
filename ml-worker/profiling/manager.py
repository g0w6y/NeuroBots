"""Entity profiling - builds and maintains behavioral baselines per user."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone, timedelta

from models.schemas import EntityProfile, GatewayEvent, Decision
from utils.logging import get_logger
from utils.helpers import utcnow, minutes_between

logger = get_logger("profiling")

MAX_TIMESTAMPS = 100
MAX_RECENT_ENDPOINTS = 20


class ProfileManager:
    """Manages in-memory entity profiles for all users."""

    def __init__(self) -> None:
        self._profiles: dict[str, EntityProfile] = {}

    def get_or_create(self, subject_id: str) -> EntityProfile:
        """Get existing profile or create a new one."""
        if subject_id not in self._profiles:
            self._profiles[subject_id] = EntityProfile(subject_id=subject_id)
            logger.debug("Created new profile for subject=%s", subject_id)
        return self._profiles[subject_id]

    def get_all_subjects(self) -> list[str]:
        """Return all tracked subject IDs."""
        return list(self._profiles.keys())

    def get_profile(self, subject_id: str) -> EntityProfile | None:
        """Return profile if it exists, else None."""
        return self._profiles.get(subject_id)

    def update_from_event(self, event: GatewayEvent) -> EntityProfile:
        """Update the profile for a subject based on a gateway event."""
        profile = self.get_or_create(event.subject)
        now = utcnow()

        profile.last_seen = now
        profile.total_requests += 1

        if event.endpoint not in profile.endpoints_seen:
            profile.endpoints_seen.append(event.endpoint)

        if event.endpoint not in profile.recent_endpoints:
            profile.recent_endpoints.append(event.endpoint)
        else:
            profile.recent_endpoints.remove(event.endpoint)
            profile.recent_endpoints.append(event.endpoint)
        profile.recent_endpoints = profile.recent_endpoints[-MAX_RECENT_ENDPOINTS:]

        if event.resource and event.object_id:
            if event.resource not in profile.objects_by_resource:
                profile.objects_by_resource[event.resource] = []
            if event.object_id not in profile.objects_by_resource[event.resource]:
                profile.objects_by_resource[event.resource].append(event.object_id)

        profile.request_timestamps.append(event.timestamp)
        if len(profile.request_timestamps) > MAX_TIMESTAMPS:
            profile.request_timestamps = profile.request_timestamps[-MAX_TIMESTAMPS:]

        if event.decision == Decision.ALLOW:
            profile.allowed_count += 1
        elif event.decision == Decision.BLOCK:
            profile.blocked_count += 1
            profile.attack_count += 1
        elif event.decision == Decision.CHALLENGE:
            profile.challenged_count += 1

        profile.baseline_rate_per_minute = self._compute_rate(profile)
        profile.distinct_objects_today = self._count_distinct_objects_today(profile, now)
        profile.distinct_endpoints_today = self._count_distinct_endpoints_today(profile, now)

        return profile

    def should_retrain(self, profile: EntityProfile, retrain_interval_minutes: float) -> bool:
        """Check if the model should be retrained."""
        if not profile.is_trained:
            return profile.total_requests >= 30
        if profile.last_retrain is None:
            return True
        elapsed = minutes_between(profile.last_retrain, utcnow())
        return elapsed >= retrain_interval_minutes

    def _compute_rate(self, profile: EntityProfile) -> float:
        """Compute requests per minute over the last hour."""
        if len(profile.request_timestamps) < 2:
            return 0.0
        now = utcnow()
        one_hour_ago = now - timedelta(hours=1)
        recent = [t for t in profile.request_timestamps if t >= one_hour_ago]
        if len(recent) < 2:
            return 0.0
        span_minutes = minutes_between(recent[0], recent[-1])
        if span_minutes < 0.1:
            return len(recent) * 60.0
        return len(recent) / span_minutes

    def _count_distinct_objects_today(self, profile: EntityProfile, now: datetime) -> int:
        """Count distinct objects accessed today."""
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        objects_today: set[str] = set()
        for resource, objects in profile.objects_by_resource.items():
            objects_today.update(objects)
        return len(objects_today)

    def _count_distinct_endpoints_today(self, profile: EntityProfile, now: datetime) -> int:
        """Count distinct endpoints accessed (simplified: all known endpoints)."""
        return len(profile.endpoints_seen)

    @property
    def profile_count(self) -> int:
        return len(self._profiles)
