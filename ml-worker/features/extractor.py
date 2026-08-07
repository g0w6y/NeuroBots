"""Feature extraction for ML models from entity profiles and events."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import numpy as np

from models.schemas import EntityProfile, GatewayEvent
from utils.helpers import hash_to_range, utcnow

FEATURE_DIMENSION = 8


def extract_features(profile: EntityProfile, event: GatewayEvent) -> np.ndarray:
    """Extract a fixed-size feature vector from a profile and event.

    Features (8 dimensions):
        0: hour_of_day (0-23)
        1: day_of_week (0-6)
        2: request_rate (smoothed requests per minute)
        3: object_id_hash (hashed to 0-1000 range)
        4: endpoint_hash (hashed to 0-1000 range)
        5: days_since_first_request
        6: distinct_objects_today
        7: distinct_endpoints_today
    """
    now = utcnow()
    days_since_first = (now - profile.first_seen).total_seconds() / 86400.0

    return np.array([
        float(event.timestamp.hour),
        float(event.timestamp.weekday()),
        profile.baseline_rate_per_minute,
        float(hash_to_range(event.object_id or "none", 0, 1000)),
        float(hash_to_range(event.endpoint, 0, 1000)),
        days_since_first,
        float(profile.distinct_objects_today),
        float(profile.distinct_endpoints_today),
    ], dtype=np.float64)


def extract_feature_matrix(
    profile: EntityProfile, events: list[GatewayEvent]
) -> np.ndarray | None:
    """Extract a feature matrix for training from a list of historical events."""
    if not events:
        return None

    rows = []
    for event in events:
        row = extract_features(profile, event)
        rows.append(row)

    return np.vstack(rows)


def normalize_features(X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Normalize features to zero mean and unit variance.

    Returns (normalized, means, stds) so we can reuse the same stats later.
    """
    means = np.mean(X, axis=0)
    stds = np.std(X, axis=0)
    stds[stds == 0] = 1.0  # avoid division by zero
    normalized = (X - means) / stds
    return normalized, means, stds


def normalize_with_stats(
    X: np.ndarray, means: np.ndarray, stds: np.ndarray
) -> np.ndarray:
    """Normalize features using precomputed statistics."""
    stds_safe = stds.copy()
    stds_safe[stds_safe == 0] = 1.0
    return (X - means) / stds_safe
