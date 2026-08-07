"""Helper utilities."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def stable_hash(value: str) -> int:
    """Produce a stable integer hash for a string (used for feature encoding)."""
    h = hashlib.md5(value.encode("utf-8")).hexdigest()
    return int(h[:8], 16)


def hash_to_range(value: str, min_val: int = 0, max_val: int = 1000) -> int:
    """Map a string to an integer in [min_val, max_val] using stable hashing."""
    h = stable_hash(value)
    return min_val + (h % (max_val - min_val + 1))


def minutes_between(a: datetime, b: datetime) -> float:
    """Return the absolute difference in minutes between two datetimes."""
    return abs((b - a).total_seconds()) / 60.0
