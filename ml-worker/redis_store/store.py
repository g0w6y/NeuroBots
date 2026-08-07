"""Redis client for storing ML risk scores and profiles."""

from __future__ import annotations

import asyncio
from typing import Any

import orjson
import redis
from redis import asyncio as aioredis

from config.settings import RedisConfig
from models.schemas import MLRiskResult, EntityProfile
from utils.logging import get_logger

logger = get_logger("redis_store")


class RedisStore:
    """Async Redis client for writing ML outputs."""

    def __init__(self, config: RedisConfig) -> None:
        self._config = config
        self._pool: aioredis.Redis | None = None

    async def connect(self) -> None:
        """Create the Redis connection pool."""
        self._pool = aioredis.from_url(
            self._config.url,
            max_connections=self._config.max_connections,
            socket_timeout=self._config.socket_timeout,
            socket_connect_timeout=self._config.socket_connect_timeout,
            retry_on_timeout=self._config.retry_on_timeout,
            decode_responses=self._config.decode_responses,
        )
        await self._pool.ping()
        logger.info("Connected to Redis at %s", self._config.url)

    async def disconnect(self) -> None:
        """Close the Redis connection pool."""
        if self._pool:
            await self._pool.aclose()
            self._pool = None
            logger.info("Disconnected from Redis")

    async def write_risk_score(
        self, result: MLRiskResult, ttl_seconds: int = 300
    ) -> None:
        """Write an ML risk score to Redis.

        Key format: ml_risk:{subject_id}
        Value: JSON with score details
        TTL: 300 seconds (5 minutes)
        """
        if not self._pool:
            raise RuntimeError("RedisStore not connected. Call connect() first.")

        key = f"ml_risk:{result.subject_id}"
        data = orjson.dumps({
            "ml_risk": result.ml_risk,
            "anomaly_score": round(result.anomaly_score, 4),
            "sequence_score": round(result.sequence_score, 4),
            "graph_score": round(result.graph_score, 4),
            "timestamp": result.timestamp.isoformat(),
            "details": result.details,
        }).decode("utf-8")

        await self._pool.setex(key, ttl_seconds, data)
        logger.debug("Wrote risk score %d for subject=%s", result.ml_risk, result.subject_id)

    async def read_risk_score(self, subject_id: str) -> dict[str, Any] | None:
        """Read an ML risk score from Redis."""
        if not self._pool:
            raise RuntimeError("RedisStore not connected. Call connect() first.")

        key = f"ml_risk:{subject_id}"
        data = await self._pool.get(key)
        if data is None:
            return None
        return orjson.loads(data)

    async def write_profile(
        self, profile: EntityProfile, ttl_seconds: int = 3600
    ) -> None:
        """Write an entity profile to Redis.

        Key format: profile:{subject_id}
        TTL: 3600 seconds (1 hour)
        """
        if not self._pool:
            raise RuntimeError("RedisStore not connected. Call connect() first.")

        key = f"profile:{profile.subject_id}"
        data = orjson.dumps(profile.to_dict()).decode("utf-8")
        await self._pool.setex(key, ttl_seconds, data)
        logger.debug("Wrote profile for subject=%s", profile.subject_id)

    async def read_profile(self, subject_id: str) -> dict[str, Any] | None:
        """Read an entity profile from Redis."""
        if not self._pool:
            raise RuntimeError("RedisStore not connected. Call connect() first.")

        key = f"profile:{subject_id}"
        data = await self._pool.get(key)
        if data is None:
            return None
        return orjson.loads(data)

    async def health_check(self) -> bool:
        """Check if Redis is reachable."""
        if not self._pool:
            return False
        try:
            await self._pool.ping()
            return True
        except Exception:
            return False
