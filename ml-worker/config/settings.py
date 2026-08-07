"""Configuration for the NeuroBots ML Worker.

All settings are loaded from environment variables with sensible defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RedisConfig:
    """Redis connection configuration."""

    url: str = "redis://127.0.0.1:6379"
    max_connections: int = 20
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0
    retry_on_timeout: bool = True
    decode_responses: bool = True


@dataclass(frozen=True)
class GatewayConfig:
    """Gateway polling configuration."""

    alerts_url: str = "http://127.0.0.1:8081/admin/alerts"
    poll_interval_seconds: float = 2.0
    request_timeout: float = 10.0
    max_retries: int = 3
    retry_backoff: float = 1.0


@dataclass(frozen=True)
class IsolationForestConfig:
    """IsolationForest anomaly detection configuration."""

    threshold: float = 0.7
    n_estimators: int = 100
    contamination: float = 0.1
    max_samples: str | int = "auto"
    retrain_interval_minutes: float = 60.0
    min_samples_for_training: int = 30
    random_state: int = 42


@dataclass(frozen=True)
class MarkovConfig:
    """Markov chain sequence analysis configuration."""

    probability_threshold: float = 0.1
    max_order: int = 1
    smoothing: float = 1e-6


@dataclass(frozen=True)
class GraphConfig:
    """NetworkX graph analysis configuration."""

    max_graph_age_days: int = 30
    fan_out_threshold_multiplier: float = 3.0
    fan_in_high_threshold: int = 100


@dataclass(frozen=True)
class RiskConfig:
    """Risk scoring configuration."""

    weights: dict[str, float] = field(default_factory=lambda: {
        "isolation_forest": 0.4,
        "markov_sequence": 0.3,
        "graph_novelty": 0.3,
    })
    score_ttl_seconds: int = 300
    profile_ttl_seconds: int = 3600

    def __post_init__(self) -> None:
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Risk weights must sum to 1.0, got {total}")


@dataclass(frozen=True)
class LoggingConfig:
    """Logging configuration."""

    level: str = "INFO"
    format: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    date_format: str = "%Y-%m-%d %H:%M:%S"
    log_dir: str = "logs"


@dataclass(frozen=True)
class AppConfig:
    """Main application configuration."""

    redis: RedisConfig = field(default_factory=RedisConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    isolation_forest: IsolationForestConfig = field(default_factory=IsolationForestConfig)
    markov: MarkovConfig = field(default_factory=MarkovConfig)
    graph: GraphConfig = field(default_factory=GraphConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config() -> AppConfig:
    """Load configuration from environment variables with defaults."""
    return AppConfig(
        redis=RedisConfig(
            url=os.getenv("REDIS_URL", "redis://127.0.0.1:6379"),
            max_connections=int(os.getenv("REDIS_MAX_CONNECTIONS", "20")),
        ),
        gateway=GatewayConfig(
            alerts_url=os.getenv(
                "GATEWAY_ALERTS_URL", "http://127.0.0.1:8081/admin/alerts"
            ),
            poll_interval_seconds=float(os.getenv("POLL_INTERVAL_SECONDS", "2")),
            request_timeout=float(os.getenv("GATEWAY_REQUEST_TIMEOUT", "10")),
        ),
        isolation_forest=IsolationForestConfig(
            threshold=float(os.getenv("ISOLATION_FOREST_THRESHOLD", "0.7")),
            n_estimators=int(os.getenv("ISOLATION_FOREST_N_ESTIMATORS", "100")),
            contamination=float(os.getenv("ISOLATION_FOREST_CONTAMINATION", "0.1")),
            retrain_interval_minutes=float(
                os.getenv("ISOLATION_FOREST_RETRAIN_MINUTES", "60")
            ),
            min_samples_for_training=int(
                os.getenv("ISOLATION_FOREST_MIN_SAMPLES", "30")
            ),
        ),
        markov=MarkovConfig(
            probability_threshold=float(
                os.getenv("MARKOV_PROBABILITY_THRESHOLD", "0.1")
            ),
        ),
        graph=GraphConfig(),
        risk=RiskConfig(
            score_ttl_seconds=int(os.getenv("ML_RISK_TTL_SECONDS", "300")),
            profile_ttl_seconds=int(os.getenv("ML_PROFILE_TTL_SECONDS", "3600")),
        ),
        logging=LoggingConfig(
            level=os.getenv("LOG_LEVEL", "INFO"),
        ),
    )
