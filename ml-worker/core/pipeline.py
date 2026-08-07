"""Core ML processing pipeline that orchestrates all components."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from config.settings import AppConfig
from models.schemas import GatewayEvent, Decision
from profiling.manager import ProfileManager
from features.extractor import extract_features
from anomaly.isolation_forest import AnomalyDetector
from markov.analyzer import MarkovAnalyzer
from graph.analyzer import GraphAnalyzer
from risk.scorer import RiskScorer
from redis_store.store import RedisStore
from core.feedback import FeedbackProcessor
from utils.logging import get_logger

logger = get_logger("pipeline")


class MLPipeline:
    """Orchestrates the full ML processing pipeline for each event."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._profiles = ProfileManager()
        self._anomaly = AnomalyDetector(config.isolation_forest)
        self._markov = MarkovAnalyzer(config.markov)
        self._graph = GraphAnalyzer(config.graph)
        self._risk = RiskScorer(config.risk)
        self._redis = RedisStore(config.redis)
        self._feedback = FeedbackProcessor(
            self._profiles, self._anomaly, self._markov, self._graph
        )
        self._events_processed = 0
        self._risk_scores_written = 0

    async def start(self) -> None:
        """Connect to Redis and prepare the pipeline."""
        await self._redis.connect()
        logger.info("ML Pipeline started")

    async def stop(self) -> None:
        """Disconnect from Redis."""
        await self._redis.disconnect()
        logger.info("ML Pipeline stopped")

    async def process_event(self, event: GatewayEvent) -> None:
        """Process a single gateway event through the full pipeline.

        Steps:
        1. Feedback learning (update baselines from allowed requests)
        2. Feature extraction
        3. Anomaly scoring
        4. Sequence scoring
        5. Graph novelty scoring
        6. Combined risk scoring
        7. Write results to Redis
        8. Check for retraining needs
        """
        self._events_processed += 1

        self._feedback.process_event(event)

        profile = self._profiles.get_or_create(event.subject)
        features = extract_features(profile, event)

        anomaly_score = self._anomaly.score(event.subject, features)
        sequence_score = self._markov.score_event(event, profile)
        graph_score = self._graph.compute_novelty(event, profile)

        risk_result = self._risk.compute(
            event, profile, anomaly_score, sequence_score, graph_score
        )

        try:
            await self._redis.write_risk_score(
                risk_result, self._config.risk.score_ttl_seconds
            )
            await self._redis.write_profile(profile, self._config.risk.profile_ttl_seconds)
            self._risk_scores_written += 1
        except Exception as e:
            logger.error("Failed to write to Redis: %s", e)

        if self._feedback.should_retrain(
            event.subject, self._config.isolation_forest.retrain_interval_minutes
        ):
            await self._feedback.retrain_models(event.subject)

        if self._events_processed % 100 == 0:
            logger.info(
                "Pipeline stats: events=%d scores_written=%d profiles=%d models=%d",
                self._events_processed,
                self._risk_scores_written,
                self._profiles.profile_count,
                self._anomaly.model_count,
            )

    async def process_batch(self, events: list[GatewayEvent]) -> None:
        """Process a batch of events."""
        for event in events:
            await self.process_event(event)

    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        return {
            "events_processed": self._events_processed,
            "risk_scores_written": self._risk_scores_written,
            "profiles_tracked": self._profiles.profile_count,
            "anomaly_models": self._anomaly.model_count,
            "markov_chains": self._markov.chain_count,
            "graph_stats": self._graph.stats,
        }
