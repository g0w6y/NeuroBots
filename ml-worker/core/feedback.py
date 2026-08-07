"""Feedback learning - learns from gateway decisions, never from attacks."""

from __future__ import annotations

from models.schemas import GatewayEvent, Decision
from profiling.manager import ProfileManager
from anomaly.isolation_forest import AnomalyDetector
from markov.analyzer import MarkovAnalyzer
from graph.analyzer import GraphAnalyzer
from features.extractor import extract_features
from utils.logging import get_logger

logger = get_logger("feedback")


class FeedbackProcessor:
    """Processes gateway decisions to update ML models.

    Only allowed requests are used for learning.
    Blocked requests are tracked but never added to baselines.
    """

    def __init__(
        self,
        profile_manager: ProfileManager,
        anomaly_detector: AnomalyDetector,
        markov_analyzer: MarkovAnalyzer,
        graph_analyzer: GraphAnalyzer,
    ) -> None:
        self._profiles = profile_manager
        self._anomaly = anomaly_detector
        self._markov = markov_analyzer
        self._graph = graph_analyzer

    def process_event(self, event: GatewayEvent) -> None:
        """Process a single event for feedback learning.

        - Allowed requests: update all models (profiling, anomaly, markov, graph)
        - Blocked requests: only update profile stats, do NOT train models
        - Challenge requests: update profiling stats only
        """
        profile = self._profiles.update_from_event(event)

        features = extract_features(profile, event)

        if event.is_allowed:
            self._anomaly.add_training_sample(event.subject, features)
            self._markov.update_from_event(event, profile)
            self._graph.update_from_event(event)
            logger.debug(
                "Learning from ALLOWED request: subject=%s endpoint=%s",
                event.subject,
                event.endpoint,
            )
        elif event.decision == Decision.BLOCK:
            logger.info(
                "Blocked request (not learning): subject=%s endpoint=%s path=%s",
                event.subject,
                event.endpoint,
                event.path,
            )
        else:
            logger.debug(
                "Challenge request (stats only): subject=%s endpoint=%s",
                event.subject,
                event.endpoint,
            )

    def should_retrain(self, subject_id: str, retrain_interval_minutes: float) -> bool:
        """Check if a subject's models need retraining."""
        profile = self._profiles.get_profile(subject_id)
        if profile is None:
            return False
        return self._profiles.should_retrain(profile, retrain_interval_minutes)

    async def retrain_models(self, subject_id: str) -> dict[str, bool]:
        """Retrain all models for a subject."""
        results = {}

        profile = self._profiles.get_profile(subject_id)
        if profile is None:
            return {"anomaly": False, "markov": False, "graph": False}

        if self._anomaly.needs_training(subject_id):
            results["anomaly"] = await self._anomaly.train(subject_id)
            if results["anomaly"]:
                profile.is_trained = True
                from utils.helpers import utcnow
                profile.last_retrain = utcnow()
                logger.info("Retrained anomaly model for subject=%s", subject_id)
        else:
            results["anomaly"] = False

        results["markov"] = True
        results["graph"] = True

        return results
