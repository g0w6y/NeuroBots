"""Risk scoring - combines all ML signals into a single risk score."""

from __future__ import annotations

from config.settings import RiskConfig
from models.schemas import MLRiskResult, GatewayEvent, EntityProfile
from utils.logging import get_logger

logger = get_logger("risk")


class RiskScorer:
    """Combines anomaly, sequence, and graph scores into a unified risk score."""

    def __init__(self, config: RiskConfig) -> None:
        self._config = config

    def compute(
        self,
        event: GatewayEvent,
        profile: EntityProfile,
        anomaly_score: float,
        sequence_score: float,
        graph_score: float,
    ) -> MLRiskResult:
        """Compute the combined ML risk score.

        The risk score is a weighted combination of the three signals,
        scaled to 0-100 as an integer.
        """
        weights = self._config.weights
        ml_risk_float = 100.0 * (
            weights["isolation_forest"] * anomaly_score
            + weights["markov_sequence"] * sequence_score
            + weights["graph_novelty"] * graph_score
        )
        ml_risk = int(min(max(ml_risk_float, 0), 100))

        details = {
            "anomaly_weight": weights["isolation_forest"],
            "sequence_weight": weights["markov_sequence"],
            "graph_weight": weights["graph_novelty"],
            "weighted_anomaly": weights["isolation_forest"] * anomaly_score,
            "weighted_sequence": weights["markov_sequence"] * sequence_score,
            "weighted_graph": weights["graph_novelty"] * graph_score,
            "total_requests": profile.total_requests,
            "allowed_count": profile.allowed_count,
            "blocked_count": profile.blocked_count,
        }

        result = MLRiskResult(
            subject_id=event.subject,
            ml_risk=ml_risk,
            anomaly_score=anomaly_score,
            sequence_score=sequence_score,
            graph_score=graph_score,
            details=details,
        )

        if ml_risk > 70:
            logger.warning(
                "HIGH RISK subject=%s score=%d anomaly=%.3f seq=%.3f graph=%.3f",
                event.subject,
                ml_risk,
                anomaly_score,
                sequence_score,
                graph_score,
            )
        elif ml_risk > 40:
            logger.info(
                "MODERATE RISK subject=%s score=%d",
                event.subject,
                ml_risk,
            )

        return result
