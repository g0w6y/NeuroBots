"""IsolationForest-based anomaly detection for API request patterns."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config.settings import IsolationForestConfig
from models.schemas import EntityProfile, GatewayEvent
from features.extractor import extract_features, extract_feature_matrix, normalize_features, normalize_with_stats
from utils.logging import get_logger

logger = get_logger("anomaly")


class AnomalyDetector:
    """Per-entity IsolationForest anomaly detector."""

    def __init__(self, config: IsolationForestConfig) -> None:
        self._config = config
        self._models: dict[str, IsolationForest] = {}
        self._scalers: dict[str, StandardScaler] = {}
        self._training_data: dict[str, list[np.ndarray]] = {}
        self._lock = asyncio.Lock()

    def add_training_sample(self, subject_id: str, features: np.ndarray) -> None:
        """Add a training sample for a subject."""
        if subject_id not in self._training_data:
            self._training_data[subject_id] = []
        self._training_data[subject_id].append(features)

    def needs_training(self, subject_id: str) -> bool:
        """Check if we have enough samples to train."""
        data = self._training_data.get(subject_id, [])
        return len(data) >= self._config.min_samples_for_training

    async def train(self, subject_id: str) -> bool:
        """Train (or retrain) the IsolationForest model for a subject."""
        async with self._lock:
            data = self._training_data.get(subject_id, [])
            if len(data) < self._config.min_samples_for_training:
                return False

            X = np.vstack(data)
            means = np.mean(X, axis=0)
            stds = np.std(X, axis=0)
            stds[stds == 0] = 1.0
            X_normalized = (X - means) / stds

            model = IsolationForest(
                n_estimators=self._config.n_estimators,
                contamination=self._config.contamination,
                max_samples=self._config.max_samples,
                random_state=self._config.random_state,
            )
            model.fit(X_normalized)

            self._models[subject_id] = model
            scaler = StandardScaler()
            scaler.fit(X_normalized)
            self._scalers[subject_id] = scaler

            logger.info(
                "Trained IsolationForest for subject=%s with %d samples",
                subject_id,
                len(data),
            )
            return True

    def score(self, subject_id: str, features: np.ndarray) -> float:
        """Score a single feature vector. Returns anomaly score 0-1 (1 = most anomalous)."""
        model = self._models.get(subject_id)
        if model is None:
            return 0.0

        means = np.mean(self._training_data.get(subject_id, [features]), axis=0)
        stds = np.std(self._training_data.get(subject_id, [features]), axis=0)
        stds[stds == 0] = 1.0
        features_normalized = (features - means) / stds

        raw_score = model.decision_function(features_normalized.reshape(1, -1))[0]
        anomaly_score = 1.0 / (1.0 + np.exp(raw_score))
        return float(np.clip(anomaly_score, 0.0, 1.0))

    def is_anomalous(self, subject_id: str, features: np.ndarray) -> tuple[bool, float]:
        """Check if a request is anomalous. Returns (is_anomaly, score)."""
        score = self.score(subject_id, features)
        return score > self._config.threshold, score

    def get_model_info(self, subject_id: str) -> dict:
        """Return info about a subject's model."""
        model = self._models.get(subject_id)
        training_count = len(self._training_data.get(subject_id, []))
        return {
            "trained": model is not None,
            "training_samples": training_count,
            "n_estimators": self._config.n_estimators if model else 0,
        }

    @property
    def model_count(self) -> int:
        return len(self._models)

    def prune_training_data(self, max_per_subject: int = 500) -> None:
        """Keep training data from growing unbounded."""
        for subject_id in list(self._training_data.keys()):
            data = self._training_data[subject_id]
            if len(data) > max_per_subject:
                self._training_data[subject_id] = data[-max_per_subject:]
