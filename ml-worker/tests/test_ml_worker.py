"""Tests for the ML Worker."""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.schemas import GatewayEvent, EntityProfile, Decision, MLRiskResult
from config.settings import load_config, AppConfig, RiskConfig
from features.extractor import extract_features, extract_feature_matrix, normalize_features
from profiling.manager import ProfileManager
from anomaly.isolation_forest import AnomalyDetector
from markov.analyzer import MarkovAnalyzer, MarkovChain
from graph.analyzer import GraphAnalyzer, AccessGraph
from risk.scorer import RiskScorer
from core.feedback import FeedbackProcessor
from core.pipeline import MLPipeline
from utils.helpers import utcnow, stable_hash, hash_to_range, minutes_between


def make_event(
    subject: str = "user1",
    endpoint: str = "/api/accounts/{id}",
    resource: str = "account",
    object_id: str = "1001",
    decision: Decision = Decision.ALLOW,
    method: str = "GET",
    path: str = "/api/accounts/1001",
) -> GatewayEvent:
    return GatewayEvent(
        subject=subject,
        method=method,
        path=path,
        endpoint=endpoint,
        resource=resource,
        object_id=object_id,
        timestamp=datetime.now(timezone.utc),
        decision=decision,
    )


class TestModels:
    def test_gateway_event_creation(self):
        event = make_event()
        assert event.subject == "user1"
        assert event.decision == Decision.ALLOW
        assert event.hour_of_day == datetime.now(timezone.utc).hour
        assert event.is_allowed is True

    def test_gateway_event_block(self):
        event = make_event(decision=Decision.BLOCK)
        assert event.is_allowed is False

    def test_entity_profile_defaults(self):
        profile = EntityProfile(subject_id="user1")
        assert profile.total_requests == 0
        assert profile.endpoints_seen == []
        assert profile.attack_count == 0

    def test_entity_profile_serialization(self):
        profile = EntityProfile(subject_id="user1")
        d = profile.to_dict()
        restored = EntityProfile.from_dict(d)
        assert restored.subject_id == "user1"
        assert restored.total_requests == 0

    def test_ml_risk_result(self):
        result = MLRiskResult(
            subject_id="user1",
            ml_risk=75,
            anomaly_score=0.8,
            sequence_score=0.6,
            graph_score=0.5,
        )
        assert result.ml_risk == 75


class TestConfig:
    def test_default_config(self):
        config = load_config()
        assert config.redis.url == "redis://127.0.0.1:6379"
        assert config.gateway.poll_interval_seconds == 2.0
        assert config.isolation_forest.threshold == 0.7
        assert config.markov.probability_threshold == 0.1
        assert config.risk.score_ttl_seconds == 300

    def test_risk_weights_sum_to_one(self):
        config = RiskConfig()
        assert abs(sum(config.weights.values()) - 1.0) < 1e-6


class TestFeatures:
    def test_extract_features(self):
        profile = EntityProfile(subject_id="user1")
        event = make_event()
        features = extract_features(profile, event)
        assert features.shape == (8,)
        assert features[0] == float(event.timestamp.hour)
        assert features[1] == float(event.timestamp.weekday())

    def test_extract_feature_matrix(self):
        profile = EntityProfile(subject_id="user1")
        events = [make_event() for _ in range(5)]
        matrix = extract_feature_matrix(profile, events)
        assert matrix is not None
        assert matrix.shape == (5, 8)

    def test_extract_feature_matrix_empty(self):
        profile = EntityProfile(subject_id="user1")
        matrix = extract_feature_matrix(profile, [])
        assert matrix is None

    def test_normalize_features(self):
        X = np.array([[1, 2], [3, 4], [5, 6]], dtype=np.float64)
        normalized, means, stds = normalize_features(X)
        assert abs(np.mean(normalized, axis=0).sum()) < 1e-10


class TestProfiling:
    def test_create_profile(self):
        pm = ProfileManager()
        profile = pm.get_or_create("user1")
        assert profile.subject_id == "user1"
        assert pm.profile_count == 1

    def test_update_from_event(self):
        pm = ProfileManager()
        event = make_event()
        profile = pm.update_from_event(event)
        assert profile.total_requests == 1
        assert event.endpoint in profile.endpoints_seen
        assert profile.allowed_count == 1

    def test_update_blocked_event(self):
        pm = ProfileManager()
        event = make_event(decision=Decision.BLOCK)
        profile = pm.update_from_event(event)
        assert profile.blocked_count == 1
        assert profile.attack_count == 1

    def test_rate_computation(self):
        pm = ProfileManager()
        now = utcnow()
        for i in range(10):
            event = make_event()
            event.timestamp = now - timedelta(minutes=9 - i)
            pm.update_from_event(event)
        profile = pm.get_profile("user1")
        assert profile.baseline_rate_per_minute > 0


class TestAnomalyDetection:
    def test_untrained_returns_zero(self):
        config = AppConfig()
        detector = AnomalyDetector(config.isolation_forest)
        features = np.zeros(8)
        score = detector.score("user1", features)
        assert score == 0.0

    def test_add_samples_and_train(self):
        config = AppConfig()
        detector = AnomalyDetector(config.isolation_forest)
        for _ in range(35):
            features = np.random.randn(8)
            detector.add_training_sample("user1", features)
        assert detector.needs_training("user1")

    @pytest.mark.asyncio
    async def test_train_and_score(self):
        config = AppConfig()
        detector = AnomalyDetector(config.isolation_forest)
        for _ in range(35):
            features = np.random.randn(8)
            detector.add_training_sample("user1", features)
        success = await detector.train("user1")
        assert success
        features = np.random.randn(8)
        score = detector.score("user1", features)
        assert 0.0 <= score <= 1.0


class TestMarkovChain:
    def test_add_transition(self):
        chain = MarkovChain("user1")
        chain.add_transition("/login", "/dashboard")
        chain.add_transition("/login", "/dashboard")
        assert chain.total_transitions["/login"] == 2

    def test_transition_probability(self):
        chain = MarkovChain("user1")
        chain.add_transition("/login", "/dashboard")
        chain.add_transition("/login", "/dashboard")
        prob = chain.transition_probability("/login", "/dashboard")
        assert prob > 0.9

    def test_unseen_transition(self):
        chain = MarkovChain("user1")
        chain.add_transition("/login", "/dashboard")
        prob = chain.transition_probability("/login", "/admin")
        assert prob < 0.1

    def test_analyzer_score(self):
        config = AppConfig()
        analyzer = MarkovAnalyzer(config.markov)
        profile = EntityProfile(subject_id="user1", recent_endpoints=["/login", "/dashboard"])
        event = make_event(endpoint="/admin/users")
        score = analyzer.score_event(event, profile)
        assert 0.0 <= score <= 1.0


class TestGraphAnalysis:
    def test_add_access(self):
        config = AppConfig()
        graph = AccessGraph(config.graph)
        graph.add_access("user1", "1001", "account")
        assert graph.user_fan_out("user1") == 1
        assert graph.object_fan_in("account", "1001") == 1

    def test_is_new_resource(self):
        config = AppConfig()
        graph = AccessGraph(config.graph)
        graph.add_access("user1", "1001", "account")
        assert graph.is_new_resource("user1", "account") is False
        assert graph.is_new_resource("user1", "admin") is True

    def test_novelty_score(self):
        config = AppConfig()
        analyzer = GraphAnalyzer(config.graph)
        profile = EntityProfile(subject_id="user1")
        event = make_event(resource="new_resource", object_id="9999")
        score = analyzer.compute_novelty(event, profile)
        assert 0.0 <= score <= 1.0

    def test_stats(self):
        config = AppConfig()
        analyzer = GraphAnalyzer(config.graph)
        event = make_event()
        analyzer.update_from_event(event)
        stats = analyzer.stats
        assert stats["user_count"] >= 1


class TestRiskScoring:
    def test_compute_risk(self):
        config = AppConfig()
        scorer = RiskScorer(config.risk)
        event = make_event()
        profile = EntityProfile(subject_id="user1")
        result = scorer.compute(event, profile, 0.8, 0.6, 0.5)
        assert 0 <= result.ml_risk <= 100
        assert result.anomaly_score == 0.8

    def test_zero_scores(self):
        config = AppConfig()
        scorer = RiskScorer(config.risk)
        event = make_event()
        profile = EntityProfile(subject_id="user1")
        result = scorer.compute(event, profile, 0.0, 0.0, 0.0)
        assert result.ml_risk == 0

    def test_max_scores(self):
        config = AppConfig()
        scorer = RiskScorer(config.risk)
        event = make_event()
        profile = EntityProfile(subject_id="user1")
        result = scorer.compute(event, profile, 1.0, 1.0, 1.0)
        assert result.ml_risk == 100


class TestHelpers:
    def test_stable_hash(self):
        h1 = stable_hash("test")
        h2 = stable_hash("test")
        assert h1 == h2
        assert h1 != stable_hash("other")

    def test_hash_to_range(self):
        h = hash_to_range("test", 0, 100)
        assert 0 <= h <= 100

    def test_minutes_between(self):
        now = utcnow()
        earlier = now - timedelta(minutes=5)
        diff = minutes_between(now, earlier)
        assert abs(diff - 5.0) < 0.01


class TestFeedback:
    def test_process_allowed_event(self):
        config = AppConfig()
        pm = ProfileManager()
        detector = AnomalyDetector(config.isolation_forest)
        markov = MarkovAnalyzer(config.markov)
        graph = GraphAnalyzer(config.graph)
        feedback = FeedbackProcessor(pm, detector, markov, graph)

        event = make_event()
        feedback.process_event(event)

        profile = pm.get_profile("user1")
        assert profile is not None
        assert profile.total_requests == 1

    def test_process_blocked_event_no_learning(self):
        config = AppConfig()
        pm = ProfileManager()
        detector = AnomalyDetector(config.isolation_forest)
        markov = MarkovAnalyzer(config.markov)
        graph = GraphAnalyzer(config.graph)
        feedback = FeedbackProcessor(pm, detector, markov, graph)

        event = make_event(decision=Decision.BLOCK)
        feedback.process_event(event)

        profile = pm.get_profile("user1")
        assert profile.blocked_count == 1
        assert detector.needs_training("user1") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
