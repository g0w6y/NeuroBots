"""
Real unit tests for ml/ - the ML worker actually wired into the gateway
(store.py's get_ml_risk() reads what this writes; main.py fuses it as the
ml_anomaly soft signal). Written during the ml/ vs ml-worker/ consolidation:
ml-worker/ had a genuine 34-test pytest suite ml/ lacked, but it tested a
parallel implementation that was never wired in and wrote an incompatible
Redis value format (JSON where the gateway's get_ml_risk() does int(val)).
These tests exercise the actual module this repo runs, not a superseded one.

Run:
    cd ml && python3 -m pytest tests/ -v
"""

import sys
import time
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from profiling import EntityProfile, parse_path
from graph import AccessGraph
from risk import compute_ml_risk, sequence_anomaly
from worker import MLWorker, infer_resource
from config import settings


# ------------------------------------------------------------------ parse_path

class TestParsePath:
    def test_numeric_object_id(self):
        endpoint, obj = parse_path("/api/accounts/1001")
        assert endpoint == "/api/accounts/{id}"
        assert obj == "1001"

    def test_fixed_route_no_object_id(self):
        endpoint, obj = parse_path("/api/admin/users")
        assert endpoint == "/api/admin/users"
        assert obj == ""

    def test_empty_path(self):
        endpoint, obj = parse_path("")
        assert obj == ""


class TestInferResource:
    def test_account(self):
        assert infer_resource("/api/accounts/1001") == "account"

    def test_transfer(self):
        assert infer_resource("/api/transfers") == "transfer"

    def test_admin(self):
        assert infer_resource("/api/admin/users") == "admin"

    def test_other(self):
        assert infer_resource("/api/whatever") == "other"


# --------------------------------------------------------------- EntityProfile

class TestEntityProfile:
    def test_starts_empty(self):
        p = EntityProfile("alice")
        assert p.requests == []
        assert p.known_attacker is False
        assert p.model is None

    def test_record_allowed_accumulates(self):
        p = EntityProfile("alice")
        p.record_allowed("/api/accounts/{id}", "1001", "account", time.time())
        assert len(p.requests) == 1
        assert "/api/accounts/{id}" in p.endpoints_seen
        assert "1001" in p.objects_by_resource["account"]

    def test_record_hostile_marks_attacker_and_never_trains(self):
        """The anti-poisoning guarantee (ML.md Part 7): once an entity has a
        confirmed hostile block, its later allowed traffic must never be
        folded into training data - the worker enforces this in process_alert,
        not in EntityProfile itself, so this test exercises that boundary via
        MLWorker, not the profile in isolation. See TestAntiPoisoning below."""
        p = EntityProfile("mallory")
        p.record_hostile()
        assert p.known_attacker is True

    def test_transitions_recorded_between_distinct_endpoints(self):
        p = EntityProfile("alice")
        now = time.time()
        p.record_allowed("/api/accounts/{id}", "1001", "account", now)
        p.record_allowed("/api/transfers", "", "transfer", now + 1)
        assert p.transitions[("/api/accounts/{id}", "/api/transfers")] == 1

    def test_no_transition_recorded_for_same_endpoint(self):
        p = EntityProfile("alice")
        now = time.time()
        p.record_allowed("/api/accounts/{id}", "1001", "account", now)
        p.record_allowed("/api/accounts/{id}", "1001", "account", now + 1)
        assert p.transitions == {}

    def test_isolation_score_none_below_min_samples(self):
        p = EntityProfile("alice")
        now = time.time()
        for i in range(settings.min_samples_to_score - 1):
            p.record_allowed("/api/accounts/{id}", "1001", "account", now + i)
            p.maybe_retrain()
        assert p.isolation_score("/api/accounts/{id}", "1001", now) is None

    def test_isolation_score_bounded_once_trained(self):
        p = EntityProfile("alice")
        now = time.time()
        for i in range(settings.min_samples_to_score + 5):
            p.record_allowed("/api/accounts/{id}", "1001", "account", now + i)
            p.maybe_retrain()
        assert p.model is not None
        score = p.isolation_score("/api/accounts/{id}", "1001", now)
        assert score is not None
        assert 0.0 <= score <= 1.0

    def test_markov_score_none_without_prior_endpoint(self):
        p = EntityProfile("alice")
        assert p.markov_score("/api/accounts/{id}") is None

    def test_markov_score_reflects_real_transition_frequency(self):
        p = EntityProfile("alice")
        now = time.time()
        # every visit to accounts is followed by transactions - a consistent
        # pattern. Build 4 full round trips, then stop on "accounts" so
        # previous_endpoint is "accounts" when we ask about the next hop -
        # markov_score returns None if you ask about the endpoint you're
        # already sitting on (no transition would be occurring).
        for i in range(4):
            p.record_allowed("/api/accounts/{id}", "1001", "account", now + i * 2)
            p.record_allowed("/api/accounts/{id}/transactions", "1001", "account", now + i * 2 + 1)
        p.record_allowed("/api/accounts/{id}", "1001", "account", now + 10)
        score = p.markov_score("/api/accounts/{id}/transactions")
        assert score > 0.9  # this transition happened every time - high probability

    def test_500_request_cap(self):
        p = EntityProfile("alice")
        now = time.time()
        for i in range(510):
            p.record_allowed("/api/accounts/{id}", "1001", "account", now + i)
        assert len(p.requests) == 500


# -------------------------------------------------------------------- AccessGraph

class TestAccessGraph:
    def test_first_touch_is_novel(self):
        g = AccessGraph()
        assert g.novelty_score("alice", "account", "1001", time.time()) > 0

    def test_repeat_touch_is_not_novel(self):
        g = AccessGraph()
        now = time.time()
        g.record_edge("alice", "account", "1001", now)
        assert g.novelty_score("alice", "account", "1001", now) == 0.0

    def test_no_object_id_is_never_novel(self):
        g = AccessGraph()
        assert g.novelty_score("alice", "admin", "", time.time()) == 0.0

    def test_shared_object_dampens_novelty(self):
        """A resource many users already touch (high fan-in) is much less
        suspicious to visit for the first time than a private one - ML.md
        Part 5's explicit "shared vs private" distinction."""
        g = AccessGraph()
        now = time.time()
        for i in range(20):
            g.record_edge(f"user{i}", "account", "shared_doc", now)
        shared_novelty = g.novelty_score("newcomer", "account", "shared_doc", now)

        g2 = AccessGraph()
        private_novelty = g2.novelty_score("attacker", "account", "victims_private_object", now)
        assert shared_novelty < private_novelty

    def test_burst_of_new_objects_raises_novelty(self):
        """Reconnaissance signature: many first-time object touches in a
        short window should score higher than a single isolated one."""
        g = AccessGraph()
        now = time.time()
        isolated = g.novelty_score("scanner", "account", "1001", now)
        g.record_edge("scanner", "account", "1001", now)
        for i in range(2, 6):
            g.record_edge("scanner", "account", str(1000 + i), now)
        bursty = g.novelty_score("scanner", "account", "9999", now)
        assert bursty >= isolated

    def test_fan_in_fan_out(self):
        g = AccessGraph()
        now = time.time()
        g.record_edge("alice", "account", "1001", now)
        g.record_edge("bob", "account", "1001", now)
        assert g.fan_in("account", "1001") == 2
        assert g.fan_out("alice") == 1


# ---------------------------------------------------------------------- risk

class TestComputeMlRisk:
    def test_all_none_is_zero_risk_not_penalized(self):
        """Missing signals contribute 0, not a penalty - matches the
        'don't punish for missing data' rule used throughout this project."""
        risk, breakdown = compute_ml_risk(None, None, None)
        assert risk == 0

    def test_bounded_0_100(self):
        risk, _ = compute_ml_risk(1.0, 1.0, 1.0)
        assert 0 <= risk <= 100

    def test_max_inputs_give_max_risk(self):
        risk, _ = compute_ml_risk(1.0, 1e-6, 1.0)  # near-zero markov prob = max sequence anomaly
        assert risk == 100

    def test_weights_match_ml_md(self):
        assert settings.ml_risk_weights == {
            "isolation_forest": 0.4,
            "markov_sequence": 0.3,
            "graph_novelty": 0.3,
        }

    def test_sequence_anomaly_low_for_expected_transition(self):
        assert sequence_anomaly(0.99) < sequence_anomaly(0.01)


# --------------------------------------------------------------- anti-poisoning

class TestAntiPoisoning:
    """The property the whole worker exists to protect: a confirmed
    attacker's later 'allowed' traffic never becomes training data again."""

    def test_hostile_block_stops_further_training(self):
        w = MLWorker()
        now = time.time()
        alert_block = {"subject": "mallory", "path": "/api/accounts/1001",
                       "decision": "block", "time": "t1"}
        w.process_alert(alert_block, now)
        profile = w.get_profile("mallory")
        assert profile.known_attacker is True
        assert len(profile.requests) == 0

        alert_allow = {"subject": "mallory", "path": "/api/accounts/1002",
                       "decision": "allow", "time": "t2"}
        w.process_alert(alert_allow, now + 1)
        # still known_attacker; the "allowed" request after the block must
        # NOT have been folded into training data
        assert profile.known_attacker is True
        assert len(profile.requests) == 0

    def test_ordinary_allowed_traffic_does_train(self):
        w = MLWorker()
        now = time.time()
        alert = {"subject": "alice", "path": "/api/accounts/1001",
                 "decision": "allow", "time": "t1"}
        w.process_alert(alert, now)
        profile = w.get_profile("alice")
        assert profile.known_attacker is False
        assert len(profile.requests) == 1

    def test_challenge_neither_trains_nor_marks_hostile(self):
        w = MLWorker()
        now = time.time()
        alert = {"subject": "bob", "path": "/api/accounts/1001",
                 "decision": "challenge", "time": "t1"}
        w.process_alert(alert, now)
        profile = w.get_profile("bob")
        assert profile.known_attacker is False
        assert len(profile.requests) == 0


# --------------------------------------------------------------- worker startup

class TestWorkerStartup:
    def test_fresh_worker_does_not_discard_opening_alerts(self):
        """Regression test for a real bug found and fixed earlier this
        session: last_processed_time used to be seeded from the latest
        existing alert on first poll, silently discarding a demo's own
        opening traffic. It must start empty so the first poll's `>`
        comparison treats everything as new."""
        w = MLWorker()
        assert w.last_processed_time == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
