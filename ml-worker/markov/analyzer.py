"""First-order Markov chain for API call sequence analysis."""

from __future__ import annotations

import math
from collections import defaultdict

from config.settings import MarkovConfig
from models.schemas import EntityProfile, GatewayEvent
from utils.logging import get_logger

logger = get_logger("markov")


class MarkovChain:
    """First-order Markov chain for a single entity."""

    def __init__(self, subject_id: str, smoothing: float = 1e-6) -> None:
        self.subject_id = subject_id
        self.transitions: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.total_transitions: dict[str, int] = defaultdict(int)
        self.smoothing = smoothing

    def add_transition(self, from_endpoint: str, to_endpoint: str) -> None:
        """Record a transition from one endpoint to another."""
        self.transitions[from_endpoint][to_endpoint] += 1
        self.total_transitions[from_endpoint] += 1

    def transition_probability(self, from_endpoint: str, to_endpoint: str) -> float:
        """Get the probability of transitioning from one endpoint to another."""
        total = self.total_transitions.get(from_endpoint, 0)
        if total == 0:
            return self.smoothing

        count = self.transitions.get(from_endpoint, {}).get(to_endpoint, 0)
        return (count + self.smoothing) / (total + self.smoothing * len(self.transitions.get(from_endpoint, {})))

    def sequence_log_probability(self, endpoints: list[str]) -> float:
        """Compute the log probability of a sequence of endpoints."""
        if len(endpoints) < 2:
            return 0.0

        log_prob = 0.0
        for i in range(1, len(endpoints)):
            prob = self.transition_probability(endpoints[i - 1], endpoints[i])
            log_prob += math.log(max(prob, 1e-15))
        return log_prob

    def get_top_transitions(self, n: int = 10) -> list[tuple[str, str, int]]:
        """Return the N most frequent transitions."""
        all_transitions = []
        for from_ep, tos in self.transitions.items():
            for to_ep, count in tos.items():
                all_transitions.append((from_ep, to_ep, count))
        all_transitions.sort(key=lambda x: x[2], reverse=True)
        return all_transitions[:n]


class MarkovAnalyzer:
    """Manages Markov chains for all entities."""

    def __init__(self, config: MarkovConfig) -> None:
        self._config = config
        self._chains: dict[str, MarkovChain] = {}

    def get_or_create(self, subject_id: str) -> MarkovChain:
        """Get existing chain or create a new one."""
        if subject_id not in self._chains:
            self._chains[subject_id] = MarkovChain(subject_id, self._config.smoothing)
        return self._chains[subject_id]

    def update_from_event(self, event: GatewayEvent, profile: EntityProfile) -> None:
        """Update the Markov chain with a new event."""
        chain = self.get_or_create(event.subject)

        recent = profile.recent_endpoints
        if len(recent) >= 2:
            prev_endpoint = recent[-2]
            chain.add_transition(prev_endpoint, event.endpoint)

    def score_event(self, event: GatewayEvent, profile: EntityProfile) -> float:
        """Score how unusual the current sequence is. Returns 0-1 (1 = most unusual)."""
        chain = self._chains.get(event.subject)
        if chain is None or not chain.total_transitions:
            return 0.0

        recent = profile.recent_endpoints
        if len(recent) < 2:
            return 0.0

        prev_endpoint = recent[-2]
        prob = chain.transition_probability(prev_endpoint, event.endpoint)

        if prob < self._config.probability_threshold:
            novelty = 1.0 - min(prob / self._config.probability_threshold, 1.0)
            return min(novelty, 1.0)
        return 0.0

    @property
    def chain_count(self) -> int:
        return len(self._chains)

    def get_chain_info(self, subject_id: str) -> dict:
        """Return info about a subject's Markov chain."""
        chain = self._chains.get(subject_id)
        if chain is None:
            return {"exists": False}
        return {
            "exists": True,
            "total_transitions": sum(chain.total_transitions.values()),
            "unique_endpoints": len(chain.transitions),
            "top_transitions": chain.get_top_transitions(5),
        }
