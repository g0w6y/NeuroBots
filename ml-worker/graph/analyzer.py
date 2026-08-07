"""NetworkX graph analysis for user-object access patterns."""

from __future__ import annotations

import networkx as nx

from config.settings import GraphConfig
from models.schemas import GatewayEvent, EntityProfile
from utils.logging import get_logger

logger = get_logger("graph")


class AccessGraph:
    """Bipartite graph of users accessing objects."""

    def __init__(self, config: GraphConfig) -> None:
        self._config = config
        self.graph = nx.Graph()
        self._user_nodes: set[str] = set()
        self._object_nodes: set[str] = set()

    def add_access(self, subject_id: str, object_id: str, resource: str) -> None:
        """Record that a user accessed an object."""
        user_node = f"user:{subject_id}"
        object_node = f"object:{resource}:{object_id}"

        self._user_nodes.add(user_node)
        self._object_nodes.add(object_node)

        if self.graph.has_edge(user_node, object_node):
            self.graph[user_node][object_node]["weight"] += 1
        else:
            self.graph.add_edge(user_node, object_node, weight=1, resource=resource)

    def user_fan_out(self, subject_id: str) -> int:
        """How many distinct objects has this user accessed?"""
        user_node = f"user:{subject_id}"
        if user_node not in self.graph:
            return 0
        return len(list(self.graph.neighbors(user_node)))

    def object_fan_in(self, resource: str, object_id: str) -> int:
        """How many distinct users access this object?"""
        object_node = f"object:{resource}:{object_id}"
        if object_node not in self.graph:
            return 0
        return len(list(self.graph.neighbors(object_node)))

    def user_resources(self, subject_id: str) -> set[str]:
        """Which resource types does this user normally touch?"""
        user_node = f"user:{subject_id}"
        if user_node not in self.graph:
            return set()
        resources = set()
        for neighbor in self.graph.neighbors(user_node):
            edge_data = self.graph[user_node][neighbor]
            resources.add(edge_data.get("resource", "unknown"))
        return resources

    def is_new_resource(self, subject_id: str, resource: str) -> bool:
        """Check if this is a new resource type for the user."""
        return resource not in self.user_resources(subject_id)

    def compute_novelty_score(
        self, subject_id: str, event: GatewayEvent, profile: EntityProfile
    ) -> float:
        """Compute graph-based novelty score 0-1 (1 = most novel/suspicious).

        Factors:
        - New resource type for user: high novelty
        - High fan-in object (shared): lower novelty
        - Sudden fan-out increase: moderate novelty
        """
        score = 0.0

        if event.resource and self.is_new_resource(subject_id, event.resource):
            score += 0.5

        if event.object_id and event.resource:
            fan_in = self.object_fan_in(event.resource, event.object_id)
            if fan_in > self._config.fan_in_high_threshold:
                score += 0.0
            elif fan_in > 10:
                score += 0.1
            else:
                score += 0.2

        fan_out = self.user_fan_out(subject_id)
        baseline = len(profile.endpoints_seen) if profile.endpoints_seen else 1
        if fan_out > baseline * self._config.fan_out_threshold_multiplier:
            score += 0.3

        return min(score, 1.0)

    @property
    def stats(self) -> dict:
        """Return graph statistics."""
        return {
            "user_count": len(self._user_nodes),
            "object_count": len(self._object_nodes),
            "edge_count": self.graph.number_of_edges(),
            "connected_components": nx.number_connected_components(self.graph),
        }


class GraphAnalyzer:
    """Manages graph analysis for all entities."""

    def __init__(self, config: GraphConfig) -> None:
        self._config = config
        self._access_graph = AccessGraph(config)

    def update_from_event(self, event: GatewayEvent) -> None:
        """Update the graph with a new event."""
        if event.object_id and event.resource:
            self._access_graph.add_access(event.subject, event.object_id, event.resource)

    def compute_novelty(
        self, event: GatewayEvent, profile: EntityProfile
    ) -> float:
        """Compute the graph novelty score for an event."""
        return self._access_graph.compute_novelty_score(
            event.subject, event, profile
        )

    @property
    def graph(self) -> AccessGraph:
        return self._access_graph

    @property
    def stats(self) -> dict:
        return self._access_graph.stats
