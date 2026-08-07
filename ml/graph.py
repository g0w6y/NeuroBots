import networkx as nx
import numpy as np


class AccessGraph:
    """
    Bipartite user<->object graph, matching ML.md Part 5.
    Nodes: "user:{subject}" and "obj:{resource}:{object_id}"
    Edges: exists if that user has ever accessed that object (allowed traffic only).
    """

    def __init__(self):
        self.graph = nx.Graph()
        self.new_edge_times: dict[str, list[float]] = {}

    def record_edge(self, subject: str, resource: str, object_id: str, now: float) -> None:
        if not object_id:
            return
        user_node = f"user:{subject}"
        obj_node = f"obj:{resource}:{object_id}"
        is_new = not self.graph.has_edge(user_node, obj_node)
        self.graph.add_edge(user_node, obj_node)
        if is_new:
            times = self.new_edge_times.setdefault(user_node, [])
            times.append(now)
            self.new_edge_times[user_node] = [t for t in times if now - t <= 3600]

    def novelty_score(self, subject: str, resource: str, object_id: str, now: float) -> float:
        """
        0..1. 0 if this user has touched this object before. Otherwise scaled by:
        - how many *other* new objects this user has touched very recently (burst
          of first-time accesses looks like reconnaissance, not routine browsing)
        - the object's fan-in (many existing owners = a shared/public resource,
          touching it for the first time is much less suspicious - ML.md Part 5:
          "object fan in ... shared vs private")
        """
        if not object_id:
            return 0.0
        user_node = f"user:{subject}"
        obj_node = f"obj:{resource}:{object_id}"
        if self.graph.has_edge(user_node, obj_node):
            return 0.0

        fan_in = self.graph.degree(obj_node) if self.graph.has_node(obj_node) else 0
        recent_new = [t for t in self.new_edge_times.get(user_node, []) if now - t <= 10]
        burst_factor = min(1.0, len(recent_new) / 5.0)

        shared_dampening = 1.0 / (1.0 + fan_in)
        base = 0.5 + 0.5 * burst_factor
        novelty = base * min(1.0, shared_dampening * 5)
        return float(np.clip(novelty, 0.0, 1.0))

    def fan_out(self, subject: str) -> int:
        user_node = f"user:{subject}"
        return self.graph.degree(user_node) if self.graph.has_node(user_node) else 0

    def fan_in(self, resource: str, object_id: str) -> int:
        obj_node = f"obj:{resource}:{object_id}"
        return self.graph.degree(obj_node) if self.graph.has_node(obj_node) else 0

    def stats(self) -> dict:
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
        }
