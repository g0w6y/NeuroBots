import networkx as nx
import numpy as np
from gnn import GNNAnomalyDetector


class AccessGraph:
    """
    Bipartite user<->object graph powered by a 2-Layer Graph Convolutional Network (GCN).
    Nodes: "user:{subject}" and "obj:{resource}:{object_id}"
    Edges: exists if that user has ever accessed that object (allowed traffic only).
    """

    def __init__(self):
        self.graph = nx.Graph()
        self.new_edge_times: dict[str, list[float]] = {}
        self.gnn = GNNAnomalyDetector()

    def record_edge(self, subject: str, resource: str, object_id: str, now: float, is_blocked: bool = False, risk_score: float = 0.0) -> None:
        if not object_id:
            return
        user_node = f"user:{subject}"
        obj_node = f"obj:{resource}:{object_id}"
        is_new = not self.graph.has_edge(user_node, obj_node)
        
        if not is_blocked:
            self.graph.add_edge(user_node, obj_node)
            
        self.gnn.record_access_event(subject, resource, object_id, is_blocked, risk_score)
        
        if is_new and not is_blocked:
            times = self.new_edge_times.setdefault(user_node, [])
            times.append(now)
            self.new_edge_times[user_node] = [t for t in times if now - t <= 3600]

        # Trigger GNN embedding forward pass & self-supervised backprop training
        edges_list = list(self.graph.edges())
        self.gnn.compute_gnn_embeddings(edges_list)
        if len(edges_list) >= 2:
            self.gnn.train_on_graph(edges_list, epochs=3, lr=0.01)

    def novelty_score(self, subject: str, resource: str, object_id: str, now: float) -> float:
        """
        0..1 heuristic novelty score based on edge recency and object fan-in.
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

    def gnn_score(self, subject: str, resource: str, object_id: str) -> float:
        """
        Computes Graph Neural Network (GCN) link prediction anomaly score (0.0 to 1.0).
        Evaluates structural embeddings of user node vs resource node.
        """
        return self.gnn.predict_edge_anomaly(subject, resource, object_id, list(self.graph.edges()))

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
            "gnn_active": True,
            "gnn_trained_samples": self.gnn.trained_samples,
        }

    def export_graph(self) -> dict:
        """Nodes/edges enriched with GNN embeddings and GNN risk metrics for dashboard."""
        gnn_export = self.gnn.get_graph_gnn_export()
        nodes = []
        for node in self.graph.nodes():
            gnn_info = gnn_export.get(str(node), {})
            if str(node).startswith("user:"):
                nodes.append({
                    "id": node,
                    "type": "user",
                    "label": str(node).split(":", 1)[1],
                    "gnn_embedding": gnn_info.get("gnn_embedding", []),
                    "gnn_risk": gnn_info.get("gnn_risk", 10),
                })
            elif str(node).startswith("obj:"):
                parts = str(node).split(":")
                resource = parts[1] if len(parts) > 1 else "unknown"
                obj_id = parts[2] if len(parts) > 2 else ""
                nodes.append({
                    "id": node,
                    "type": "resource",
                    "label": obj_id,
                    "resource": resource,
                    "gnn_embedding": gnn_info.get("gnn_embedding", []),
                    "gnn_risk": gnn_info.get("gnn_risk", 10),
                })
            else:
                nodes.append({
                    "id": str(node),
                    "type": "unknown",
                    "label": str(node),
                    "gnn_risk": 10,
                })
        edge_list = list(self.graph.edges())
        edge_attentions = self.gnn.get_edge_attentions(edge_list)
        attn_map = {(ea["source"], ea["target"]): ea["gat_attention"] for ea in edge_attentions}

        edges = []
        for u, v in self.graph.edges():
            attn = attn_map.get((str(u), str(v))) or attn_map.get((str(v), str(u))) or 0.1
            edges.append({
                "source": str(u),
                "target": str(v),
                "gat_attention": attn,
                "is_anomalous": attn > 0.4
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "gnn_meta": {
                "active": True,
                "architecture": "Graph Attention Network (GAT) with Multi-Head Self-Attention",
                "trained_samples": self.gnn.trained_samples,
            }
        }
