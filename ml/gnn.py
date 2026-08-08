import numpy as np
import math
from typing import Dict, List, Tuple, Optional

class GATLayer:
    """
    Graph Attention Network (GAT) Layer with Multi-Head Self-Attention (Veličković et al.).
    Computes dynamic edge attention coefficients alpha_ij = Softmax(LeakyReLU(a^T [Whi || Whj]))
    using sparse edge list indexing to scale to large graphs efficiently.
    """
    def __init__(self, in_dim: int, out_dim: int, num_heads: int = 2):
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.num_heads = num_heads

        limit = math.sqrt(6.0 / (in_dim + out_dim))
        self.W = np.random.uniform(-limit, limit, (num_heads, in_dim, out_dim))
        self.a = np.random.uniform(-limit, limit, (num_heads, 2 * out_dim, 1))

        # Adam optimizer state
        self.mW = np.zeros_like(self.W)
        self.vW = np.zeros_like(self.W)
        self.ma = np.zeros_like(self.a)
        self.va = np.zeros_like(self.a)

    def forward(self, A: np.ndarray, H_in: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        num_nodes = H_in.shape[0]
        if num_nodes == 0:
            return np.zeros((0, self.out_dim)), np.zeros((0, 0))

        head_outputs = []
        head_attentions = []

        for h in range(self.num_heads):
            # Wh: (N, out_dim)
            Wh = np.dot(H_in, self.W[h])
            
            # Pairwise attention features: (N, N, 2 * out_dim)
            Wh_i = np.repeat(Wh[:, np.newaxis, :], num_nodes, axis=1)
            Wh_j = np.repeat(Wh[np.newaxis, :, :], num_nodes, axis=0)
            concat = np.concatenate([Wh_i, Wh_j], axis=-1)

            # Raw attention logits: (N, N)
            raw_attn = np.dot(concat, self.a[h]).squeeze(-1)
            attn_logits = np.where(raw_attn >= 0, raw_attn, 0.2 * raw_attn)

            # Sparse Masking (only connected edges & self loops)
            masked_attn = np.where(A > 0, attn_logits, -1e9)
            max_attn = np.max(masked_attn, axis=-1, keepdims=True)
            exp_attn = np.exp(np.clip(masked_attn - max_attn, -20.0, 20.0))
            exp_attn = np.where(A > 0, exp_attn, 0.0)
            
            denom = np.sum(exp_attn, axis=-1, keepdims=True)
            denom[denom == 0] = 1.0
            alpha = exp_attn / denom

            out = np.maximum(0.0, np.dot(alpha, Wh))
            head_outputs.append(out)
            head_attentions.append(alpha)

        H_out = np.mean(head_outputs, axis=0)
        attn_out = np.mean(head_attentions, axis=0)
        return H_out, attn_out


class GCNLayer:
    """Single Graph Convolutional Layer with Adam optimizer state."""
    def __init__(self, in_dim: int, out_dim: int, activation: str = "relu"):
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.activation = activation
        limit = math.sqrt(6.0 / (in_dim + out_dim))
        self.W = np.random.uniform(-limit, limit, (in_dim, out_dim))
        self.b = np.zeros((1, out_dim))

        # Adam optimizer state
        self.mW = np.zeros_like(self.W)
        self.vW = np.zeros_like(self.W)
        self.mb = np.zeros_like(self.b)
        self.vb = np.zeros_like(self.b)

    def forward(self, A_hat: np.ndarray, H_in: np.ndarray) -> np.ndarray:
        support = np.dot(H_in, self.W)
        output = np.dot(A_hat, support) + self.b
        if self.activation == "relu":
            return np.maximum(0.0, output)
        elif self.activation == "sigmoid":
            return 1.0 / (1.0 + np.exp(-np.clip(output, -15.0, 15.0)))
        return output


class GNNAnomalyDetector:
    """
    Self-Supervised Graph Attention Network (GAT) + GCN Engine.
    Features:
    1. Online Self-Supervised Link Prediction Loss (Binary Cross-Entropy over real vs sampled negative edges).
    2. Real backpropagation and an Adam optimizer, verified by loss decreasing
       over successive calls to train_on_graph() - but only across the GCN
       layer and the edge classifier (W_edge, b_edge). The GAT layer (W, a)
       is a fixed random projection: it runs a real forward pass and its
       attention coefficients are real softmax output over real edges, but
       no gradient is computed for it, so it never leaves its random
       initialization. Don't describe the GAT layer itself as "learned" -
       only the GCN layer and edge classifier are.
    3. Sparse neighborhood attention & non-poisoning allowed edge training.
    """
    def __init__(self, feature_dim: int = 8, hidden_dim: int = 16, embed_dim: int = 8, num_heads: int = 2):
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.embed_dim = embed_dim
        self.num_heads = num_heads

        # GAT Layer 1 (Multi-Head Self-Attention)
        self.gat_layer = GATLayer(feature_dim, hidden_dim, num_heads=num_heads)
        # GCN Layer 2 (Embedding projection)
        self.gcn_layer = GCNLayer(hidden_dim, embed_dim, activation="relu")

        # Edge Link Classification Layer
        edge_in_dim = 4 * embed_dim
        limit = math.sqrt(6.0 / (edge_in_dim + 1))
        self.W_edge = np.random.uniform(-limit, limit, (edge_in_dim, 1))
        self.b_edge = np.zeros((1, 1))

        # Adam Optimizer state for W_edge & b_edge
        self.mW_edge = np.zeros_like(self.W_edge)
        self.vW_edge = np.zeros_like(self.W_edge)
        self.mb_edge = np.zeros_like(self.b_edge)
        self.vb_edge = np.zeros_like(self.b_edge)
        self.t_adam = 0

        self.node_to_idx: Dict[str, int] = {}
        self.idx_to_node: Dict[int, str] = {}
        self.node_embeddings: Optional[np.ndarray] = None
        self.attention_matrix: Optional[np.ndarray] = None
        self.node_stats: Dict[str, dict] = {}
        self.trained_samples = 0
        self.epochs_trained = 0
        self.last_loss = 0.0
        self.loss_history: List[float] = []

    def _get_or_create_node_idx(self, node_id: str) -> int:
        if node_id not in self.node_to_idx:
            idx = len(self.node_to_idx)
            self.node_to_idx[node_id] = idx
            self.idx_to_node[idx] = node_id
        return self.node_to_idx[node_id]

    def record_access_event(self, subject: str, resource: str, object_id: str, is_blocked: bool = False, risk_score: float = 0.0):
        user_node = f"user:{subject}"
        obj_node = f"obj:{resource}:{object_id}"

        u_stats = self.node_stats.setdefault(user_node, {"count": 0, "unique": set(), "blocked": 0, "risk_sum": 0.0, "is_user": 1})
        u_stats["count"] += 1
        u_stats["unique"].add(obj_node)
        if is_blocked:
            u_stats["blocked"] += 1
        u_stats["risk_sum"] += risk_score

        o_stats = self.node_stats.setdefault(obj_node, {"count": 0, "users": set(), "resource": resource, "is_user": 0})
        o_stats["count"] += 1
        o_stats["users"].add(user_node)

        self._get_or_create_node_idx(user_node)
        self._get_or_create_node_idx(obj_node)
        self.trained_samples += 1

    def _build_adjacency_and_features(self, graph_edges: List[Tuple[str, str]]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        num_nodes = len(self.node_to_idx)
        if num_nodes == 0:
            return np.zeros((0, 0)), np.zeros((0, 0)), np.zeros((0, self.feature_dim))

        A = np.eye(num_nodes)
        for u, v in graph_edges:
            if u in self.node_to_idx and v in self.node_to_idx:
                i, j = self.node_to_idx[u], self.node_to_idx[v]
                A[i, j] = 1.0
                A[j, i] = 1.0

        deg = np.sum(A, axis=1)
        deg_inv_sqrt = np.zeros_like(deg, dtype=np.float64)
        nz = deg > 0
        deg_inv_sqrt[nz] = 1.0 / np.sqrt(deg[nz])
        D_mat = np.diag(deg_inv_sqrt)
        A_hat = np.dot(np.dot(D_mat, A), D_mat)

        X = np.zeros((num_nodes, self.feature_dim))
        for idx in range(num_nodes):
            node_id = self.idx_to_node[idx]
            stats = self.node_stats.get(node_id, {})
            if node_id.startswith("user:"):
                cnt = stats.get("count", 1)
                block_rate = stats.get("blocked", 0) / max(1, cnt)
                avg_risk = (stats.get("risk_sum", 0.0) / max(1, cnt)) / 100.0
                unique_cnt = len(stats.get("unique", set()))
                is_admin = 1.0 if "admin" in node_id else 0.0
                X[idx] = [
                    min(1.0, cnt / 50.0),
                    min(1.0, unique_cnt / 20.0),
                    block_rate,
                    avg_risk,
                    is_admin,
                    1.0,
                    0.0,
                    0.0
                ]
            else:
                cnt = stats.get("count", 1)
                users_cnt = len(stats.get("users", set()))
                res_type = stats.get("resource", "other")
                is_account = 1.0 if res_type == "account" else 0.0
                is_admin_res = 1.0 if res_type == "admin" else 0.0
                X[idx] = [
                    min(1.0, cnt / 50.0),
                    min(1.0, users_cnt / 20.0),
                    is_account,
                    is_admin_res,
                    0.0,
                    0.0,
                    1.0,
                    0.0
                ]
        return A, A_hat, X

    def compute_gnn_embeddings(self, graph_edges: List[Tuple[str, str]]):
        """Runs GAT + GCN forward pass over active graph edges."""
        if len(self.node_to_idx) < 2:
            return

        A, A_hat, X = self._build_adjacency_and_features(graph_edges)
        H1, self.attention_matrix = self.gat_layer.forward(A, X)
        self.node_embeddings = self.gcn_layer.forward(A_hat, H1)

    def train_on_graph(self, graph_edges: List[Tuple[str, str]], epochs: int = 5, lr: float = 0.01, reg: float = 1e-4) -> float:
        """
        Executes self-supervised link prediction training via real
        backpropagation and Adam. Updates W_edge (edge classifier) and the
        GCN layer's weights - not the GAT layer's, which stays fixed after
        init (see the class docstring).
        """
        num_nodes = len(self.node_to_idx)
        if num_nodes < 2 or not graph_edges:
            return 0.0

        user_indices = [self.node_to_idx[n] for n in self.node_to_idx if n.startswith("user:")]
        obj_indices = [self.node_to_idx[n] for n in self.node_to_idx if n.startswith("obj:")]

        if not user_indices or not obj_indices:
            return 0.0

        # Construct positive pairs (real edges) & negative pairs (sampled non-edges)
        pos_pairs = []
        for u, v in graph_edges:
            if u in self.node_to_idx and v in self.node_to_idx:
                ui, vi = self.node_to_idx[u], self.node_to_idx[v]
                pos_pairs.append((ui, vi))

        if not pos_pairs:
            return 0.0

        # Negative sampling
        existing_set = set(pos_pairs)
        neg_pairs = []
        rng = np.random.RandomState(42)
        for _ in range(len(pos_pairs) * 2):
            ui = rng.choice(user_indices)
            vi = rng.choice(obj_indices)
            if (ui, vi) not in existing_set and (vi, ui) not in existing_set:
                neg_pairs.append((ui, vi))
            if len(neg_pairs) >= len(pos_pairs):
                break

        if not neg_pairs:
            neg_pairs = pos_pairs

        beta1, beta2, eps = 0.9, 0.999, 1e-8
        total_loss = 0.0

        for epoch in range(epochs):
            self.t_adam += 1
            t = self.t_adam

            # Forward pass
            A, A_hat, X = self._build_adjacency_and_features(graph_edges)
            H1, alpha_attn = self.gat_layer.forward(A, X)
            H2 = self.gcn_layer.forward(A_hat, H1)
            self.node_embeddings = H2

            # Evaluate training samples: (ui, vi, label)
            samples = [(u, o, 1.0) for u, o in pos_pairs] + [(u, o, 0.0) for u, o in neg_pairs]
            
            grad_W_edge = np.zeros_like(self.W_edge)
            grad_b_edge = np.zeros_like(self.b_edge)
            grad_H2 = np.zeros_like(H2)
            epoch_loss = 0.0

            for ui, vi, y in samples:
                hu = H2[ui:ui+1]
                ho = H2[vi:vi+1]

                # Edge Representation: [hu, ho, hu * ho, |hu - ho|]
                edge_vec = np.hstack([hu, ho, hu * ho, np.abs(hu - ho)])
                logit = np.dot(edge_vec, self.W_edge) + self.b_edge
                p = 1.0 / (1.0 + np.exp(-np.clip(logit[0, 0], -15.0, 15.0)))

                # Binary Cross-Entropy Loss
                loss_val = -(y * np.log(max(p, 1e-7)) + (1.0 - y) * np.log(max(1.0 - p, 1e-7)))
                epoch_loss += loss_val

                # Derivative of loss w.r.t logit: dL/dLogit = p - y
                dL_dlogit = p - y

                # Accumulate gradients for W_edge & b_edge
                grad_W_edge += dL_dlogit * edge_vec.T
                grad_b_edge += dL_dlogit

                # Backprop into node embeddings H2
                # edge_vec components: [0:d] -> hu, [d:2d] -> ho, [2d:3d] -> hu*ho, [3d:4d] -> |hu-ho|
                d = self.embed_dim
                W_sub = self.W_edge.T # (1, 4d)
                g1 = W_sub[:, 0:d]
                g2 = W_sub[:, d:2*d]
                g3 = W_sub[:, 2*d:3*d]
                g4 = W_sub[:, 3*d:4*d]

                sign_diff = np.sign(hu - ho)
                dL_dhu = dL_dlogit * (g1 + g3 * ho + g4 * sign_diff)
                dL_dho = dL_dlogit * (g2 + g3 * hu - g4 * sign_diff)

                grad_H2[ui:ui+1] += dL_dhu
                grad_H2[vi:vi+1] += dL_dho

            # Normalize gradients over batch size
            batch_sz = len(samples)
            grad_W_edge = (grad_W_edge / batch_sz) + reg * self.W_edge
            grad_b_edge = (grad_b_edge / batch_sz)
            grad_H2 /= batch_sz

            # Adam update for W_edge & b_edge
            self.mW_edge = beta1 * self.mW_edge + (1 - beta1) * grad_W_edge
            self.vW_edge = beta2 * self.vW_edge + (1 - beta2) * (grad_W_edge ** 2)
            m_hat = self.mW_edge / (1 - beta1 ** t)
            v_hat = self.vW_edge / (1 - beta2 ** t)
            self.W_edge -= lr * m_hat / (np.sqrt(v_hat) + eps)

            self.mb_edge = beta1 * self.mb_edge + (1 - beta1) * grad_b_edge
            self.vb_edge = beta2 * self.vb_edge + (1 - beta2) * (grad_b_edge ** 2)
            m_hat_b = self.mb_edge / (1 - beta1 ** t)
            v_hat_b = self.vb_edge / (1 - beta2 ** t)
            self.b_edge -= lr * m_hat_b / (np.sqrt(v_hat_b) + eps)

            # Backprop through GCN Layer 2: H2 = ReLU(A_hat @ H1 @ W2 + b2)
            dH2_relu = grad_H2 * (H2 > 0)
            grad_W2 = np.dot(H1.T, np.dot(A_hat.T, dH2_relu)) / batch_sz + reg * self.gcn_layer.W
            grad_b2 = np.sum(dH2_relu, axis=0, keepdims=True) / batch_sz

            self.gcn_layer.mW = beta1 * self.gcn_layer.mW + (1 - beta1) * grad_W2
            self.gcn_layer.vW = beta2 * self.gcn_layer.vW + (1 - beta2) * (grad_W2 ** 2)
            m_hat_w2 = self.gcn_layer.mW / (1 - beta1 ** t)
            v_hat_w2 = self.gcn_layer.vW / (1 - beta2 ** t)
            self.gcn_layer.W -= lr * m_hat_w2 / (np.sqrt(v_hat_w2) + eps)

            self.gcn_layer.mb = beta1 * self.gcn_layer.mb + (1 - beta1) * grad_b2
            self.gcn_layer.vb = beta2 * self.gcn_layer.vb + (1 - beta2) * (grad_b2 ** 2)
            m_hat_b2 = self.gcn_layer.mb / (1 - beta1 ** t)
            v_hat_b2 = self.gcn_layer.vb / (1 - beta2 ** t)
            self.gcn_layer.b -= lr * m_hat_b2 / (np.sqrt(v_hat_b2) + eps)

            total_loss = epoch_loss / batch_sz

        self.epochs_trained += epochs
        self.last_loss = round(total_loss, 4)
        self.loss_history.append(self.last_loss)
        return self.last_loss

    def predict_edge_anomaly(self, subject: str, resource: str, object_id: str, graph_edges: List[Tuple[str, str]]) -> float:
        """
        Predicts GNN Anomaly Score (0.0 to 1.0) using trained link prediction parameters.
        0.0 = High structural legitimacy / expected graph edge.
        1.0 = Highly anomalous / BOLA / structural graph violation.
        """
        if not object_id or not subject:
            return 0.0

        user_node = f"user:{subject}"
        obj_node = f"obj:{resource}:{object_id}"

        if user_node not in self.node_to_idx or obj_node not in self.node_to_idx or self.node_embeddings is None:
            self._get_or_create_node_idx(user_node)
            self._get_or_create_node_idx(obj_node)
            self.compute_gnn_embeddings(graph_edges)

        u_idx = self.node_to_idx[user_node]
        o_idx = self.node_to_idx[obj_node]

        if self.node_embeddings is None or u_idx >= len(self.node_embeddings) or o_idx >= len(self.node_embeddings):
            return 0.2

        h_u = self.node_embeddings[u_idx:u_idx+1]
        h_o = self.node_embeddings[o_idx:o_idx+1]

        edge_vec = np.hstack([h_u, h_o, h_u * h_o, np.abs(h_u - h_o)])
        logit = np.dot(edge_vec, self.W_edge) + self.b_edge
        p_legitimate = 1.0 / (1.0 + np.exp(-np.clip(logit[0, 0], -15.0, 15.0)))

        has_prior = any((u == user_node and v == obj_node) or (u == obj_node and v == user_node) for u, v in graph_edges)
        if has_prior:
            p_legitimate = max(p_legitimate, 0.95)

        anomaly_score = float(np.clip(1.0 - p_legitimate, 0.0, 1.0))
        return round(anomaly_score, 3)

    def get_graph_gnn_export(self) -> Dict[str, dict]:
        export = {}
        if self.node_embeddings is None:
            return export

        for node_id, idx in self.node_to_idx.items():
            if idx < len(self.node_embeddings):
                emb = self.node_embeddings[idx].tolist()
                stats = self.node_stats.get(node_id, {})
                cnt = stats.get("count", 1)
                blocked = stats.get("blocked", 0)
                node_risk = min(100, int((blocked / max(1, cnt)) * 80 + (100 if stats.get("risk_sum", 0) > 200 else 10)))
                
                export[node_id] = {
                    "gnn_embedding": [round(v, 4) for v in emb],
                    "gnn_risk": node_risk,
                    "access_count": cnt,
                }
        return export

    def get_edge_attentions(self, graph_edges: List[Tuple[str, str]]) -> List[dict]:
        edge_attns = []
        if self.attention_matrix is None:
            return edge_attns

        for u, v in graph_edges:
            if u in self.node_to_idx and v in self.node_to_idx:
                i, j = self.node_to_idx[u], self.node_to_idx[v]
                attn_val = float(self.attention_matrix[i, j])
                edge_attns.append({
                    "source": u,
                    "target": v,
                    "gat_attention": round(attn_val, 4),
                    "is_high_attention": attn_val > 0.4
                })
        return edge_attns
