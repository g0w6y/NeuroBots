import math
from config import settings


def sequence_anomaly(prob: float) -> float:
    """ML.md Part 4: 'sequence anomaly score as the negative log probability'.
    Normalized into 0..1 so it combines cleanly with the other scores."""
    if prob <= 0:
        prob = 1e-6
    return min(1.0, -math.log(prob) / 5.0)


def compute_ml_risk(isolation_score, markov_prob, graph_novelty, gnn_anomaly: float = None) -> tuple[int, dict]:
    """
    ML Risk Fusion incorporating:
    - Isolation Forest anomaly score (scikit-learn)
    - Markov sequence transition probability
    - NetworkX graph novelty score
    - 2-Layer Graph Convolutional Network (GCN) link anomaly score
    """
    iso = isolation_score if isolation_score is not None else 0.0
    seq = sequence_anomaly(markov_prob) if markov_prob is not None else 0.0
    graph = graph_novelty if graph_novelty is not None else 0.0
    gnn = gnn_anomaly if gnn_anomaly is not None else 0.0

    w = getattr(settings, "ml_risk_weights", {
        "isolation_forest": 0.35,
        "markov_sequence": 0.25,
        "graph_novelty": 0.20,
        "gnn_anomaly": 0.20
    })

    w_iso = w.get("isolation_forest", 0.35)
    w_seq = w.get("markov_sequence", 0.25)
    w_graph = w.get("graph_novelty", 0.20)
    w_gnn = w.get("gnn_anomaly", 0.20)

    ml_risk = 100 * (w_iso * iso + w_seq * seq + w_graph * graph + w_gnn * gnn)
    ml_risk = int(max(0, min(100, round(ml_risk))))

    breakdown = {
        "isolation_forest_score": round(iso, 3),
        "sequence_anomaly_score": round(seq, 3),
        "graph_novelty_score": round(graph, 3),
        "gnn_anomaly_score": round(gnn, 3),
        "gnn_active": True,
    }
    return ml_risk, breakdown
