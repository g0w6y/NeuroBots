import math
from config import settings


def sequence_anomaly(prob: float) -> float:
    """ML.md Part 4: 'sequence anomaly score as the negative log probability'.
    Normalized into 0..1 so it combines cleanly with the other two scores."""
    if prob <= 0:
        prob = 1e-6
    return min(1.0, -math.log(prob) / 5.0)


def compute_ml_risk(isolation_score, markov_prob, graph_novelty) -> tuple[int, dict]:
    """
    ML.md Part 6 fusion, weights: 0.4 isolation forest, 0.3 markov sequence,
    0.3 graph novelty. Any component that's None (not enough data for that
    signal yet) contributes 0, not a penalty - matches "don't punish for
    missing data" used throughout the rest of this project.
    """
    iso = isolation_score if isolation_score is not None else 0.0
    seq = sequence_anomaly(markov_prob) if markov_prob is not None else 0.0
    graph = graph_novelty if graph_novelty is not None else 0.0

    w = settings.ml_risk_weights
    ml_risk = 100 * (w["isolation_forest"] * iso + w["markov_sequence"] * seq + w["graph_novelty"] * graph)
    ml_risk = int(max(0, min(100, round(ml_risk))))

    breakdown = {
        "isolation_forest_score": round(iso, 3),
        "sequence_anomaly_score": round(seq, 3),
        "graph_novelty_score": round(graph, 3),
    }
    return ml_risk, breakdown
