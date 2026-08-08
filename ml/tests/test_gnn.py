import pytest
import sys
import os
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gnn import GNNAnomalyDetector, GCNLayer, GATLayer
from graph import AccessGraph
from risk import compute_ml_risk

def test_gat_layer_multihead():
    gat = GATLayer(in_dim=8, out_dim=16, num_heads=2)
    A = np.array([[1, 1], [1, 1]])
    H_in = np.ones((2, 8))
    H_out, attn_out = gat.forward(A, H_in)
    assert H_out.shape == (2, 16)
    assert attn_out.shape == (2, 2)
    assert np.allclose(np.sum(attn_out, axis=1), 1.0)

def test_gcn_layer_forward():
    layer = GCNLayer(in_dim=8, out_dim=16, activation="relu")
    A_hat = np.eye(3)
    H_in = np.ones((3, 8))
    H_out = layer.forward(A_hat, H_in)
    assert H_out.shape == (3, 16)
    assert np.all(H_out >= 0)

def test_gnn_anomaly_detector_training():
    gnn = GNNAnomalyDetector(feature_dim=8, hidden_dim=16, embed_dim=8, num_heads=2)
    gnn.record_access_event("alice", "account", "1001", is_blocked=False, risk_score=0.0)
    gnn.record_access_event("alice", "account", "1002", is_blocked=True, risk_score=85.0)
    gnn.record_access_event("bob", "account", "1002", is_blocked=False, risk_score=0.0)

    edges = [("user:alice", "obj:account:1001"), ("user:bob", "obj:account:1002")]
    gnn.compute_gnn_embeddings(edges)

    assert gnn.node_embeddings is not None
    assert len(gnn.node_to_idx) == 4

    # Test GNN self-supervised training & backprop gradient optimization
    initial_loss = gnn.train_on_graph(edges, epochs=1, lr=0.01)
    final_loss = gnn.train_on_graph(edges, epochs=15, lr=0.01)
    assert gnn.epochs_trained == 16
    assert final_loss <= initial_loss # Loss decreases via backprop optimization!

    attentions = gnn.get_edge_attentions(edges)
    assert len(attentions) == 2
    assert "gat_attention" in attentions[0]

    # Predict edge anomaly for normal vs cross-tenant edge
    score_normal = gnn.predict_edge_anomaly("alice", "account", "1001", edges)
    assert 0.0 <= score_normal <= 1.0

    export = gnn.get_graph_gnn_export()
    assert "user:alice" in export
    assert len(export["user:alice"]["gnn_embedding"]) == 8

def test_access_graph_with_gnn():
    ag = AccessGraph()
    ag.record_edge("alice", "account", "1001", now=100.0)
    ag.record_edge("bob", "account", "1002", now=100.0)

    stats = ag.stats()
    assert stats["gnn_active"] is True

    gnn_score = ag.gnn_score("alice", "account", "1002")
    assert 0.0 <= gnn_score <= 1.0

    export = ag.export_graph()
    assert export["gnn_meta"]["active"] is True
    assert "Graph Attention Network" in export["gnn_meta"]["architecture"]
    assert len(export["edges"]) == 2
    assert "gat_attention" in export["edges"][0]

def test_risk_fusion_with_gnn():
    ml_risk, breakdown = compute_ml_risk(
        isolation_score=0.8,
        markov_prob=0.01,
        graph_novelty=0.7,
        gnn_anomaly=0.9
    )
    assert 0 <= ml_risk <= 100
    assert "gnn_anomaly_score" in breakdown
    assert breakdown["gnn_anomaly_score"] == 0.9
