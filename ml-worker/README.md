# NeuroBots ML Worker

Machine Learning Worker for the NeuroBots API Security Gateway. Provides behavioral analytics, anomaly detection, and risk scoring for API requests.

## Architecture

```
ml-worker/
├── config/             # Configuration (env vars, dataclasses)
│   └── settings.py
├── core/               # Pipeline orchestration
│   ├── pipeline.py     # Main ML processing pipeline
│   └── feedback.py     # Learning from gateway decisions
├── events/             # Event consumer
│   └── consumer.py     # HTTP polling of /admin/alerts
├── profiling/          # Entity profiling
│   └── manager.py      # Per-user behavioral baselines
├── features/           # Feature extraction
│   └── extractor.py    # 8-dimensional feature vectors
├── anomaly/            # Anomaly detection
│   └── isolation_forest.py  # scikit-learn IsolationForest
├── markov/             # Sequence analysis
│   └── analyzer.py     # First-order Markov chains
├── graph/              # Graph analysis
│   └── analyzer.py     # NetworkX user-object access graph
├── risk/               # Risk scoring
│   └── scorer.py       # Weighted combination of signals
├── redis_store/        # Redis integration
│   └── store.py        # Async Redis client
├── models/             # Pydantic data models
│   └── schemas.py      # GatewayEvent, EntityProfile, MLRiskResult
├── utils/              # Utilities
│   ├── logging.py      # Structured logging
│   └── helpers.py      # Hash, time utilities
├── tests/              # Test suite
│   ├── test_ml_worker.py  # 34 unit tests
│   └── mock_gateway.py    # Mock gateway for testing
├── main.py             # CLI entry point (typer)
└── requirements.txt    # Python dependencies
```

## How It Works

### Data Flow

```
Gateway (port 8081)  →  EventConsumer (polls /admin/alerts every 2s)
                              ↓
                        MLPipeline.process_event()
                              ↓
                   ┌──────────┼──────────┐
                   ↓          ↓          ↓
             AnomalyDF    Markov      Graph
             (Isolation   (Sequence   (NetworkX
              Forest)     Analysis)   Analysis)
                   ↓          ↓          ↓
                   └──────────┼──────────┘
                              ↓
                        RiskScorer
                   (weighted combination)
                              ↓
                    RedisStore.write_risk_score()
                    RedisStore.write_profile()
```

### ML Techniques

1. **IsolationForest** (40% weight) — Detects anomalous request patterns using 8 features: hour of day, day of week, request rate, object/endpoint hashes, days since first request, distinct objects/endpoints.

2. **Markov Chains** (30% weight) — Flags unusual endpoint-to-endpoint sequences. Low-probability transitions score high.

3. **NetworkX Graph** (30% weight) — Builds a user-to-object access graph. Detects new resource types, unusual fan-out/fan-in patterns.

### Feedback Learning

- **Allowed requests**: Update all models (anomaly, Markov, graph)
- **Blocked requests**: Track in profile stats only, NEVER train on them
- **Challenge requests**: Update profile stats only

This prevents the system from learning attack patterns as normal behavior.

## Quick Start

### Prerequisites

- Python 3.13+
- Redis running on `127.0.0.1:6379`
- NeuroBots Gateway running on port 8081

### Install Dependencies

```bash
cd ml-worker
pip install -r requirements.txt
```

### Run Tests

```bash
python -m pytest tests/ -v
```

### Start the Worker

```bash
python main.py start --redis-url redis://127.0.0.1:6379 --gateway-url http://127.0.0.1:8081/admin/alerts
```

### Check Status

```bash
python main.py status --redis-url redis://127.0.0.1:6379
```

## Configuration

All settings are configurable via environment variables:

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://127.0.0.1:6379` | Redis connection URL |
| `GATEWAY_ALERTS_URL` | `http://127.0.0.1:8081/admin/alerts` | Gateway events endpoint |
| `POLL_INTERVAL_SECONDS` | `2` | How often to poll the gateway |
| `ISOLATION_FOREST_THRESHOLD` | `0.7` | Anomaly score threshold |
| `ISOLATION_FOREST_N_ESTIMATORS` | `100` | Number of trees in forest |
| `ISOLATION_FOREST_RETRAIN_MINUTES` | `60` | Retrain interval |
| `ISOLATION_FOREST_MIN_SAMPLES` | `30` | Min samples before training |
| `MARKOV_PROBABILITY_THRESHOLD` | `0.1` | Unusual sequence threshold |
| `ML_RISK_TTL_SECONDS` | `300` | Risk score TTL in Redis |
| `ML_PROFILE_TTL_SECONDS` | `3600` | Profile TTL in Redis |
| `LOG_LEVEL` | `INFO` | Logging level |

## Redis Keys Written

| Key Pattern | TTL | Description |
|---|---|---|
| `ml_risk:{subject}` | 300s | JSON with ml_risk, anomaly_score, sequence_score, graph_score |
| `profile:{subject}` | 3600s | Full entity profile JSON |

## Testing

Run the full test suite:

```bash
python -m pytest tests/test_ml_worker.py -v
```

34 tests covering:
- Models (GatewayEvent, EntityProfile, MLRiskResult)
- Configuration loading
- Feature extraction and normalization
- Entity profiling and rate computation
- IsolationForest training and scoring
- Markov chain transitions and probabilities
- Graph analysis (fan-out, fan-in, novelty)
- Risk scoring (weighted combination)
- Feedback learning (allowed vs blocked)
- Helper utilities

## Tech Stack

- **Python 3.13+** — Modern async Python
- **scikit-learn** — IsolationForest
- **NetworkX** — Graph analysis
- **Redis** (async) — Risk score caching
- **Pydantic** — Data validation
- **httpx** — Async HTTP client
- **typer** — CLI interface
- **orjson** — Fast JSON serialization
