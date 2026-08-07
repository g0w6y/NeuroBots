import os


class MLSettings:
    redis_url: str = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379")
    gateway_url: str = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080")
    admin_api_key: str = os.environ.get("ADMIN_API_KEY", "changeme-admin-key")

    poll_interval_sec: float = float(os.environ.get("ML_POLL_INTERVAL_SECONDS", "2"))

    # an entity needs at least this many allowed requests before the models say
    # anything at all - an IsolationForest trained on 2 samples is noise, not
    # signal. below this, the worker only accumulates data.
    #
    # calibration note, found by real end-to-end testing: even at 15 samples
    # of pure, uniform, repetitive legitimate traffic (same user, same
    # endpoint, same object), the IsolationForest scored 0.767 - moderately
    # "anomalous" for genuinely boring traffic. Small-sample IsolationForest
    # scores are inherently noisy; this isn't a bug in the fusion logic, it's
    # a property of training a model on very little data. Raised the floor to
    # reduce that noise. It is NOT eliminated by this alone - what actually
    # protects against it is that ml_anomaly is always a soft signal: alone
    # it can challenge (step-up auth) but never block, and blocking requires
    # a second, independent corroborating signal (fuse_signals' 2+ soft
    # signal rule). Don't rely on threshold-tuning alone to fix ML noise;
    # the corroboration requirement is the real safety net.
    min_samples_to_score: int = int(os.environ.get("ML_MIN_SAMPLES", "25"))

    # retrain the per-entity IsolationForest every N new allowed samples, not on
    # every single event - real cost control for "scale to thousands of entities"
    retrain_every_n_samples: int = int(os.environ.get("ML_RETRAIN_EVERY_N", "5"))

    isolation_forest_threshold: float = float(os.environ.get("ML_ISOLATION_THRESHOLD", "0.7"))
    markov_probability_threshold: float = float(os.environ.get("ML_MARKOV_THRESHOLD", "0.1"))

    ml_risk_weights = {
        "isolation_forest": 0.4,
        "markov_sequence": 0.3,
        "graph_novelty": 0.3,
    }

    ml_risk_ttl_sec: int = 300
    profile_ttl_sec: int = 300


settings = MLSettings()
