"""
NeuroBots Predictive Threat Forecasting Engine.

Time-series entropy analysis on the alert stream to predict future attack waves.
Uses sliding-window Shannon entropy, exponential smoothing, and confidence
intervals to forecast threat volume 5 minutes into the future.
"""

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any


def _shannon_entropy(values: list) -> float:
    """Shannon entropy of a discrete distribution — measures attack diversity."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _exponential_smoothing(series: list, alpha: float = 0.3) -> list:
    """Simple exponential smoothing for time-series forecasting."""
    if not series:
        return []
    smoothed = [series[0]]
    for val in series[1:]:
        smoothed.append(alpha * val + (1 - alpha) * smoothed[-1])
    return smoothed


def generate_threat_forecast(
    alerts: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Analyze the alert stream and predict future threat activity."""
    now = datetime.now(timezone.utc)

    BUCKET_MINUTES = 1
    NUM_BUCKETS = 60

    buckets: Dict[int, dict] = defaultdict(
        lambda: {"total": 0, "blocked": 0, "challenged": 0, "detectors": [], "risk_scores": []}
    )

    for alert in alerts:
        ts_str = alert.get("time", "")
        try:
            if ts_str.endswith("Z"):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            continue

        age_minutes = (now - ts).total_seconds() / 60
        if age_minutes < 0 or age_minutes > NUM_BUCKETS:
            continue

        idx = int(age_minutes / BUCKET_MINUTES)
        bucket = buckets[idx]
        bucket["total"] += 1

        decision = alert.get("decision", "allow")
        if decision == "block":
            bucket["blocked"] += 1
        elif decision == "challenge":
            bucket["challenged"] += 1

        for sig in alert.get("signals", []):
            bucket["detectors"].append(sig.get("detector", ""))

        bucket["risk_scores"].append(alert.get("risk", 0))

    # Build chronological series (oldest → newest)
    threat_series = []
    entropy_series = []
    risk_series = []

    for i in range(NUM_BUCKETS - 1, -1, -1):
        b = buckets.get(i, {"total": 0, "blocked": 0, "challenged": 0, "detectors": [], "risk_scores": []})
        threat_series.append(b["total"])
        entropy_series.append(_shannon_entropy(b["detectors"]))
        risk_series.append(sum(b["risk_scores"]) / max(len(b["risk_scores"]), 1))

    # Smoothed forecasts
    smoothed_threats = _exponential_smoothing(threat_series, alpha=0.3)
    smoothed_entropy = _exponential_smoothing(entropy_series, alpha=0.25)
    smoothed_risk = _exponential_smoothing(risk_series, alpha=0.3)

    # Trend from the most recent 10 minutes
    recent_window = threat_series[-10:] if len(threat_series) >= 10 else threat_series
    trend = (recent_window[-1] - recent_window[0]) / max(len(recent_window), 1) if len(recent_window) >= 2 else 0

    # Forecast next 5 minutes
    forecast_horizon = 5
    last_threat = smoothed_threats[-1] if smoothed_threats else 0
    last_risk = smoothed_risk[-1] if smoothed_risk else 0

    forecast_threats = [round(max(0, last_threat + trend * i), 1) for i in range(1, forecast_horizon + 1)]
    forecast_risk = [round(max(0, min(100, last_risk + trend * i * 0.5)), 1) for i in range(1, forecast_horizon + 1)]

    # Confidence interval
    if len(recent_window) >= 3:
        mean = sum(recent_window) / len(recent_window)
        variance = sum((x - mean) ** 2 for x in recent_window) / len(recent_window)
        std_dev = math.sqrt(variance)
    else:
        std_dev = 0

    # Threat level
    current_rate = threat_series[-1] if threat_series else 0
    avg_rate = sum(threat_series) / max(len(threat_series), 1)

    if current_rate > avg_rate * 3:
        threat_level, threat_trend = "CRITICAL", "escalating"
    elif current_rate > avg_rate * 2:
        threat_level, threat_trend = "HIGH", "elevated"
    elif current_rate > avg_rate:
        threat_level, threat_trend = "MODERATE", "rising"
    elif current_rate > 0:
        threat_level, threat_trend = "LOW", "stable"
    else:
        threat_level, threat_trend = "MINIMAL", "quiet"

    # Entropy-based diversity assessment
    current_entropy = entropy_series[-1] if entropy_series else 0
    avg_entropy = sum(entropy_series) / max(len(entropy_series), 1)

    if current_entropy > avg_entropy * 1.5 and current_entropy > 1.5:
        diversity = "Multi-vector campaign — probing multiple attack surfaces simultaneously"
    elif current_entropy > 1.0:
        diversity = "Moderate attack diversity — multiple detection categories active"
    elif current_entropy > 0:
        diversity = "Focused attack — single vector exploitation attempt"
    else:
        diversity = "No active threat vectors in the current window"

    # Timeline for visualization
    timeline = [
        {
            "minute": i - NUM_BUCKETS + 1,
            "threats": threat_series[i],
            "smoothed": round(smoothed_threats[i], 1) if i < len(smoothed_threats) else 0,
            "entropy": round(entropy_series[i], 2) if i < len(entropy_series) else 0,
            "avg_risk": round(risk_series[i], 1) if i < len(risk_series) else 0,
        }
        for i in range(len(threat_series))
    ]

    return {
        "engine": "NeuroBots Predictive Threat Forecasting v1.0",
        "generated_at": now.isoformat() + "Z",
        "current_state": {
            "threat_level": threat_level,
            "threat_trend": threat_trend,
            "current_rate": current_rate,
            "average_rate": round(avg_rate, 1),
            "current_entropy": round(current_entropy, 2),
            "diversity_assessment": diversity,
        },
        "forecast": {
            "horizon_minutes": forecast_horizon,
            "predicted_threats": forecast_threats,
            "predicted_risk": forecast_risk,
            "confidence_band": round(std_dev * 1.96, 1),
            "trend_per_minute": round(trend, 2),
        },
        "timeline": timeline,
        "incidents_in_window": len(incidents),
    }
