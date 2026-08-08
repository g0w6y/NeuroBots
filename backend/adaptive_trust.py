"""
NeuroBots Adaptive Zero-Trust Scoring Engine.

Dynamic trust scoring that evolves based on behavioural history.
Trust builds slowly over time with clean requests and degrades rapidly
on suspicious activity, with time-based recovery for reformed subjects.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any

# Trust score parameters
INITIAL_TRUST = 50
MAX_TRUST = 100
MIN_TRUST = 0
TRUST_BUILD_RATE = 0.5      # points earned per clean request
TRUST_DECAY_BLOCK = 25      # points lost per block
TRUST_DECAY_CHALLENGE = 10  # points lost per challenge
TRUST_DECAY_OBSERVE = 2     # points lost per observe
TRUST_RECOVERY_RATE = 0.1   # points recovered per minute of inactivity

TRUST_TIERS = [
    {"tier": "Trusted",     "min": 80, "icon": "verified_user",     "color": "safe",    "policy": "Relaxed rate limits, skip step-up for low-risk operations"},
    {"tier": "Established", "min": 60, "icon": "shield",            "color": "safe",    "policy": "Standard enforcement, normal thresholds"},
    {"tier": "Neutral",     "min": 40, "icon": "person",            "color": "caution",  "policy": "Standard enforcement, baseline monitoring"},
    {"tier": "Suspicious",  "min": 20, "icon": "warning",           "color": "caution",  "policy": "Enhanced monitoring, lower challenge threshold"},
    {"tier": "Hostile",     "min":  0, "icon": "gpp_bad",           "color": "danger",   "policy": "Maximum enforcement, pre-emptive challenge on all requests"},
]


def _get_tier(score: float) -> dict:
    for tier in TRUST_TIERS:
        if score >= tier["min"]:
            return tier
    return TRUST_TIERS[-1]


def compute_trust_scores(
    alerts: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute adaptive trust scores for all observed entities."""
    now = datetime.now(timezone.utc)

    profiles: Dict[str, dict] = defaultdict(lambda: {
        "trust_score": INITIAL_TRUST,
        "total": 0, "clean": 0, "blocked": 0, "challenged": 0, "observed": 0,
        "trust_history": [],
        "detectors": set(),
        "first_seen": None, "last_seen": None,
    })

    # Process alerts chronologically to evolve trust
    for alert in sorted(alerts, key=lambda a: a.get("time", "")):
        subject = alert.get("subject", "")
        if not subject:
            continue

        p = profiles[subject]
        p["total"] += 1
        ts = alert.get("time", "")

        if p["first_seen"] is None or ts < p["first_seen"]:
            p["first_seen"] = ts
        if p["last_seen"] is None or ts > p["last_seen"]:
            p["last_seen"] = ts

        decision = alert.get("decision", "allow")
        if decision == "block":
            p["blocked"] += 1
            p["trust_score"] = max(MIN_TRUST, p["trust_score"] - TRUST_DECAY_BLOCK)
        elif decision == "challenge":
            p["challenged"] += 1
            p["trust_score"] = max(MIN_TRUST, p["trust_score"] - TRUST_DECAY_CHALLENGE)
        elif decision == "observe":
            p["observed"] += 1
            p["trust_score"] = max(MIN_TRUST, p["trust_score"] - TRUST_DECAY_OBSERVE)
        else:
            p["clean"] += 1
            p["trust_score"] = min(MAX_TRUST, p["trust_score"] + TRUST_BUILD_RATE)

        for sig in alert.get("signals", []):
            p["detectors"].add(sig.get("detector", ""))

        if p["total"] % 5 == 0:
            p["trust_history"].append({
                "event_index": p["total"],
                "trust_score": round(p["trust_score"], 1),
                "timestamp": ts,
            })

    # Time-based recovery for inactive subjects
    for subject, p in profiles.items():
        if p["last_seen"] and p["trust_score"] < INITIAL_TRUST:
            try:
                last_str = p["last_seen"]
                if last_str.endswith("Z"):
                    last = datetime.fromisoformat(last_str.replace("Z", "+00:00"))
                else:
                    last = datetime.fromisoformat(last_str)
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                idle_min = (now - last).total_seconds() / 60
                recovery = idle_min * TRUST_RECOVERY_RATE
                if recovery > 0:
                    p["trust_score"] = min(INITIAL_TRUST, p["trust_score"] + recovery)
            except Exception:
                pass

    # Build output
    scores = []
    for subject, p in profiles.items():
        tier = _get_tier(p["trust_score"])
        total = p["total"]
        scores.append({
            "subject": subject,
            "trust_score": round(p["trust_score"], 1),
            "tier": tier["tier"],
            "tier_icon": tier["icon"],
            "tier_color": tier["color"],
            "policy_effect": tier["policy"],
            "total_requests": total,
            "clean_requests": p["clean"],
            "clean_rate": round(p["clean"] / max(total, 1) * 100, 1),
            "blocked_requests": p["blocked"],
            "challenged_requests": p["challenged"],
            "detectors_triggered": sorted(p["detectors"]),
            "first_seen": p["first_seen"],
            "last_seen": p["last_seen"],
            "trust_history": p["trust_history"][-20:],
            "mitigated": any(i.get("target") == subject for i in incidents),
        })

    scores.sort(key=lambda s: s["trust_score"])

    tier_dist: Dict[str, int] = defaultdict(int)
    for s in scores:
        tier_dist[s["tier"]] += 1

    avg_trust = sum(s["trust_score"] for s in scores) / max(len(scores), 1)

    if avg_trust >= 70:
        health = "healthy"
    elif avg_trust >= 50:
        health = "moderate"
    elif avg_trust >= 30:
        health = "degraded"
    else:
        health = "compromised"

    return {
        "engine": "NeuroBots Adaptive Zero-Trust Scoring v1.0",
        "generated_at": now.isoformat() + "Z",
        "overall_health": health,
        "average_trust": round(avg_trust, 1),
        "total_entities": len(scores),
        "tier_distribution": dict(tier_dist),
        "tier_definitions": TRUST_TIERS,
        "scores": scores[:50],
    }
