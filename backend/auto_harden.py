"""
NeuroBots Autonomous API Hardening Recommendation Engine.

Analyzes traffic patterns to generate actionable, endpoint-level
hardening recommendations and machine-readable route patches.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any


def generate_hardening_recommendations(
    alerts: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Analyze attack patterns and generate hardening recommendations."""
    now = datetime.now(timezone.utc)

    # Aggregate attack data per endpoint
    endpoint_attacks: Dict[str, dict] = defaultdict(lambda: {
        "total": 0, "blocked": 0, "challenged": 0,
        "attackers": set(), "detectors": Counter(),
        "owasp": Counter(), "peak_risk": 0,
    })

    for alert in alerts:
        path = alert.get("path", "")
        method = alert.get("method", "GET")
        key = f"{method} {path}"

        ep = endpoint_attacks[key]
        ep["total"] += 1

        decision = alert.get("decision", "allow")
        if decision == "block":
            ep["blocked"] += 1
        elif decision == "challenge":
            ep["challenged"] += 1

        subject = alert.get("subject", "")
        if subject:
            ep["attackers"].add(subject)

        risk = alert.get("risk", 0)
        if risk > ep["peak_risk"]:
            ep["peak_risk"] = risk

        for sig in alert.get("signals", []):
            ep["detectors"][sig.get("signal", "")] += 1
            ep["owasp"][sig.get("owasp", "")] += 1

    # Build recommendations
    recommendations = []
    route_patches = []

    for endpoint, data in sorted(
        endpoint_attacks.items(), key=lambda x: x[1]["blocked"], reverse=True
    ):
        if data["blocked"] == 0 and data["challenged"] == 0:
            continue

        parts = endpoint.split(" ", 1)
        method = parts[0] if len(parts) == 2 else "GET"
        path = parts[1] if len(parts) == 2 else endpoint

        attack_ratio = (data["blocked"] + data["challenged"]) / max(data["total"], 1)
        distinct_attackers = len(data["attackers"])
        top_detector = data["detectors"].most_common(1)[0] if data["detectors"] else ("none", 0)
        top_owasp = data["owasp"].most_common(1)[0] if data["owasp"] else ("none", 0)

        # Severity classification
        if attack_ratio > 0.5:
            severity = "critical"
        elif attack_ratio > 0.2:
            severity = "high"
        else:
            severity = "medium"

        rec: Dict[str, Any] = {
            "endpoint": endpoint,
            "method": method,
            "path": path,
            "severity": severity,
            "attack_ratio": round(attack_ratio * 100, 1),
            "distinct_attackers": distinct_attackers,
            "blocked_requests": data["blocked"],
            "peak_risk": data["peak_risk"],
            "primary_threat": top_detector[0],
            "primary_owasp": top_owasp[0],
            "actions": [],
        }

        detectors = data["detectors"]

        # Pattern-specific hardening actions
        if detectors.get("bola_cross_user", 0) > 0 or detectors.get("bola_enumeration", 0) > 0:
            bola_total = detectors.get("bola_cross_user", 0) + detectors.get("bola_enumeration", 0)
            rec["actions"].append({
                "type": "enable_strict_bola",
                "description": f"Enable strict BOLA mode — {bola_total} cross-user/enumeration events",
                "config": {"BOLA_STRICT_MODE": True},
                "priority": "critical",
            })

        if detectors.get("rate_limit_burst", 0) + detectors.get("rate_limit_sustained", 0) > 0:
            rate_total = detectors.get("rate_limit_burst", 0) + detectors.get("rate_limit_sustained", 0)
            rec["actions"].append({
                "type": "tighten_rate_limit",
                "description": f"Reduce rate limit — {rate_total} volumetric events",
                "config": {"RATE_LIMIT_BURST": "15/2s"},
                "priority": "high",
            })

        if detectors.get("bfla_role_violation", 0) > 0:
            rec["actions"].append({
                "type": "enforce_rbac",
                "description": f"Lock admin functions — {detectors['bfla_role_violation']} privilege escalation attempts",
                "config": {"required_roles": ["admin"]},
                "priority": "critical",
            })

        jwt_attacks = sum(v for k, v in detectors.items() if k.startswith("jwt_"))
        if jwt_attacks > 0:
            rec["actions"].append({
                "type": "strengthen_auth",
                "description": f"Enforce RS256 + strict audience — {jwt_attacks} credential abuse events",
                "config": {"JWT_ALGORITHMS": ["RS256"]},
                "priority": "high",
            })

        if detectors.get("missing_token", 0) > 0:
            rec["actions"].append({
                "type": "require_authentication",
                "description": f"Mandate authentication — {detectors['missing_token']} unauthenticated requests",
                "config": {"require_auth": True},
                "priority": "high",
            })

        if distinct_attackers >= 3:
            rec["actions"].append({
                "type": "enable_resource_hardening",
                "description": f"Lower hardening threshold — {distinct_attackers} distinct attackers",
                "config": {"RESOURCE_HARDENING_THRESHOLD": 2},
                "priority": "medium",
            })

        if not rec["actions"]:
            rec["actions"].append({
                "type": "monitor",
                "description": "Continue monitoring — no specific hardening action matched",
                "config": {},
                "priority": "low",
            })

        recommendations.append(rec)

        # Machine-readable route patch
        if rec["actions"] and rec["actions"][0]["type"] != "monitor":
            patch = {
                "method": method,
                "pattern": path,
                "changes": {},
            }
            for action in rec["actions"]:
                patch["changes"].update(action.get("config", {}))
            route_patches.append(patch)

    # Overall hardening score (100 = maximally hardened, 0 = fully exposed)
    total = len(endpoint_attacks)
    attacked = len([e for e in endpoint_attacks.values() if e["blocked"] > 0])
    hardening_score = max(0, 100 - int((attacked / max(total, 1)) * 100))

    return {
        "engine": "NeuroBots Autonomous Hardening Engine v1.0",
        "generated_at": now.isoformat() + "Z",
        "hardening_score": hardening_score,
        "total_endpoints_analyzed": total,
        "endpoints_under_attack": attacked,
        "recommendations": recommendations[:20],
        "route_patches": route_patches[:10],
        "autonomous_incidents": len(incidents),
    }
