"""
NeuroBots Attack Kill Chain Reconstruction Engine.

Correlates individual alerts into multi-step attack kill chains
using temporal + identity clustering mapped to MITRE ATT&CK phases.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any


# MITRE ATT&CK Enterprise kill-chain phases mapped to our detector names.
KILL_CHAIN_PHASES = [
    {
        "phase": "Reconnaissance",
        "phase_id": "recon",
        "mitre_id": "TA0043",
        "description": "Target information gathering",
        "detectors": ["bola_enumeration", "excessive_data_exposure", "bulk_data_exposure"],
        "icon": "search",
    },
    {
        "phase": "Initial Access",
        "phase_id": "initial_access",
        "mitre_id": "TA0001",
        "description": "Credential exploitation and unauthorized entry",
        "detectors": [
            "missing_token", "jwt_alg_none", "jwt_alg_confusion", "jwt_wrong_key",
            "jwt_expired", "jwt_bad_issuer", "jwt_bad_audience", "jwt_malformed",
        ],
        "icon": "key",
    },
    {
        "phase": "Privilege Escalation",
        "phase_id": "priv_esc",
        "mitre_id": "TA0004",
        "description": "Attempting elevated permissions",
        "detectors": ["bfla_role_violation", "control_plane_anomaly"],
        "icon": "admin_panel_settings",
    },
    {
        "phase": "Lateral Movement",
        "phase_id": "lateral",
        "mitre_id": "TA0008",
        "description": "Cross-tenant and cross-object access",
        "detectors": ["bola_cross_user", "cross_tenant_data_exposure"],
        "icon": "swap_horiz",
    },
    {
        "phase": "Collection",
        "phase_id": "collection",
        "mitre_id": "TA0009",
        "description": "Automated data harvesting",
        "detectors": ["bola_enumeration", "rate_limit_sustained"],
        "icon": "inventory_2",
    },
    {
        "phase": "Impact",
        "phase_id": "impact",
        "mitre_id": "TA0040",
        "description": "Service disruption or resource exhaustion",
        "detectors": ["rate_limit_burst", "resource_hardening_active"],
        "icon": "dangerous",
    },
]

_DETECTOR_TO_PHASE: Dict[str, str] = {}
for _phase in KILL_CHAIN_PHASES:
    for _det in _phase["detectors"]:
        _DETECTOR_TO_PHASE.setdefault(_det, _phase["phase_id"])


def reconstruct_kill_chains(
    alerts: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Group alerts by identity and reconstruct multi-step attack chains."""
    now = datetime.now(timezone.utc)

    # Group by subject
    by_subject: Dict[str, list] = defaultdict(list)
    for alert in alerts:
        subject = alert.get("subject", "") or alert.get("ip", "unknown")
        by_subject[subject].append(alert)

    chains = []

    for subject, subject_alerts in by_subject.items():
        sorted_alerts = sorted(subject_alerts, key=lambda a: a.get("timestamp", ""))
        hostile = [a for a in sorted_alerts if a.get("decision") in ("block", "challenge")]
        if not hostile:
            continue

        # Map each alert to kill-chain phases
        phases_hit: Dict[str, dict] = defaultdict(
            lambda: {"count": 0, "first_seen": None, "last_seen": None, "alerts": []}
        )

        for alert in sorted_alerts:
            for sig in alert.get("signals", []):
                detector = sig.get("signal", "")
                phase_id = _DETECTOR_TO_PHASE.get(detector)
                if not phase_id:
                    continue

                phase = phases_hit[phase_id]
                phase["count"] += 1
                ts = alert.get("timestamp", "")
                if phase["first_seen"] is None or ts < phase["first_seen"]:
                    phase["first_seen"] = ts
                if phase["last_seen"] is None or ts > phase["last_seen"]:
                    phase["last_seen"] = ts
                phase["alerts"].append({
                    "id": alert.get("id", ""),
                    "timestamp": ts,
                    "detector": detector,
                    "decision": alert.get("decision", ""),
                    "risk": alert.get("risk", 0),
                    "path": alert.get("path", ""),
                })

        if not phases_hit:
            continue

        total_phases = len(KILL_CHAIN_PHASES)
        phases_completed = len(phases_hit)
        completion_pct = round((phases_completed / total_phases) * 100)

        # Phase progression timeline
        phase_progression = []
        for phase_def in KILL_CHAIN_PHASES:
            pid = phase_def["phase_id"]
            if pid in phases_hit:
                phase_progression.append({
                    "phase": phase_def["phase"],
                    "phase_id": pid,
                    "mitre_id": phase_def["mitre_id"],
                    "icon": phase_def["icon"],
                    "status": "completed",
                    "event_count": phases_hit[pid]["count"],
                    "first_seen": phases_hit[pid]["first_seen"],
                    "last_seen": phases_hit[pid]["last_seen"],
                })
            else:
                phase_progression.append({
                    "phase": phase_def["phase"],
                    "phase_id": pid,
                    "mitre_id": phase_def["mitre_id"],
                    "icon": phase_def["icon"],
                    "status": "not_observed",
                    "event_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                })

        if completion_pct >= 80:
            severity = "critical"
        elif completion_pct >= 50:
            severity = "high"
        elif completion_pct >= 30:
            severity = "medium"
        else:
            severity = "low"

        all_timestamps = [a.get("timestamp", "") for a in sorted_alerts if a.get("timestamp")]

        chains.append({
            "subject": subject,
            "severity": severity,
            "completion_pct": completion_pct,
            "phases_completed": phases_completed,
            "total_phases": total_phases,
            "total_events": len(sorted_alerts),
            "blocked_events": len([a for a in sorted_alerts if a.get("decision") == "block"]),
            "first_seen": min(all_timestamps) if all_timestamps else "",
            "last_seen": max(all_timestamps) if all_timestamps else "",
            "phase_progression": phase_progression,
            "peak_risk": max((a.get("risk", 0) for a in sorted_alerts), default=0),
            "mitigated": any(i.get("target") == subject for i in incidents),
        })

    chains.sort(key=lambda c: (c["completion_pct"], c["total_events"]), reverse=True)

    # Phase heat map: which phases are reached most often
    phase_heat = {}
    total_chains = len(chains)
    for phase_def in KILL_CHAIN_PHASES:
        pid = phase_def["phase_id"]
        hit_count = sum(
            1 for c in chains
            if any(p["phase_id"] == pid and p["status"] == "completed" for p in c["phase_progression"])
        )
        phase_heat[pid] = {
            "phase": phase_def["phase"],
            "mitre_id": phase_def["mitre_id"],
            "chains_reaching": hit_count,
            "percentage": round((hit_count / max(total_chains, 1)) * 100),
        }

    return {
        "engine": "NeuroBots Kill Chain Reconstruction v1.0",
        "generated_at": now.isoformat() + "Z",
        "total_chains": total_chains,
        "critical_chains": len([c for c in chains if c["severity"] == "critical"]),
        "high_chains": len([c for c in chains if c["severity"] == "high"]),
        "chains": chains[:25],
        "phase_definitions": KILL_CHAIN_PHASES,
        "phase_heatmap": phase_heat,
    }
