"""
NeuroBots Threat Intelligence Correlation Feed.

Maintains a local threat intelligence database of attacker fingerprints,
cross-correlates traffic patterns, and generates IOC (Indicators of Compromise)
reports with automated bot detection via timing analysis.
"""

import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any


def _fingerprint(alerts: list) -> str:
    """Generate a behaviour fingerprint from an attacker's request pattern."""
    detectors = sorted({sig.get("signal", "") for a in alerts for sig in a.get("signals", [])})
    paths = sorted({a.get("path", "") for a in alerts})
    methods = sorted({a.get("method", "") for a in alerts})
    pattern = f"{','.join(methods)}|{','.join(paths[:5])}|{','.join(detectors)}"
    return hashlib.sha256(pattern.encode()).hexdigest()[:16]


def _timing_analysis(alerts: list) -> Dict[str, Any]:
    """Analyze request timing patterns for bot vs. human classification."""
    timestamps: list = []
    for a in alerts:
        ts_str = a.get("timestamp", "")
        try:
            if ts_str.endswith("Z"):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = datetime.fromisoformat(ts_str)
            timestamps.append(ts.timestamp())
        except Exception:
            continue

    if len(timestamps) < 3:
        return {"pattern": "insufficient_data", "avg_interval_sec": 0, "regularity_score": 0, "total_duration_sec": 0}

    timestamps.sort()
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

    avg_interval = sum(intervals) / len(intervals)
    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)

    if avg_interval > 0:
        cv = (variance ** 0.5) / avg_interval
        regularity = max(0, min(100, 100 - int(cv * 100)))
    else:
        regularity = 0

    if regularity > 80:
        pattern = "automated_bot"
    elif regularity > 50:
        pattern = "scripted_tool"
    else:
        pattern = "human_interactive"

    return {
        "pattern": pattern,
        "avg_interval_sec": round(avg_interval, 2),
        "regularity_score": regularity,
        "total_duration_sec": round(timestamps[-1] - timestamps[0], 1),
    }


def generate_threat_intel(
    alerts: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build threat intelligence report with IOCs and attacker profiles."""
    now = datetime.now(timezone.utc)

    by_subject: Dict[str, list] = defaultdict(list)
    for alert in alerts:
        by_subject[alert.get("subject", "unknown")].append(alert)

    iocs = []
    attack_signatures: Dict[str, list] = defaultdict(list)

    for subject, subject_alerts in by_subject.items():
        hostile = [a for a in subject_alerts if a.get("decision") in ("block", "challenge")]
        if not hostile:
            continue

        detectors: Counter = Counter()
        owasp_cats: Counter = Counter()
        mitre_techs: Counter = Counter()
        paths_hit: Counter = Counter()
        ips_used: set = set()

        for a in subject_alerts:
            paths_hit[a.get("path", "")] += 1
            if a.get("ip"):
                ips_used.add(a["ip"])
            for sig in a.get("signals", []):
                detectors[sig.get("signal", "")] += 1
                owasp_cats[sig.get("owasp", "")] += 1
                mitre_techs[sig.get("mitre", "")] += 1

        timing = _timing_analysis(subject_alerts)
        fp = _fingerprint(subject_alerts)

        total = len(subject_alerts)
        blocked_pct = len(hostile) / max(total, 1) * 100

        if blocked_pct > 80 and total > 5:
            classification, confidence = "confirmed_threat", "high"
        elif blocked_pct > 50:
            classification, confidence = "probable_threat", "medium"
        elif blocked_pct > 20:
            classification, confidence = "suspicious", "low"
        else:
            classification, confidence = "low_risk", "informational"

        iocs.append({
            "subject": subject,
            "fingerprint": fp,
            "classification": classification,
            "confidence": confidence,
            "total_requests": total,
            "blocked_requests": len(hostile),
            "block_rate": round(blocked_pct, 1),
            "distinct_ips": sorted(ips_used),
            "top_paths": [p for p, _ in paths_hit.most_common(5)],
            "top_detectors": [{"detector": d, "count": c} for d, c in detectors.most_common(5)],
            "owasp_categories": [cat for cat, _ in owasp_cats.most_common(3)],
            "mitre_techniques": [tech for tech, _ in mitre_techs.most_common(3)],
            "timing_analysis": timing,
            "mitigated": any(i.get("target") == subject for i in incidents),
            "peak_risk": max((a.get("risk", 0) for a in subject_alerts), default=0),
        })

        attack_signatures[fp].append(subject)

    # Sort by threat severity
    severity_order = {"confirmed_threat": 0, "probable_threat": 1, "suspicious": 2, "low_risk": 3}
    iocs.sort(key=lambda x: (severity_order.get(x["classification"], 99), -x["total_requests"]))

    # Cross-correlation: coordinated campaigns sharing fingerprints
    coordinated_campaigns = [
        {
            "fingerprint": fp,
            "subjects": subjects,
            "subject_count": len(subjects),
            "assessment": "Coordinated campaign — multiple subjects using identical attack patterns",
        }
        for fp, subjects in attack_signatures.items()
        if len(subjects) >= 2
    ]

    total_threats = len(iocs)
    return {
        "engine": "NeuroBots Threat Intelligence Correlation v1.0",
        "generated_at": now.isoformat() + "Z",
        "summary": {
            "total_threat_actors": total_threats,
            "confirmed_threats": len([i for i in iocs if i["classification"] == "confirmed_threat"]),
            "probable_threats": len([i for i in iocs if i["classification"] == "probable_threat"]),
            "automated_bots_detected": len([i for i in iocs if i["timing_analysis"]["pattern"] == "automated_bot"]),
            "coordinated_campaigns": len(coordinated_campaigns),
        },
        "iocs": iocs[:30],
        "coordinated_campaigns": coordinated_campaigns,
        "global_detectors": dict(Counter(
            sig.get("signal", "") for a in alerts for sig in a.get("signals", [])
        ).most_common(10)),
    }
