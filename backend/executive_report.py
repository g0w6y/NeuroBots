"""
Executive reporting: aggregates already-decided facts (alerts, incidents)
into a summary a non-technical stakeholder can read. Deterministic and
template-based, not a live LLM call - the same principle already applied to
the Guardian narrative agent (agents.py): summarizing decisions is fine,
deciding them is not, and an LLM should never be the thing that decides a
security verdict. Nothing here computes a new risk score or changes any
decision - it only counts and ranks what already happened.
"""

from collections import Counter
from datetime import datetime, timezone


def generate_executive_report(alerts: list, incidents: list) -> dict:
    total = len(alerts)
    blocked = sum(1 for a in alerts if a.get("decision") == "block")
    challenged = sum(1 for a in alerts if a.get("decision") == "challenge")
    allowed = sum(1 for a in alerts if a.get("decision") in ("allow", "observe"))

    owasp_counts = Counter()
    mitre_counts = Counter()
    subject_peak_risk = {}
    subject_blocks = Counter()

    for a in alerts:
        for s in a.get("signals", []):
            owasp = (s.get("owasp") or "").split(":")[0]
            mitre = (s.get("mitre") or "").split(" ")[0]
            if owasp:
                owasp_counts[owasp] += 1
            if mitre:
                mitre_counts[mitre] += 1

        subject = a.get("subject", "")
        risk = a.get("risk", 0)
        if subject:
            subject_peak_risk[subject] = max(subject_peak_risk.get(subject, 0), risk)
            if a.get("decision") == "block":
                subject_blocks[subject] += 1

    top_risky = sorted(subject_peak_risk.items(), key=lambda kv: -kv[1])[:10]
    top_offenders = subject_blocks.most_common(10)
    block_rate_pct = round((blocked / total) * 100, 1) if total else 0.0

    lines = [f"{total} requests reviewed in this period. {blocked} blocked ({block_rate_pct}%), {challenged} challenged, {allowed} allowed."]

    if owasp_counts:
        top3 = owasp_counts.most_common(3)
        lines.append("Top attack categories: " + ", ".join(f"{k} ({v})" for k, v in top3) + ".")

    if top_offenders:
        top3 = top_offenders[:3]
        lines.append("Most-blocked identities: " + ", ".join(f"{k} ({v} blocks)" for k, v in top3) + ".")

    if incidents:
        lines.append(f"{len(incidents)} autonomous mitigation event(s) in this period - repeat offenders were automatically contained without human intervention.")
    else:
        lines.append("No autonomous mitigation events in this period.")

    if total == 0:
        lines = ["No traffic recorded in this period."]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "period_requests_reviewed": total,
        "summary": {
            "blocked": blocked,
            "challenged": challenged,
            "allowed": allowed,
            "block_rate_pct": block_rate_pct,
        },
        "owasp_breakdown": dict(owasp_counts),
        "mitre_breakdown": dict(mitre_counts),
        "top_risky_entities": [{"subject": s, "peak_risk": r} for s, r in top_risky],
        "most_blocked_entities": [{"subject": s, "block_count": c} for s, c in top_offenders],
        "autonomous_mitigation_events": len(incidents),
        "narrative": " ".join(lines),
    }
