from typing import List, Dict, Optional
from datetime import datetime
import time

class Signal:
    def __init__(self, detector: str, weight: int, owasp: str, mitre: str, evidence: str, hard: bool = False):
        self.detector = detector
        self.weight = weight
        self.owasp = owasp
        self.mitre = mitre
        self.evidence = evidence
        self.hard = hard

    def to_dict(self):
        return {
            "detector": self.detector,
            "weight": self.weight,
            "owasp": self.owasp,
            "mitre": self.mitre,
            "evidence": self.evidence,
            "hard": self.hard
        }

class Decision:
    def __init__(self, action: str, risk: int, signals: List[Signal], explain: str):
        self.action = action
        self.risk = risk
        self.signals = signals
        self.explain = explain

def check_bola(subject: str, resource: str, object_id: str, is_owner: bool, fan_in: int, strict: bool = False) -> Optional[Signal]:
    if not object_id:
        return None

    if is_owner:
        return None

    if fan_in == 0:
        if strict:
            return Signal(
                "bola_unprovisioned",
                80,
                "API1:2023 Broken Object Level Authorization",
                "T1078 Valid Accounts",
                f"{subject} accessed {resource}/{object_id} which has no provisioned owner (strict mode, deny by default)",
                hard=True
            )
        return None

    if fan_in <= 5:
        return Signal(
            "bola_cross_user",
            80,
            "API1:2023 Broken Object Level Authorization",
            "T1078 Valid Accounts",
            f"{subject} accessed {resource}/{object_id} not owned by them (fan-in={fan_in})",
            hard=True
        )

    return None

def check_bfla(subject_roles: List[str], required_roles: List[str]) -> Optional[Signal]:
    if not required_roles:
        return None

    has_role = any(role.lower() in [r.lower() for r in required_roles] for role in subject_roles)
    if not has_role:
        return Signal(
            "bfla_role_violation",
            85,
            "API5:2023 Broken Function Level Authorization",
            "T1548 Abuse Elevation Control",
            f"roles {subject_roles} lack required {required_roles}",
            hard=True
        )

    return None

def check_rate_limit(request_count: int, limit: int, window_sec: int, detector: str = "rate_limit") -> Optional[Signal]:
    if request_count > limit:
        return Signal(
            detector,
            75,
            "API4:2023 Unrestricted Resource Consumption",
            "T1499 Endpoint DoS",
            f"{request_count} requests in {window_sec}s exceeds {limit}",
            hard=True
        )
    return None

def check_missing_token(jwt_valid: bool, require_auth: bool) -> Optional[Signal]:
    if require_auth and not jwt_valid:
        return Signal(
            "missing_token",
            80,
            "API2:2023 Broken Authentication",
            "T1078 Valid Accounts",
            "protected route accessed with no valid token",
            hard=True
        )
    return None

def check_enumeration(distinct_count: int, threshold: int = 8) -> Optional[Signal]:
    if distinct_count >= threshold:
        return Signal(
            "bola_enumeration",
            70,
            "API1:2023 Broken Object Level Authorization",
            "T1119 Automated Collection",
            f"{distinct_count} distinct objects accessed in window (enumeration pattern)",
            hard=True
        )
    return None

def fuse_signals(signals: List[Signal], threshold_block: int = 70, threshold_challenge: int = 45) -> str:
    if not signals:
        return "allow"

    has_hard = any(s.hard for s in signals)
    score = sum(s.weight for s in signals)
    score = min(score, 100)

    if has_hard:
        return "block"

    if score >= threshold_block and len(signals) >= 2:
        return "block"

    if score >= threshold_challenge:
        return "challenge"

    if score > 0:
        return "observe"

    return "allow"

def explain_decision(subject: str, method: str, path: str, action: str, score: int, signals: List[Signal]) -> str:
    if not signals:
        return f"{action.upper()} (score {score}) for {method} {path} by {subject}"

    signal_strs = []
    for s in signals:
        signal_strs.append(f"{s.detector} [{s.owasp} / {s.mitre}]: {s.evidence}")

    return f"{action.upper()} (score {score}) for {method} {path} by {subject} — {'; '.join(signal_strs)}"
