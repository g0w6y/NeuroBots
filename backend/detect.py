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

    # The object has a known owner set and this subject is not in it. That is a
    # BOLA violation regardless of how many owners the object has.
    #
    # This was previously gated on `fan_in <= 5`, which meant any object with six
    # or more provisioned owners - a shared team account, a joint account, a
    # family plan - silently became a permanent BOLA blind spot for everyone on
    # earth, and the accessor was then granted ownership of it. The gate had no
    # comment explaining it and no threshold can justify it: "several people own
    # this" is not evidence that a stranger may read it.
    return Signal(
        "bola_cross_user",
        80,
        "API1:2023 Broken Object Level Authorization",
        "T1078 Valid Accounts",
        f"{subject} accessed {resource}/{object_id} not owned by them (fan-in={fan_in})",
        hard=True
    )

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

def risk_score(signals: List[Signal]) -> int:
    """Fuse signal weights into a single 0-100 risk score.

    BACKEND.md Part 6 specifies max-with-cap-100. Straight summation (the
    previous behaviour) let two individually-unremarkable signals add their way
    past the block threshold, which manufactures exactly the false positive this
    gateway is measured on. Corroboration is still worth something - two
    independent detectors agreeing is stronger evidence than one - so each
    additional signal adds a small fixed bump rather than its full weight.
    """
    if not signals:
        return 0
    top = max(s.weight for s in signals)
    return min(100, top + 5 * (len(signals) - 1))


def fuse_signals(signals: List[Signal], threshold_block: int = 70, threshold_challenge: int = 45) -> str:
    if not signals:
        return "allow"

    score = risk_score(signals)

    # A "hard" signal is a determination of fact - a signature that does not
    # verify, an object the subject demonstrably does not own - rather than a
    # heuristic guess, so it is always acted on rather than merely observed.
    # But *how* firmly to act is still the score's call. An expired token is a
    # hard fact at weight 60, and the correct response there is to make the user
    # re-authenticate, not to slam the door on a paying customer whose session
    # aged out thirty seconds ago. Treating every hard signal as an automatic
    # block made the "challenge" decision unreachable in practice - the policy
    # engine advertised three outcomes and could only ever produce two - and
    # turned routine token expiry into an outage.
    hard_score = max((s.weight for s in signals if s.hard), default=0)

    if score >= threshold_block or hard_score >= threshold_block:
        return "block"

    if score >= threshold_challenge or hard_score > 0:
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
