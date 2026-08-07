from typing import List, Dict, Optional
from datetime import datetime
import json
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
    hard_signals = [s for s in signals if s.hard]
    soft_signals = [s for s in signals if not s.hard]
    hard_score = max((s.weight for s in hard_signals), default=0)

    # The documented policy is "hard signal -> block; 2+ corroborating soft ->
    # block; single soft -> challenge", but the score alone did not encode that:
    # a lone behavioural signal is scored at its full weight, and both live soft
    # detectors peak above the 70 block threshold (sequence anomaly 80, volume
    # spike 75). So one uncorroborated *inference* could slam the door on its
    # own. Verified against the running gateway: a legitimate subject that merely
    # sped up - 22 req/10s against its usual 5, under both the 25/3s burst limit
    # and the 120/60s sustained limit, nothing forged, nothing it did not own -
    # produced a bare control_plane_anomaly and nothing else. Behaviour unlike
    # your own past behaviour is not proof of intent; it is a reason to ask the
    # user to prove who they are, which is exactly what `challenge` is for.
    corroborated = bool(hard_signals) or len(soft_signals) >= 2

    if hard_score >= threshold_block:
        return "block"

    if score >= threshold_block and corroborated:
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


# ----------------------------------------------------- API3: response inspection
#
# OWASP API3:2023 Excessive Data Exposure. Every other check in this file runs on
# the REQUEST and asks "should this caller reach this endpoint?". This one runs on
# the RESPONSE and asks a question no request-side check can: "did the upstream
# hand back more than this caller should see?"
#
# That distinction is the whole point. The upstream in this demo is deliberately
# vulnerable - it returns whatever it has, with no field-level filtering - which
# is exactly the real-world pattern where a mobile client is trusted to hide
# fields the server sent anyway. An authorized GET on an object you own can still
# leak a password hash, an internal note or somebody else's record nested in the
# payload, and the request looked perfectly legitimate.
#
# Detection is deliberately conservative, because this signal fires on traffic
# that already passed authorization. A false positive here means blocking a real
# user on a legitimate read, which is the failure this gateway is measured on. So:
#   - sensitive field names are matched exactly, not by substring ("account_id"
#     must not trip a rule aimed at "id_number")
#   - cross-tenant leakage is only reported when an owner field genuinely
#     disagrees with the caller, never when it is simply absent
#   - it emits a SOFT signal by default. The data has already been served by the
#     time we see it, so blocking the response is not a containment win; the win
#     is the audit record and the corroboration it lends to other signals.

# Field names that should never leave the API, at any level of nesting. Exact
# match on the key, case-insensitive.
SENSITIVE_FIELDS = {
    "password", "passwd", "password_hash", "pwd_hash", "hash",
    "ssn", "social_security_number", "national_id", "aadhaar",
    "card_number", "cvv", "pan", "full_card",
    "private_key", "secret", "api_key", "api_secret", "client_secret",
    "session_token", "refresh_token", "mfa_secret", "totp_secret",
    "internal_note", "internal_notes", "admin_comment", "debug",
}

# Keys whose value names the owning subject, used for the cross-tenant check.
OWNER_FIELDS = {"owner", "owner_id", "user", "user_id", "subject", "account_owner", "customer_id"}

# Beyond this many records in one response, the caller is being handed a
# collection rather than a record - the shape of a data-dump, not a lookup.
BULK_RECORD_THRESHOLD = 50

MAX_INSPECT_BYTES = 512 * 1024


def _walk(node, found_fields, owners, depth=0, records=0):
    """Single recursive pass collecting sensitive keys, owner values and record count."""
    # Depth cap: a hostile or merely pathological upstream can return deeply
    # nested JSON, and this runs on the response path of every allowed request.
    if depth > 12:
        return records
    if isinstance(node, dict):
        for k, v in node.items():
            kl = str(k).lower()
            if kl in SENSITIVE_FIELDS:
                found_fields.add(kl)
            if kl in OWNER_FIELDS and isinstance(v, (str, int)):
                owners.add(str(v))
            records = _walk(v, found_fields, owners, depth + 1, records)
    elif isinstance(node, list):
        records += len(node)
        for item in node:
            records = _walk(item, found_fields, owners, depth + 1, records)
    return records


def inspect_response(body: bytes, content_type: str, subject: str, path: str,
                     roles: List[str] | None = None) -> List[Signal]:
    """API3 checks over an upstream response. Returns [] for anything not JSON."""
    signals: List[Signal] = []

    if not body or "json" not in (content_type or "").lower():
        return signals
    # An oversized body is itself worth noting, but parsing it on the response
    # path is not worth the latency - and truncating would produce invalid JSON.
    if len(body) > MAX_INSPECT_BYTES:
        signals.append(Signal(
            detector="excessive_data_exposure_size",
            weight=30,
            owasp="API3:2023 Broken Object Property Level Authorization",
            mitre="T1119 Automated Collection",
            evidence=f"upstream returned {len(body) // 1024}KB for {path}, above the {MAX_INSPECT_BYTES // 1024}KB inspection ceiling",
            hard=False,
        ))
        return signals

    try:
        parsed = json.loads(body)
    except Exception:
        return signals

    found_fields: set = set()
    owners: set = set()
    records = _walk(parsed, found_fields, owners)

    if found_fields:
        signals.append(Signal(
            detector="excessive_data_exposure",
            weight=45,
            owasp="API3:2023 Broken Object Property Level Authorization",
            mitre="T1119 Automated Collection",
            evidence=f"response for {path} exposed sensitive field(s): {', '.join(sorted(found_fields))}",
            hard=False,
        ))

    # Cross-tenant: the response names an owner, and none of the named owners is
    # the caller. Only meaningful for an authenticated, non-admin caller - an
    # admin listing every user legitimately sees other people's records, and an
    # anonymous subject has no identity to compare against.
    is_admin = "admin" in (roles or [])
    if owners and subject and not subject.startswith("anon:") and not is_admin:
        if subject not in owners:
            signals.append(Signal(
                detector="cross_tenant_data_exposure",
                weight=55,
                owasp="API3:2023 Broken Object Property Level Authorization",
                mitre="T1530 Data from Cloud Storage",
                evidence=f"response for {path} carried records owned by {', '.join(sorted(owners)[:3])}, not {subject}",
                hard=False,
            ))

    if records > BULK_RECORD_THRESHOLD and not is_admin:
        signals.append(Signal(
            detector="bulk_data_exposure",
            weight=40,
            owasp="API3:2023 Broken Object Property Level Authorization",
            mitre="T1119 Automated Collection",
            evidence=f"response for {path} returned {records} records to a non-admin caller",
            hard=False,
        ))

    return signals
