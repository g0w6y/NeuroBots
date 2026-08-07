"""
Four additional OWASP API Top 10 (2023) detectors, closing the gap from
5/10 to 9/10 coverage. API10 (Unsafe Consumption of APIs) is deliberately
NOT attempted here - it's about the backend's own outbound calls to third
party APIs, which an inbound reverse-proxy gateway has no visibility into
without a fundamentally different architecture (an egress monitor). Don't
claim it; it isn't real.

Each function here is pure - no I/O, no side effects, easy to test in
isolation and easy to verify does exactly what it claims.
"""

import ipaddress
import re
from urllib.parse import urlparse
from typing import Optional
from detect import Signal


# ---------------------------------------------------------------------------
# API3:2023 Broken Object Property Level Authorization (excessive data exposure)
# ---------------------------------------------------------------------------
# Response-body inspection: fields listed here are masked in the response
# unless the requester holds one of the allowed roles. This is real field-level
# redaction on the actual response body the client receives, not just a signal
# raised after the fact - the sensitive value never reaches an unauthorized
# caller. Policy is intentionally simple (resource -> field -> allowed roles);
# a real deployment would source this from the same schema the upstream API
# itself uses, not a hand-maintained table like this demo one.
SENSITIVE_FIELDS = {
    "account": {
        "ssn": {"allowed_roles": ["admin"]},
        "tax_id": {"allowed_roles": ["admin"]},
    },
}


def _mask(value) -> str:
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return "*" * (len(s) - 4) + s[-4:]


def inspect_response_body(resource: str, body, roles: list) -> tuple:
    """
    Returns (possibly-redacted body, violations). Non-dict bodies (lists,
    scalars, non-JSON) pass through unchanged - this only ever redacts
    fields it explicitly recognizes, never guesses.
    """
    policy = SENSITIVE_FIELDS.get(resource)
    if not policy or not isinstance(body, dict):
        return body, []

    redacted = dict(body)
    violations = []
    for field, rule in policy.items():
        if field not in redacted:
            continue
        allowed = any(r in rule.get("allowed_roles", []) for r in roles)
        if not allowed:
            violations.append(field)
            redacted[field] = _mask(redacted[field])
    return redacted, violations


def excessive_exposure_signal(resource: str, violations: list, subject: str) -> Optional[Signal]:
    if not violations:
        return None
    return Signal(
        "excessive_data_exposure_prevented",
        20,
        "API3:2023 Broken Object Property Level Authorization",
        "T1005 Data from Local System",
        f"redacted {len(violations)} restricted field(s) from {resource} response for {subject}: {', '.join(violations)}",
        hard=False,
    )


# ---------------------------------------------------------------------------
# API7:2023 Server Side Request Forgery
# ---------------------------------------------------------------------------
# Real SSRF prevention for a reverse-proxy gateway looks like URL allowlisting
# at the edge: scan request bodies for URL-shaped fields and block anything
# targeting a private/internal address range before it ever reaches the
# upstream, which is exactly the class of request an SSRF exploit sends (e.g.
# a "fetch this URL" field pointed at the cloud metadata endpoint or an
# internal service). This can't catch SSRF via a DNS name that only resolves
# internally without an actual DNS lookup (deliberately not added here - a
# synchronous DNS resolution on the hot request path is a real latency and
# availability risk of its own); heuristic hostname suffixes are checked
# instead as a best-effort backstop, not a complete solution.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, includes 169.254.169.254 cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
_INTERNAL_SUFFIXES = (".internal", ".local", ".corp", ".lan")


def _is_private_target(url: str) -> bool:
    try:
        host = urlparse(url).hostname
    except Exception:
        return False
    if not host:
        return False
    if host == "localhost" or host.endswith(_INTERNAL_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False  # a normal external hostname, not an IP - not flagged


def scan_body_for_ssrf(body) -> list:
    """Recursively walk a parsed JSON body, return every URL string found
    that targets a private/internal address."""
    hits = []

    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str) and _URL_PATTERN.match(obj) and _is_private_target(obj):
            hits.append(obj)

    walk(body)
    return hits


def ssrf_signal(hits: list, subject: str) -> Optional[Signal]:
    if not hits:
        return None
    return Signal(
        "ssrf_internal_target",
        90,
        "API7:2023 Server Side Request Forgery",
        "T1090 Proxy",
        f"{subject} submitted a request body containing {len(hits)} URL(s) targeting a private/internal address: {hits[0]}",
        hard=True,
    )


# ---------------------------------------------------------------------------
# API8:2023 Security Misconfiguration
# ---------------------------------------------------------------------------
# Two real, narrow, honestly-scoped pieces: (1) security response headers
# enforced on every response, (2) a startup/on-demand audit of this gateway's
# OWN configuration for exactly the misconfigurations most likely to matter -
# default secrets and permissive CORS. This does not attempt to audit the
# upstream API's configuration, which this gateway has no visibility into.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Permitted-Cross-Domain-Policies": "none",
}


def audit_config(settings) -> list:
    warnings = []
    if settings.jwt_secret == "demo-hs256-secret-change-me":
        warnings.append("JWT_SECRET is still the default demo value - rotate before any real deployment")
    if settings.admin_api_key == "changeme-admin-key":
        warnings.append("ADMIN_API_KEY is still the default demo value - rotate before any real deployment")
    if settings.cors_allowed_origins.strip() == "*":
        warnings.append("CORS_ALLOWED_ORIGINS is wildcard (*) - fine for a local demo, not for production")
    if not getattr(settings, "tls_enabled", False):
        warnings.append("TLS is not enabled - traffic to this gateway is unencrypted")
    if settings.database_url.startswith("postgresql://user:password@"):
        warnings.append("DATABASE_URL is still the default demo credential - rotate before any real deployment")
    return warnings


# ---------------------------------------------------------------------------
# API9:2023 Improper Inventory Management
# ---------------------------------------------------------------------------
# Visibility, deliberately not enforcement: a request to a path that matches
# no known route in this gateway's route table is exactly what "improper
# inventory management" describes - traffic to an undocumented or forgotten
# endpoint. This is flagged as a soft, informational signal (weight low
# enough that it can never trigger anything alone), not hard-blocked -
# blocking every unrecognized path would break legitimate traffic to
# endpoints this gateway's route table simply hasn't been told about yet
# (a health check, a newly added upstream route), which is a functional
# regression, not a security improvement.
def shadow_endpoint_signal(path: str, subject: str) -> Optional[Signal]:
    if not path.startswith("/api/"):
        return None
    return Signal(
        "shadow_endpoint_access",
        30,
        "API9:2023 Improper Inventory Management",
        "T1595 Active Scanning",
        f"{subject} accessed {path}, which matches no route in this gateway's inventory",
        hard=False,
    )
