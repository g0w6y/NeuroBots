"""
NeuroBots Red Team Sandbox & Attack Simulation Engine (red_team.py).

Allows operators to trigger live BOLA, BFLA, JWT manipulation, rate abuse,
and enumeration attacks directly from the console dashboard or API endpoints.
"""

import time
import jwt
from typing import Dict, Any
from config import settings


def generate_test_tokens() -> Dict[str, str]:
    now = int(time.time())
    payload_alice = {"sub": "alice", "role": "user", "iat": now, "exp": now + 3600, "jti": "jti_alice_test"}
    payload_mallory = {"sub": "mallory", "role": "user", "iat": now, "exp": now + 3600, "jti": "jti_mallory_test"}
    payload_admin = {"sub": "root", "role": "admin", "iat": now, "exp": now + 3600, "jti": "jti_admin_test"}

    token_alice = jwt.encode(payload_alice, settings.jwt_secret, algorithm="HS256")
    token_mallory = jwt.encode(payload_mallory, settings.jwt_secret, algorithm="HS256")
    token_admin = jwt.encode(payload_admin, settings.jwt_secret, algorithm="HS256")

    # Unsigned token (alg=none attack)
    token_alg_none = jwt.encode(payload_mallory, "", algorithm="none")

    return {
        "alice": token_alice,
        "mallory": token_mallory,
        "admin": token_admin,
        "alg_none": token_alg_none,
    }


def get_attack_payload(attack_type: str) -> Dict[str, Any]:
    """Builds realistic test attack request headers and path for live simulation."""
    tokens = generate_test_tokens()

    if attack_type == "bola":
        return {
            "name": "Broken Object Level Authorization (BOLA)",
            "method": "GET",
            "path": "/api/accounts/acc_101",
            "token": tokens["mallory"],
            "description": "Mallory (User B) attempts to access acc_101 owned by Alice (User A).",
            "expected_decision": "block",
            "expected_owasp": "API1:2023 Broken Object Level Authorization",
        }
    elif attack_type == "bfla":
        return {
            "name": "Broken Function Level Authorization (BFLA)",
            "method": "GET",
            "path": "/api/admin/users",
            "token": tokens["alice"],
            "description": "Alice (Standard User) attempts to access restricted Admin route.",
            "expected_decision": "block",
            "expected_owasp": "API5:2023 Broken Function Level Authorization",
        }
    elif attack_type == "alg_none":
        return {
            "name": "JWT Algorithm Confusion (alg=none)",
            "method": "GET",
            "path": "/api/accounts/acc_101",
            "token": tokens["alg_none"],
            "description": "Attacker submits unsigned JWT token with alg=none signature bypass.",
            "expected_decision": "block",
            "expected_owasp": "API2:2023 Broken Authentication",
        }
    elif attack_type == "missing_token":
        return {
            "name": "Unauthenticated Protected Route Access",
            "method": "GET",
            "path": "/api/accounts/acc_101",
            "token": "",
            "description": "Unauthenticated request hitting protected account API endpoint.",
            "expected_decision": "block",
            "expected_owasp": "API2:2023 Broken Authentication",
        }
    elif attack_type == "enumeration":
        return {
            "name": "BOLA Object ID Scraper / Enumeration",
            "method": "GET",
            "path": "/api/accounts/acc_9999",
            "token": tokens["mallory"],
            "description": "Attacker rapidly probes non-existent resource object IDs.",
            "expected_decision": "block",
            "expected_owasp": "API1:2023 Broken Object Level Authorization",
        }
    else:  # legitimate
        return {
            "name": "Legitimate Owner Access",
            "method": "GET",
            "path": "/api/accounts/acc_101",
            "token": tokens["alice"],
            "description": "Alice accesses her own authorized acc_101 resource.",
            "expected_decision": "allow",
            "expected_owasp": "None (Authorized)",
        }
