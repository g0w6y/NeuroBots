import jwt
import json
import base64
import time
from typing import Optional, List
from datetime import datetime
from config import settings

class JWTResult:
    def __init__(self):
        self.present = False
        self.valid = False
        self.subject = ""
        self.roles = []
        self.scopes = []
        self.tenant = ""
        self.issuer = ""
        self.problem = ""

def decode_base64(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "==")
    except Exception:
        return b""

def validate_jwt(authz: str) -> JWTResult:
    result = JWTResult()

    if not authz or not authz.startswith("Bearer "):
        return result

    token = authz.replace("Bearer ", "").strip()
    if not token:
        return result

    result.present = True

    try:
        parts = token.split(".")
        if len(parts) != 3:
            result.problem = "malformed"
            return result

        header_data = json.loads(decode_base64(parts[0]))
        payload_data = json.loads(decode_base64(parts[1]))

        alg = header_data.get("alg", "").upper()

        if alg == "NONE" or alg == "":
            result.problem = "none_alg"
            return result

        if alg == "HS256":
            if settings.jwt_rsa_pub_pem:
                result.problem = "alg_confusion"
                return result
            try:
                decode_options = {"verify_exp": False, "verify_aud": False, "verify_iss": False, "verify_nbf": False}
                decoded = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], options=decode_options)
            except jwt.InvalidSignatureError:
                result.problem = "bad_sig"
                return result
            except jwt.ExpiredSignatureError:
                result.problem = "expired"
                return result
            except Exception:
                result.problem = "bad_sig"
                return result
        else:
            result.problem = "unsupported_alg"
            return result

        now = time.time()
        exp = payload_data.get("exp", 0)
        nbf = payload_data.get("nbf", 0)

        if exp and now >= exp:
            result.problem = "expired"
            return result

        if nbf and now < nbf:
            result.problem = "nbf"
            return result

        iss = payload_data.get("iss", "")
        if settings.issuer and iss != settings.issuer:
            result.problem = "bad_iss"
            return result

        aud = payload_data.get("aud", "")
        if settings.audience and aud != settings.audience:
            result.problem = "bad_aud"
            return result

        result.valid = True
        result.subject = payload_data.get("sub", "")
        result.roles = payload_data.get("roles", [])
        result.scopes = payload_data.get("scopes", [])
        result.tenant = payload_data.get("tenant", "")
        result.issuer = iss

        return result

    except Exception:
        result.problem = "malformed"
        return result

def jwt_error_signal(problem: str) -> dict:
    signals = {
        "none_alg": {"detector": "jwt_alg_none", "weight": 90, "owasp": "API2:2023 Broken Authentication", "mitre": "T1078 Valid Accounts", "evidence": "JWT with alg=none", "hard": True},
        "alg_confusion": {"detector": "jwt_alg_confusion", "weight": 90, "owasp": "API2:2023 Broken Authentication", "mitre": "T1078 Valid Accounts", "evidence": "JWT algorithm confusion", "hard": True},
        "bad_sig": {"detector": "jwt_bad_signature", "weight": 90, "owasp": "API2:2023 Broken Authentication", "mitre": "T1078 Valid Accounts", "evidence": "JWT signature invalid", "hard": True},
        "expired": {"detector": "jwt_expired", "weight": 60, "owasp": "API2:2023 Broken Authentication", "mitre": "T1078 Valid Accounts", "evidence": "JWT expired", "hard": True},
        "nbf": {"detector": "jwt_not_yet_valid", "weight": 60, "owasp": "API2:2023 Broken Authentication", "mitre": "T1078 Valid Accounts", "evidence": "JWT not yet valid", "hard": True},
        "bad_aud": {"detector": "jwt_bad_audience", "weight": 75, "owasp": "API2:2023 Broken Authentication", "mitre": "T1550 Use Alternate Auth", "evidence": "JWT audience mismatch", "hard": True},
        "bad_iss": {"detector": "jwt_bad_issuer", "weight": 75, "owasp": "API2:2023 Broken Authentication", "mitre": "T1550 Use Alternate Auth", "evidence": "JWT issuer not trusted", "hard": True},
        "malformed": {"detector": "jwt_malformed", "weight": 90, "owasp": "API2:2023 Broken Authentication", "mitre": "T1078 Valid Accounts", "evidence": "JWT malformed", "hard": True},
    }
    return signals.get(problem, {"detector": "jwt_invalid", "weight": 90, "owasp": "API2:2023 Broken Authentication", "mitre": "T1078 Valid Accounts", "evidence": "JWT invalid", "hard": True})
