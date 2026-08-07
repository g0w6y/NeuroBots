from fastapi import FastAPI, Request, Header, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import time
import json
import os
import asyncio
from collections import defaultdict
from datetime import datetime
from config import settings
from auth import validate_jwt, jwt_error_signal
from detect import Signal, check_bola, check_bfla, check_rate_limit, check_missing_token, check_enumeration, fuse_signals, explain_decision
from agents import control_plane, generate_narrative
from store import store
from audit_log import audit_log


def utc_iso(dt: datetime = None) -> str:
    # datetime.utcnow().isoformat() produces a naive string with no timezone
    # marker (e.g. "2026-08-07T17:37:10"). A browser's `new Date(...)` treats
    # that as LOCAL time, not UTC, so every timestamp the frontend renders is
    # off by exactly the client's UTC offset. Every timestamp that leaves this
    # process as JSON must go through this helper instead of a bare isoformat().
    d = dt if dt is not None else datetime.utcnow()
    return d.isoformat() + "Z"


def require_admin(x_admin_key: str = Header(default="")):
    if x_admin_key != settings.admin_api_key:
        raise HTTPException(status_code=401, detail="admin auth required")


app = FastAPI(title="NeuroBots API Security Gateway")

_cors_origins = ["*"] if settings.cors_allowed_origins.strip() == "*" else [
    o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,  # auth is a header (X-Admin-Key/Authorization), never a cookie -
                               # wildcard origin + credentialed requests is what browsers block anyway
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    await store.connect()
    if store.connected:
        control_plane.use_client(store.redis_client)
    await control_plane.start()
    await audit_log.connect()
    await load_ownership_seed()


@app.on_event("shutdown")
async def shutdown_event():
    await control_plane.stop()
    await store.close()
    await audit_log.close()


class EntityProfile:
    def __init__(self, subject_id):
        self.subject_id = subject_id
        self.first_seen = datetime.utcnow()
        self.objects = defaultdict(set)
        self.roles = []
        self.tenant = ""
        self.risk_score = 0


entities = {}


def get_entity(subject_id: str) -> EntityProfile:
    if subject_id not in entities:
        entities[subject_id] = EntityProfile(subject_id)
    return entities[subject_id]


def client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def load_ownership_seed():
    if not os.path.exists(settings.ownership_seed_file):
        return
    try:
        with open(settings.ownership_seed_file) as f:
            seed = json.load(f)
        count = 0
        for resource, objects in seed.items():
            for object_id, subjects in objects.items():
                for subj in subjects:
                    await store.grant_ownership(resource, object_id, subj)
                    count += 1
        print(f"Ownership seed loaded: {count} grants from {settings.ownership_seed_file}")
    except Exception as e:
        print(f"Ownership seed load failed: {e}")


ROUTES = [
    ("GET", ["api", "accounts", "{id}"], {"resource": "account", "object_param": "id", "required_roles": [], "require_auth": True}),
    ("GET", ["api", "accounts", "{id}", "transactions"], {"resource": "account", "object_param": "id", "required_roles": [], "require_auth": True}),
    ("POST", ["api", "transfers"], {"resource": "transfer", "object_param": "", "required_roles": [], "require_auth": True}),
    ("GET", ["api", "admin", "users"], {"resource": "admin", "object_param": "", "required_roles": ["admin"], "require_auth": True}),
    ("GET", ["api", "admin", "audit"], {"resource": "admin", "object_param": "", "required_roles": ["admin"], "require_auth": True}),
]


def match_route(method: str, path: str) -> tuple:
    segments = [s for s in path.split("/") if s]
    for r_method, pattern, config in ROUTES:
        if r_method != method or len(pattern) != len(segments):
            continue
        params = {}
        matched = True
        for p_seg, r_seg in zip(pattern, segments):
            if p_seg.startswith("{") and p_seg.endswith("}"):
                params[p_seg[1:-1]] = r_seg
            elif p_seg != r_seg:
                matched = False
                break
        if matched:
            return config, params
    return None, {}


# Detectors eligible to drive autonomous escalation: signals that require deliberately
# crafted, forged, or scripted input a normally-functioning legitimate client cannot
# produce by accident. Excluded on purpose, even though each one still blocks the
# individual request: jwt_expired/jwt_not_yet_valid (normal token lifecycle, clock
# skew), jwt_bad_audience/jwt_bad_issuer (usually config/environment mismatch, not
# an attack), missing_token (client hasn't authenticated, or forgot a header once),
# bfla_role_violation (a stale bookmark or a frontend bug calling an endpoint on
# every render can trigger this repeatedly with zero malicious intent), rate_limit
# _sustained (a legitimate busy session or aggressive polling can organically cross
# 120 req/60s), bola_unprovisioned (a strict-mode config gap, not an attack),
# control_plane_anomaly (a heuristic soft signal, not a deterministic fact).
HOSTILE_ESCALATION_DETECTORS = {
    "bola_cross_user",
    "bola_enumeration",
    "jwt_alg_none",
    "jwt_alg_confusion",
    "jwt_bad_signature",
    "jwt_malformed",
    "rate_limit_burst",
}


def is_hostile_block(signals: list) -> bool:
    return any(s.hard and s.detector in HOSTILE_ESCALATION_DETECTORS for s in signals)


def build_auto_block_alert(subject: str, ip: str, method: str, path: str, blocked_until: float, reason: str, latency_ms: float) -> dict:
    return {
        "time": utc_iso(),
        "subject": subject,
        "ip": ip,
        "method": method,
        "path": path,
        "decision": "block",
        "risk": 100,
        "signals": [{
            "detector": "auto_escalated_block",
            "weight": 100,
            "owasp": "API4:2023 Unrestricted Resource Consumption",
            "mitre": "T1499 Endpoint DoS",
            "evidence": f"{reason} under active cooldown until {utc_iso(datetime.utcfromtimestamp(blocked_until))}",
            "hard": True
        }],
        "explain": f"AUTO-BLOCK (score 100) for {method} {path} by {subject} — cooldown active, no re-analysis needed ({reason})",
        "narrative": f"{subject} from {ip} is under an automatic cooldown after repeated confirmed violations ({reason}). Blocked without re-running checks.",
        "latency_ms": latency_ms,
        "status_code": 403
    }


async def escalate(key: str, reason: str, now: float) -> dict:
    esc_count = await store.increment_escalation_count(key)
    multiplier = min(esc_count, settings.auto_block_max_multiplier)
    cooldown = settings.auto_block_cooldown_sec * multiplier
    blocked_until = now + cooldown
    await store.set_blocked(key, blocked_until, cooldown)

    incident = {
        "time": utc_iso(),
        "type": "auto_block_escalation",
        "target": key,
        "target_type": "source_ip" if key.startswith("ip:") else "identity",
        "reason": reason,
        "escalation_count": esc_count,
        "cooldown_sec": cooldown,
        "blocked_until": utc_iso(datetime.utcfromtimestamp(blocked_until)),
        "blocked_until_epoch": blocked_until,
        "narrative": f"Autonomous mitigation: {key} escalated to a {cooldown}s cooldown after {reason}. This is escalation #{esc_count} for this identity/IP."
    }
    asyncio.create_task(audit_log.write_incident(incident))
    return incident


async def check_and_forward(request: Request) -> tuple[str, int, dict, object]:
    start_time = time.time()

    # step 1: extract
    method = request.method
    path = request.url.path
    ip = client_ip(request)

    # step 2: jwt validation
    jwt_result = validate_jwt(request.headers.get("Authorization", ""))
    subject = jwt_result.subject if jwt_result.valid else f"anon:{ip}"
    ip_key = f"ip:{ip}"

    entity = get_entity(subject)
    now = time.time()
    await store.record_request_time(subject, now)

    # autonomous mitigation: identity or source IP already proven hostile, short-circuit
    subject_blocked_until = await store.get_blocked_until(subject, now)
    ip_blocked_until = await store.get_blocked_until(ip_key, now)
    if subject_blocked_until or ip_blocked_until:
        if subject_blocked_until >= ip_blocked_until:
            blocked_until, reason = subject_blocked_until, "identity previously escalated"
        else:
            blocked_until, reason = ip_blocked_until, "source IP previously escalated"
        latency_ms = (time.time() - start_time) * 1000
        alert = build_auto_block_alert(subject, ip, method, path, blocked_until, reason, latency_ms)
        asyncio.create_task(audit_log.write_alert(alert))
        return "block", 403, alert, None

    route_config, path_params = match_route(method, path)
    signals = []

    if route_config and route_config.get("require_auth") and not jwt_result.valid:
        if jwt_result.present and jwt_result.problem:
            signals.append(Signal(**jwt_error_signal(jwt_result.problem)))
        else:
            missing_sig = check_missing_token(jwt_result.valid, route_config.get("require_auth", False))
            if missing_sig:
                signals.append(missing_sig)

    # step 3: rate limit (early, cheap, true sliding window)
    sustained_count = await store.count_requests_in_window(subject, now, settings.rate_limit_window_sec)
    sustained_sig = check_rate_limit(sustained_count, settings.rate_limit_requests, settings.rate_limit_window_sec, "rate_limit_sustained")
    if sustained_sig:
        signals.append(sustained_sig)

    burst_count = await store.count_requests_in_window(subject, now, settings.rate_limit_burst_sec)
    burst_sig = check_rate_limit(burst_count, settings.rate_limit_burst_requests, settings.rate_limit_burst_sec, "rate_limit_burst")
    if burst_sig:
        signals.append(burst_sig)

    # step 4: extract features + step 5: authorize (bola/bfla/enumeration)
    resource = ""
    object_id = ""
    if route_config:
        resource = route_config.get("resource", "")

        if route_config.get("required_roles"):
            bfla_sig = check_bfla(jwt_result.roles if jwt_result.valid else [], route_config["required_roles"])
            if bfla_sig:
                signals.append(bfla_sig)

        if route_config.get("object_param"):
            object_id = path_params.get(route_config["object_param"], "")
            if object_id:
                is_owner = await store.is_owner(resource, object_id, subject)
                fan_in = await store.fan_in(resource, object_id)
                bola_sig = check_bola(subject, resource, object_id, is_owner, fan_in, settings.bola_strict_mode)
                if bola_sig:
                    signals.append(bola_sig)
                else:
                    await store.grant_ownership(resource, object_id, subject)
                    entity.objects[resource].add(object_id)

                await store.record_object_hit(subject, resource, object_id, now)
                distinct_count = await store.distinct_objects_in_window(subject, resource, now, settings.enum_window_sec)
                enum_sig = check_enumeration(distinct_count, settings.enum_threshold)
                if enum_sig:
                    signals.append(enum_sig)

    # step 6: risk score (cached async anomaly, read-only, non-blocking)
    enriched_risk = await control_plane.get_enriched_risk(subject)
    if enriched_risk and not enriched_risk.get("baseline_stats", {}).get("is_learning"):
        anomaly_score = enriched_risk.get("anomaly_score", 0.0)
        anomaly_reason = enriched_risk.get("anomaly_reason", "")

        if anomaly_score > 40:
            signals.append(Signal(
                "control_plane_anomaly",
                int(anomaly_score),
                "API6:2023 Unrestricted Access to Sensitive Business Flows",
                "T1087 Account Discovery",
                f"anomaly: {anomaly_reason}",
                hard=False
            ))

    # step 7: policy decision
    action = fuse_signals(signals)
    risk_score = sum(min(s.weight, 100) for s in signals)
    if len(signals) > 1:
        risk_score = min(sum(s.weight for s in signals), 100)
    else:
        risk_score = signals[0].weight if signals else 0

    entity.risk_score = risk_score

    if action == "block" and is_hostile_block(signals):
        # identity-level escalation only applies to a verified, cryptographically
        # confirmed subject. an anon:{ip} pseudo-identity carries no real distinguishing
        # information beyond the IP itself, so escalating it at the low identity
        # threshold (3) would silently reintroduce the same shared-IP/NAT collateral
        # risk the higher ip-level threshold (10) exists specifically to avoid.
        # unauthenticated/invalid-token traffic is covered by the ip_key path only.
        ip_count = await store.record_block_event(ip_key, now, settings.auto_block_window_sec)

        if jwt_result.valid:
            subj_count = await store.record_block_event(subject, now, settings.auto_block_window_sec)
            if subj_count >= settings.auto_block_threshold:
                await escalate(subject, f"{subj_count} confirmed hostile blocks in {settings.auto_block_window_sec}s", now)

        if ip_count >= settings.auto_block_ip_threshold:
            await escalate(ip_key, f"{ip_count} confirmed hostile blocks from this source in {settings.auto_block_window_sec}s", now)

    explain = explain_decision(subject, method, path, action, risk_score, signals)
    narrative = generate_narrative(subject, method, path, action, signals)
    latency_ms = (time.time() - start_time) * 1000

    alert = {
        "time": utc_iso(),
        "subject": subject,
        "ip": ip,
        "method": method,
        "path": path,
        "decision": action,
        "risk": risk_score,
        "signals": [s.to_dict() for s in signals],
        "explain": explain,
        "narrative": narrative,
        "latency_ms": latency_ms,
        "status_code": None
    }

    # step 9: emit event to intelligence agents (async, non-blocking, fire-and-forget)
    asyncio.create_task(
        control_plane.record_request_async(subject, method, path, resource, object_id)
    )

    # status_code is finalized per-branch below, then the alert is written once it's
    # complete — writing before this would race with the later status_code assignment
    # for the forwarded case, sometimes persisting the alert without it.
    if action == "block":
        alert["status_code"] = 403
        asyncio.create_task(audit_log.write_alert(alert))
        return action, 403, alert, None
    elif action == "challenge":
        alert["status_code"] = 401
        asyncio.create_task(audit_log.write_alert(alert))
        return action, 401, alert, None
    else:
        body = await request.body()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                upstream_req = client.build_request(method, settings.upstream_url + path, content=body, headers=dict(request.headers))
                resp = await client.send(upstream_req)
                alert["status_code"] = resp.status_code
                asyncio.create_task(audit_log.write_alert(alert))
                return action, resp.status_code, alert, resp
        except Exception:
            alert["status_code"] = 502
            asyncio.create_task(audit_log.write_alert(alert))
            return action, 502, alert, None


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "shared_store_redis": "connected" if store.connected else "disconnected (in-memory fallback active)",
        "audit_log_postgres": "connected" if audit_log.connected else "disconnected (in-memory fallback active)",
        "control_plane_agent": "running" if control_plane.running else "stopped",
        "bola_strict_mode": settings.bola_strict_mode
    }


@app.get("/admin/metrics", dependencies=[Depends(require_admin)])
async def metrics():
    counts = await audit_log.counts()
    return {
        "requests": counts["requests"],
        "blocked": counts["blocked"],
        "challenged": counts["challenged"],
        "allowed": counts["allowed"],
        "entities": len(entities),
        "incidents": counts["incidents"],
        "policy": {
            "block_threshold": settings.block_threshold,
            "challenge_threshold": settings.challenge_threshold,
            "rate_limit": settings.rate_limit_requests,
            "auto_block_threshold": settings.auto_block_threshold,
            "auto_block_ip_threshold": settings.auto_block_ip_threshold,
            "bola_strict_mode": settings.bola_strict_mode
        }
    }


@app.get("/admin/alerts", dependencies=[Depends(require_admin)])
async def get_alerts():
    return await audit_log.recent_alerts()


@app.get("/admin/incidents", dependencies=[Depends(require_admin)])
async def get_incidents():
    return await audit_log.recent_incidents()


@app.get("/admin/entities", dependencies=[Depends(require_admin)])
async def get_entities():
    result = []
    now = time.time()
    for subj_id, entity in entities.items():
        blocked_until = await store.get_blocked_until(subj_id, now)
        result.append({
            "id": subj_id,
            "risk": entity.risk_score,
            "roles": entity.roles,
            "tenant": entity.tenant,
            "blocked": bool(blocked_until),
            "blocked_until": utc_iso(datetime.utcfromtimestamp(blocked_until)) if blocked_until else None
        })
    return result


@app.post("/admin/ownership", dependencies=[Depends(require_admin)])
async def provision_ownership(payload: dict):
    resource = payload.get("resource", "")
    object_id = payload.get("object_id", "")
    subject = payload.get("subject", "")
    if not (resource and object_id and subject):
        raise HTTPException(status_code=400, detail="resource, object_id, subject are required")
    await store.grant_ownership(resource, object_id, subject)
    return {"status": "granted", "resource": resource, "object_id": object_id, "subject": subject}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway(request: Request):
    action, status_code, alert, resp = await check_and_forward(request)

    if action == "block":
        return JSONResponse(
            status_code=403,
            content={"error": "blocked", "risk": alert["risk"]},
            headers={"X-ZT-Decision": "block", "X-ZT-Risk": str(alert["risk"])}
        )
    elif action == "challenge":
        return JSONResponse(
            status_code=401,
            content={"error": "step_up_required", "risk": alert["risk"]},
            headers={"X-ZT-Decision": "challenge", "WWW-Authenticate": 'Bearer error="step_up_required"'}
        )
    elif resp is not None:
        try:
            content_type = resp.headers.get("content-type", "")
            content = resp.json() if content_type.startswith("application/json") else resp.text
        except Exception:
            content = resp.text
        return JSONResponse(
            status_code=resp.status_code,
            content=content,
            headers={"X-ZT-Decision": action, "X-ZT-Risk": str(alert["risk"])}
        )
    else:
        return JSONResponse(status_code=502, content={"error": "upstream_unreachable"})


if __name__ == "__main__":
    import uvicorn
    print(f"Gateway: {settings.listen_addr}:{settings.listen_port}")
    uvicorn.run(app, host=settings.listen_addr, port=settings.listen_port)
