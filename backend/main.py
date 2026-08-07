from fastapi import FastAPI, Request, Header, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response
import hmac
from fastapi.middleware.cors import CORSMiddleware
import httpx
import time
import json
import os
import asyncio
import itertools
from collections import defaultdict
from datetime import datetime
from config import settings
from auth import validate_jwt, jwt_error_signal
from detect import Signal, check_bola, check_bfla, check_rate_limit, check_missing_token, check_enumeration, fuse_signals, risk_score, explain_decision
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
    # constant-time: a plain != leaks key material through timing, and this is
    # the only thing standing between the internet and the full decision log
    if not hmac.compare_digest(x_admin_key, settings.admin_api_key):
        raise HTTPException(status_code=401, detail="admin auth required")


app = FastAPI(
    title="NeuroBots API Security Gateway",
    # FastAPI mounts /docs, /redoc and /openapi.json at construction, i.e. ahead
    # of the catch-all proxy route. That published the whole admin surface to
    # anyone who asked, with no X-Admin-Key, and simultaneously made those three
    # paths unreachable on any upstream that serves its own API docs.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# One pooled client for the process rather than a new one per proxied request.
# `async with httpx.AsyncClient()` inside the request path built a fresh
# connection pool, completed a fresh TCP handshake and tore it all down on every
# single forward - about 6ms of pure setup cost per request, against a stated
# budget of 15ms for the whole decision, and no keep-alive to the upstream at all.
upstream_client: httpx.AsyncClient = None

# asyncio keeps only a weak reference to a task, so a fire-and-forget
# create_task() whose handle is discarded can be garbage-collected part-way
# through. Every audit write and control-plane event was created that way, which
# means alerts could vanish from /admin/alerts under load - silently, since the
# evidence of the loss is the very record that was dropped.
_background_tasks = set()


def spawn(coro):
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


class EventHub:
    """Fan-out of decision events to connected dashboards.

    BACKEND.md Part 8 asks for decisions to be emitted to a queue or WebSocket
    so the frontend gets live updates; only 2-second polling existed, and each
    poll re-fetched up to 500 full alert objects and recomputed every derived
    metric client-side. Pushing is both cheaper and actually live.

    Polling stays as the fallback, so a dashboard that cannot hold a socket open
    still works. Broadcast is best-effort by design: a slow or dead subscriber
    is dropped rather than allowed to apply backpressure to the request path.
    """

    def __init__(self):
        self._subscribers: set = set()

    def subscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.add(queue)

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def publish(self, event_type: str, payload: dict) -> None:
        if not self._subscribers:
            return
        message = {"type": event_type, "data": payload}
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # subscriber is not keeping up; drop this event for them rather
                # than blocking the decision path on a stalled browser tab
                pass


event_hub = EventHub()


def emit_alert(alert: dict) -> None:
    """Persist a decision and push it to live subscribers.

    Both happen off the request path. The audit write is fire-and-forget (but
    retained, so it cannot be garbage-collected mid-flight); the broadcast is
    synchronous but non-blocking, since it only ever puts onto in-process queues.
    """
    spawn(audit_log.write_alert(alert))
    event_hub.publish("alert", alert)


def emit_incident(incident: dict) -> None:
    spawn(audit_log.write_incident(incident))
    event_hub.publish("incident", incident)

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
    global upstream_client
    upstream_client = httpx.AsyncClient(timeout=10)
    load_route_config()
    await store.connect()
    if store.connected:
        control_plane.use_client(store.redis_client)
    await control_plane.start()
    await audit_log.connect()
    await load_ownership_seed()
    spawn(entity_sweeper())


@app.on_event("shutdown")
async def shutdown_event():
    await control_plane.stop()
    await store.close()
    await audit_log.close()
    if upstream_client is not None:
        await upstream_client.aclose()


# How much of an entity's peak risk survives each subsequent request. 0.9 means
# a subject that peaked at 100 needs ~22 clean requests to fall back under 30
# (the dashboard's "flagged" line) - long enough to stay visible to an operator
# through a demo, short enough that a genuinely reformed client clears.
RISK_DECAY = 0.9


class EntityProfile:
    def __init__(self, subject_id):
        self.subject_id = subject_id
        self.first_seen = datetime.utcnow()
        self.objects = defaultdict(set)
        self.endpoints = set()
        self.request_count = 0
        self.last_seen = time.time()
        self.roles = []
        self.tenant = ""
        # Peak-with-decay, not last-request risk. A raw assignment lets an
        # attacker who has just triggered five BOLA blocks reset themselves to
        # 000/green with a single innocent request, which puts them at the bottom
        # of a table sorted by risk - exactly the row an operator most needs to
        # see. Decaying instead means risk fades as behaviour stays clean, but
        # never snaps back in one request.
        self.risk_score = 0

    def observe_risk(self, request_risk: int):
        self.risk_score = max(request_risk, int(self.risk_score * RISK_DECAY))


entities = {}

# Bounds on the entity table. Every distinct subject gets an EntityProfile, and
# unauthenticated traffic mints one per source address, so without a ceiling and
# a sweep this map grows for the lifetime of the process - and /admin/entities
# walks all of it on every 2-second dashboard poll.
MAX_ENDPOINTS_PER_ENTITY = 200
MAX_ENTITIES = 5000
ENTITY_IDLE_SEC = 900


def sweep_entities(now: float) -> int:
    stale = [s for s, e in entities.items() if now - e.last_seen > ENTITY_IDLE_SEC]
    for s in stale:
        del entities[s]
    if len(entities) > MAX_ENTITIES:
        for s, _ in sorted(entities.items(), key=lambda kv: kv[1].last_seen)[: len(entities) - MAX_ENTITIES]:
            del entities[s]
            stale.append(s)
    return len(stale)


async def entity_sweeper():
    while True:
        await asyncio.sleep(60)
        try:
            dropped = sweep_entities(time.time())
            if dropped:
                print(f"Entities: swept {dropped} idle profiles")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"Entities: sweep failed ({type(e).__name__}: {e})")

# Alerts previously carried no identifier, so the dashboard synthesised a React
# key from time+subject+path. Two requests by one subject to one path inside the
# same microsecond collide there - and a burst-rate-limit attack is exactly the
# traffic shape that produces them, i.e. the loudest moment of the demo. A
# monotonic counter is unambiguous and costs nothing. This is process-local by
# design: it orders one gateway's alert stream, it is not a distributed ID.
_alert_seq = itertools.count(1)


def next_alert_id() -> str:
    return f"a{next(_alert_seq)}"


def get_entity(subject_id: str) -> EntityProfile:
    if subject_id not in entities:
        entities[subject_id] = EntityProfile(subject_id)
    return entities[subject_id]


# Headers that describe *this* hop and must not be relayed to the next one.
# `dict(request.headers)` forwarded all of them verbatim: Host addressed the
# gateway rather than the upstream (fine against a local uvicorn, a 404 or 421
# against anything virtual-hosted or TLS-terminated), and Content-Length /
# Transfer-Encoding are client-supplied framing that httpx will not recompute -
# relaying both at once produces the conflicting pair that request-smuggling
# defences reject outright. Letting httpx derive framing from the body we
# actually read is both correct and simpler.
HOP_BY_HOP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection", "keep-alive",
    "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization",
}

# Upstream response headers that belong to the gateway's own connection to the
# upstream and must not be replayed to the client.
UPSTREAM_STRIP_HEADERS = HOP_BY_HOP_HEADERS | {"content-encoding"}


def forwardable_headers(request: Request, real_ip: str) -> dict:
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    # tell the upstream who the gateway believes the caller really is, appending
    # rather than replacing so an existing chain is preserved
    existing = request.headers.get("X-Forwarded-For", "")
    headers["X-Forwarded-For"] = f"{existing}, {real_ip}" if existing else real_ip
    headers["X-Forwarded-Proto"] = request.url.scheme
    return headers


def trusted_proxies() -> set:
    return {p.strip() for p in settings.trusted_proxies.split(",") if p.strip()}


def client_ip(request: Request) -> str:
    """Resolve the client address, trusting X-Forwarded-For only from a proxy we
    actually put there.

    This value is not cosmetic: it becomes the `anon:{ip}` identity for
    unauthenticated traffic, the rate-limit bucket, and the key the autonomous
    IP cooldown is written against. Honouring an unvalidated X-Forwarded-For
    therefore handed every one of those controls to the caller - rotate the
    header per request and you get a fresh rate-limit bucket each time, walk
    straight past an active cooldown, and can pin a cooldown onto any third-party
    address you feel like naming. A header a client can set is not evidence of
    where the client is.
    """
    peer = request.client.host if request.client else "unknown"
    if peer not in trusted_proxies():
        return peer
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return peer


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


# Fallback route table, used only if routes.json is missing or unreadable. The
# gateway must come up with *some* policy rather than none - an empty route table
# would mean no object- or role-level rules anywhere.
DEFAULT_ROUTES = [
    ("GET", ["api", "accounts", "{id}"], {"resource": "account", "object_param": "id", "required_roles": [], "require_auth": True}),
    ("GET", ["api", "accounts", "{id}", "transactions"], {"resource": "account", "object_param": "id", "required_roles": [], "require_auth": True}),
    ("POST", ["api", "transfers"], {"resource": "transfer", "object_param": "", "required_roles": [], "require_auth": True}),
    ("GET", ["api", "admin", "users"], {"resource": "admin", "object_param": "", "required_roles": ["admin"], "require_auth": True}),
    ("GET", ["api", "admin", "audit"], {"resource": "admin", "object_param": "", "required_roles": ["admin"], "require_auth": True}),
]

ROUTES = list(DEFAULT_ROUTES)

# Any path under one of these prefixes is protected whether or not it appears in
# ROUTES. Without this the gateway failed OPEN on every unlisted path: ROUTES
# holds five entries, and anything else - notably POST/PUT/DELETE on
# /api/accounts/{id}, mutations of the exact resource this product exists to
# protect - was proxied upstream with no token check whatsoever. "Deny unless
# explicitly described" is the whole premise of a zero-trust gateway; an allowlist
# that only covers what someone remembered to enumerate is the opposite.
PROTECTED_PREFIXES = ("api",)


def load_route_config():
    """Load the route table from JSON, per BACKEND.md Part 3.

    The table was a Python literal, which meant protecting a new endpoint
    required editing source and restarting - and, combined with the fail-open
    behaviour that used to accompany it, made forgetting an endpoint a silent
    security hole rather than a config error.
    """
    global ROUTES, PROTECTED_PREFIXES

    if not os.path.exists(settings.route_config_file):
        print(f"Route config: {settings.route_config_file} not found, using {len(ROUTES)} built-in routes")
        return

    try:
        with open(settings.route_config_file, encoding="utf-8") as f:
            cfg = json.load(f)

        parsed = []
        for entry in cfg.get("routes", []):
            method = entry["method"].upper()
            segments = [s for s in entry["pattern"].split("/") if s]
            parsed.append((method, segments, {
                "resource": entry.get("resource", ""),
                "object_param": entry.get("object_param", ""),
                "required_roles": entry.get("required_roles", []),
                "require_auth": entry.get("require_auth", True),
            }))

        if not parsed:
            raise ValueError("route config contains no routes")

        ROUTES = parsed
        prefixes = cfg.get("protected_prefixes")
        if prefixes:
            PROTECTED_PREFIXES = tuple(prefixes)

        print(f"Route config: loaded {len(ROUTES)} routes from {settings.route_config_file}, "
              f"protected prefixes {PROTECTED_PREFIXES}")
    except Exception as e:
        # Keep the built-in table rather than starting with none. A malformed
        # config must not be a way to turn authorization off.
        print(f"Route config: {settings.route_config_file} unusable ({e}); "
              f"keeping {len(ROUTES)} built-in routes")

# Unlisted-but-protected paths get authentication only. Object- and role-level
# rules need a route definition to say which parameter is the object and which
# roles are required, and inventing either would be guesswork - so an unlisted
# path is authenticated, logged, and passed on, rather than silently trusted.
UNLISTED_PROTECTED_ROUTE = {
    "resource": "",
    "object_param": "",
    "required_roles": [],
    "require_auth": True,
    "unlisted": True,
}


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

    if segments and segments[0] in PROTECTED_PREFIXES:
        return UNLISTED_PROTECTED_ROUTE, {}

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
    "jwt_no_expiry",
}
# rate_limit_burst was in this set and should not have been. The threshold is 25
# requests in 3 seconds, which a single-page app opening a dashboard, a fan-out
# of parallel fetches, or one Promise.all of 30 calls clears without any hostile
# intent - and membership here does not merely block the request, it escalates
# the *identity* into a five-minute lockout after three occurrences. The same
# reasoning already excluded rate_limit_sustained (120 req/60s); a window short
# enough that ordinary client concurrency trips it makes the argument stronger,
# not weaker. Burst still blocks the individual request, it just no longer
# convicts the user.


def is_hostile_block(signals: list) -> bool:
    return any(s.hard and s.detector in HOSTILE_ESCALATION_DETECTORS for s in signals)


def build_auto_block_alert(subject: str, ip: str, method: str, path: str, blocked_until: float, reason: str, latency_ms: float) -> dict:
    return {
        "id": next_alert_id(),
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
        "explain": f"AUTO-BLOCK (score 100) for {method} {path} by {subject} â€” cooldown active, no re-analysis needed ({reason})",
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
    emit_incident(incident)
    return incident


async def check_and_forward(request: Request) -> tuple[str, int, dict, object]:
    # perf_counter, not time.time(). time.time() on Windows has ~15.6ms
    # resolution, so a sub-millisecond decision measured with it quantises to
    # 0.0 or 15.6 - and "gateway overhead under 15ms" is the product's headline
    # number. Measuring it with a clock coarser than the budget is not a
    # measurement. perf_counter is monotonic and sub-microsecond everywhere.
    start_time = time.perf_counter()

    # step 1: extract
    method = request.method
    path = request.url.path
    ip = client_ip(request)

    # step 2: jwt validation
    jwt_result = validate_jwt(request.headers.get("Authorization", ""))
    subject = jwt_result.subject if jwt_result.valid else f"anon:{ip}"
    ip_key = f"ip:{ip}"

    entity = get_entity(subject)
    entity.request_count += 1
    entity.last_seen = time.time()
    # cap the per-entity endpoint set: an attacker walking distinct URLs would
    # otherwise pin one string per request in memory for the process lifetime
    if len(entity.endpoints) < MAX_ENDPOINTS_PER_ENTITY:
        entity.endpoints.add(f"{method} {path}")
    if jwt_result.valid:
        # roles/tenant come off the verified token, so they are only trustworthy
        # when the signature checked out. Previously these were declared on
        # EntityProfile and never assigned, so /admin/entities served [] and ""
        # for every subject and the dashboard had nothing to show.
        entity.roles = jwt_result.roles
        entity.tenant = jwt_result.tenant
    now = time.time()
    await store.record_request_time(subject, now)

    # autonomous mitigation: identity or source IP already proven hostile, short-circuit
    subject_blocked_until = await store.get_blocked_until(subject, now)

    # An IP-level cooldown is a blunt instrument. It is the only lever that works
    # against an attacker who rotates forged identities faster than we can track
    # them - but on any shared egress (corporate NAT, a mobile carrier, a demo
    # laptop where the attack script and the real user are both 127.0.0.1) it
    # would also take out every innocent user behind that address. So it applies
    # only to traffic that cannot prove who it is. A request carrying a
    # cryptographically valid token is judged on that identity's own escalation
    # record - `subject_blocked_until` above - and never inherits a punishment
    # earned by a different identity that merely shares its source address.
    # Without this, running the attack suite on one machine blocks every
    # legitimate request from that machine for the next cooldown window, which
    # is precisely the false positive this gateway exists to avoid.
    ip_blocked_until = 0.0 if jwt_result.valid else await store.get_blocked_until(ip_key, now)

    if subject_blocked_until or ip_blocked_until:
        if subject_blocked_until >= ip_blocked_until:
            blocked_until, reason = subject_blocked_until, "identity previously escalated"
        else:
            blocked_until, reason = ip_blocked_until, "source IP previously escalated"
        latency_ms = (time.perf_counter() - start_time) * 1000
        alert = build_auto_block_alert(subject, ip, method, path, blocked_until, reason, latency_ms)
        emit_alert(alert)
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
    #
    # Authorization only means something once we know *who* is asking. When a
    # protected route is hit without a usable token the caller is `anon:{ip}`, a
    # placeholder rather than an identity, and asking "does anon:127.0.0.1 own
    # account 1001?" is a category error. Running these checks anyway did real
    # damage in three ways:
    #   1. it stacked a bogus bola_cross_user (80) on top of the actual finding,
    #      so an expired session was explained to the operator as account theft
    #      and scored 85 instead of 60 - which also made it un-challengeable;
    #   2. it let the ownership model be written by unauthenticated traffic, via
    #      the grant_ownership call below, so an attacker with no credential at
    #      all could pre-claim an unseen object and lock its real owner out;
    #   3. it buried the one fact that actually matters - the token is bad - in a
    #      list of downstream noise.
    # The auth signal already blocks the request on its own. Nothing is lost.
    identity_established = jwt_result.valid or not (route_config or {}).get("require_auth")

    resource = ""
    object_id = ""
    if route_config and identity_established:
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
    # two INDEPENDENT soft signal sources are read here, deliberately not one:
    # - control_plane_anomaly: the deterministic rule engine in agents.py
    #   (thresholds like "8 distinct objects in 5s"), always running inside
    #   this process
    # - ml_anomaly: a genuinely separate process (ml/worker.py) with real
    #   trained models - per-entity IsolationForest, a Markov transition
    #   table, a NetworkX access graph - publishing to the same Redis
    # Having two independent sources is what makes the "2+ soft signals
    # required to block" corroboration rule in fuse_signals mean something -
    # with only one source, that path could never be reached.
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

    ml_risk = await store.get_ml_risk(subject)
    if ml_risk is not None and ml_risk > 40:
        signals.append(Signal(
            "ml_anomaly",
            ml_risk,
            "API6:2023 Unrestricted Access to Sensitive Business Flows",
            "T1087 Account Discovery",
            f"ML worker flagged behavioral anomaly (score {ml_risk}): IsolationForest + Markov sequence + graph novelty",
            hard=False
        ))

    # step 7: policy decision
    # thresholds come from config so that tuning policy actually changes
    # behaviour - fuse_signals() was previously called with its defaults, which
    # silently ignored settings.block_threshold / settings.challenge_threshold.
    action = fuse_signals(signals, settings.block_threshold, settings.challenge_threshold)
    risk = risk_score(signals)

    entity.observe_risk(risk)

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

    explain = explain_decision(subject, method, path, action, risk, signals)
    narrative = generate_narrative(subject, method, path, action, signals)
    latency_ms = (time.perf_counter() - start_time) * 1000

    alert = {
        "id": next_alert_id(),
        "time": utc_iso(),
        "subject": subject,
        "ip": ip,
        "method": method,
        "path": path,
        "decision": action,
        "risk": risk,
        "signals": [s.to_dict() for s in signals],
        "explain": explain,
        "narrative": narrative,
        "latency_ms": latency_ms,
        "status_code": None
    }

    # step 9: emit event to intelligence agents (async, non-blocking, fire-and-forget)
    spawn(
        control_plane.record_request_async(subject, method, path, resource, object_id)
    )

    # status_code is finalized per-branch below, then the alert is written once it's
    # complete â€” writing before this would race with the later status_code assignment
    # for the forwarded case, sometimes persisting the alert without it.
    if action == "block":
        alert["status_code"] = 403
        emit_alert(alert)
        return action, 403, alert, None
    elif action == "challenge":
        alert["status_code"] = 401
        emit_alert(alert)
        return action, 401, alert, None
    else:
        body = await request.body()
        try:
            upstream_req = upstream_client.build_request(
                method,
                settings.upstream_url + path,
                content=body,
                headers=forwardable_headers(request, ip),
            )
            resp = await upstream_client.send(upstream_req)
            alert["status_code"] = resp.status_code
            emit_alert(alert)
            return action, resp.status_code, alert, resp
        except Exception as exc:
            alert["status_code"] = 502
            alert["explain"] += f" | upstream forward failed: {type(exc).__name__}: {exc}"
            emit_alert(alert)
            return action, 502, alert, None


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "shared_store_redis": "connected" if store.connected else "disconnected (in-memory fallback active)",
        "audit_log_postgres": "connected" if audit_log.connected else "disconnected (in-memory fallback active)",
        "control_plane_agent": "running" if control_plane.running else "stopped",
        "control_plane_baselines": len(control_plane.detector.entity_baselines),
        "live_subscribers": event_hub.subscriber_count,
        "routes_loaded": len(ROUTES),
        "bola_strict_mode": settings.bola_strict_mode
    }


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """Live decision stream (BACKEND.md Part 8).

    Auth is the same X-Admin-Key as the REST admin routes, accepted either as a
    header or as a query parameter - browsers cannot set headers on a WebSocket
    handshake, so a header-only rule would make this endpoint unusable from the
    dashboard it exists to serve.
    """
    key = websocket.headers.get("x-admin-key") or websocket.query_params.get("key", "")
    if not hmac.compare_digest(key, settings.admin_api_key):
        await websocket.close(code=4401)
        return

    await websocket.accept()
    # bounded: a subscriber that stops reading loses events instead of growing
    # this queue until the process runs out of memory
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    event_hub.subscribe(queue)

    try:
        await websocket.send_json({"type": "hello", "data": {"policy_routes": len(ROUTES)}})
        while True:
            message = await queue.get()
            await websocket.send_json(message)
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        pass
    finally:
        event_hub.unsubscribe(queue)


@app.post("/admin/reset", dependencies=[Depends(require_admin)])
async def admin_reset():
    """Clear runtime state so a demo can be re-run without restarting.

    Once an IP or identity cooldown fired there was no way to clear it short of
    killing the process - which also threw away the audit log the dashboard was
    displaying. Ownership grants are deliberately preserved: they are the
    provisioned authorization data, and wiping them would leave every object
    unowned, which makes the next BOLA demonstration silently pass.
    """
    local = store.reset_runtime_state()
    redis_keys = await store.reset_redis_runtime_state()
    entities.clear()
    control_plane.detector.entity_baselines.clear()
    control_plane._local_cache.clear()
    cleared_alerts = audit_log.reset()

    event_hub.publish("reset", {"time": utc_iso()})
    return {
        "status": "reset",
        "cleared": {**local, "redis_keys": redis_keys, "alerts": cleared_alerts},
        "preserved": "ownership grants, so BOLA detection still has provisioned owners",
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
    # snapshot first: get_blocked_until awaits, and with Redis connected that
    # await suspends inside the loop body. A concurrent request from a new
    # subject then inserts into `entities` mid-iteration and this raises
    # RuntimeError: dictionary changed size during iteration - a 500 that flips
    # the dashboard to its error state, and one that only appears once Redis is
    # up, i.e. exactly in the full-stack demo configuration.
    for subj_id, entity in list(entities.items()):
        blocked_until = await store.get_blocked_until(subj_id, now)
        result.append({
            "id": subj_id,
            "risk": entity.risk_score,
            "roles": entity.roles,
            "tenant": entity.tenant,
            # request_count / endpoints / objects are tracked per-entity for the
            # whole life of the process. The dashboard previously had to derive
            # these by re-scanning its alert window, which meant the numbers
            # silently reset once traffic aged out of that window; these are the
            # real lifetime figures, and `objects` (the FRONTEND.md "objects
            # accessed" column) was tracked here but never serialised at all.
            "request_count": entity.request_count,
            "endpoints": len(entity.endpoints),
            "objects": sum(len(v) for v in entity.objects.values()),
            "first_seen": utc_iso(entity.first_seen),
            "blocked": bool(blocked_until),
            "blocked_until": utc_iso(datetime.utcfromtimestamp(blocked_until)) if blocked_until else None
        })
    result.sort(key=lambda e: e["risk"], reverse=True)
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


@app.get("/admin/ml-status", dependencies=[Depends(require_admin)])
async def ml_status():
    # read-only visibility into the ML worker (ml/worker.py) - a genuinely
    # separate process, this gateway never runs any model itself. Everything
    # here comes from what that process actually wrote to the shared Redis;
    # nothing is computed or guessed here. An empty list is a true, expected
    # state (worker never run, or Redis unreachable), not an error.
    profiles = await store.list_ml_profiles()
    trained = [p for p in profiles if p.get("has_model")]
    attackers = [p for p in profiles if p.get("known_attacker")]
    return {
        "worker_reachable": store.connected and len(profiles) > 0,
        "profiled_entities": len(profiles),
        "trained_models": len(trained),
        "known_attackers_excluded_from_training": len(attackers),
        "profiles": profiles
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway(request: Request):
    action, status_code, alert, resp = await check_and_forward(request)

    if action == "block":
        # BACKEND.md Part 5 calls for 429 on rate-limit denials, and the
        # distinction is not cosmetic: 403 tells a client "you may not do this,
        # ever", so a well-behaved client stops. 429 with Retry-After tells it
        # "not right now", which is the truth and lets it back off and recover.
        # Every denial was previously flattened to 403.
        rate_limited = any(s["detector"].startswith("rate_limit") for s in alert["signals"])
        if rate_limited:
            retry_after = settings.rate_limit_burst_sec if any(
                s["detector"] == "rate_limit_burst" for s in alert["signals"]
            ) else settings.rate_limit_window_sec
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited", "risk": alert["risk"]},
                headers={
                    "X-ZT-Decision": "block",
                    "X-ZT-Risk": str(alert["risk"]),
                    "Retry-After": str(retry_after),
                }
            )
        return JSONResponse(
            status_code=403,
            content={"error": "blocked", "risk": alert["risk"]},
            headers={"X-ZT-Decision": "block", "X-ZT-Risk": str(alert["risk"])}
        )
    elif action == "challenge":
        return JSONResponse(
            status_code=401,
            content={"error": "step_up_required", "risk": alert["risk"]},
            headers={
                "X-ZT-Decision": "challenge",
                # was omitted here while block and allow both set it, so a client
                # inspecting the header saw None on exactly the decision where
                # the score is the interesting part
                "X-ZT-Risk": str(alert["risk"]),
                "WWW-Authenticate": 'Bearer error="step_up_required"',
            }
        )
    elif resp is not None:
        # Relay the upstream response as-is.
        #
        # This used to re-wrap everything in a JSONResponse, which quietly
        # destroyed any upstream that is not a pure JSON API: every response
        # header was dropped (Content-Type, Set-Cookie, Location, Cache-Control,
        # ETag, WWW-Authenticate), an HTML or CSV body came back JSON-quoted and
        # labelled application/json, binary payloads were mangled by .text
        # decoding, and a 204 was given a body. A security gateway has to be
        # transparent to the traffic it is protecting - the only thing it should
        # add is its own verdict.
        passthrough = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in UPSTREAM_STRIP_HEADERS
        }
        passthrough["X-ZT-Decision"] = action
        passthrough["X-ZT-Risk"] = str(alert["risk"])
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=passthrough,
        )
    else:
        return JSONResponse(status_code=502, content={"error": "upstream_unreachable"})


if __name__ == "__main__":
    import uvicorn
    print(f"Gateway: {settings.listen_addr}:{settings.listen_port}")
    # proxy_headers defaults to True with forwarded_allow_ips="127.0.0.1", which
    # means uvicorn rewrites request.client.host from X-Forwarded-For before the
    # application ever sees it - so hardening client_ip() alone is not enough,
    # the spoof has already been applied a layer below. Both layers must agree on
    # which peers are actually trusted proxies, and by default none are.
    uvicorn.run(
        app,
        host=settings.listen_addr,
        port=settings.listen_port,
        proxy_headers=bool(trusted_proxies()),
        forwarded_allow_ips=",".join(trusted_proxies()) or None,
    )
