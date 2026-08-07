import json
import time
from collections import deque
from typing import Optional
import asyncpg
from config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    subject TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk INT NOT NULL,
    signals JSONB NOT NULL,
    explain TEXT NOT NULL,
    narrative TEXT NOT NULL,
    latency_ms DOUBLE PRECISION NOT NULL,
    status_code INT
);
CREATE INDEX IF NOT EXISTS idx_alerts_subject ON alerts (subject);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_decision ON alerts (decision);

CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    escalation_count INT NOT NULL,
    cooldown_sec INT NOT NULL,
    blocked_until TIMESTAMPTZ NOT NULL,
    narrative TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_target ON incidents (target);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents (ts DESC);
"""


class AuditLog:
    """
    Durable audit log for alerts and incidents, backed by PostgreSQL.
    Falls back to the existing in-memory deques when Postgres is unreachable —
    same pattern as store.py's Redis fallback. A dead audit DB must never
    block or slow down the request path: every write here is fire-and-forget
    from the caller's perspective, wrapped so a DB failure never raises.
    """

    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        self.connected = False
        self._alerts_fallback = deque(maxlen=500)
        self._incidents_fallback = deque(maxlen=200)
        # The deques are a bounded *display* window; they are not a counter.
        # Deriving lifetime totals from len(deque) meant "total requests",
        # "allowed" and "blocked" all silently froze the moment the 500th request
        # landed - and a burst-rate-limit demo crosses 500 in seconds, so the
        # headline tiles stop moving exactly when the attack gets interesting.
        # These counters are monotonic and independent of the window.
        self._totals = {"requests": 0, "block": 0, "challenge": 0, "allow": 0, "observe": 0}
        self._incident_total = 0

    async def connect(self):
        try:
            self.pool = await asyncpg.create_pool(
                dsn=settings.database_url,
                min_size=1,
                max_size=5,
                command_timeout=5,
                timeout=3,
            )
            async with self.pool.acquire() as conn:
                await conn.execute(SCHEMA)
            self.connected = True
            print("Audit Log: PostgreSQL connected, schema ensured")
        except Exception as e:
            print(f"Audit Log: PostgreSQL unavailable, using in-memory fallback ({e})")
            self.pool = None
            self.connected = False

    async def close(self):
        if self.pool:
            try:
                await self.pool.close()
            except Exception:
                pass

    async def write_alert(self, alert: dict) -> None:
        self._alerts_fallback.append(alert)
        self._totals["requests"] += 1
        decision = alert.get("decision", "")
        if decision in self._totals:
            self._totals[decision] += 1
        if not self.connected:
            return
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO alerts
                        (subject, ip, method, path, decision, risk, signals, explain, narrative, latency_ms, status_code)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    """,
                    alert.get("subject", ""),
                    alert.get("ip", ""),
                    alert.get("method", ""),
                    alert.get("path", ""),
                    alert.get("decision", ""),
                    alert.get("risk", 0),
                    json.dumps(alert.get("signals", [])),
                    alert.get("explain", ""),
                    alert.get("narrative", ""),
                    alert.get("latency_ms", 0.0),
                    alert.get("status_code"),
                )
        except Exception:
            pass

    async def write_incident(self, incident: dict) -> None:
        self._incidents_fallback.append(incident)
        self._incident_total += 1
        if not self.connected:
            return
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO incidents
                        (type, target, target_type, reason, escalation_count, cooldown_sec, blocked_until, narrative)
                    VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), $8)
                    """,
                    incident.get("type", ""),
                    incident.get("target", ""),
                    incident.get("target_type", ""),
                    incident.get("reason", ""),
                    incident.get("escalation_count", 0),
                    incident.get("cooldown_sec", 0),
                    incident.get("blocked_until_epoch", time.time()),
                    incident.get("narrative", ""),
                )
        except Exception:
            pass

    async def recent_alerts(self, limit: int = 500) -> list:
        if not self.connected:
            return list(self._alerts_fallback)[-limit:]
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, ts, subject, ip, method, path, decision, risk, signals, explain, narrative, latency_ms, status_code
                    FROM alerts ORDER BY ts DESC LIMIT $1
                    """,
                    limit,
                )
            return [
                {
                    # keep the same "a<n>" id shape the in-memory path emits, so
                    # the dashboard's row identity does not change meaning
                    # depending on whether Postgres happens to be up
                    "id": f"a{r['id']}",
                    "time": r["ts"].isoformat(),
                    "subject": r["subject"],
                    "ip": r["ip"],
                    "method": r["method"],
                    "path": r["path"],
                    "decision": r["decision"],
                    "risk": r["risk"],
                    "signals": json.loads(r["signals"]),
                    "explain": r["explain"],
                    "narrative": r["narrative"],
                    "latency_ms": r["latency_ms"],
                    "status_code": r["status_code"],
                }
                for r in rows
            ]
        except Exception:
            return list(self._alerts_fallback)[-limit:]

    def reset(self) -> int:
        """Clear the in-memory display window and counters for a fresh demo run.

        Postgres rows are deliberately left alone - an audit log that can be
        erased through the API is not an audit log. With Postgres connected the
        admin routes keep serving durable history; only the in-process view of
        it resets.
        """
        cleared = len(self._alerts_fallback)
        self._alerts_fallback.clear()
        self._incidents_fallback.clear()
        for k in self._totals:
            self._totals[k] = 0
        self._incident_total = 0
        return cleared

    def _fallback_counts(self) -> dict:
        return {
            "requests": self._totals["requests"],
            "blocked": self._totals["block"],
            "challenged": self._totals["challenge"],
            "allowed": self._totals["allow"] + self._totals["observe"],
            "incidents": self._incident_total,
        }

    async def counts(self) -> dict:
        if not self.connected:
            return self._fallback_counts()
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch("SELECT decision, count(*) AS c FROM alerts GROUP BY decision")
                incident_count = await conn.fetchval("SELECT count(*) FROM incidents")
            by_decision = {r["decision"]: r["c"] for r in rows}
            return {
                "requests": sum(by_decision.values()),
                "blocked": by_decision.get("block", 0),
                "challenged": by_decision.get("challenge", 0),
                "allowed": by_decision.get("allow", 0) + by_decision.get("observe", 0),
                "incidents": incident_count or 0,
            }
        except Exception:
            return self._fallback_counts()

    async def recent_incidents(self, limit: int = 200) -> list:
        if not self.connected:
            return list(self._incidents_fallback)[-limit:]
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT ts, type, target, target_type, reason, escalation_count, cooldown_sec, blocked_until, narrative
                    FROM incidents ORDER BY ts DESC LIMIT $1
                    """,
                    limit,
                )
            return [
                {
                    "time": r["ts"].isoformat(),
                    "type": r["type"],
                    "target": r["target"],
                    "target_type": r["target_type"],
                    "reason": r["reason"],
                    "escalation_count": r["escalation_count"],
                    "cooldown_sec": r["cooldown_sec"],
                    "blocked_until": r["blocked_until"].isoformat(),
                    "narrative": r["narrative"],
                }
                for r in rows
            ]
        except Exception:
            return list(self._incidents_fallback)[-limit:]


audit_log = AuditLog()
