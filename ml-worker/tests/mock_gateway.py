"""Mock NeuroBots Gateway for testing the ML Worker."""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="Mock NeuroBots Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

events_store: list[dict[str, Any]] = []
USERS = ["alice", "bob", "charlie", "diana", "eve"]
ENDPOINTS = [
    ("/api/accounts/{id}", "account"),
    ("/api/users/{id}", "user"),
    ("/api/transactions/{id}", "transaction"),
    ("/api/admin/users", "admin"),
    ("/api/health", "health"),
]
METHODS = ["GET", "POST", "PUT", "DELETE"]


def generate_event() -> dict[str, Any]:
    """Generate a realistic gateway event."""
    user = random.choice(USERS)
    endpoint, resource = random.choice(ENDPOINTS)
    obj_id = str(random.randint(1000, 9999))
    path = endpoint.replace("{id}", obj_id)
    method = random.choice(METHODS)
    decision = random.choices(
        ["allow", "block", "challenge"],
        weights=[0.85, 0.10, 0.05],
    )[0]

    return {
        "subject": user,
        "method": method,
        "path": path,
        "endpoint": endpoint,
        "resource": resource,
        "object_id": obj_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "risk_score": random.randint(0, 100) if decision != "allow" else 0,
        "latency_ms": round(random.uniform(1.0, 15.0), 2),
    }


@app.on_event("startup")
async def startup():
    for _ in range(20):
        events_store.append(generate_event())


@app.get("/admin/alerts")
async def get_alerts() -> list[dict[str, Any]]:
    """Return recent events for the ML worker to consume."""
    new_events = [generate_event() for _ in range(random.randint(1, 5))]
    events_store.extend(new_events)
    return events_store[-50:]


@app.get("/admin/metrics")
async def get_metrics() -> dict[str, Any]:
    return {
        "total_requests": len(events_store),
        "allowed": sum(1 for e in events_store if e["decision"] == "allow"),
        "blocked": sum(1 for e in events_store if e["decision"] == "block"),
        "challenged": sum(1 for e in events_store if e["decision"] == "challenge"),
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8081)
