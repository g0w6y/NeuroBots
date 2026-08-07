"""
Minimal protected API for the gateway to sit in front of during a demo.

This is real, working sample data — not a mock of the gateway's own logic.
The gateway's decisions (JWT validation, BOLA, BFLA, rate limiting, autonomous
mitigation) are all real regardless of what runs here; this file only exists
because a gateway needs an actual service behind it to forward "allow"
decisions to, otherwise every legitimate request 502s with nothing to show.

Run standalone on :9000 (matches config.py's default upstream_url):
    python3 demo_upstream.py
"""

from fastapi import FastAPI, Request

app = FastAPI(title="NeuroBots Demo Upstream API")

# Deliberately over-serving. Every account carries fields a client has no business
# receiving - a password hash, a national id, a full card number, an internal note.
# This is not a strawman: it is the single most common real-world API shape, where
# the server returns its whole row and the mobile client is trusted to display only
# part of it. The request for your own account is perfectly authorized; the
# response still leaks. That gap is what OWASP calls API3, and what the gateway's
# step-8 response inspection exists to catch - no change to this file required,
# which is the point.
ACCOUNTS = {
    "1001": {
        "account_id": "1001", "owner": "alice", "balance": 4520.10, "currency": "USD",
        "password_hash": "$2b$12$K8fj2LmN9pQrS7tUvWxYz.demo",
        "ssn": "512-88-4417",
        "internal_note": "flagged for manual review 2026-07-02",
    },
    "1002": {
        "account_id": "1002", "owner": "bob", "balance": 812.44, "currency": "USD",
        "password_hash": "$2b$12$Zq7wE3rT5yU8iO1pA.demo",
        "card_number": "4539-8821-0037-9915",
    },
    "1003": {
        "account_id": "1003", "owner": "carol", "balance": 15300.00, "currency": "USD",
        "password_hash": "$2b$12$Mn4bV6cX8zL2kJ5hG.demo",
        "ssn": "409-22-7781",
    },
}

TRANSACTIONS = {
    "1001": [
        {"id": "t1", "amount": -42.50, "merchant": "Coffee Shop", "date": "2026-08-05"},
        {"id": "t2", "amount": 2000.00, "merchant": "Payroll", "date": "2026-08-01"},
    ],
    "1002": [
        {"id": "t3", "amount": -120.00, "merchant": "Electric Co", "date": "2026-08-04"},
    ],
    "1003": [
        {"id": "t4", "amount": -899.99, "merchant": "Electronics Store", "date": "2026-08-06"},
    ],
}

ADMIN_USERS = [
    {"id": "alice", "role": "user", "status": "active"},
    {"id": "bob", "role": "user", "status": "active"},
    {"id": "carol", "role": "user", "status": "active"},
    {"id": "admin", "role": "admin", "status": "active"},
]


@app.get("/api/accounts/{account_id}")
def get_account(account_id: str):
    if account_id in ACCOUNTS:
        return ACCOUNTS[account_id]
    return {"account_id": account_id, "owner": "demo", "balance": 0.0, "currency": "USD"}


@app.get("/api/accounts/{account_id}/transactions")
def get_transactions(account_id: str):
    return {"account_id": account_id, "transactions": TRANSACTIONS.get(account_id, [])}


@app.post("/api/transfers")
async def create_transfer(request: Request):
    body = await request.json()
    return {
        "transfer_id": "tr_demo_001",
        "from_account": body.get("from_account"),
        "to_account": body.get("to_account"),
        "amount": body.get("amount"),
        "status": "completed"
    }


@app.get("/api/admin/users")
def list_users():
    return {"users": ADMIN_USERS}


@app.get("/api/admin/audit")
def audit_log():
    return {"audit_entries": [], "note": "demo upstream, no real audit history"}


if __name__ == "__main__":
    import uvicorn
    print("Demo upstream API starting on 0.0.0.0:9000")
    uvicorn.run(app, host="0.0.0.0", port=9000)
