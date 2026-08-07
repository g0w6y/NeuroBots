# Backend and API Gateway

**Team:** Gouri Sankar A, Jeevan George

## Problem

APIs are the entry point for data breaches. The hardest attacks to catch are authorization attacks, where a real logged in user asks for data that belongs to someone else. Example: a user changes their account ID in the URL from 1001 to 1002 and the server gives them someone else's account. This is Broken Object Level Authorization (BOLA). Another example: a normal user hits an admin endpoint they are not allowed to access. This is Broken Function Level Authorization (BFLA).

Traditional firewalls miss these attacks because the requests look normal and well formed. The user is logged in, the token is valid, the request is syntactically correct. There is nothing obviously broken.

## Solution

Build a reverse proxy gateway in Python FastAPI that sits between the client and the real API. On every single request, validate the token, check if the user is allowed to access that specific object or function, score the risk, and decide whether to allow, challenge or block the request.

The gateway must be fast (under 15 milliseconds overhead) so it does not slow down the API. It must be accurate so it blocks attacks but does not block real users (zero false positives). It must be explainable so operators know exactly why each request was blocked.

## Your Deliverables

You are building the core gateway application in Python with FastAPI.

### Part 1: Foundation (hours 0 to 3)

Set up the FastAPI application with async request handling. Create a reverse proxy that accepts a request, forwards it to an upstream API, and returns the response to the client. Use httpx library for async HTTP requests to the upstream.

Handle HTTPS and accept connections on port 8080. Accept requests on all paths and methods. Forward to an upstream URL defined in config (default http://127.0.0.1:9000).

### Part 2: Authentication (hours 3 to 6)

Add JWT validation using PyJWT library. On every request:
- Extract the JWT token from the Authorization header (Bearer scheme)
- Decode the token using a shared secret key
- Validate the signature is correct
- Validate the token is not expired (check exp claim)
- Validate the issuer matches config (iss claim)
- Validate the audience matches config (aud claim)
- Extract the subject (sub claim) as the user identity
- Extract roles as an array from the token
- If token is missing, invalid, expired or tampered, return 401 Unauthorized

Store the validated identity (subject and roles) in the request context for use in later steps.

### Part 3: Object Level Authorization (hours 6 to 9)

Implement BOLA checking against Redis.

Read a route configuration file (JSON) that defines which endpoints are which resources. Example:
GET /api/accounts/{id} is the account resource with object parameter id
GET /api/admin/users is the admin resource with no object parameter

On each request, match the method and path to a route in the config. Extract the object ID from the path parameter.

Query Redis with SISMEMBER authorized:{subject} {object_id}. If the result is NO (the user does not own that object), return 403 Forbidden with a clear error message. If the result is YES or the object is not known yet, continue.

If the object is not known (first time anyone accesses it), allow it and let the ML system learn ownership from this request later.

### Part 4: Function Level Authorization (hours 9 to 12)

Implement BFLA checking with an in memory role matrix.

Read the route config which lists required_roles for each endpoint. Example:
GET /api/admin/users requires role admin

Compare the user's roles from the token against the required_roles for that endpoint. If the user does not have at least one required role, return 403 Forbidden.

If an endpoint has no required_roles, allow it (public endpoint).

### Part 5: Rate Limiting (hours 12 to 15)

Implement per user rate limiting using Redis token buckets.

On each request:
- Increment a counter in Redis for the user: INCR rate:{subject}:minute
- Set an expiry of 60 seconds: EXPIRE rate:{subject}:minute 60
- Read the config for the rate limit (default 120 requests per 60 seconds)
- If the counter exceeds the limit, return 429 Too Many Requests

Also implement a burst limit: if the user makes more than 25 requests in 3 seconds, flag it.

### Part 6: Risk Scoring (hours 15 to 18)

Implement a simple risk scoring engine.

Fuse signals into a 0 to 100 score:
- Missing token: risk 80
- Invalid token: risk 90
- Expired token: risk 60
- BOLA violation: risk 100
- BFLA violation: risk 85
- Rate limit exceeded: risk 75
- No signals: risk 0

For multiple signals, take the maximum score (100 is the cap).

### Part 7: Policy Decision and Enforcement (hours 18 to 21)

Implement a policy decision engine.

Read the policy config:
- block_threshold: 70 (score above this blocks)
- challenge_threshold: 45 (score above this requests step up auth)

Decision logic:
- If risk score is above block_threshold, return 403 Forbidden
- If risk score is above challenge_threshold, return 401 Unauthorized with WWW Authenticate header
- Otherwise, allow the request to proceed to the upstream API

On block, write the token ID to a revocation set in Redis so it is blocked on future requests.

### Part 8: Logging and Audit (hours 21 to 24)

Log every decision to PostgreSQL.

After making a decision, insert a row into an audit table with:
- timestamp (now)
- subject (user identity)
- ip (client IP from X Forwarded For header)
- method (HTTP method)
- path (request path)
- decision (allow, challenge, block)
- risk_score (computed score)
- signals (list of signals that fired)
- explanation (human readable reason)

Also emit the decision event to a message queue or WebSocket so the frontend gets live updates. Use FastAPI WebSockets or a simple in memory queue that the frontend can poll.

## Technical Requirements

- Python 3.x with FastAPI framework
- PyJWT for token validation
- httpx for async HTTP proxying
- Redis client library (redis py)
- PostgreSQL async client (asyncpg)
- Config in JSON format (routes, policy, rate limits)
- No external security libraries (build auth from first principles using PyJWT)
- All decisions must be made in under 15 milliseconds
- Support concurrent requests (async throughout)

## Testing

Before 24 hour mark, run the attack simulator against your gateway:
python3 attack sim/simulate.py

Expected results:
- 8 out of 8 attack classes detected
- 0 false positives on benign traffic
- Latency under 15 milliseconds

## Success Criteria

Gateway must:
1. Validate tokens correctly (block fake, expired, tampered tokens)
2. Detect BOLA (block cross user object access)
3. Detect BFLA (block unauthorized function access)
4. Enforce rate limits
5. Stay under 15 milliseconds latency
6. Have zero false positives on legitimate traffic
7. Explain every decision with clear signals

## Config File Format

```json
{
  "listen_addr": ":8080",
  "upstream": "http://127.0.0.1:9000",
  "jwt_secret": "your-secret-key",
  "issuer": "your-issuer",
  "audience": "your-audience",
  "policy": {
    "block_threshold": 70,
    "challenge_threshold": 45,
    "rate_limit_requests": 120,
    "rate_limit_window_sec": 60
  },
  "routes": [
    {
      "method": "GET",
      "pattern": "/api/accounts/{id}",
      "resource": "account",
      "object_param": "id",
      "required_roles": []
    },
    {
      "method": "GET",
      "pattern": "/api/admin/users",
      "resource": "admin",
      "object_param": "",
      "required_roles": ["admin"]
    }
  ]
}
```

## Environment Variables

- DATABASE_URL: PostgreSQL connection string
- REDIS_URL: Redis connection string
- JWT_SECRET: JWT secret key
- UPSTREAM_URL: Upstream API URL
