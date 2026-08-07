# DevOps, Infrastructure and Testing

**Team:** Nirmal Josekutty

## Problem

A security platform is only useful if it actually runs. You need to:
1. Deploy all the services (gateway, ML worker, frontend, databases) in a way that works on any machine
2. Test that the platform actually detects attacks correctly (detection accuracy)
3. Measure that it stays fast (latency) and handles load (throughput)
4. Prove all of this with concrete numbers

Without this, the gateway and ML system are just code that might work on one laptop.

## Solution

Build Docker containers for all services, orchestrate them with Docker Compose so one command brings everything up, build an attack simulation suite that proves the platform works, and run benchmarks that measure latency and throughput.

## Your Deliverables

You are building infrastructure, testing, documentation and demo scripts.

### Part 1: Docker Setup (hours 0 to 4)

Create Dockerfiles for:

**Dockerfile.gateway** (Python FastAPI):
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ .
EXPOSE 8080 8081
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
```

**Dockerfile.ml** (Python ML worker):
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY ml/requirements.txt .
RUN pip install -r requirements.txt
COPY ml/ .
CMD ["python", "worker.py"]
```

**Dockerfile.frontend** (React):
```dockerfile
FROM node:18-alpine as build
WORKDIR /app
COPY frontend/package.json .
RUN npm install
COPY frontend/ .
RUN npm run build

FROM node:18-alpine
WORKDIR /app
RUN npm install -g serve
COPY --from=build /app/dist .
EXPOSE 3000
CMD ["serve", "-s", ".", "-l", "3000"]
```

All Dockerfiles must:
- Start from a slim base image (alpine or slim variants)
- Install only production dependencies
- Use a non root user for security
- Expose only necessary ports

### Part 2: Docker Compose Orchestration (hours 4 to 7)

Create docker compose.yml that brings up the entire stack in one command:

```yaml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: neurobots
      POSTGRES_PASSWORD: password
      POSTGRES_DB: neurobots
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  gateway:
    build:
      context: .
      dockerfile: backend/Dockerfile
    environment:
      DATABASE_URL: postgresql://neurobots:password@postgres:5432/neurobots
      REDIS_URL: redis://redis:6379
      JWT_SECRET: secret key
      UPSTREAM_URL: http://demo-api:9000
    ports:
      - "8080:8080"
      - "8081:8081"
    depends_on:
      - redis
      - postgres
      - demo-api

  ml:
    build:
      context: .
      dockerfile: ml/Dockerfile
    environment:
      REDIS_URL: redis://redis:6379
      GATEWAY_URL: http://gateway:8081
    depends_on:
      - redis
      - gateway

  frontend:
    build:
      context: .
      dockerfile: frontend/Dockerfile
    environment:
      REACT_APP_GATEWAY_URL: http://gateway:8081
    ports:
      - "3000:3000"
    depends_on:
      - gateway

  demo-api:
    image: python:3.12-slim
    working_dir: /app
    command: python demo_api.py
    volumes:
      - ./demo-api:/app
    ports:
      - "9000:9000"

volumes:
  redis_data:
  postgres_data:
```

Run with: `docker compose up --build`

Must:
- Define all services (gateway, ML, frontend, Redis, PostgreSQL, demo API)
- Set environment variables correctly
- Define dependencies so services start in the right order
- Expose the right ports
- Mount volumes for data persistence

### Part 3: PostgreSQL Schema (hours 7 to 10)

Create the audit log table schema:

```sql
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    subject VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path VARCHAR(1024) NOT NULL,
    decision VARCHAR(50) NOT NULL,  -- allow, challenge, block
    risk_score INTEGER NOT NULL,
    signals TEXT,  -- JSON array of signals
    explanation TEXT,
    response_status INTEGER,
    latency_ms FLOAT
);

CREATE INDEX idx_audit_subject ON audit_log(subject);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_decision ON audit_log(decision);
```

Initialize the database automatically when the gateway starts. Use SQLAlchemy or raw asyncpg to connect and create tables if they do not exist.

### Part 4: Attack Simulation Suite (hours 10 to 16)

Build a Python script that simulates realistic attacks and measures detection rate.

Attacks to simulate:

**1. BOLA Cross User:** alice tries to read bob's account
**2. BOLA Enumeration:** a user scans many account IDs sequentially
**3. BFLA Privilege Escalation:** normal user hits /admin/users endpoint
**4. JWT None Algorithm:** attacker forges a token with alg=none
**5. JWT Tampering:** attacker modifies the token payload and signature becomes invalid
**6. JWT Expired:** attacker uses an old, expired token
**7. Rate Abuse Flood:** a user makes 200 requests in 10 seconds
**8. Missing Auth:** a request to a protected endpoint has no Authorization header

For each attack:
- Generate a valid starting point (legit user, valid token)
- Mutate it to become an attack
- Send it through the gateway
- Check the response code (should be 401 or 403)
- Log the result

Example:

```python
def test_bola_cross_user():
    alice_token = login('alice')
    response = requests.get(
        'http://127.0.0.1:8080/api/accounts/1002',  # bob's account
        headers={'Authorization': f'Bearer {alice_token}'}
    )
    assert response.status_code == 403, "BOLA cross user should be blocked"
    return True
```

Also measure benign traffic:
- alice reads her own account 10 times
- bob reads his own account 10 times
- users access various endpoints they are allowed to access

Measure:
- Detection rate: how many of 8 attacks were blocked?
- False positive rate: what % of benign requests were blocked?

Output:
```
Attack Simulation Results
========================
Total attacks: 8
Detected: 8
Detection rate: 100%

Benign requests: 50
Blocked: 0
False positive rate: 0%
```

### Part 5: Performance Benchmark (hours 16 to 20)

Build a benchmark script that measures latency and throughput.

Generate synthetic load:
- 1000 concurrent users
- Each user makes 100 requests over 2 minutes
- Each request is unique (different user, different IP)

Measure:
- Latency percentiles: p50, p95, p99 (should all be under 15ms)
- Throughput: requests per second
- CPU and memory usage

Use a load testing library like locust or apache bench.

Example with requests:

```python
import time
import threading
import statistics

def worker(user_id, results):
    for i in range(100):
        start = time.time()
        response = requests.get(
            'http://127.0.0.1:8080/api/test',
            headers={'X-Forwarded-For': f'10.0.{user_id}.{i}'}
        )
        latency = (time.time() - start) * 1000  # ms
        results.append(latency)

results = []
threads = []
for user_id in range(1000):
    t = threading.Thread(target=worker, args=(user_id, results))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

results.sort()
print(f"P50: {results[len(results)//2]:.2f}ms")
print(f"P95: {results[int(len(results)*0.95)]:.2f}ms")
print(f"P99: {results[int(len(results)*0.99)]:.2f}ms")
print(f"Max: {results[-1]:.2f}ms")
print(f"Throughput: {len(results) / elapsed_time:.0f} req/s")
```

Output to a file: BENCHMARK.md

### Part 6: Demo Vulnerable API (hours 20 to 22)

Build a simple demo API that is intentionally vulnerable (no auth checks, no BOLA checks). This is what the gateway protects.

```python
# demo_api.py
from flask import Flask, request, jsonify

app = Flask(__name__)

ACCOUNTS = {
    '1001': {'owner': 'alice', 'balance': 1000},
    '1002': {'owner': 'bob', 'balance': 2000},
    '1003': {'owner': 'carol', 'balance': 3000},
}

@app.route('/api/accounts/<account_id>', methods=['GET'])
def get_account(account_id):
    # INTENTIONALLY VULNERABLE: no auth check
    if account_id in ACCOUNTS:
        return jsonify(ACCOUNTS[account_id])
    return {'error': 'not found'}, 404

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    # INTENTIONALLY VULNERABLE: no role check
    return jsonify({'users': list(ACCOUNTS.keys())})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
```

The point is to show that the gateway protects this vulnerable API without modifying it.

### Part 7: Documentation (hours 22 to 23)

Write:
1. **README.md:** How to build and run the whole system with Docker Compose
2. **ARCHITECTURE.md:** Diagrams and explanation of the system design
3. **TESTING.md:** How to run the attack simulator and benchmark
4. **DEPLOYMENT.md:** How to deploy to a real server (scaling considerations)

Document:
- What each Docker container does
- How to configure environment variables
- How to interpret the benchmark results
- How the attack simulator works

### Part 8: Demo Script (hours 23 to 24)

Create a shell script that:
1. Starts the full stack with Docker Compose
2. Waits for all services to be healthy
3. Runs the attack simulator
4. Displays results
5. Opens the dashboard in a browser

```bash
#!/bin/bash
echo "Starting NeuroBots..."
docker compose up -d --build

echo "Waiting for services to be ready..."
sleep 10

echo "Running attack simulator..."
python3 attack_sim/simulate.py

echo "Benchmark..."
python3 scripts/benchmark.py

echo "Opening dashboard..."
open http://127.0.0.1:3000
```

## Technical Requirements

- Docker and Docker Compose
- Python 3.x for scripts
- PostgreSQL and Redis (via Docker images)
- Load testing library (locust or similar)
- SQL schema and migrations

## Success Criteria

DevOps must deliver:
1. One command that brings the entire system up: `docker compose up --build`
2. Attack simulator that proves 8/8 detection
3. Benchmark showing all latencies under 15ms
4. Zero false positives on benign traffic
5. Complete documentation
6. Demo script that works start to finish

## Testing Checklist

Before 24 hour mark:
- [ ] Docker Compose brings up all services
- [ ] Gateway is reachable on http://127.0.0.1:8080
- [ ] Frontend dashboard is reachable on http://127.0.0.1:3000
- [ ] Database is initialized with audit table
- [ ] Redis is reachable and storing data
- [ ] Attack simulator runs and detects all 8 attacks
- [ ] Benign traffic has 0% block rate
- [ ] Benchmark shows p99 latency under 15ms
- [ ] Demo script runs end to end
- [ ] Dashboard shows live alerts as attacks come in

## Files to Create

- docker-compose.yml
- backend/Dockerfile
- ml/Dockerfile
- frontend/Dockerfile
- scripts/attack_sim.py
- scripts/benchmark.py
- scripts/demo.sh
- demo-api/app.py (vulnerable demo)
- docs/DEPLOYMENT.md
- docs/TESTING.md
- docs/README.md
