# Machine Learning and Behavioral Analytics

**Team:** Melwin Santhosh

## Problem

The gateway makes fast block decisions based on rules (BOLA, BFLA, rate limits). But rules are not enough. Attackers evade rules by:
- Accessing objects slowly over time instead of flooding
- Changing their pattern gradually to look normal
- Switching between user accounts
- Making requests from new locations or devices

We need a learning system that builds a profile of what normal looks like for each user, then flags when they deviate from that normal. This is where machine learning comes in.

## Solution

Build an async machine learning worker that runs alongside the gateway. It listens to a stream of request events from the gateway, updates behavioral baselines for each user, detects anomalies, and pushes updated risk scores back to Redis where the gateway reads them.

The ML system never blocks on its own. It only produces a risk score that the gateway uses as one signal in its decision. This keeps the gateway fast and the ML system responsible only for accuracy, not for latency.

## Your Deliverables

You are building the machine learning worker in Python using scikit learn, NetworkX and simple statistical models.

### Part 1: Setup and Event Consumer (hours 0 to 2)

Create a Python worker that:
- Listens to request events from the gateway (via a shared queue or by polling the gateway API)
- Parses each event to extract: subject, method, path, endpoint, resource, object_id, timestamp, decision
- Maintains in memory data structures for all entities (users)

The gateway will push events to a simple HTTP endpoint or queue. For simplicity, you can poll the gateway /admin/alerts endpoint every 2 seconds to get new events.

### Part 2: Entity Profiling (hours 2 to 8)

For each unique subject (user), maintain a profile:

```python
class EntityProfile:
    def __init__(self, subject_id):
        self.subject_id = subject_id
        self.first_seen = now
        self.requests = []  # list of request details
        self.endpoints_seen = set()  # unique endpoints accessed
        self.objects_by_resource = {}  # resource -> set of object IDs
        self.request_times = deque(maxlen=100)  # recent request timestamps
        self.baseline_rate = None  # expected requests per second
        self.baseline_endpoints = []  # normal endpoints for this user
```

Update profiles as events arrive:
- Add endpoint to endpoints_seen
- Add timestamp to request_times
- Add object to objects_by_resource

Compute rolling statistics:
- Request rate (requests per minute, per hour)
- Most common endpoints
- Most common resources

### Part 3: Anomaly Detection with IsolationForest (hours 8 to 14)

For each request, extract features:
- Hour of day (0 to 23)
- Day of week (0 to 6)
- Request rate (requests in last minute, smoothed)
- Object ID as one hot encoding (numeric hash)
- Endpoint as one hot encoding (numeric hash)
- Days since first request
- Number of distinct objects accessed today
- Number of distinct endpoints accessed today

Train an IsolationForest model on historical normal requests for each entity. When a new request arrives:
- Extract features
- Pass through the model
- Get an anomaly score (0 to 1, where 1 is most anomalous)
- If score > threshold (0.7), flag it as anomalous

Update the model periodically (every hour) with new normal data.

### Part 4: Sequence Modeling with Markov Chains (hours 14 to 17)

Build a first order Markov model for call sequences.

For each entity:
- Track transitions from one endpoint to the next: endpoint_A -> endpoint_B
- Count how many times each transition occurs
- Compute probability of each transition

When a new request arrives:
- Get the previous endpoint for this user
- Look up the probability of current_endpoint given previous_endpoint
- If probability is low (e.g. < 0.1), it is an unusual sequence

Compute sequence anomaly score as the negative log probability of the transition.

Example: if alice always goes from /login to /dashboard, a transition to /admin/users is unusual and scores high.

### Part 5: Graph Analysis with NetworkX (hours 17 to 20)

Build a user to object access graph:

Nodes: users and objects
Edges: (user, object) if the user accessed that object

Compute metrics:
- User fan out: how many distinct objects has this user accessed? (should be relatively stable)
- Object fan in: how many distinct users access this object? (shared vs private)
- User to resource graph: which resources does this user normally touch?

When a new request arrives:
- Check if the user is accessing a resource they have never touched before (new fan out)
- Check if the object has a very high fan in (shared resource, less suspicious)
- Flag if a user suddenly starts accessing many new resources

### Part 6: Risk Scoring and Caching (hours 20 to 23)

Combine all signals into a single risk score for each entity:

```python
def compute_ml_risk(entity_profile, latest_request):
    anomaly_score = isolation_forest_score  # 0 to 1
    sequence_score = markov_sequence_score  # 0 to 1
    graph_score = graph_novelty_score  # 0 to 1
    
    # Weight them
    ml_risk = 100 * (0.4 * anomaly_score + 0.3 * sequence_score + 0.3 * graph_score)
    return int(ml_risk)  # 0 to 100
```

Write this score to Redis:
```
SET ml_risk:{subject} {score}
EXPIRE ml_risk:{subject} 300  # expire after 5 minutes
```

The gateway will read this key on the next request from this user.

Also write the full profile to Redis for dashboard display:
```
SET profile:{subject} {json_encoded_profile}
```

### Part 7: Learning from Feedback (hours 23 to 24)

Read blocked and allowed decisions from the gateway.

For blocked requests:
- Do NOT include them in the baseline (do not learn attacks as normal)
- Mark them as attacks in the profile

For allowed requests:
- Include them in the baseline (update the normal profile)
- Update the Markov model
- Update the graph

This ensures the system never poisons itself by learning attacks as normal behavior.

## Technical Requirements

- Python 3.x
- scikit learn for IsolationForest
- NetworkX for graph analysis
- Redis client (redis py) for writing scores
- numpy for numerical operations
- No TensorFlow or PyTorch (too slow to train in 24 hours)
- Statistical models only (Markov, IsolationForest, z scores)
- Async worker (asyncio) to not block on Redis or HTTP calls

## Data Flow

Gateway emits events (HTTP POST or queue) → ML worker receives
ML worker updates profiles in memory
ML worker computes anomaly scores with IsolationForest
ML worker builds Markov chains and graph
ML worker writes risk scores to Redis
Gateway reads risk scores from Redis on next request from that user

## Success Criteria

ML system must:
1. Maintain accurate behavioral baselines for each user
2. Detect anomalies with IsolationForest
3. Flag unusual call sequences with Markov chains
4. Build and analyze the access graph with NetworkX
5. Produce a risk score (0 to 100) for each user
6. Cache the score in Redis for fast gateway access
7. Learn from legitimate traffic only (no self poisoning)
8. Scale to handle thousands of entities

## Config

```python
ISOLATION_FOREST_THRESHOLD = 0.7  # anomaly threshold
MARKOV_PROBABILITY_THRESHOLD = 0.1  # unusual sequence threshold
REDIS_URL = 'redis://127.0.0.1:6379'
GATEWAY_ALERTS_URL = 'http://127.0.0.1:8081/admin/alerts'
POLL_INTERVAL_SECONDS = 2
ML_RISK_WEIGHTS = {
    'isolation_forest': 0.4,
    'markov_sequence': 0.3,
    'graph_novelty': 0.3
}
```

## Testing

Before 24 hour mark:
1. Start the gateway and ML worker together
2. Run the attack simulator
3. Watch ML risk scores update in Redis
4. Verify Markov chains detect unusual sequences
5. Verify IsolationForest flags anomalies
6. Confirm the gateway reads and uses ML risk scores in decisions
