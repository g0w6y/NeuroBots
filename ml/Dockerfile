# Project0 ML worker (per-entity IsolationForest, Markov sequence model,
# NetworkX access graph). Standalone process - it publishes a soft anomaly
# signal into Redis and is never on the request path.
#
# Build context is the REPO ROOT - see docker-compose.yml.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# scikit-learn/numpy ship manylinux wheels for CPython 3.12, so no compiler is
# needed here. If you ever bump to a Python with no prebuilt wheel this will
# start failing at build time rather than silently producing a slower image -
# fix it by adding build-essential in a builder stage, not by pinning to source.
COPY ml/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ml/ .

RUN useradd --create-home --uid 10002 mlworker \
    && chown -R mlworker:mlworker /app
USER mlworker

# No EXPOSE: the worker opens no listening socket. It polls the gateway over
# HTTP and writes to Redis, both outbound.

CMD ["python", "-u", "worker.py"]
