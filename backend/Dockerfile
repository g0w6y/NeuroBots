# Project0 gateway (FastAPI reverse proxy + detection engine).
#
# Build context is the REPO ROOT, not backend/ - see docker-compose.yml. That
# keeps one .dockerignore in charge of every image and lets this file reference
# backend/ explicitly rather than depending on which directory you ran from.
FROM python:3.12-slim

# Bytecode files and stdout buffering both hurt in a container: .pyc writes dirty
# the layer at runtime, and buffered stdout means `docker logs` shows nothing
# until the buffer flushes, which during an incident is exactly the wrong time.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# requirements.txt is copied and installed on its own layer, before the source.
# Docker caches layers by input hash, so editing main.py then rebuilds only the
# COPY below instead of reinstalling every dependency.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# Non-root, per DEVOPS.md. A gateway whose whole job is enforcing authorization
# should not be the one process on the host running as uid 0.
RUN useradd --create-home --uid 10001 project0 \
    && chown -R project0:project0 /app
USER project0

# 8080 only. The gateway serves its admin API and its WebSocket stream on the
# same port; there is no second listener to expose.
EXPOSE 8080

# HEALTHCHECK is what makes `depends_on: condition: service_healthy` in the
# compose file mean anything - without it Docker calls the container healthy the
# instant the process spawns, which is well before uvicorn is accepting.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"

# main.py's __main__ block reads LISTEN_ADDR/LISTEN_PORT from config.py and
# configures uvicorn's proxy-header trust from TRUSTED_PROXIES. Invoking uvicorn
# directly here would bypass that and silently reset trusted_proxies to the
# uvicorn default, so run the module as the app itself does.
CMD ["python", "main.py"]
