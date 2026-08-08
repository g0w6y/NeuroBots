#!/usr/bin/env python3
"""
NeuroBots: one command to run the whole stack.

    python3 run.py

Starts Redis + PostgreSQL (Docker, if available), installs backend/frontend
dependencies on first run if missing, then starts the demo upstream API, the
gateway, the ML worker, and the dashboard - all from this one process, all in
one terminal. Real health checks between each step, not fixed sleeps. Ctrl-C
stops everything it started, cleanly.

This does not replace start_all.sh/stop_all.sh or docker-compose - it's a
single-command wrapper around the same real services those already start,
for anyone who wants one command instead of five terminals.
"""

import atexit
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(ROOT, "backend")
FRONTEND = os.path.join(ROOT, "frontend")
ML = os.path.join(ROOT, "ml")

GATEWAY_URL = "http://127.0.0.1:8080"
UPSTREAM_URL = "http://127.0.0.1:9000"
DASHBOARD_URL = "http://localhost:3000"

PROCS = []  # (name, subprocess.Popen)


def log(msg):
    print(f"[run.py] {msg}", flush=True)


def http_ok(url, timeout=2):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status < 500
    except urllib.error.HTTPError as e:
        # 401/404 still means something real is listening and answering
        return e.code < 500
    except Exception:
        return False


def wait_for(url, name, timeout_sec=30):
    log(f"waiting for {name} at {url} ...")
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if http_ok(url):
            log(f"{name} is up")
            return True
        time.sleep(0.5)
    log(f"WARNING: {name} did not respond within {timeout_sec}s - check its log above")
    return False


def spawn(name, cmd, cwd, env=None):
    log(f"starting {name}: {' '.join(cmd)}")
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    p = subprocess.Popen(cmd, cwd=cwd, env=full_env)
    PROCS.append((name, p))
    return p


def stop_all():
    if not PROCS:
        return
    log("stopping everything this script started ...")
    for name, p in reversed(PROCS):
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
    time.sleep(1)
    for name, p in reversed(PROCS):
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass
        log(f"stopped {name}")


def docker_available():
    return shutil.which("docker") is not None


def docker_container_running(name):
    try:
        out = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        return name in out.stdout
    except Exception:
        return False


def docker_container_exists(name):
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        return name in out.stdout
    except Exception:
        return False


def start_redis_postgres():
    if not docker_available():
        log("Docker not found - skipping Redis/PostgreSQL. Gateway runs fine on")
        log("in-memory fallback (rate limits, BOLA, audit log all still work); you")
        log("just lose durable history and the ML worker's Redis signal.")
        return False

    started_any = False
    for name, run_args in (
        ("neurobots-redis", ["docker", "run", "-d", "--name", "neurobots-redis",
                              "-p", "6379:6379", "redis:7-alpine"]),
        ("neurobots-postgres", ["docker", "run", "-d", "--name", "neurobots-postgres",
                                 "-p", "5432:5432",
                                 "-e", "POSTGRES_USER=user", "-e", "POSTGRES_PASSWORD=password",
                                 "-e", "POSTGRES_DB=neurobots", "postgres:15-alpine"]),
    ):
        if docker_container_running(name):
            log(f"{name} already running, reusing it")
            continue
        if docker_container_exists(name):
            log(f"{name} exists but stopped, starting it")
            subprocess.run(["docker", "start", name], capture_output=True, timeout=15)
            started_any = True
            continue
        log(f"starting {name} ...")
        r = subprocess.run(run_args, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            log(f"WARNING: could not start {name}: {r.stderr.strip()[:200]}")
        else:
            started_any = True

    if started_any:
        log("waiting a few seconds for Redis/Postgres to accept connections ...")
        time.sleep(4)
    return True


def ensure_backend_deps():
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        import pydantic  # noqa: F401
        return
    except ImportError:
        pass
    log("backend dependencies missing - installing (first run only) ...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "-r",
         os.path.join(BACKEND, "requirements.txt")],
        check=True,
    )


def ensure_ml_deps():
    try:
        import sklearn  # noqa: F401
        import networkx  # noqa: F401
        return
    except ImportError:
        pass
    log("ML worker dependencies missing - installing (first run only) ...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "-r",
         os.path.join(ML, "requirements.txt")],
        check=True,
    )


def ensure_frontend_deps():
    if os.path.isdir(os.path.join(FRONTEND, "node_modules")):
        return
    npm = shutil.which("npm")
    if not npm:
        log("WARNING: npm not found - cannot install/run the dashboard. Backend still works.")
        return False
    log("frontend dependencies missing - running npm install (first run only) ...")
    subprocess.run([npm, "install"], cwd=FRONTEND, check=True)
    return True


def main():
    atexit.register(stop_all)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: sys.exit(0))

    log("=== NeuroBots: one-command startup ===")

    redis_up = start_redis_postgres()

    log("checking backend dependencies ...")
    ensure_backend_deps()

    log("=== 1/4 demo upstream API ===")
    spawn("demo_upstream", [sys.executable, "-u", "demo_upstream.py"], cwd=BACKEND)
    wait_for(f"{UPSTREAM_URL}/api/accounts/1001", "demo upstream")

    log("=== 2/4 gateway ===")
    env = {"REDIS_URL": "redis://127.0.0.1:6379"} if redis_up else {}
    spawn("gateway", [sys.executable, "-u", "main.py"], cwd=BACKEND, env=env)
    wait_for(f"{GATEWAY_URL}/health", "gateway")

    log("=== 3/4 ML worker ===")
    if redis_up and http_ok(GATEWAY_URL + "/health"):
        ensure_ml_deps()
        spawn(
            "ml_worker", [sys.executable, "-u", "worker.py"], cwd=ML,
            env={
                "REDIS_URL": "redis://127.0.0.1:6379",
                "GATEWAY_URL": GATEWAY_URL,
                "ADMIN_API_KEY": os.environ.get("ADMIN_API_KEY", "changeme-admin-key"),
            },
        )
        time.sleep(1)
    else:
        log("Redis not available - skipping ML worker. Detection is fully unaffected;")
        log("this only means the extra ML anomaly signal is not being computed.")

    log("=== 4/4 dashboard ===")
    frontend_started = False
    if os.path.isdir(FRONTEND):
        try:
            frontend_started = ensure_frontend_deps() is not False
            npm = shutil.which("npm")
            if npm:
                spawn("dashboard", [npm, "run", "dev"], cwd=FRONTEND)
                wait_for(DASHBOARD_URL, "dashboard", timeout_sec=20)
                frontend_started = True
        except Exception as e:
            log(f"WARNING: could not start the dashboard: {e}")

    print()
    log("=== everything that could start is up ===")
    log(f"gateway   : {GATEWAY_URL}")
    log(f"upstream  : {UPSTREAM_URL}")
    if frontend_started:
        log(f"dashboard : {DASHBOARD_URL}")
    log("attack suite (run in another terminal, once per gateway start):")
    log(f"  cd backend && python3 attack_sim/simulate.py")
    log("")
    log("Press Ctrl-C to stop everything this script started.")

    try:
        while True:
            time.sleep(1)
            for name, p in PROCS:
                if p.poll() is not None:
                    log(f"WARNING: {name} exited unexpectedly (code {p.returncode}) - check its output above")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
