from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    listen_addr: str = "0.0.0.0"
    listen_port: int = 8080
    upstream_url: str = "http://127.0.0.1:9000"

    jwt_secret: str = "demo-hs256-secret-change-me"
    jwt_rsa_pub_pem: str = ""
    issuer: str = "zt-idp"
    audience: str = "zt-api"

    redis_url: str = "redis://127.0.0.1:6379"
    database_url: str = "postgresql://user:password@localhost/project0"

    admin_api_key: str = "changeme-admin-key"

    learning_window_sec: int = 8
    block_threshold: int = 70
    challenge_threshold: int = 45
    enum_threshold: int = 8
    enum_window_sec: int = 10
    rate_limit_requests: int = 120
    rate_limit_window_sec: int = 60
    rate_limit_burst_requests: int = 25
    rate_limit_burst_sec: int = 3

    auto_block_threshold: int = 3
    auto_block_window_sec: int = 60
    auto_block_cooldown_sec: int = 300
    auto_block_max_multiplier: int = 4

    auto_block_ip_threshold: int = 10

    # Autonomous API hardening (bonus): distinct from auto-mitigation above,
    # which punishes a proven attacker. This raises a RESOURCE's own bar
    # when enough distinct attackers (not just one, repeatedly) hit it
    # within the window - see detect.py's resource_hardening_signal and
    # store.py's record_resource_attack for the full anti-gaming reasoning.
    resource_hardening_distinct_attackers: int = 3
    resource_hardening_window_sec: int = 300
    resource_hardening_cooldown_sec: int = 180

    bola_strict_mode: bool = False
    ownership_seed_file: str = "seed_ownership.json"
    route_config_file: str = "routes.json"

    # Comma-separated peer addresses whose X-Forwarded-For header is believed.
    # Empty by default, which means the socket peer is always used. The client
    # address decides the anon identity, the rate-limit bucket and the IP
    # cooldown key, so believing an unvalidated header hands all three to the
    # caller. Set this to your load balancer's address when you deploy behind one.
    trusted_proxies: str = ""

    # demo-mode default: permissive so the frontend can connect from any dev host/port
    # (varies by laptop, LAN IP, Vite port) without per-machine config during the
    # hackathon. The actual access boundary on every /admin/* route is the X-Admin-Key
    # header, not CORS - a page from an unlisted origin still can't read protected data
    # without knowing the key. Tighten this to a fixed origin list before any real
    # deployment beyond the demo.
    cors_allowed_origins: str = "*"

    # end-to-end encryption (transit): off by default so local dev/demo needs
    # no setup, genuinely functional when turned on. Generate a local dev
    # cert with generate_dev_cert.sh; use a real CA-issued cert in production.
    # Encryption at rest (the database) is an infrastructure-level
    # responsibility (e.g. cloud-provider disk/RDS encryption) - not
    # something meaningfully implemented by adding application code here,
    # since nothing sensitive enough to warrant field-level encryption is
    # actually stored (no raw credentials, no unredacted PII - see
    # security_checks.py's API3 response redaction for the latter).
    tls_enabled: bool = False
    tls_certfile: str = "certs/gateway.crt"
    tls_keyfile: str = "certs/gateway.key"

    # Horizontal scaling: 1 (default) keeps the simple single-process path
    # uvicorn.run(app, ...) already used. >1 requires passing the app as an
    # import string instead of an object - uvicorn's multiprocess workers
    # each import and start their own copy, which an already-instantiated
    # object can't be handed to. Only safe with Redis reachable: BOLA
    # ownership, rate-limit windows, and escalation state all live there
    # specifically so independent worker processes don't silently diverge.
    # Without Redis, each worker keeps its own in-memory fallback state and
    # WILL diverge - verified 2026-08-08, see backend/MEMORY.md.
    workers: int = 1

    # Production fail-closed gate (see main.py's startup check): when true,
    # the gateway refuses to start with any default secret still in place,
    # rather than silently running with demo-mode credentials in a
    # deployment that claims to be production.
    require_production_secrets: bool = False

    class Config:
        env_file = ".env"

settings = Settings()
