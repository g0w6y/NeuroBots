#!/bin/bash
# Generates a self-signed certificate for local TLS testing/demo use only.
# For a real deployment, replace certs/gateway.{crt,key} with a certificate
# from a real CA (Let's Encrypt, your org's internal CA, etc.) - this script
# exists so TLS_ENABLED=true is genuinely testable without one.

set -e
CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/gateway.key" \
    -out "$CERT_DIR/gateway.crt" \
    -days 365 \
    -subj "/CN=localhost/O=Project0 Dev" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo ""
echo "Generated: $CERT_DIR/gateway.crt, $CERT_DIR/gateway.key"
echo "Enable with: TLS_ENABLED=true python3 main.py"
echo "Test with:   curl -k https://127.0.0.1:8080/health"
echo "(-k needed because this is self-signed - a real cert wouldn't need it)"
