#!/bin/sh
# Generate a self-signed TLS certificate for local HTTPS.
# For production use a real cert (Let's Encrypt, etc.).
#
# Usage:
#   chmod +x nginx/gen-certs.sh
#   ./nginx/gen-certs.sh
#
# Then in docker-compose.yml:
#   1. Uncomment the HTTPS_PORT line under nginx ports
#   2. Swap nginx.conf volume to nginx-ssl.conf
#   3. Uncomment the nginx/certs volume
#   4. Set COOKIE_SECURE=true and APP_ENV=production in .env

set -e

CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$CERT_DIR/key.pem" \
  -out "$CERT_DIR/cert.pem" \
  -subj "/CN=rootnotes-local" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/key.pem"

echo ""
echo "Certificates written to $CERT_DIR"
echo "  cert.pem  — self-signed certificate (valid 10 years)"
echo "  key.pem   — private key (chmod 600)"
echo ""
echo "Next steps:"
echo "  1. In docker-compose.yml nginx section:"
echo "       - Uncomment: - \"\${HTTPS_PORT:-3443}:443\""
echo "       - Replace nginx.conf volume line with nginx-ssl.conf"
echo "       - Uncomment: - ./nginx/certs:/etc/nginx/certs:ro"
echo "  2. In .env set: COOKIE_SECURE=true  APP_ENV=production"
echo "  3. docker compose up -d --build"
