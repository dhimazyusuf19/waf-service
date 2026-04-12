#!/bin/bash
set -e
SSL_DIR="./nginx/ssl"
mkdir -p "$SSL_DIR"
echo "[*] Generating default SSL certificate..."
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "${SSL_DIR}/default.key" \
  -out    "${SSL_DIR}/default.crt" \
  -subj   "/C=ID/ST=Jawa Barat/L=Bogor/O=PSSN/CN=waf.local" \
  -addext "subjectAltName=DNS:waf.local,DNS:localhost,IP:127.0.0.1"
echo "[+] Done: ${SSL_DIR}/default.crt + default.key"
