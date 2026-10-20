#!/usr/bin/env bash
set -e

echo "============================================================"
echo "   ARAGOS v3.0 — Neural Cyber Reconnaissance & OSINT Suite"
echo "   4GB-RAM Optimized · Three.js Glassmorphism · Ollama Ready"
echo "============================================================"

cd "$(dirname "$0")"

if ! python3 -c "import fastapi, uvicorn, rich, dns, bs4" >/dev/null 2>&1; then
  echo "[*] Installing Python dependencies..."
  pip install -r requirements.txt || pip install --break-system-packages -r requirements.txt
fi

export PORT="${PORT:-8000}"
echo "[+] Starting ARAGOS Web Platform on http://0.0.0.0:${PORT}"
exec python3 server.py
