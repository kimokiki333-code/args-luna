#!/usr/bin/env bash
set -e

echo "============================================================"
echo "   ARAGOS v3.0 — Neural Cyber Reconnaissance & OSINT Suite"
echo "   4GB-RAM Optimized · Three.js Glassmorphism · Ollama Ready"
echo "============================================================"

cd "$(dirname "$0")"

if command -v ollama >/dev/null 2>&1; then
  export OLLAMA_ORIGINS="*"
  export OLLAMA_KEEP_ALIVE="2m"
  if ! curl -s http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
    echo "[*] Starting Ollama daemon in the background..."
    nohup ollama serve >/dev/null 2>&1 &
    sleep 2
  else
    echo "[+] Ollama daemon is already running on port 11434."
  fi
fi

if ! python3 -c "import fastapi, uvicorn, rich, dns, bs4" >/dev/null 2>&1; then
  echo "[*] Installing Python dependencies..."
  pip install -r requirements.txt || pip install --break-system-packages -r requirements.txt
fi

export PORT="${PORT:-8000}"
echo "[+] Starting ARAGOS Web Platform on http://localhost:${PORT}"
exec python3 server.py
