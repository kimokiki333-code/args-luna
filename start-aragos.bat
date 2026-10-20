@echo off
title ARAGOS v3.0 — Neural Cyber Reconnaissance Platform
echo ============================================================
echo    ARAGOS v3.0 — Neural Cyber Reconnaissance ^& OSINT Suite
echo    4GB-RAM Optimized · Three.js Glassmorphism · Ollama Ready
echo ============================================================

cd /d "%~dp0"

python -c "import fastapi, uvicorn, rich, dns, bs4" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing Python dependencies...
    pip install -r requirements.txt
)

if "%PORT%"=="" set PORT=8000
echo [+] Starting ARAGOS Web Platform on http://localhost:%PORT%
start "" http://localhost:%PORT%
python server.py
pause
