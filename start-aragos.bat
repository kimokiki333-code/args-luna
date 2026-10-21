@echo off
title ARAGOS v3.0 — Neural Cyber Reconnaissance Platform
echo ============================================================
echo    ARAGOS v3.0 — Neural Cyber Reconnaissance ^& OSINT Suite
echo    4GB-RAM Optimized · Three.js Glassmorphism · Ollama Ready
echo ============================================================

cd /d "%~dp0"

REM 1. Check and auto-start Ollama in the background if installed
where ollama >nul 2>&1
if not errorlevel 1 (
    set OLLAMA_ORIGINS=*
    set OLLAMA_KEEP_ALIVE=2m
    curl -s http://127.0.0.1:11434/api/version >nul 2>&1
    if errorlevel 1 (
        echo [*] Starting Ollama daemon in the background...
        start "Ollama Daemon" /min ollama serve
        timeout /t 2 /nobreak >nul
    ) else (
        echo [+] Ollama daemon is already running on port 11434.
    )
) else (
    echo [i] Ollama CLI not found in PATH — using ARAGOS Built-in Neural Core.
)

REM 2. Check and install Python dependencies if needed
python -c "import fastapi, uvicorn, rich, dns, bs4" >nul 2>&1
if errorlevel 1 (
    echo [*] First-time setup: Installing Python dependencies...
    pip install -r requirements.txt
)

REM 3. Open the website and start the ARAGOS server
if "%PORT%"=="" set PORT=8000
echo [+] Opening http://localhost:%PORT% in your browser...
start "" http://localhost:%PORT%
echo [+] Starting ARAGOS Server on http://localhost:%PORT% (Keep this window open)
python server.py
pause
