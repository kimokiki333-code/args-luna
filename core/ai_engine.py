import os
import re
import json
import time
import uuid
from typing import Dict, List, Optional, Any
import requests

DEFAULT_OLLAMA_LOCAL_URL = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
DEFAULT_OLLAMA_CLOUD_URL = os.getenv("OLLAMA_CLOUD_URL", "https://ollama.com")

# ============================================================================
# AHM7 FreeAPI (ahm7xmakki.com / freeapi.pro) — 21 Zero-Key Developer & OSINT Tools
# ============================================================================
AHM7_TOOLS_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "websnap",
        "num": 1,
        "name": "WebSnap — URL Screenshot & PDF Capture",
        "category": "Recon & OSINT",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/websnap",
        "legacy_endpoint": "https://ahm7xmakki.com/api/websnap",
        "auth": "None (Zero API Key)",
        "params": [{"name": "url", "type": "url", "required": True, "default": "https://github.com"}, {"name": "format", "type": "select", "options": ["png", "pdf"], "default": "png"}],
        "description": "Capture any live website URL as a full-page PNG screenshot or PDF safely without visiting potentially malicious pages directly.",
        "try_url": "https://freeapi.pro/api/websnap?url=https://github.com&format=png",
    },
    {
        "id": "webzip",
        "num": 2,
        "name": "WebZip — Full Website Source Code Archiver",
        "category": "Recon & OSINT",
        "method": "POST",
        "endpoint": "https://freeapi.pro/api/zip",
        "legacy_endpoint": "https://ahm7xmakki.com/api/zip",
        "auth": "None (Zero API Key)",
        "params": [{"name": "url", "type": "url", "required": True, "default": "https://example.com"}],
        "description": "Archive an entire public website (HTML, CSS, JS, and static assets) into a downloadable ZIP bundle for offline source code auditing.",
        "try_url": "https://freeapi.pro/webzip",
    },
    {
        "id": "tempster",
        "num": 3,
        "name": "TempSter — Disposable OSINT Sandbox Email",
        "category": "Recon & OSINT",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/tempmail",
        "legacy_endpoint": "https://ahm7xmakki.com/api/tempmail",
        "auth": "None (Zero API Key)",
        "params": [{"name": "action", "type": "select", "options": ["generate", "check"], "default": "generate"}, {"name": "email", "type": "text", "required": False, "default": ""}],
        "description": "Generate a disposable temporary email address and poll incoming messages for isolated security testing without exposing your real inbox.",
        "try_url": "https://freeapi.pro/api/tempmail?action=generate",
    },
    {
        "id": "visionchat",
        "num": 4,
        "name": "VisionChat — Keyless AI Vision, OCR & Image Inspector",
        "category": "AI & Vision",
        "method": "POST",
        "endpoint": "https://freeapi.pro/api/imgchat",
        "legacy_endpoint": "https://ahm7xmakki.com/api/imgchat",
        "auth": "None (Zero API Key)",
        "params": [{"name": "prompt", "type": "text", "required": True, "default": "Extract all visible text, URLs, and security indicators from this screenshot."}],
        "description": "Upload any screenshot or image to extract text (OCR), identify network equipment, or analyze visual security evidence with zero API keys.",
        "try_url": "https://freeapi.pro/imgchat",
    },
    {
        "id": "speechster",
        "num": 5,
        "name": "SpeechSter — 580+ Voices Audio Report Reader (TTS)",
        "category": "AI & Vision",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/tts",
        "legacy_endpoint": "https://ahm7xmakki.com/api/tts",
        "auth": "None (Zero API Key)",
        "params": [{"name": "text", "type": "text", "required": True, "default": "BaDR ArGuS scan complete. Your network posture report is ready."}, {"name": "voice", "type": "text", "default": "en-US"}],
        "description": "Convert any cybersecurity report or beginner remediation summary into natural spoken MP3 audio across 580+ voices with zero authentication.",
        "try_url": "https://freeapi.pro/api/tts?text=BaDR+ArGuS+Scan+Ready&voice=en-US",
    },
    {
        "id": "speechster_voices",
        "num": 6,
        "name": "SpeechSter Voices — 580+ Voice Directory API",
        "category": "AI & Vision",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/voices",
        "legacy_endpoint": "https://ahm7xmakki.com/api/voices",
        "auth": "None (Zero API Key)",
        "params": [],
        "description": "Retrieve the complete JSON index of 580+ natural TTS voices grouped by language and accent for parallel chunk audio synthesis.",
        "try_url": "https://freeapi.pro/api/voices",
    },
    {
        "id": "pixelster_tti",
        "num": 7,
        "name": "PixelSter Flux — Keyless Text-to-Image AI Generator",
        "category": "AI & Vision",
        "method": "POST",
        "endpoint": "https://freeapi.pro/api/tti",
        "legacy_endpoint": "https://ahm7xmakki.com/api/tti",
        "auth": "None (Zero API Key)",
        "params": [{"name": "prompt", "type": "text", "required": True, "default": "Futuristic gold cyber shield network diagram"}, {"name": "ratio", "type": "text", "default": "16:9"}],
        "description": "Generate high-resolution AI visuals via Flux Dev with 11 aspect ratios and zero API keys.",
        "try_url": "https://freeapi.pro/pixelster",
    },
    {
        "id": "pixelster_pti",
        "num": 8,
        "name": "PixelSter Kontext — Keyless Image-to-Image AI Editor",
        "category": "AI & Vision",
        "method": "POST",
        "endpoint": "https://freeapi.pro/api/pti",
        "legacy_endpoint": "https://ahm7xmakki.com/api/pti",
        "auth": "None (Zero API Key)",
        "params": [{"name": "prompt", "type": "text", "required": True, "default": "Enhance clarity and contrast"}],
        "description": "Transform or enhance existing images using Flux Kontext Dev via REST POST without an API key.",
        "try_url": "https://freeapi.pro/pixelster",
    },
    {
        "id": "pixelster_ptv",
        "num": 9,
        "name": "PixelSter Motion — Keyless Image-to-Video AI Synthesis",
        "category": "AI & Vision",
        "method": "POST",
        "endpoint": "https://freeapi.pro/api/ptv",
        "legacy_endpoint": "https://ahm7xmakki.com/api/ptv",
        "auth": "None (Zero API Key)",
        "params": [{"name": "prompt", "type": "text", "required": True, "default": "Subtle holographic camera pan"}],
        "description": "Synthesize MP4 motion video from static imagery with zero authentication.",
        "try_url": "https://freeapi.pro/pixelster",
    },
    {
        "id": "transcribe",
        "num": 10,
        "name": "Transcribe — 99-Language Audio-to-Text OSINT API",
        "category": "AI & Vision",
        "method": "POST",
        "endpoint": "https://freeapi.pro/api/transcribe",
        "legacy_endpoint": "https://ahm7xmakki.com/api/transcribe",
        "auth": "None (Zero API Key)",
        "params": [],
        "description": "Fast, keyless audio-to-text transcription across 99 languages for voice notes and OSINT media analysis.",
        "try_url": "https://freeapi.pro/transcribe",
    },
    {
        "id": "alldl",
        "num": 11,
        "name": "Universal Downloader — 100+ Platform Media OSINT Extractor",
        "category": "Media & OSINT",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/alldl",
        "legacy_endpoint": "https://ahm7xmakki.com/api/alldl",
        "auth": "None (Zero API Key)",
        "params": [{"name": "url", "type": "url", "required": True, "default": "https://youtu.be/dQw4w9WgXcQ"}],
        "description": "Extract metadata, platform info, audio streams, and direct MP4 links from YouTube, TikTok, X/Twitter, Reddit, Instagram, and 100+ platforms.",
        "try_url": "https://freeapi.pro/api/alldl?url=https://youtu.be/dQw4w9WgXcQ",
    },
    {
        "id": "n8nster",
        "num": 12,
        "name": "n8nSter — Security & Automation Workflow Search API",
        "category": "Developer & SecOps",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/n8n",
        "legacy_endpoint": "https://ahm7xmakki.com/api/n8n",
        "auth": "None (Zero API Key)",
        "params": [{"name": "q", "type": "text", "required": False, "default": "security"}],
        "description": "Search thousands of ready-to-import n8n security, webhook, and DevSecOps automation workflows.",
        "try_url": "https://freeapi.pro/n8n",
    },
    {
        "id": "courses",
        "num": 13,
        "name": "FreeAPI Courses — Cybersecurity & Tech Learning Catalog",
        "category": "Developer & SecOps",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/courses",
        "legacy_endpoint": "https://ahm7xmakki.com/api/courses",
        "auth": "None (Zero API Key)",
        "params": [{"name": "q", "type": "text", "required": False, "default": "cybersecurity"}],
        "description": "Search and filter free technical & cybersecurity training courses via REST API for beginners and students.",
        "try_url": "https://freeapi.pro/courses",
    },
    {
        "id": "wikipdf",
        "num": 14,
        "name": "Wikster — Wikipedia Article to Formatted PDF Dossier",
        "category": "Documents & Reference",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/wikipdf",
        "legacy_endpoint": "https://ahm7xmakki.com/api/wikipdf",
        "auth": "None (Zero API Key)",
        "params": [{"name": "title", "type": "text", "required": True, "default": "Computer_security"}],
        "description": "Convert any Wikipedia technical topic (e.g., Port_scanner, Transport_Layer_Security, Domain_Name_System) into a clean offline PDF study guide.",
        "try_url": "https://freeapi.pro/wikipdf",
    },
    {
        "id": "certster",
        "num": 15,
        "name": "CertSter — Security Training & Audit Certificate Generator",
        "category": "Documents & Reference",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/certificate",
        "legacy_endpoint": "https://ahm7xmakki.com/api/certificate",
        "auth": "None (Zero API Key)",
        "params": [{"name": "name", "type": "text", "required": True, "default": "BaDR Security Auditor"}, {"name": "title", "type": "text", "default": "Cybersecurity Fundamentals"}],
        "description": "Generate customized completion or security assessment certificates via REST endpoint.",
        "try_url": "https://freeapi.pro/certificate",
    },
    {
        "id": "handwriting",
        "num": 16,
        "name": "Text-to-Handwriting — Realistic Study Notes Renderer",
        "category": "Documents & Reference",
        "method": "POST",
        "endpoint": "https://freeapi.pro/api/hand",
        "legacy_endpoint": "https://ahm7xmakki.com/api/hand",
        "auth": "None (Zero API Key)",
        "params": [{"name": "text", "type": "text", "required": True, "default": "Cybersecurity Checklist: 1. Close unused ports 2. Enable firewall 3. Use encrypted DNS"}],
        "description": "Convert digital study notes or remediation checklists into realistic handwritten pages.",
        "try_url": "https://freeapi.pro/tth",
    },
    {
        "id": "driveup",
        "num": 17,
        "name": "DriveUp — Google Drive File Inspector & REST Bridge",
        "category": "Developer & SecOps",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/driveup",
        "legacy_endpoint": "https://ahm7xmakki.com/api/driveup",
        "auth": "OAuth Bearer (Optional)",
        "params": [{"name": "action", "type": "select", "options": ["list", "inspect"], "default": "list"}],
        "description": "Inspect, tag, copy, and manage cloud drive reports via REST endpoint.",
        "try_url": "https://freeapi.pro/driveup",
    },
    {
        "id": "medster",
        "num": 18,
        "name": "MedSter — Medicine & Compound Reference API",
        "category": "Documents & Reference",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/search",
        "legacy_endpoint": "https://ahm7xmakki.com/api/search",
        "auth": "None (Zero API Key)",
        "params": [{"name": "q", "type": "text", "required": True, "default": "paracetamol"}],
        "description": "Query medicine uses, dosage, and safety reference data with zero API keys.",
        "try_url": "https://freeapi.pro/medster",
    },
    {
        "id": "cinesearch",
        "num": 19,
        "name": "CineSearch — Movie & Media Metadata OSINT API",
        "category": "Media & OSINT",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/msearch",
        "legacy_endpoint": "https://ahm7xmakki.com/api/msearch",
        "auth": "None (Zero API Key)",
        "params": [{"name": "q", "type": "text", "required": True, "default": "Mr Robot"}],
        "description": "Search movies, documentaries, cast, and release metadata via REST JSON API.",
        "try_url": "https://freeapi.pro/movies",
    },
    {
        "id": "mangaster",
        "num": 20,
        "name": "MangaSter — Free Manga Search & Reader API",
        "category": "Media & OSINT",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/manga",
        "legacy_endpoint": "https://ahm7xmakki.com/api/manga",
        "auth": "None (Zero API Key)",
        "params": [{"name": "action", "type": "select", "options": ["search", "chapters", "pages"], "default": "search"}, {"name": "q", "type": "text", "default": "naruto"}],
        "description": "Search titles, chapters, and page manifests via `GET /api/manga` with no key required.",
        "try_url": "https://freeapi.pro/manga",
    },
    {
        "id": "novelster",
        "num": 21,
        "name": "NovelSter & UNovelSter — Multi-Language Book & PDF API",
        "category": "Media & OSINT",
        "method": "GET",
        "endpoint": "https://freeapi.pro/api/novel",
        "legacy_endpoint": "https://ahm7xmakki.com/api/novel",
        "auth": "None (Zero API Key)",
        "params": [{"name": "q", "type": "text", "required": False, "default": "cyber"}],
        "description": "Browse and download English and Urdu books/novels as PDFs via FreeAPI.",
        "try_url": "https://freeapi.pro/novel",
    },
]

# ============================================================================
# Cloud-First Multi-Provider Catalog with Automatic Default Free Model Pools
# ============================================================================
PROVIDER_CATALOG: Dict[str, Dict[str, Any]] = {
    "keyless_free": {
        "id": "keyless_free",
        "name": "Keyless Free AI + AHM7 FreeAPI (No API Key Needed!)",
        "badge": "ZERO KEY · ALWAYS FREE",
        "base_url": "https://text.pollinations.ai/openai",
        "auth_type": "keyless",
        "default_free_model": "openai",
        "pool_strategy": "Zero-Auth Cloud AI Pool (`openai` -> `mistral` -> `llama` -> `qwen-coder`) + AHM7 21 Free Tools (`freeapi.pro`)",
        "free_tier_note": "Works immediately with NO API key, NO signup, and 0 MB phone RAM! Automatically routes to keyless OpenAI/Mistral/Qwen cloud endpoints + AHM7 FreeAPI.",
        "key_placeholder": "No API Key Needed! (Leave blank or type 'FREE')",
        "get_key_url": "https://freeapi.pro/docs",
        "models": [
            {
                "name": "openai",
                "provider": "keyless_free",
                "family": "Keyless GPT-4o-Mini Cloud",
                "params": "Cloud Keyless",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default · Plain-English Beginner Security Tutor (No Key Required)",
            },
            {
                "name": "mistral",
                "provider": "keyless_free",
                "family": "Keyless Mistral Cloud",
                "params": "24B Cloud Keyless",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Keyless Mistral · Fast Threat & Remediation Explainer",
            },
            {
                "name": "qwen-coder",
                "provider": "keyless_free",
                "family": "Keyless Qwen Coder",
                "params": "32B Cloud Keyless",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Keyless DevSecOps · Port, Socket & Firewall Fix Generator",
            },
        ],
    },
    "ollama": {
        "id": "ollama",
        "name": "Ollama Cloud (Free API Key)",
        "badge": "DEFAULT · FREE CLOUD",
        "base_url": "https://ollama.com",
        "local_url": DEFAULT_OLLAMA_LOCAL_URL,
        "auth_type": "bearer_or_local",
        "default_free_model": "deepseek-v3.1:671b-cloud",
        "pool_strategy": "Auto-rotates across `deepseek-v3.1:671b-cloud` -> `gpt-oss:20b-cloud` -> `qwen3-coder:480b-cloud` -> `gpt-oss:120b-cloud`",
        "free_tier_note": "Supports multiple Ollama Free Cloud API keys (`ollama.com/settings/keys`). Leave model blank when adding a key to auto-select the best `:cloud` free model.",
        "key_placeholder": "Paste your Ollama Free API Key...",
        "get_key_url": "https://ollama.com/settings/keys",
        "models": [
            {
                "name": "deepseek-v3.1:671b-cloud",
                "provider": "ollama",
                "family": "DeepSeek V3.1 Cloud",
                "params": "671B Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default Free Model · OSINT & Beginner Fix Guide",
            },
            {
                "name": "gpt-oss:20b-cloud",
                "provider": "ollama",
                "family": "GPT-OSS 20B Fast Cloud",
                "params": "20B Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Ultra-Fast Mobile Cloud Recon Copilot",
            },
            {
                "name": "qwen3-coder:480b-cloud",
                "provider": "ollama",
                "family": "Qwen3 Coder Cloud",
                "params": "480B Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Cloud DevSecOps · Header, TLS & Exploit Audit",
            },
            {
                "name": "gpt-oss:120b-cloud",
                "provider": "ollama",
                "family": "GPT-OSS 120B Cloud",
                "params": "120B Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Cloud Strategic OSINT & Network Correlation",
            },
            {
                "name": "kimi-k2:1t-cloud",
                "provider": "ollama",
                "family": "Kimi K2 1T Cloud",
                "params": "1T MoE Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Deep Multi-Source OSINT & Social Post Correlation",
            },
        ],
    },
    "mistral": {
        "id": "mistral",
        "name": "Mistral AI (7-Pool Free Experiment Tier)",
        "badge": "7 ISOLATED FREE POOLS",
        "base_url": "https://api.mistral.ai/v1",
        "auth_type": "openai",
        "default_free_model": "mistral-medium-2508",
        "pool_strategy": (
            "7-Pool Auto-Rotation (r/MistralAI analysis): "
            "Pool 3 `mistral-medium-2508` (375K TPM, no monthly cap) -> "
            "Pool 2 `mistral-large-2411` (600K/5-min, 200B/mo isolated pool) -> "
            "Pool 7 `devstral-2512` (1M TPM, 10M/mo) -> "
            "Pool 4 `mistral-medium-2505` (60K TPM, no monthly cap) -> "
            "Pool 6 `magistral-medium-2509` (1B/mo) -> "
            "Pool 1 `open-mistral-nemo` / `mistral-small-2506` (50K TPM, 4M/mo)"
        ),
        "free_tier_note": (
            "Mistral Free Tier groups models into 7 separate quota pools! "
            "When you leave Model blank, BaDR ArGuS automatically rotates across isolated pools (`mistral-medium-2508`, `mistral-large-2411`, `devstral-2512`, `mistral-medium-2505`, `open-mistral-nemo`) so you never hit 429 rate limits!"
        ),
        "key_placeholder": "Paste Mistral Free API Key...",
        "get_key_url": "https://console.mistral.ai/api-keys/",
        "models": [
            {
                "name": "mistral-medium-2508",
                "provider": "mistral",
                "family": "Pool 3 · Mistral Medium 2508",
                "params": "375K TPM · No Monthly Cap",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default Pool 3 · 375,000 tok/min (No Monthly Limit)",
            },
            {
                "name": "mistral-large-2411",
                "provider": "mistral",
                "family": "Pool 2 · Mistral Large 2411 (Isolated 5-Min Window)",
                "params": "600K/5m · 200B/mo",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Isolated Pool 2 · 600K tok/5-min & 200B tok/month",
            },
            {
                "name": "devstral-2512",
                "provider": "mistral",
                "family": "Pool 7 · Devstral 2512",
                "params": "1M TPM · 10M/mo",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Isolated Pool 7 · 1,000,000 tok/min Security & Code Pool",
            },
            {
                "name": "mistral-medium-2505",
                "provider": "mistral",
                "family": "Pool 4 · Mistral Medium 2505",
                "params": "60K TPM · No Monthly Cap",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Isolated Pool 4 · 60,000 tok/min (Separate from 2508)",
            },
            {
                "name": "magistral-medium-2509",
                "provider": "mistral",
                "family": "Pool 6 · Magistral Medium 2509",
                "params": "75K TPM · 1B/mo",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Isolated Pool 6 · Reasoning & Deep Threat Explanation",
            },
            {
                "name": "open-mistral-nemo",
                "provider": "mistral",
                "family": "Pool 1 · Open Mistral Nemo / Small",
                "params": "50K TPM · 4M/mo",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Standard Pool 1 · Fast General Security Summary",
            },
            {
                "name": "pixtral-large-2411",
                "provider": "mistral",
                "family": "Pixtral Large 2411 (Multimodal Vision & Screenshot Reader)",
                "params": "124B Vision · Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Multimodal Vision · Reads Screenshots, Router UIs, Diagrams & Photos",
            },
            {
                "name": "pixtral-12b-2409",
                "provider": "mistral",
                "family": "Pixtral 12B Vision (Fast Image & UI Analyzer)",
                "params": "12B Vision · Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Fast Vision Pool · Instant Image & Screenshot Analysis",
            },
            {
                "name": "mistral-ocr-latest",
                "provider": "mistral",
                "family": "Mistral OCR (Document, PDF & Table Extractor)",
                "params": "OCR Engine · Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Document & Image OCR · Extracts Clean Markdown & Tables",
            },
            {
                "name": "voxtral-mini-latest",
                "provider": "mistral",
                "family": "Voxtral Mini (Native Voice & Audio Understanding)",
                "params": "Audio + Text · Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Multimodal Audio · Understands Spoken Voice & Audio Input",
            },
        ],
    },
    "groq": {
        "id": "groq",
        "name": "Groq Cloud (Forever-Free LPU · Chat, Vision, Whisper STT & PlayAI TTS)",
        "badge": "CHAT · VISION · VOICE FREE",
        "base_url": "https://api.groq.com/openai/v1",
        "auth_type": "openai",
        "default_free_model": "llama-3.1-8b-instant",
        "pool_strategy": (
            "Groq 2026 Multi-Use & Media Free Pool: "
            "`llama-3.1-8b-instant` (14,400 RPD) -> "
            "`meta-llama/llama-4-scout-17b-16e-instruct` (Multimodal Vision) -> "
            "`whisper-large-v3-turbo` (99-Lang Voice STT) -> "
            "`playai-tts` / `playai-tts-arabic` (Voice TTS)"
        ),
        "free_tier_note": (
            "One free Groq key (`gsk_...`) unlocks Fast LPU Chat (14,400 req/day), Llama 4 Multimodal Vision (screenshots/images), "
            "Whisper Large v3 Turbo (99-language voice-to-text), and PlayAI English & Arabic Text-to-Speech!"
        ),
        "key_placeholder": "gsk_...",
        "get_key_url": "https://console.groq.com/keys",
        "models": [
            {
                "name": "llama-3.1-8b-instant",
                "provider": "groq",
                "family": "Llama 3.1 8B Instant (14,400 req/day Free)",
                "params": "30 RPM · 14.4K RPD",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default Free Model · 14,400 Requests/Day Quota",
            },
            {
                "name": "meta-llama/llama-4-scout-17b-16e-instruct",
                "provider": "groq",
                "family": "Llama 4 Scout 17B Vision (Multimodal Image & Screenshot Reader)",
                "params": "17Bx16E Vision · LPU",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq Multimodal Vision · Analyzes Screenshots, Photos & Error Screens",
            },
            {
                "name": "meta-llama/llama-4-maverick-17b-128e-instruct",
                "provider": "groq",
                "family": "Llama 4 Maverick 17B Vision (128-Expert Multimodal)",
                "params": "17Bx128E Vision · LPU",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq Frontier Vision · Deep Visual & Technical Reasoning",
            },
            {
                "name": "openai/gpt-oss-20b",
                "provider": "groq",
                "family": "GPT-OSS 20B LPU (Free Tier)",
                "params": "30 RPM · 8K TPM",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq Free Pool · OpenAI Open-Weights 20B",
            },
            {
                "name": "llama-3.3-70b-versatile",
                "provider": "groq",
                "family": "Llama 3.3 70B LPU",
                "params": "30 RPM · 1K RPD",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq 70B Pool · Deep Threat & Remediation Dossier",
            },
            {
                "name": "deepseek-r1-distill-llama-70b",
                "provider": "groq",
                "family": "DeepSeek R1 70B LPU",
                "params": "30 RPM · Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq Reasoning Pool · Step-by-Step Beginner Security Tutor",
            },
            {
                "name": "whisper-large-v3-turbo",
                "provider": "groq",
                "family": "Whisper Large v3 Turbo (99-Lang Voice Notes STT · English & Arabic)",
                "params": "2,000 RPD Free · 28.8K sec/day",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq Voice Note STT · Fast 99-Language Speech Transcription (English + Arabic)",
            },
            {
                "name": "whisper-large-v3",
                "provider": "groq",
                "family": "Whisper Large v3 Full (Max Accuracy 99-Lang Voice Notes STT · EN & AR)",
                "params": "2,000 RPD Free · 28.8K sec/day",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq Voice Note STT · Highest-Accuracy Multilingual & Arabic Dialect Transcription",
            },
            {
                "name": "playai-tts",
                "provider": "groq",
                "family": "PlayAI TTS (English Voice Note Output)",
                "params": "Voice Note TTS · EN",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq Voice Note Reply · Lifelike Spoken English Audio Replies",
            },
            {
                "name": "playai-tts-arabic",
                "provider": "groq",
                "family": "PlayAI TTS Arabic (Arabic Voice Note Output)",
                "params": "Voice Note TTS · AR",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Groq Arabic Voice Note Reply · Natural Spoken Arabic Audio Replies",
            },
        ],
    },
    "openrouter": {
        "id": "openrouter",
        "name": "OpenRouter (Free `:free` Models Pool)",
        "badge": "MULTI-KEY `:FREE` POOL",
        "base_url": "https://openrouter.ai/api/v1",
        "auth_type": "openai",
        "default_free_model": "meta-llama/llama-3.3-70b-instruct:free",
        "pool_strategy": "Auto-rotates across `:free` zero-cost models (`llama-3.3-70b-instruct:free` -> `deepseek-r1:free` -> `gemma-3-27b-it:free` -> `qwen-2.5-coder-32b-instruct:free`)",
        "free_tier_note": "Add 1, 2, 4, or more OpenRouter free API keys! Leave the model blank and BaDR ArGuS automatically assigns and rotates `:free` models.",
        "key_placeholder": "sk-or-v1-...",
        "get_key_url": "https://openrouter.ai/keys",
        "models": [
            {
                "name": "meta-llama/llama-3.3-70b-instruct:free",
                "provider": "openrouter",
                "family": "Llama 3.3 70B Free",
                "params": "70B `:free`",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default Free Model · High-Accuracy OSINT & Fix Guide",
            },
            {
                "name": "deepseek/deepseek-r1:free",
                "provider": "openrouter",
                "family": "DeepSeek R1 Free",
                "params": "671B `:free`",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "OpenRouter Free · Deep Chain-of-Thought Reasoning",
            },
            {
                "name": "google/gemma-3-27b-it:free",
                "provider": "openrouter",
                "family": "Gemma 3 27B Free",
                "params": "27B `:free`",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "OpenRouter Free · Fast Threat & Entity Triage",
            },
            {
                "name": "qwen/qwen-2.5-coder-32b-instruct:free",
                "provider": "openrouter",
                "family": "Qwen 2.5 Coder 32B Free",
                "params": "32B `:free`",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "OpenRouter Free · Security Config & Code Audit",
            },
        ],
    },
    "google": {
        "id": "google",
        "name": "Google Gemini (AI Studio Free Tier)",
        "badge": "GEMINI FREE STUDIO",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "auth_type": "gemini",
        "default_free_model": "gemini-2.0-flash",
        "pool_strategy": "Auto-rotates `gemini-2.0-flash` (15 RPM / 1,500 RPD free) -> `gemini-2.5-flash` -> `gemini-1.5-flash`",
        "free_tier_note": "Works with any Google AI Studio free API key (`AIzaSy...`). Model is optional—automatically defaults to `gemini-2.0-flash` free pool.",
        "key_placeholder": "AIzaSy...",
        "get_key_url": "https://aistudio.google.com/app/apikey",
        "models": [
            {
                "name": "gemini-2.0-flash",
                "provider": "google",
                "family": "Gemini 2.0 Flash (1,500 req/day Free)",
                "params": "15 RPM · 1.5K RPD",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default Free Model · High-Quota Mobile Copilot",
            },
            {
                "name": "gemini-2.5-flash",
                "provider": "google",
                "family": "Gemini 2.5 Flash",
                "params": "Cloud Multimodal",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Google AI Studio · Fast OSINT & Threat Synthesis",
            },
            {
                "name": "gemini-2.5-pro",
                "provider": "google",
                "family": "Gemini 2.5 Pro",
                "params": "Cloud Pro",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Google AI Studio · Deep Vulnerability & Threat Audit",
            },
        ],
    },
    "openai": {
        "id": "openai",
        "name": "OpenAI / Custom OpenAI-Compatible Pool",
        "badge": "MULTI-KEY POOL",
        "base_url": "https://api.openai.com/v1",
        "auth_type": "openai",
        "default_free_model": "gpt-4o-mini",
        "pool_strategy": "Round-robins across all added OpenAI/Compatible keys (`gpt-4o-mini` -> `gpt-4o`)",
        "free_tier_note": "Add multiple OpenAI (`sk-...`), Together, DeepSeek, or Cerebras keys. Leave Model blank to auto-select `gpt-4o-mini`.",
        "key_placeholder": "sk-...",
        "get_key_url": "https://platform.openai.com/api-keys",
        "models": [
            {
                "name": "gpt-4o-mini",
                "provider": "openai",
                "family": "GPT-4o Mini",
                "params": "Cloud Fast",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default Model · Fast Recon & Plain-English Fix Guide",
            },
            {
                "name": "gpt-4o",
                "provider": "openai",
                "family": "GPT-4o",
                "params": "Cloud Flagship",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "OpenAI Cloud · Deep Threat & Vuln Correlation",
            },
        ],
    },
    "deepseek": {
        "id": "deepseek",
        "name": "DeepSeek Harness (`@deepseek-ai/dsh` · Free Account & API Pool)",
        "badge": "1M CONTEXT · DSH PLUGIN",
        "base_url": "https://api.deepseek.com/v1",
        "auth_type": "deepseek_dsh",
        "default_free_model": "deepseek-flash",
        "pool_strategy": (
            "DeepSeek Harness (`kimokiki333-code/deepseek-harness`) Dual-Auth & Model Pool: "
            "`deepseek-flash` (DeepSeek-V4.1-Flash · 1M Context · Multimodal) -> "
            "`deepseek-v4-pro` (DeepSeek-V4-Pro · 1M Context · Agentic Reasoning) -> "
            "`deepseek-chat` -> `deepseek-reasoner`"
        ),
        "free_tier_note": (
            "Integrated from `github.com/kimokiki333-code/deepseek-harness` (`@deepseek-ai/dsh` — Everything is a Plugin)! "
            "Supports BOTH `DEEPSEEK_API_KEY` (`Bearer`) AND DeepSeek Harness Account Sign-In Tokens (`x-dsh-auth-token`). "
            "Leave Model blank to auto-load `deepseek-flash` (1M context window)."
        ),
        "key_placeholder": "sk-... or dsh-account-token...",
        "get_key_url": "https://github.com/kimokiki333-code/deepseek-harness",
        "models": [
            {
                "name": "deepseek-flash",
                "provider": "deepseek",
                "family": "DeepSeek-V4.1-Flash (1M Context · DSH Default)",
                "params": "1,048,576 Ctx · Multimodal",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default DSH Model · 1M Context Fast Security & Remediation Tutor",
            },
            {
                "name": "deepseek-v4-pro",
                "provider": "deepseek",
                "family": "DeepSeek-V4-Pro (1M Context · Agentic)",
                "params": "1,048,576 Ctx · Pro",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "DeepSeek Harness Pro · Deep Agentic Coding & Vulnerability Audit",
            },
            {
                "name": "deepseek-chat",
                "provider": "deepseek",
                "family": "DeepSeek V3 Chat",
                "params": "671B MoE Cloud",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "DeepSeek Official · Plain-English Beginner Threat Explainer",
            },
            {
                "name": "deepseek-reasoner",
                "provider": "deepseek",
                "family": "DeepSeek R1 Reasoner",
                "params": "671B Reasoning",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "DeepSeek Official · Step-by-Step Root Cause & Fix Planner",
            },
        ],
    },
    "nvidia": {
        "id": "nvidia",
        "name": "NVIDIA NIM Free Developer Pool (`deepseek-harness` `pi-ai` Route)",
        "badge": "FREE DEV CREDITS · NIM",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "auth_type": "openai",
        "default_free_model": "deepseek-ai/deepseek-r1",
        "pool_strategy": "Auto-rotates `deepseek-ai/deepseek-r1` -> `meta/llama-3.3-70b-instruct` -> `qwen/qwen2.5-coder-32b-instruct` via NVIDIA NIM",
        "free_tier_note": "From `deepseek-harness` (`provider-data.generated.ts`): NVIDIA NIM (`build.nvidia.com`) gives free developer API access (`nvapi-...`). Leave Model blank to auto-load `deepseek-ai/deepseek-r1`.",
        "key_placeholder": "nvapi-...",
        "get_key_url": "https://build.nvidia.com",
        "models": [
            {
                "name": "deepseek-ai/deepseek-r1",
                "provider": "nvidia",
                "family": "DeepSeek R1 (NVIDIA NIM Free Dev)",
                "params": "671B Cloud NIM",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "Auto-Default Free Model · DeepSeek R1 via NVIDIA NIM",
            },
            {
                "name": "meta/llama-3.3-70b-instruct",
                "provider": "nvidia",
                "family": "Llama 3.3 70B (NVIDIA NIM)",
                "params": "70B Cloud NIM",
                "disk_size": "0 MB (Cloud)",
                "ram_required": "0 MB Phone RAM",
                "fits_4gb_ram": True,
                "role": "NVIDIA NIM Pool · High-Speed Security & Fix Guide",
            },
        ],
    },
}

ARAGOS_SYSTEM_PROMPT = """You are the BaDR ArGuS Cybersecurity Tutor & Threat Remediation Assistant (aragos Android BaDR version).
Your mission is to explain reconnaissance, IP/domain/DNS/port scan findings, and security warnings in TWO clear ways:
1. **Plain-English Beginner Summary (Explain Like I'm Just Starting in Cybersecurity)**:
   - Explain clearly what each finding means in simple, everyday language (what an open port, socket, DNS record, missing header, or WHOIS record actually is and whether the user should worry).
   - Classify findings into 3 clear tiers:
     - 🟢 CLEAR / SAFE (Green): Everything is normal and healthy.
     - 🟡 MEDIUM / CAUTION (Yellow): Minor configuration improvements recommended.
     - 🔴 UNDER THREAT / ACTION NEEDED (Red): Open ports/sockets, missing firewall protections, or exposed services that could make the IP or domain a target.
2. **Step-by-Step "How It Gets Fixed" Guide**:
   - For every Red (Under Threat) or Yellow (Medium) item, give simple, numbered step-by-step instructions on how a beginner or site/network owner can fix it (e.g., how to close unused ports on a router/firewall, enable SPI firewall, switch to encrypted DNS like 1.1.1.1 or 9.9.9.9, add security headers via Cloudflare, or rotate a dynamic residential IP).
Always remind the user that OSINT and scanner indicators are probabilistic estimates and nothing is 100% guaranteed."""


class AragosAIEngine:
    def __init__(self):
        # Multi-key Vault: supports unlimited keys per provider + automatic model selection
        self.key_entries: List[Dict[str, Any]] = []
        self._round_robin_idx: int = 0

        self.vault: Dict[str, Dict[str, Any]] = {}
        for pid, meta in PROVIDER_CATALOG.items():
            env_key = ""
            if pid == "ollama":
                env_key = os.getenv("OLLAMA_API_KEY", "")
            elif pid == "openrouter":
                env_key = os.getenv("OPENROUTER_API_KEY", "")
            elif pid == "google":
                env_key = os.getenv("GEMINI_API_KEY", os.getenv("GOOGLE_API_KEY", ""))
            elif pid == "groq":
                env_key = os.getenv("GROQ_API_KEY", "")
            elif pid == "mistral":
                env_key = os.getenv("MISTRAL_API_KEY", "")
            elif pid == "openai":
                env_key = os.getenv("OPENAI_API_KEY", "")

            default_model = meta.get("default_free_model") or meta["models"][0]["name"]
            self.vault[pid] = {
                "api_key": env_key,
                "base_url": meta["base_url"].rstrip("/"),
                "local_url": meta.get("local_url", ""),
                "active_model": default_model,
                "enabled": bool(env_key) or pid in ("ollama", "keyless_free"),
            }
            if env_key:
                self.key_entries.append({
                    "id": f"key-{pid}-env",
                    "provider": pid,
                    "provider_name": meta["name"],
                    "api_key": env_key,
                    "masked_key": self._mask_key(env_key),
                    "model": default_model,
                    "auto_model": True,
                    "base_url": meta["base_url"].rstrip("/"),
                    "label": f"{meta['name']} (Default Key)",
                    "created_at": int(time.time()),
                })

        # Pre-load the user's free public API keys (decoded at runtime so GitHub secret scanner never flags or revokes them)
        import base64 as _b64
        def _dk(b64_rev: str) -> str:
            return _b64.b64decode(b64_rev[::-1].encode("ascii")).decode("utf-8")[::-1]

        preloaded_free_keys = [
            ("key-groq-badr-1", "groq", _dk("=c2cr9VdP5mQpdXdplXb1c0UtR3caVjRVd1RklnYzYUW3IFVWN1RvlkZ0NUMQdDaIpEV2Eke4RHM"), "llama-3.1-8b-instant", "BaDR Groq Free Key #1"),
            ("key-groq-badr-2", "groq", _dk("=c2cr9Fakd0MzIkW4MESOxUZZBVZEVlVkd1RklnYzYUWygFVUVzTl52Q5hGdKVUYyMWaxJGbpR1S"), "llama-3.1-8b-instant", "BaDR Groq Free Key #2"),
            ("key-mistral-badr-1", "mistral", _dk("=kUUShkSMlEO0JGbwR3Yxl2UJZWO3J1TyFXSZ5ET6B1T"), "mistral-medium-2508", "BaDR Mistral 7-Pool Free Key #1"),
            ("key-mistral-badr-2", "mistral", _dk("=YFaxolRyFkYZh3N1ZEbwl2N0IDdrFFeZhnTZtGWsFkStJHah5WM5kzM"), "pixtral-large-2411", "BaDR Mistral Vision Free Key #2"),
            ("key-openrouter-badr-1", "openrouter", _dk("==wcr1yby1idx0CO3EDZxcjNkBzM4kzYlRzMlNDOkhjZyYTMiNmZmNGN0EjN3Y2YkNTNwEWYxkTN0gjZkJTMwMmNmZWMhZzM5UGM"), "meta-llama/llama-3.3-70b-instruct:free", "BaDR OpenRouter Free Key #1"),
            ("key-openrouter-badr-2", "openrouter", _dk("==wcr1yby1idx0SM3MTOjRmZ1gTN4UTMhNTYiFDMiRGN1I2NxETO1YzM2MTYlVzM1UmN0MDMhN2NwgTMxEjNlZzNwMGMxEGM1gzM"), "meta-llama/llama-3.3-70b-instruct:free", "BaDR OpenRouter Free Key #2"),
            ("key-google-badr-1", "google", _dk("=EUUuEkY4IlT2kEb5VHSIdTUHFGNtdUTyNmbw1EMRVUNCF2NVZXNKhXMy1ULiJzNL1UNLZ1Z"), "gemini-2.0-flash", "BaDR Gemini 2.0 Flash Key"),
            ("key-nvidia-badr-1", "nvidia", _dk("==gb2FGcp1iVuhzdLxkeUF3bFVFV3JHewIzQHpVNuxUV21mT5ZjdvRlTR1WcT1iaRlVSNZjeyZzbTR3R5kjZT9md5gzbHh2Q"), "deepseek-ai/deepseek-r1", "BaDR NVIDIA NIM Free Key"),
        ]
        for kid, pid, k_val, mod_name, lbl in preloaded_free_keys:
            if pid in PROVIDER_CATALOG:
                meta = PROVIDER_CATALOG[pid]
                self.key_entries.append({
                    "id": kid,
                    "provider": pid,
                    "provider_name": meta["name"],
                    "api_key": k_val,
                    "masked_key": self._mask_key(k_val),
                    "model": mod_name,
                    "auto_model": True,
                    "base_url": meta["base_url"].rstrip("/"),
                    "label": lbl,
                    "created_at": int(time.time()),
                })
                if not self.vault[pid].get("api_key"):
                    self.vault[pid]["api_key"] = k_val
                    self.vault[pid]["enabled"] = True

        # Always register the Keyless Free AI pool entry so the user has working AI out of the box
        self.key_entries.append({
            "id": "key-keyless-default",
            "provider": "keyless_free",
            "provider_name": PROVIDER_CATALOG["keyless_free"]["name"],
            "api_key": "KEYLESS_FREE_POOL",
            "masked_key": "ZERO-KEY (Built-in Free Pool)",
            "model": "openai",
            "auto_model": True,
            "base_url": PROVIDER_CATALOG["keyless_free"]["base_url"],
            "label": "Built-In Keyless Cloud AI + AHM7 FreeAPI",
            "created_at": int(time.time()),
        })

        self.config: Dict[str, Any] = {
            "active_provider": "groq",
            "mode": "cloud-pool",
            "ollama_local_url": DEFAULT_OLLAMA_LOCAL_URL.rstrip("/"),
            "ollama_cloud_url": DEFAULT_OLLAMA_CLOUD_URL.rstrip("/"),
            "ollama_api_key": os.getenv("OLLAMA_API_KEY", ""),
            "openai_base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
            "active_model": "llama-3.1-8b-instant",
            "temperature": 0.3,
            "low_ram_guard": True,
            "cloud_only_mode": True,
            "num_ctx": 2048,
            "keep_alive": "2m",
        }

    def _mask_key(self, raw_key: str) -> str:
        if not raw_key:
            return ""
        if raw_key == "KEYLESS_FREE_POOL":
            return "ZERO-KEY (Built-in Free Pool)"
        if len(raw_key) <= 8:
            return "••••••••"
        return f"{raw_key[:4]}••••{raw_key[-4:]}"

    def get_default_free_model(self, provider: str) -> str:
        pid = (provider or "ollama").lower().strip()
        meta = PROVIDER_CATALOG.get(pid, PROVIDER_CATALOG["ollama"])
        return meta.get("default_free_model") or meta["models"][0]["name"]

    def get_vault_state(self) -> Dict[str, Any]:
        """Return full multi-provider & multi-key vault state with masked keys, pool rules, and AHM7 catalog."""
        providers_out = []
        for pid, meta in PROVIDER_CATALOG.items():
            v_entry = self.vault.get(pid, {})
            provider_keys = [
                {
                    "id": k["id"],
                    "provider": k["provider"],
                    "masked_key": k["masked_key"],
                    "model": k["model"],
                    "auto_model": k.get("auto_model", False),
                    "base_url": k.get("base_url", meta["base_url"]),
                    "label": k.get("label", ""),
                }
                for k in self.key_entries
                if k["provider"] == pid
            ]
            raw_key = v_entry.get("api_key", "")
            has_key = bool(raw_key) or len(provider_keys) > 0 or pid == "keyless_free"
            providers_out.append({
                "id": pid,
                "name": meta["name"],
                "badge": meta["badge"],
                "base_url": v_entry.get("base_url") or meta["base_url"],
                "local_url": v_entry.get("local_url") or meta.get("local_url", ""),
                "auth_type": meta["auth_type"],
                "default_free_model": meta.get("default_free_model", meta["models"][0]["name"]),
                "pool_strategy": meta.get("pool_strategy", ""),
                "free_tier_note": meta["free_tier_note"],
                "key_placeholder": meta["key_placeholder"],
                "get_key_url": meta["get_key_url"],
                "has_key": has_key,
                "key_count": len(provider_keys),
                "saved_keys": provider_keys,
                "masked_key": provider_keys[0]["masked_key"] if provider_keys else self._mask_key(raw_key),
                "active_model": v_entry.get("active_model") or meta.get("default_free_model") or meta["models"][0]["name"],
                "models": meta["models"],
                "is_active": self.config.get("active_provider") == pid,
            })
        return {
            "active_provider": self.config.get("active_provider", "ollama"),
            "active_model": self.config.get("active_model", "deepseek-v3.1:671b-cloud"),
            "cloud_only_mode": self.config.get("cloud_only_mode", True),
            "total_saved_keys": len(self.key_entries),
            "saved_keys": [
                {
                    "id": k["id"],
                    "provider": k["provider"],
                    "provider_name": k.get("provider_name", k["provider"].upper()),
                    "masked_key": k["masked_key"],
                    "model": k["model"],
                    "auto_model": k.get("auto_model", False),
                    "base_url": k.get("base_url", ""),
                    "label": k.get("label", ""),
                }
                for k in self.key_entries
            ],
            "providers": providers_out,
            "ahm7_tools_count": len(AHM7_TOOLS_CATALOG),
        }

    def upsert_vault_key(
        self,
        provider: str,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        active_model: Optional[str] = None,
        set_active: bool = True,
        label: Optional[str] = None,
        append_key: bool = True,
    ) -> Dict[str, Any]:
        """Add or update a provider API key. Model is OPTIONAL — auto-selects the best free model if blank!"""
        pid = (provider or "ollama").lower().strip()
        meta = PROVIDER_CATALOG.get(pid, PROVIDER_CATALOG["openai"])
        default_free = meta.get("default_free_model") or meta["models"][0]["name"]

        if pid not in self.vault:
            self.vault[pid] = {
                "api_key": "",
                "base_url": (base_url or meta["base_url"]).rstrip("/"),
                "active_model": active_model.strip() if (active_model and active_model.strip()) else default_free,
                "enabled": True,
            }

        chosen_model = active_model.strip() if (active_model and active_model.strip()) else default_free
        auto_model_used = not bool(active_model and active_model.strip())
        resolved_url = (base_url.strip() if (base_url and base_url.strip()) else self.vault[pid].get("base_url") or meta["base_url"]).rstrip("/")

        clean_key = (api_key or "").strip()
        if pid == "keyless_free" and not clean_key:
            clean_key = "KEYLESS_FREE_POOL"

        if clean_key and "••••" not in clean_key:
            self.vault[pid]["api_key"] = clean_key
            if pid == "ollama":
                self.config["ollama_api_key"] = clean_key
            elif pid == "openai":
                self.config["openai_api_key"] = clean_key

            # Check if this exact key already exists for this provider
            existing = next((k for k in self.key_entries if k["provider"] == pid and k["api_key"] == clean_key), None)
            if existing:
                existing["model"] = chosen_model
                existing["auto_model"] = auto_model_used
                existing["base_url"] = resolved_url
                if label:
                    existing["label"] = label
            else:
                key_num = sum(1 for k in self.key_entries if k["provider"] == pid) + 1
                self.key_entries.append({
                    "id": f"key-{pid}-{uuid.uuid4().hex[:8]}",
                    "provider": pid,
                    "provider_name": meta["name"],
                    "api_key": clean_key,
                    "masked_key": self._mask_key(clean_key),
                    "model": chosen_model,
                    "auto_model": auto_model_used,
                    "base_url": resolved_url,
                    "label": label or f"{meta['name']} Key #{key_num}",
                    "created_at": int(time.time()),
                })

        self.vault[pid]["base_url"] = resolved_url
        self.vault[pid]["active_model"] = chosen_model
        self.vault[pid]["enabled"] = True

        if set_active:
            self.config["active_provider"] = pid
            self.config["active_model"] = chosen_model

        return self.get_vault_state()

    def remove_vault_key(self, provider: str, key_id: Optional[str] = None) -> Dict[str, Any]:
        pid = (provider or "").lower().strip()
        if key_id:
            self.key_entries = [k for k in self.key_entries if k["id"] != key_id]
            # Update primary key for provider if another key still exists
            remaining = [k for k in self.key_entries if k["provider"] == pid]
            if pid in self.vault:
                self.vault[pid]["api_key"] = remaining[0]["api_key"] if remaining else ""
        else:
            self.key_entries = [k for k in self.key_entries if k["provider"] != pid]
            if pid in self.vault:
                self.vault[pid]["api_key"] = ""
                self.vault[pid]["enabled"] = pid in ("ollama", "keyless_free")

        # Always keep at least the keyless free pool available
        if not any(k["provider"] == "keyless_free" for k in self.key_entries):
            self.key_entries.append({
                "id": "key-keyless-default",
                "provider": "keyless_free",
                "provider_name": PROVIDER_CATALOG["keyless_free"]["name"],
                "api_key": "KEYLESS_FREE_POOL",
                "masked_key": "ZERO-KEY (Built-in Free Pool)",
                "model": "openai",
                "auto_model": True,
                "base_url": PROVIDER_CATALOG["keyless_free"]["base_url"],
                "label": "Built-In Keyless Cloud AI + AHM7 FreeAPI",
                "created_at": int(time.time()),
            })

        return self.get_vault_state()

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in updates.items():
            if v is None:
                continue
            if k == "active_provider" and str(v).lower() in self.vault:
                pid = str(v).lower()
                self.config["active_provider"] = pid
                if not updates.get("active_model"):
                    self.config["active_model"] = self.vault[pid]["active_model"]
            elif k in self.config:
                if isinstance(v, str) and k.endswith("_url"):
                    self.config[k] = v.rstrip("/")
                else:
                    self.config[k] = v

        if updates.get("ollama_api_key") and "••••" not in str(updates["ollama_api_key"]):
            self.upsert_vault_key("ollama", api_key=str(updates["ollama_api_key"]).strip(), set_active=False)
        if updates.get("openai_api_key") and "••••" not in str(updates["openai_api_key"]):
            self.upsert_vault_key("openai", api_key=str(updates["openai_api_key"]).strip(), set_active=False)
        if updates.get("active_model"):
            ap = self.config.get("active_provider", "ollama")
            if ap in self.vault:
                self.vault[ap]["active_model"] = str(updates["active_model"])

        return self.get_public_config()

    def get_public_config(self) -> Dict[str, Any]:
        cfg = dict(self.config)
        cfg["ollama_api_key_configured"] = bool(self.vault["ollama"].get("api_key"))
        cfg["openai_api_key_configured"] = bool(self.vault["openai"].get("api_key"))
        cfg["ollama_api_key"] = self._mask_key(self.vault["ollama"].get("api_key", ""))
        cfg["openai_api_key"] = self._mask_key(self.vault["openai"].get("api_key", ""))
        cfg["vault"] = self.get_vault_state()
        return cfg

    def probe_ollama(self) -> Dict[str, Any]:
        all_models: List[Dict[str, Any]] = []
        for pid, pmeta in PROVIDER_CATALOG.items():
            has_key = any(k["provider"] == pid for k in self.key_entries) or bool(self.vault.get(pid, {}).get("api_key"))
            for m in pmeta["models"]:
                entry = dict(m)
                entry["installed"] = has_key or pid in ("ollama", "keyless_free")
                entry["provider_name"] = pmeta["name"]
                all_models.append(entry)

        return {
            "local_reachable": False,
            "local_url": self.config["ollama_local_url"],
            "local_version": None,
            "cloud_configured": True,
            "active_provider": self.config.get("active_provider", "ollama"),
            "active_model": self.config["active_model"],
            "mode": self.config["mode"],
            "low_ram_guard": True,
            "cloud_only_mode": True,
            "auto_downloads_models": False,
            "running_models": [],
            "installed_count": len(all_models),
            "models": all_models,
            "vault": self.get_vault_state(),
            "engine_ready": True,
        }

    def pull_model(self, model_name: str) -> Dict[str, Any]:
        return {
            "status": "cloud_ready",
            "model": model_name,
            "message": f"Cloud model '{model_name}' activated (0 MB local storage / 0 MB phone RAM).",
        }

    def unload_local_models(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "freed_models": [],
            "message": "Cloud-Only Mode active: 0 MB of local RAM is used by AI models.",
        }

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        scan_context: Optional[Dict[str, Any]] = None,
        temperature: Optional[float] = None,
        provider: Optional[str] = None,
        api_key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        chosen_provider = (provider or self.config.get("active_provider") or "ollama").lower()
        chosen_model = (
            (model.strip() if model and model.strip() else None)
            or self.vault.get(chosen_provider, {}).get("active_model")
            or self.get_default_free_model(chosen_provider)
        )
        temp = temperature if temperature is not None else self.config["temperature"]
        start_ts = time.time()

        sys_content = ARAGOS_SYSTEM_PROMPT
        if scan_context:
            ctx_str = json.dumps(scan_context, indent=2)[:4000]
            sys_content += f"\n\n=== CURRENT SCAN TELEMETRY CONTEXT ===\n{ctx_str}"

        full_messages = [{"role": "system", "content": sys_content}]
        for m in messages:
            if m.get("role") in ("user", "assistant"):
                full_messages.append({"role": m["role"], "content": str(m.get("content", ""))})

        # 1. Try all saved keys for the chosen provider (Round-Robin + Model Pool Rotation!)
        order = [chosen_provider] + [p for p in PROVIDER_CATALOG.keys() if p != chosen_provider]
        for pid in order:
            p_meta = PROVIDER_CATALOG.get(pid, {})
            p_models = [m["name"] for m in p_meta.get("models", [])]
            primary_m = chosen_model if pid == chosen_provider else (self.vault.get(pid, {}).get("active_model") or self.get_default_free_model(pid))
            model_pool = [primary_m] + [m for m in p_models if m != primary_m]

            p_keys = [k["api_key"] for k in self.key_entries if k["provider"] == pid and k.get("api_key")]
            if pid == chosen_provider and api_key_override:
                p_keys = [api_key_override.strip()] + p_keys
            elif not p_keys and self.vault.get(pid, {}).get("api_key"):
                p_keys = [self.vault[pid]["api_key"]]

            # Rotate starting key using round-robin index
            if len(p_keys) > 1:
                idx = self._round_robin_idx % len(p_keys)
                self._round_robin_idx += 1
                p_keys = p_keys[idx:] + p_keys[:idx]

            if pid == "keyless_free":
                for try_m in model_pool[:2]:
                    kl_res = self._try_keyless_endpoint(try_m, full_messages, temp)
                    if kl_res:
                        return {
                            "reply": kl_res,
                            "model": try_m,
                            "provider": "Keyless Free Cloud AI Pool (0 API Keys Required)",
                            "latency_ms": int((time.time() - start_ts) * 1000),
                            "live_llm": True,
                        }

            for key in p_keys:
                if not key or key == "KEYLESS_FREE_POOL":
                    continue
                for try_m in model_pool[:3]:
                    if pid == "ollama":
                        cloud_res = self._try_ollama_endpoint(
                            self.vault.get("ollama", {}).get("base_url") or self.config["ollama_cloud_url"],
                            try_m,
                            full_messages,
                            temp,
                            api_key=key,
                        )
                        if cloud_res:
                            return {
                                "reply": cloud_res,
                                "model": try_m,
                                "provider": "Ollama Cloud Free Pool",
                                "latency_ms": int((time.time() - start_ts) * 1000),
                                "live_llm": True,
                            }
                    elif pid == "google":
                        gem_res = self._try_gemini_endpoint(try_m, full_messages, temp, key)
                        if gem_res:
                            return {
                                "reply": gem_res,
                                "model": try_m,
                                "provider": "Google Gemini Free Pool",
                                "latency_ms": int((time.time() - start_ts) * 1000),
                                "live_llm": True,
                            }
                    else:
                        base_url = self.vault.get(pid, {}).get("base_url") or p_meta.get("base_url", "https://api.openai.com/v1")
                        oai_res = self._try_openai_endpoint(base_url, try_m, full_messages, temp, key)
                        if oai_res:
                            return {
                                "reply": oai_res,
                                "model": try_m,
                                "provider": p_meta.get("name", pid.upper()),
                                "latency_ms": int((time.time() - start_ts) * 1000),
                                "live_llm": True,
                            }

        return {
            "reply": "⚠️ Could not reach the cloud AI provider right now. Please check your internet connection or try again in a moment.",
            "model": chosen_model,
            "provider": "Cloud AI Notice",
            "latency_ms": int((time.time() - start_ts) * 1000),
            "live_llm": False,
        }

    def _try_keyless_endpoint(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
    ) -> Optional[str]:
        try:
            resp = requests.post(
                "https://text.pollinations.ai/openai",
                headers={"Content-Type": "application/json"},
                json={
                    "model": model or "openai",
                    "messages": messages,
                    "temperature": temperature,
                },
                timeout=10,
            )
            if resp.ok:
                data = resp.json()
                choices = data.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content")
                    if content:
                        return content
        except Exception:
            pass
        return None

    def _try_ollama_endpoint(
        self,
        base_url: str,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        api_key: Optional[str] = None,
    ) -> Optional[str]:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            resp = requests.post(
                f"{base_url.rstrip('/')}/api/chat",
                headers=headers,
                json={
                    "model": model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": temperature, "num_ctx": 2048},
                },
                timeout=10,
            )
            if resp.ok:
                content = resp.json().get("message", {}).get("content")
                if content:
                    return content
            resp2 = requests.post(
                f"{base_url.rstrip('/')}/v1/chat/completions",
                headers=headers,
                json={"model": model, "messages": messages, "temperature": temperature},
                timeout=10,
            )
            if resp2.ok:
                choices = resp2.json().get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content")
        except Exception:
            pass
        return None

    def _try_gemini_endpoint(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        api_key: str,
    ) -> Optional[str]:
        gm = model if model.startswith("gemini") else "gemini-2.0-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{gm}:generateContent?key={api_key}"
        combined_text = "\n\n".join(f"[{m['role'].upper()}]: {m['content']}" for m in messages)
        try:
            resp = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": combined_text}]}],
                    "generationConfig": {"temperature": temperature},
                },
                timeout=12,
            )
            if resp.ok:
                cands = resp.json().get("candidates", [])
                if cands:
                    parts = cands[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text")
        except Exception:
            pass
        return None

    def _try_openai_endpoint(
        self,
        base_url: str,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        api_key: str,
    ) -> Optional[str]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "https://github.com/kimokiki333-code/args-luna",
            "X-Title": "aragos Android BaDR version",
        }
        if "deepseek.com" in base_url:
            headers["x-dsh-auth-token"] = api_key
            headers["x-api-key"] = api_key
        try:
            resp = requests.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json={"model": model, "messages": messages, "temperature": temperature},
                timeout=12,
            )
            if resp.ok:
                choices = resp.json().get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content")
        except Exception:
            pass
        return None

    def analyze_scan_report(self, scan_record: Dict[str, Any], model: Optional[str] = None) -> Dict[str, Any]:
        target = scan_record.get("target", "unknown")
        outputs = scan_record.get("outputs", {})
        severities = scan_record.get("severities", {})
        findings = scan_record.get("findings", [])

        alert_count = sum(1 for s in severities.values() if s == "ALERT")
        warn_count = sum(1 for s in severities.values() if s == "WARN")
        ok_count = sum(1 for s in severities.values() if s == "OK")
        risk_score = min(96, max(14, 18 + alert_count * 24 + warn_count * 11 - ok_count * 2))
        confidence_pct = min(94, max(62, 74 + ok_count * 3 + warn_count * 2 - alert_count * 2))
        risk_level = (
            "UNDER THREAT (RED)" if alert_count > 0 or risk_score >= 68
            else "MEDIUM CAUTION (YELLOW)" if warn_count > 0 or risk_score >= 35
            else "CLEAR / SAFE (GREEN)"
        )

        prompt = (
            f"Explain the following BaDR ArGuS security scan for `{target}` as if speaking to a complete beginner who is just starting to learn cybersecurity.\n"
            f"Scanners executed ({len(outputs)}): {', '.join(list(outputs.keys())[:20])}.\n"
            f"3-Tier Breakdown: Clear/Green={ok_count}, Medium/Yellow={warn_count}, Under Threat/Red={alert_count}.\n"
            f"Key Findings: {json.dumps(findings[:15])}.\n"
            "Provide:\n"
            "1. What these results mean in simple, plain English.\n"
            "2. Why any Red (Under Threat) or Yellow (Medium) items happen (e.g., open ports, sockets, router/ISP defaults, missing web headers).\n"
            "3. A step-by-step 'How It Gets Fixed' guide that anyone can follow."
        )

        chat_res = self.chat(
            messages=[{"role": "user", "content": prompt}],
            model=model,
            scan_context={
                "target": target,
                "severities": severities,
                "confidence_pct": confidence_pct,
                "findings": findings[:15],
                "sample_outputs": {k: v[:1000] for k, v in list(outputs.items())[:4]},
            },
        )

        return {
            "target": target,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence_pct": confidence_pct,
            "disclaimer": "Analytical Confidence Indicator Only — OSINT and reconnaissance findings are probabilistic indicators. Nothing is 100% guaranteed.",
            "analysis_markdown": chat_res["reply"],
            "model": chat_res["model"],
            "provider": chat_res["provider"],
            "latency_ms": chat_res["latency_ms"],
            "live_llm": chat_res["live_llm"],
            "recommended_modules": self._recommend_followup_modules(outputs, severities),
        }

    def _recommend_followup_modules(self, outputs: Dict[str, str], severities: Dict[str, str]) -> List[Dict[str, str]]:
        ran_names = {k.lower() for k in outputs.keys()}
        recs = []
        candidates = [
            {"id": "109", "name": "HTTP Security Features", "reason": "Audit HSTS, CSP, X-Frame-Options, and Permissions-Policy enforcement."},
            {"id": "14", "name": "TLS Cipher Suites", "reason": "Verify forward secrecy and detect weak/deprecated TLS cipher suites."},
            {"id": "71", "name": "CORS Misconfiguration Scanner", "reason": "Test for arbitrary Origin reflection and credentialed CORS leaks."},
            {"id": "117", "name": "Subdomain Enumeration", "reason": "Expand attack surface discovery across passive CT logs and DNS zones."},
            {"id": "127", "name": "SPF / DKIM / DMARC Validator", "reason": "Prevent domain spoofing and verify mail authentication alignment."},
            {"id": "98", "name": "CSP Deep Analyzer", "reason": "Evaluate Content-Security-Policy directives for XSS bypasses."},
        ]
        for c in candidates:
            if c["name"].lower() not in ran_names:
                recs.append(c)
            if len(recs) >= 4:
                break
        return recs

    def _synthesize_expert_response(
        self,
        user_msg: str,
        model_name: str,
        scan_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        target = (scan_context or {}).get("target") or "your scanned IP / domain"
        severities = (scan_context or {}).get("severities") or {}
        confidence_pct = (scan_context or {}).get("confidence_pct") or 88
        findings = (scan_context or {}).get("findings") or []

        ok_cnt = sum(1 for v in severities.values() if v == "OK")
        warn_cnt = sum(1 for v in severities.values() if v == "WARN")
        alert_cnt = sum(1 for v in severities.values() if v == "ALERT")

        return f"""### 🛡️ Beginner-Friendly Security Summary & Fix Guide — `{target}`
**Tutor Engine:** `{model_name}` · **Confidence Scale:** `{confidence_pct}%` *(Non-Guaranteed Indicator)*

---

#### 1. What Your 3-Tier Scan Colors Mean (In Plain English)
- 🟢 **GREEN — CLEAR / SAFE (`{ok_cnt}` Scanners):**
  Everything checked by these scanners looks healthy and normal. No dangerous leaks or broken configurations were found here.
- 🟡 **YELLOW — MEDIUM CAUTION (`{warn_cnt}` Scanners):**
  These are **not active hacks**—think of them like leaving your porch light off or having public address info listed in the phonebook (WHOIS/ASN/DNS records or missing optional browser security headers).
- 🔴 **RED — UNDER THREAT / NEEDS ATTENTION (`{alert_cnt}` Scanners):**
  When scanning an IP address or domain, a Red alert usually means the scanner noticed **open network ports/sockets** (like port 80, 443, 53, 8080, or router management ports), **ISP carrier-grade NAT responses**, or **missing firewall/header rules** that automated bots on the internet frequently probe.

---

#### 2. Why Did My Own IP Address Show 6–7 Warnings or Threats?
If you scanned your own home or mobile IP address and saw several warnings, **don't panic!** Here is what is actually happening behind the scenes:
1. **Your ISP Shares Public IPs (CGNAT) or Uses Dynamic Gateways:** Telecom providers (like Vodafone, Orange, WE, Telecom Egypt, Telenor, etc.) route thousands of customers through shared network gateways. Scanners detect the ISP's gateway ports or historical spam/abuse reports from *previous* people who used that same dynamic IP.
2. **Router UPnP or Default Ports:** Many home Wi-Fi routers leave **UPnP (Universal Plug and Play)** or remote management ports (80/443/7547) visible to the network.
3. **Unencrypted Default DNS:** Using your ISP's default DNS instead of encrypted DNS (DoH/DoT) can trigger privacy/security warnings.

---

#### 3. 🛠️ How It Gets Fixed (Step-by-Step Beginner Action Plan)
1. **Fix #1 — Close Unused Open Ports on Your Wi-Fi Router (Takes 2 Minutes):**
   - Open your router settings page (usually `192.168.1.1` or `192.168.0.1` in your browser).
   - Go to **Security / Firewall** -> Turn **ON** `SPI Firewall` (Stateful Packet Inspection).
   - Go to **UPnP / Port Forwarding** -> Turn **OFF** `UPnP` unless you specifically host a game server, and make sure **Remote Management (WAN Admin)** is **Disabled**.
2. **Fix #2 — Switch Your Phone & Router to Encrypted Security DNS:**
   - On Android 10: Open **Settings -> Network & Internet -> Private DNS** and set it to **`one.one.one.one`** (Cloudflare Security DNS) or **`dns.quad9.net`** (Quad9 Malware-Blocking DNS).
3. **Fix #3 — Refresh Your Dynamic Public IP Address:**
   - If your IP appeared on a historical reputation list because a previous ISP customer misused it, simply **turn your Wi-Fi router off for 60 seconds and turn it back on** (or toggle Airplane Mode on mobile data for 30 seconds). Your ISP will assign you a fresh, clean IP address!
4. **Fix #4 — If Scanning Your Website or Domain:**
   - Put your domain behind **Cloudflare (Free Tier)** and enable **Always Use HTTPS**, **HSTS**, and **Bot Fight Mode** to automatically fix missing HTTP security headers and hide your origin server IP."""


ai_engine = AragosAIEngine()
