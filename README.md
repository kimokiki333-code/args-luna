# 🛡️ aragos Android BaDR version (`BaDR ArGuS scanner`)

> **Standalone 151-Scanner Android 10 APK & Cloud OSINT Security Tutor**  
> Built for **Android 10+ (including 4 GB RAM / 64 GB phones like the OPPO F9)** and modern web browsers — **Zero Local Phone RAM AI Overhead**.

---

## 🌟 About & Credits to Original Creator

**Original Foundation Credit:**  
We gratefully credit and thank the original creator and open-source contributors of the **Argos / ArGuS Python Reconnaissance & OSINT Framework**, who designed the modular 3-pillar scanner architecture:
1. **Network & Infrastructure** (Modules `#1–#52`)
2. **Web Application Analysis** (Modules `#53–#101`)
3. **Security & Threat Intelligence** (Modules `#102–#147` + Suite Runners `#148–#151`)

---

## 🚀 What Was Added in `aragos Android BaDR version`

1. **📦 Standalone Installable Android APK (`BaDR-ArGuS-Scanner.apk`)**
   - Packaged with an AOSP-compliant Android binary manifest (`AndroidManifest.xml`), compiled `resources.arsc`, native Dalvik bytecode (`classes.dex`), 4-byte `zipalign`, and dual **JAR v1 + APK Signature Scheme v2 Merkle signatures**.
   - Installs and opens directly like a native Android app with all **151 scanners embedded inside the APK** (no local server setup required, and automatically hides the web APK download banner once installed on the phone).

2. **🛰️ Startup Live Self-IP, WHOIS, DNS, Geo Coordinates & Tor/Proxy/VPN Popup**
   - The moment you open the app, it automatically detects your live public IP address, runs a **WHOIS / ASN / ISP lookup**, checks your **DNS**, maps your **Geographic Coordinates (Latitude / Longitude, City, Country)**, checks whether your connection is a **Tor exit node, Open Proxy, or VPN**, and displays a **Startup 3-Tier Connection Status Popup**.

3. **🚦 3-Tier Traffic-Light Threat Classification & Beginner "How It Gets Fixed" Guide**
   - Every scan result is grouped into 3 plain-English tiers:
     - 🟢 **CLEAR / NO PROBLEM (Green):** Safe and properly configured.
     - 🟡 **MEDIUM CAUTION (Yellow):** Minor configuration or privacy advisories.
     - 🔴 **UNDER THREAT (Red):** Open network ports/sockets, gateway exposures, or missing security shields.
   - Written for **complete beginners to cybersecurity**: explains in everyday words what an open port, socket, DNS record, or WHOIS flag means, why ISP shared gateways trigger port warnings on home/mobile IPs, and **numbered step-by-step instructions on how to fix every single warning**.

4. **👈👉 Native Android Swipe Left/Right Navigation & Futuristic Custom SVG Icons**
   - Separated into **6 swipeable Android sections** (`Scanner`, `151 Tools`, `Reports`, `Key Vault`, `AI Tutor`, `About`) so you never get stuck scrolling through 151 modules.
   - Inside **Reports**, swipe left/right or tap across **5 report modes**:
     1. **🛡️ Beginner Summary & How To Fix**
     2. **📊 Normal Report**
     3. **📑 Full Report & History**
     4. **🧠 AI Deep Report**
     5. **💻 Raw Report**
   - Styled with a **readable comic / handwriting font** (`Comic Neue`, `Patrick Hand`, `Comic Sans MS`) and **custom-designed futuristic SVG icons**.

5. **🚀 Full Scan (Run ALL 151 Scanners Together) + Expanded Preset Suites**
   - One-tap **Full 151 Scanners Omni-Scan** for any Domain, IP address, Email, or Username.
   - Selecting **IP & Ports** automatically selects all **52 Network, IP, Port, Socket & DNS scanners**; selecting **Domain / Web** selects all **53 Web & SSL scanners**; selecting **Email / Breach** selects all **46 Security & Threat Intelligence scanners**.

6. **🔑 Multi-Key Cloud AI Vault (`+ Add New Free API Key`) + DeepSeek Harness (`@deepseek-ai/dsh`), Optional Auto-Model & Keyless AI**
   - Add **multiple free API keys** per provider (e.g., multiple DeepSeek Harness tokens/keys, 4 OpenRouter keys, multiple Ollama Cloud keys, Mistral keys, Groq keys, NVIDIA NIM keys, Google Gemini keys, or OpenAI keys).
   - **DeepSeek Harness (`@deepseek-ai/dsh` — `kimokiki333-code/deepseek-harness`) Built In:** Supports **DeepSeek-V4.1-Flash (`deepseek-flash` · 1M Context)**, **DeepSeek-V4-Pro (`deepseek-v4-pro` · 1M Context)**, `deepseek-chat`, and `deepseek-reasoner` using **both** `DEEPSEEK_API_KEY` (`Bearer`) and DeepSeek Harness Account Tokens (`x-dsh-auth-token`), plus NVIDIA NIM Free Developer Routes (`deepseek-ai/deepseek-r1`).
   - **Model Selection is Optional:** Leave the model field blank and the app automatically selects the best free model and rotates across rate-limit pools:
     - **Mistral 7-Pool Free Tier Router:** Rotates across isolated free quota pools (`mistral-medium-2508` 375K TPM, `mistral-large-2411` 200B/mo, `devstral-2512` 1M TPM, `open-mistral-nemo`).
     - **Groq Forever-Free LPU Router:** Rotates across `llama-3.1-8b-instant` & `openai/gpt-oss-20b` (14,400 free requests/day) and `llama-3.3-70b-versatile`.
     - **Keyless Free Cloud AI:** Works with **zero API keys** out of the box!

7. **🔄 Live In-App Over-The-Air (OTA) Updater (`v4.8`)**
   - Compiled with **Google's Official Android SDK Build-Tools (`aapt`, `javac`, `dx`, `zipalign`, and `apksigner` v1 + v2 + v3 schemes)** and a persistent release certificate (`2020–2050`).
   - Includes a built-in **Live OTA Updater (`🔄 Check & Apply Live Update`)** in the top header that syncs future UI, styling, and scanner updates directly from GitHub inside the installed Android app without needing to reinstall the APK!

7. **🧰 AHM7 FreeAPI (`freeapi.pro` / `ahm7xmakki.com`) — 21 Zero-Key Tools Built In**
   - Direct frontend & backend integration with all **21 keyless REST APIs** by Ahmad Makki (`freeapi.pro`):
     `WebSnap` (`/api/websnap`), `WebZip` (`/api/zip`), `TempSter` (`/api/tempmail`), `VisionChat` (`/api/imgchat`), `SpeechSter` (`/api/tts` & `/api/voices`), `PixelSter Flux` (`/api/tti`, `/api/pti`, `/api/ptv`), `Transcribe` (`/api/transcribe`), `Universal Downloader` (`/api/alldl`), `n8nSter` (`/api/n8n`), `FreeAPI Courses` (`/api/courses`), `Wikster` (`/api/wikipdf`), `CertSter` (`/api/certificate`), `Text-to-Handwriting` (`/api/hand`), `DriveUp` (`/api/driveup`), `MedSter` (`/api/search`), `CineSearch` (`/api/msearch`), `MangaSter` (`/api/manga`), and `NovelSter` (`/api/novel`).

---

## 🎓 Educational & Defensive Cybersecurity Purpose

`aragos Android BaDR version` is created strictly for **educational cybersecurity learning, defensive network self-auditing, and helping beginners understand and secure their own internet connections, routers, and domains**. Always scan only your own connection or targets you have permission to test.
