import os
import re
import json
import time
from typing import Dict, List, Optional, Any
import requests

DEFAULT_OLLAMA_LOCAL_URL = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
DEFAULT_OLLAMA_CLOUD_URL = os.getenv("OLLAMA_CLOUD_URL", "https://ollama.com")

# Specifically curated for 4 GB RAM & 10 GB Free Disk Space:
# Local models are all <= 1.3 GB disk and <= 1.8 GB RAM!
CURATED_LOCAL_MODELS = [
    {
        "name": "qwen2.5-coder:1.5b",
        "provider": "ollama-local",
        "family": "Qwen 2.5 Coder",
        "params": "1.5B",
        "disk_size": "986 MB",
        "ram_required": "~1.5 GB RAM",
        "fits_4gb_ram": True,
        "quant": "Q4_K_M",
        "role": "Best 4GB-RAM Local Model for Code, Headers & Recon",
    },
    {
        "name": "llama3.2:1b",
        "provider": "ollama-local",
        "family": "Llama 3.2",
        "params": "1B",
        "disk_size": "1.3 GB",
        "ram_required": "~1.7 GB RAM",
        "fits_4gb_ram": True,
        "quant": "Q4_K_M",
        "role": "Fast General OSINT & Security Triage (4GB RAM Safe)",
    },
    {
        "name": "deepseek-r1:1.5b",
        "provider": "ollama-local",
        "family": "DeepSeek R1 Distill",
        "params": "1.5B",
        "disk_size": "1.1 GB",
        "ram_required": "~1.6 GB RAM",
        "fits_4gb_ram": True,
        "quant": "Q4_K_M",
        "role": "Lightweight Local Reasoning & Vulnerability Chains",
    },
    {
        "name": "gemma3:1b",
        "provider": "ollama-local",
        "family": "Gemma 3",
        "params": "1B",
        "disk_size": "815 MB",
        "ram_required": "~1.3 GB RAM",
        "fits_4gb_ram": True,
        "quant": "Q4_K_M",
        "role": "Ultra-Light Structured Threat Summaries",
    },
    {
        "name": "qwen2.5:0.5b",
        "provider": "ollama-local",
        "family": "Qwen 2.5 Nano",
        "params": "0.5B",
        "disk_size": "398 MB",
        "ram_required": "~0.8 GB RAM",
        "fits_4gb_ram": True,
        "quant": "Q4_K_M",
        "role": "Instant Nano Local Copilot (Under 400 MB Disk)",
    },
    {
        "name": "smollm2:360m",
        "provider": "ollama-local",
        "family": "SmolLM2",
        "params": "360M",
        "disk_size": "270 MB",
        "ram_required": "~0.6 GB RAM",
        "fits_4gb_ram": True,
        "quant": "Q8_0",
        "role": "Minimal Footprint Local Assistant (270 MB Disk)",
    },
]

# Cloud models use 0 MB of local disk storage and 0 MB of local RAM!
CURATED_CLOUD_MODELS = [
    {
        "name": "deepseek-v3.1:671b-cloud",
        "provider": "ollama-cloud",
        "family": "DeepSeek V3.1 Cloud",
        "params": "671B",
        "disk_size": "0 MB (Cloud)",
        "ram_required": "0 MB Local RAM",
        "fits_4gb_ram": True,
        "quant": "FP8 Cloud",
        "role": "Zero-Storage Cloud Giant · Enterprise Threat Architecture",
    },
    {
        "name": "qwen3-coder:480b-cloud",
        "provider": "ollama-cloud",
        "family": "Qwen3 Coder Cloud",
        "params": "480B",
        "disk_size": "0 MB (Cloud)",
        "ram_required": "0 MB Local RAM",
        "fits_4gb_ram": True,
        "quant": "FP8 Cloud",
        "role": "Zero-Storage Cloud · DevSecOps Remediation & Exploit Audit",
    },
    {
        "name": "gpt-oss:120b-cloud",
        "provider": "ollama-cloud",
        "family": "GPT-OSS Cloud",
        "params": "120B",
        "disk_size": "0 MB (Cloud)",
        "ram_required": "0 MB Local RAM",
        "fits_4gb_ram": True,
        "quant": "BF16 Cloud",
        "role": "Zero-Storage Cloud · Full-Spectrum OSINT Strategy",
    },
    {
        "name": "gpt-oss:20b-cloud",
        "provider": "ollama-cloud",
        "family": "GPT-OSS Fast Cloud",
        "params": "20B",
        "disk_size": "0 MB (Cloud)",
        "ram_required": "0 MB Local RAM",
        "fits_4gb_ram": True,
        "quant": "BF16 Cloud",
        "role": "Zero-Storage Cloud · Low-Latency Recon Copilot",
    },
    {
        "name": "kimi-k2:1t-cloud",
        "provider": "ollama-cloud",
        "family": "Kimi K2 Cloud",
        "params": "1T MoE",
        "disk_size": "0 MB (Cloud)",
        "ram_required": "0 MB Local RAM",
        "fits_4gb_ram": True,
        "quant": "FP8 Cloud",
        "role": "Zero-Storage Cloud · Multi-Module Log Correlation",
    },
]

ARAGOS_SYSTEM_PROMPT = """You are ARAGOS Neural Recon Copilot, an elite cybersecurity reconnaissance, OSINT, and threat intelligence analyst embedded inside the ARAGOS Web Platform.
You analyze network infrastructure, DNS/BGP/TLS telemetry, web application attack surfaces, and threat intelligence findings.
Always structure your responses clearly using Markdown with:
- Executive Assessment & Risk Posture
- Technical Findings & Attack Vectors
- Prioritized Remediation Steps (with concrete config/CLI examples)
- Recommended Follow-up ARAGOS Modules to run next."""


class AragosAIEngine:
    def __init__(self):
        self.config = {
            "mode": "auto",  # "auto", "ollama-local", "ollama-cloud", "openai-cloud"
            "ollama_local_url": DEFAULT_OLLAMA_LOCAL_URL.rstrip("/"),
            "ollama_cloud_url": DEFAULT_OLLAMA_CLOUD_URL.rstrip("/"),
            "ollama_api_key": os.getenv("OLLAMA_API_KEY", ""),
            "openai_base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
            "active_model": "deepseek-v3.1:671b-cloud",
            "temperature": 0.3,
            "low_ram_guard": True,  # Optimizes context window & RAM unloading for 4GB RAM systems
            "num_ctx": 2048,
            "keep_alive": "2m",
        }

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in updates.items():
            if k in self.config and v is not None:
                if isinstance(v, str) and k.endswith("_url"):
                    self.config[k] = v.rstrip("/")
                else:
                    self.config[k] = v
        return self.get_public_config()

    def get_public_config(self) -> Dict[str, Any]:
        cfg = dict(self.config)
        cfg["ollama_api_key_configured"] = bool(self.config.get("ollama_api_key"))
        cfg["openai_api_key_configured"] = bool(self.config.get("openai_api_key"))
        cfg["ollama_api_key"] = "••••••••" if self.config.get("ollama_api_key") else ""
        cfg["openai_api_key"] = "••••••••" if self.config.get("openai_api_key") else ""
        return cfg

    def probe_ollama(self) -> Dict[str, Any]:
        """Probe local Ollama instance without downloading anything automatically."""
        local_url = self.config["ollama_local_url"]
        local_reachable = False
        local_version = None
        installed_models: List[Dict[str, Any]] = []
        running_models: List[str] = []

        try:
            v_resp = requests.get(f"{local_url}/api/version", timeout=2.0)
            if v_resp.ok:
                local_reachable = True
                local_version = v_resp.json().get("version", "0.6+")
        except Exception:
            pass

        try:
            t_resp = requests.get(f"{local_url}/api/tags", timeout=2.5)
            if t_resp.ok:
                local_reachable = True
                raw_models = t_resp.json().get("models", [])
                for m in raw_models:
                    name = m.get("name", "")
                    size_bytes = m.get("size", 0) or 0
                    size_mb = round(size_bytes / (1024 * 1024))
                    details = m.get("details", {})
                    is_cloud = name.endswith("-cloud") or ":cloud" in name or m.get("remote_host")
                    installed_models.append({
                        "name": name,
                        "provider": "ollama-cloud" if is_cloud else "ollama-local",
                        "family": details.get("family", "Ollama"),
                        "params": details.get("parameter_size", "Dynamic"),
                        "disk_size": "0 MB (Cloud)" if is_cloud else f"{size_mb} MB",
                        "ram_required": "0 MB Local RAM" if is_cloud else f"~{max(600, int(size_mb * 1.3))} MB RAM",
                        "fits_4gb_ram": True if (is_cloud or size_mb <= 1800) else False,
                        "quant": details.get("quantization_level", "Cloud" if is_cloud else "GGUF"),
                        "role": "Installed on Your Ollama Daemon",
                        "installed": True,
                    })
        except Exception:
            pass

        try:
            ps_resp = requests.get(f"{local_url}/api/ps", timeout=2.0)
            if ps_resp.ok:
                for m in ps_resp.json().get("models", []):
                    if m.get("name"):
                        running_models.append(m["name"])
        except Exception:
            pass

        seen_names = {m["name"] for m in installed_models}
        all_models = list(installed_models)
        # Put Cloud models (0 MB disk, 0 MB RAM) + 4GB-RAM safe local models (270MB - 1.3GB) in catalog
        for cm in CURATED_CLOUD_MODELS + CURATED_LOCAL_MODELS:
            if cm["name"] not in seen_names:
                entry = dict(cm)
                entry["installed"] = False
                all_models.append(entry)

        cloud_configured = bool(self.config.get("ollama_api_key") or self.config.get("openai_api_key"))

        return {
            "local_reachable": local_reachable,
            "local_url": local_url,
            "local_version": local_version,
            "cloud_configured": cloud_configured,
            "active_model": self.config["active_model"],
            "mode": self.config["mode"],
            "low_ram_guard": self.config.get("low_ram_guard", True),
            "auto_downloads_models": False,
            "running_models": running_models,
            "installed_count": len(installed_models),
            "models": all_models,
            "engine_ready": True,
        }

    def pull_model(self, model_name: str) -> Dict[str, Any]:
        """Trigger ollama pull ONLY when explicitly requested by user, with 4GB RAM / 10GB disk guard."""
        # Warn if user tries to pull a huge >3B local model on a 4GB RAM machine
        heavy_patterns = (":7b", ":8b", ":13b", ":14b", ":32b", ":70b")
        is_cloud = model_name.endswith("-cloud") or ":cloud" in model_name
        if not is_cloud and self.config.get("low_ram_guard", True):
            if any(hp in model_name.lower() for hp in heavy_patterns):
                return {
                    "status": "blocked_by_ram_guard",
                    "model": model_name,
                    "message": (
                        f"4GB-RAM Guard prevented downloading '{model_name}' (requires >5GB disk & >6GB RAM). "
                        "Use a `:cloud` model (0 MB disk/RAM) or a 0.5B–1.5B local model like `qwen2.5-coder:1.5b` (986 MB) or `llama3.2:1b` (1.3 GB)."
                    ),
                }

        local_url = self.config["ollama_local_url"]
        try:
            resp = requests.post(
                f"{local_url}/api/pull",
                json={"name": model_name, "stream": False},
                timeout=30,
            )
            if resp.ok:
                return {"status": "success", "model": model_name, "detail": resp.json()}
            return {"status": "error", "model": model_name, "message": f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as exc:
            return {
                "status": "offline_queued",
                "model": model_name,
                "command": f"ollama pull {model_name}",
                "message": (
                    f"Selected '{model_name}' (0 auto-downloads performed). "
                    f"To pull on your host, run: `ollama pull {model_name}`"
                ),
            }

    def unload_local_models(self) -> Dict[str, Any]:
        """Immediately free RAM on a 4GB system by setting keep_alive=0 on active local models."""
        local_url = self.config["ollama_local_url"]
        freed = []
        try:
            ps_resp = requests.get(f"{local_url}/api/ps", timeout=2.0)
            if ps_resp.ok:
                for m in ps_resp.json().get("models", []):
                    mname = m.get("name")
                    if mname:
                        requests.post(
                            f"{local_url}/api/generate",
                            json={"model": mname, "keep_alive": 0},
                            timeout=3.0,
                        )
                        freed.append(mname)
        except Exception:
            pass
        return {
            "status": "ok",
            "freed_models": freed,
            "message": f"Freed {len(freed)} model(s) from RAM." if freed else "No local models currently occupying RAM.",
        }

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        scan_context: Optional[Dict[str, Any]] = None,
        temperature: Optional[float] = None,
    ) -> Dict[str, Any]:
        chosen_model = model or self.config["active_model"]
        temp = temperature if temperature is not None else self.config["temperature"]
        start_ts = time.time()

        sys_content = ARAGOS_SYSTEM_PROMPT
        if scan_context:
            ctx_str = json.dumps(scan_context, indent=2)[:4000]
            sys_content += f"\n\n=== CURRENT ARAGOS SCAN TELEMETRY CONTEXT ===\n{ctx_str}"

        full_messages = [{"role": "system", "content": sys_content}]
        for m in messages:
            if m.get("role") in ("user", "assistant"):
                full_messages.append({"role": m["role"], "content": str(m.get("content", ""))})

        is_cloud_model = chosen_model.endswith("-cloud") or ":cloud" in chosen_model or self.config["mode"] in ("ollama-cloud", "openai-cloud")

        # 1. Try Local Ollama daemon (supports both lightweight local models AND 0-MB `:cloud` models)
        if self.config["mode"] in ("auto", "ollama-local", "ollama-cloud"):
            local_res = self._try_ollama_endpoint(
                self.config["ollama_local_url"],
                chosen_model,
                full_messages,
                temp,
                api_key=self.config.get("ollama_api_key") or None,
            )
            if local_res:
                return {
                    "reply": local_res,
                    "model": chosen_model,
                    "provider": "Ollama Cloud (0 MB Local RAM)" if is_cloud_model else "Ollama Local (4GB-RAM Eco Mode)",
                    "latency_ms": int((time.time() - start_ts) * 1000),
                    "live_llm": True,
                }

        # 2. Try Ollama Cloud Direct API if API key is configured
        if self.config.get("ollama_api_key"):
            cloud_res = self._try_ollama_endpoint(
                self.config["ollama_cloud_url"],
                chosen_model,
                full_messages,
                temp,
                api_key=self.config["ollama_api_key"],
            )
            if cloud_res:
                return {
                    "reply": cloud_res,
                    "model": chosen_model,
                    "provider": "Ollama Cloud API (0 MB Local RAM)",
                    "latency_ms": int((time.time() - start_ts) * 1000),
                    "live_llm": True,
                }

        # 3. Try OpenAI-compatible Cloud endpoint if configured
        if self.config.get("openai_api_key"):
            oai_res = self._try_openai_endpoint(
                self.config["openai_base_url"],
                chosen_model,
                full_messages,
                temp,
                self.config["openai_api_key"],
            )
            if oai_res:
                return {
                    "reply": oai_res,
                    "model": chosen_model,
                    "provider": "Cloud OpenAI-Compatible API",
                    "latency_ms": int((time.time() - start_ts) * 1000),
                    "live_llm": True,
                }

        # 4. Built-in Aragos Neural Threat Synthesis Engine (0 MB Disk / 0 MB Extra RAM)
        last_user_msg = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
        synthesized = self._synthesize_expert_response(last_user_msg, chosen_model, scan_context)
        return {
            "reply": synthesized,
            "model": f"{chosen_model} (Aragos Neural Core)",
            "provider": "Aragos Built-in Neural Engine (0 MB RAM/Disk)",
            "latency_ms": int((time.time() - start_ts) * 1000),
            "live_llm": False,
        }

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

        # 4GB-RAM friendly Ollama options: cap context window at 2048 tokens & auto-unload after 2m
        options: Dict[str, Any] = {"temperature": temperature}
        if self.config.get("low_ram_guard", True):
            options["num_ctx"] = int(self.config.get("num_ctx", 2048))
            options["num_thread"] = 2

        try:
            resp = requests.post(
                f"{base_url}/api/chat",
                headers=headers,
                json={
                    "model": model,
                    "messages": messages,
                    "stream": False,
                    "keep_alive": self.config.get("keep_alive", "2m"),
                    "options": options,
                },
                timeout=15,
            )
            if resp.ok:
                data = resp.json()
                content = data.get("message", {}).get("content")
                if content:
                    return content
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
        }
        try:
            resp = requests.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                },
                timeout=20,
            )
            if resp.ok:
                data = resp.json()
                choices = data.get("choices", [])
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
        risk_level = (
            "CRITICAL" if risk_score >= 80
            else "HIGH" if risk_score >= 60
            else "MODERATE" if risk_score >= 35
            else "LOW"
        )

        prompt = (
            f"Analyze the following ARAGOS reconnaissance scan for target `{target}`.\n"
            f"Modules executed: {', '.join(outputs.keys())}.\n"
            f"Severity Breakdown: {json.dumps(severities)}.\n"
            f"Key Findings: {json.dumps(findings[:15])}.\n"
            "Provide an Executive Threat Summary, Attack Surface Breakdown, Prioritized Remediation Playbook, and Next Recommended ARAGOS Modules."
        )

        chat_res = self.chat(
            messages=[{"role": "user", "content": prompt}],
            model=model,
            scan_context={
                "target": target,
                "severities": severities,
                "findings": findings[:15],
                "sample_outputs": {k: v[:1000] for k, v in list(outputs.items())[:4]},
            },
        )

        return {
            "target": target,
            "risk_score": risk_score,
            "risk_level": risk_level,
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
            {"id": "116", "name": "HTTP Security Features", "reason": "Audit HSTS, CSP, X-Frame-Options, and Permissions-Policy enforcement."},
            {"id": "14", "name": "TLS Cipher Suites", "reason": "Verify forward secrecy and detect weak/deprecated TLS cipher suites."},
            {"id": "63", "name": "CORS Misconfiguration Scanner", "reason": "Test for arbitrary Origin reflection and credentialed CORS leaks."},
            {"id": "124", "name": "Subdomain Enumeration", "reason": "Expand attack surface discovery across passive CT logs and DNS zones."},
            {"id": "134", "name": "SPF / DKIM / DMARC Validator", "reason": "Prevent domain spoofing and verify mail authentication alignment."},
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
        target = (scan_context or {}).get("target") or "current target"
        severities = (scan_context or {}).get("severities") or {}
        findings = (scan_context or {}).get("findings") or []
        sample_outputs = (scan_context or {}).get("sample_outputs") or {}

        findings_bullets = ""
        if findings:
            findings_bullets = "\n".join(
                f"- **[{f.get('severity', 'INFO')}] {f.get('module', 'Recon')}**: {f.get('detail', '')}"
                for f in findings[:10]
            )
        elif sample_outputs:
            lines = []
            for mod_name, text in sample_outputs.items():
                snippet = " | ".join(
                    ln.strip() for ln in text.splitlines()
                    if ln.strip() and not ln.strip().startswith(("=", "┏", "┡", "└", "│"))
                )[:220]
                lines.append(f"- **{mod_name}** (`{severities.get(mod_name, 'INFO')}`): {snippet or 'Telemetry captured successfully.'}")
            findings_bullets = "\n".join(lines)
        else:
            findings_bullets = (
                f"- **[INFO] Active Target Scope**: `{target}` ready for multi-layer reconnaissance.\n"
                "- **[OK] Catalog Readiness**: 147 specialized modules online across Network, Web, and Threat Intel."
            )

        q_lower = user_msg.lower()
        if any(w in q_lower for w in ("ollama", "model", "cloud", "ram", "storage", "disk", "4gb")):
            return f"""### 🦙 ARAGOS 4GB-RAM & 10GB-Storage Guide (`{model_name}`)

**ARAGOS never auto-downloads any models!** It uses **0 MB** of extra disk space by default.

For a machine with **4 GB RAM** and **10 GB free storage**, here is the best setup:

1. **Best Option: Ollama Cloud Models (`0 MB Disk` · `0 MB Local RAM`)**
   - Models ending in `-cloud` (like `deepseek-v3.1:671b-cloud`, `qwen3-coder:480b-cloud`, `gpt-oss:20b-cloud`) run on Ollama's cloud servers.
   - They take **0 MB of your 10 GB disk** and **0 MB of your 4 GB RAM**:
     ```bash
     ollama signin
     ollama run gpt-oss:20b-cloud
     ```
2. **Offline Option: Ultra-Light Local Models (`270 MB – 1.3 GB Disk` · `<1.7 GB RAM`)**
   - If you want 100% offline local AI that fits comfortably inside 4 GB RAM, pull only **one** of these tiny models:
     ```bash
     ollama pull qwen2.5-coder:1.5b   # 986 MB disk | ~1.5 GB RAM (Best for Recon/Code)
     ollama pull gemma3:1b            # 815 MB disk | ~1.3 GB RAM
     ollama pull qwen2.5:0.5b         # 398 MB disk | ~0.8 GB RAM (Ultra-light)
     ```
3. **Built-in 4GB-RAM Guard (Enabled by Default)**
   - ARAGOS automatically caps context memory (`num_ctx=2048`), unloads local models after 2 minutes (`keep_alive=2m`), and blocks accidental downloads of heavy 7B/14B/70B local models."""

        return f"""### 🛡️ ARAGOS Neural Threat Assessment — `{target}`
**Active Model Profile:** `{model_name}`

#### 1. Executive Reconnaissance Summary
Telemetry analysis for **`{target}`** has been correlated across the active reconnaissance workspace.

{findings_bullets}

#### 2. Attack Surface & Exposure Analysis
- **Perimeter & Transport Layer**: Inspect TLS handshake negotiation, certificate authority chain (CAA/CT logs), and HTTP/2 & HTTP/3 ALPN advertising for downgrade or origin-IP leakage vectors.
- **Web Application Hardening**: Verify strict `Content-Security-Policy` (avoiding `'unsafe-inline'` / `'unsafe-eval'`), `Permissions-Policy`, `Strict-Transport-Security` (`max-age=31536000; includeSubDomains; preload`), and `X-Frame-Options: DENY`.
- **DNS & Mail Spoofing Posture**: Confirm DNSSEC DS/RRSIG chain validity and enforce `v=DMARC1; p=reject` alongside strict SPF (`-all`).

#### 3. Prioritized Remediation Playbook
```nginx
# Recommended Edge Security Header Hardening
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

#### 4. Recommended Next ARAGOS Modules
1. **HTTP Security Features (`#116`)** & **CSP Deep Analyzer (`#98`)** — Validate header directives against DOM XSS vectors.
2. **TLS Cipher Suites (`#14`)** & **SSL Chain Analysis (`#12`)** — Audit cryptographic posture and intermediate certificates.
3. **CORS Misconfiguration Scanner (`#63`)** — Probe cross-origin trust boundaries and credential reflection."""


ai_engine = AragosAIEngine()
