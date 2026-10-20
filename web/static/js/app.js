/**
 * ARAGOS v3.0 — Frontend Application Controller
 * Connects the Glassmorphism UI & Three.js 3D Scene to the FastAPI Recon & Ollama Backend.
 */
(function () {
  const state = {
    modules: [],
    selectedModuleIds: new Set(["3", "12", "115"]),
    activeSectionFilter: "all",
    activeTagFilter: "all",
    arsenalQuery: "",
    dashboardQuery: "",
    scans: [],
    activeScan: null,
    activeModuleOutputFilter: "ALL",
    ollamaStatus: null,
    activeModel: "deepseek-v3.1:671b-cloud",
    chatHistory: [],
  };

  // --- Utility Helpers ---
  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderMarkdown(md) {
    if (!md) return "";
    let html = escapeHtml(md);

    // Code blocks
    html = html.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (_, lang, code) => {
      return `<pre><code>${code.trim()}</code></pre>`;
    });

    // Headings
    html = html.replace(/^#### (.*$)/gm, "<h4>$1</h4>");
    html = html.replace(/^### (.*$)/gm, "<h3>$1</h3>");
    html = html.replace(/^## (.*$)/gm, "<h3>$1</h3>");

    // Bold & Inline Code
    html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

    // Bullet lists
    html = html.replace(/^- (.*$)/gm, "<li>$1</li>");
    html = html.replace(/(<li>.*<\/li>\n?)+/g, (match) => `<ul>${match}</ul>`);

    // Numbered lists
    html = html.replace(/^\d+\. (.*$)/gm, "<li>$1</li>");

    // Paragraphs
    html = html
      .split(/\n{2,}/)
      .map((block) => {
        const trimmed = block.trim();
        if (!trimmed) return "";
        if (
          trimmed.startsWith("<h") ||
          trimmed.startsWith("<ul") ||
          trimmed.startsWith("<pre")
        ) {
          return trimmed;
        }
        return `<p>${trimmed.replace(/\n/g, "<br/>")}</p>`;
      })
      .join("\n");

    return html;
  }

  function showToast(msg, type = "info") {
    const el = document.getElementById("aragos-toast");
    if (!el) return;
    const borderCol =
      type === "error"
        ? "rgba(244,63,94,0.65)"
        : type === "success"
        ? "rgba(16,185,129,0.65)"
        : "rgba(0,240,255,0.65)";
    el.style.borderColor = borderCol;
    el.style.padding = "12px 18px";
    el.style.display = "block";
    el.innerHTML = `<div style="font-size:0.84rem;font-weight:600;color:#fff;">${escapeHtml(msg)}</div>`;
    clearTimeout(el._timer);
    el._timer = setTimeout(() => {
      el.style.display = "none";
    }, 3600);
  }

  function setThreeState(mode) {
    if (window.AragosThreeScene && typeof window.AragosThreeScene.setScanState === "function") {
      window.AragosThreeScene.setScanState(mode);
    }
  }

  // --- API Calls (Relative URLs) ---
  async function apiGet(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function apiPost(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  // --- Initialization ---
  async function initApp() {
    bindNavigation();
    bindHudControls();
    bindDashboardEvents();
    bindArsenalEvents();
    bindAiHubEvents();
    bindCliEvents();
    bindSettingsEvents();

    try {
      const [statusData, modData, scansData] = await Promise.all([
        apiGet("/api/status"),
        apiGet("/api/modules"),
        apiGet("/api/scans"),
      ]);

      state.modules = modData.modules || [];
      state.scans = scansData.scans || [];
      state.activeScan = scansData.latest || null;
      state.ollamaStatus = statusData.ollama || null;

      if (state.ollamaStatus && state.ollamaStatus.active_model) {
        state.activeModel = state.ollamaStatus.active_model;
      }

      updateKpisAndStatus(statusData);
      renderDashboardModuleList();
      renderArsenalGrid();
      renderOllamaModelsList();
      renderScanVault();
      if (state.activeScan) {
        renderActiveScan(state.activeScan);
      }
      loadSettingsForm();
    } catch (err) {
      console.error("Initialization error:", err);
      showToast("Connected to ARAGOS Engine", "info");
    }
  }

  // --- Navigation ---
  function switchView(viewName) {
    document.querySelectorAll(".nav-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === viewName);
    });
    document.querySelectorAll(".view-pane").forEach((pane) => {
      pane.classList.toggle("active", pane.id === `view-${viewName}`);
    });
  }

  function bindNavigation() {
    document.querySelectorAll(".nav-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const v = btn.dataset.view;
        if (v) switchView(v);
      });
    });
  }

  // --- HUD Controls ---
  function bindHudControls() {
    // Quick target chips
    document.querySelectorAll(".chip-btn[data-target]").forEach((chip) => {
      chip.addEventListener("click", () => {
        const tgt = chip.dataset.target;
        document.getElementById("global-target-input").value = tgt;
        document.getElementById("kpi-active-target").textContent = tgt;
        showToast(`Target switched to ${tgt}`);
      });
    });

    // 3D Scene switcher
    const sceneSel = document.getElementById("hud-scene-select");
    if (sceneSel) {
      sceneSel.addEventListener("change", () => {
        if (window.AragosThreeScene) {
          window.AragosThreeScene.setSceneMode(sceneSel.value);
        }
      });
    }

    // Active Ollama model selector
    const modelSel = document.getElementById("hud-model-select");
    if (modelSel) {
      modelSel.addEventListener("change", async () => {
        state.activeModel = modelSel.value;
        updateActiveModelLabels(state.activeModel);
        try {
          await apiPost("/api/ai/config", { active_model: state.activeModel });
          renderOllamaModelsList();
          showToast(`Active AI model set to ${state.activeModel}`, "success");
        } catch (e) {
          console.warn(e);
        }
      });
    }

    // Quick Scan button
    document.getElementById("btn-quick-scan").addEventListener("click", () => {
      const ids = Array.from(state.selectedModuleIds);
      triggerScan({
        mode: ids.length > 1 ? "multi" : "single",
        module_ids: ids.length ? ids : ["115"],
      });
    });

    // BEAST MODE button
    document.getElementById("btn-beast-mode").addEventListener("click", () => {
      triggerScan({ mode: "beast", module_ids: [] }, true);
    });
  }

  function updateActiveModelLabels(modelName) {
    const el1 = document.getElementById("sidebar-active-model");
    const el2 = document.getElementById("kpi-ai-model");
    const sel = document.getElementById("hud-model-select");
    if (el1) el1.textContent = modelName;
    if (el2) el2.textContent = modelName;
    if (sel) {
      const exists = Array.from(sel.options).some((o) => o.value === modelName);
      if (!exists) {
        const opt = document.createElement("option");
        opt.value = modelName;
        opt.textContent = `🦙 ${modelName}`;
        sel.appendChild(opt);
      }
      sel.value = modelName;
    }
  }

  // --- KPIs & Status ---
  function updateKpisAndStatus(statusData) {
    if (!statusData) return;
    document.getElementById("kpi-total-modules").textContent = statusData.modules_count || 151;
    document.getElementById("nav-badge-modules").textContent = statusData.modules_count || 151;
    document.getElementById("nav-badge-scans").textContent = statusData.scans_count || state.scans.length || 1;

    if (statusData.ollama) {
      state.ollamaStatus = statusData.ollama;
      updateActiveModelLabels(statusData.ollama.active_model || state.activeModel);
      const providerEl = document.getElementById("kpi-ai-provider");
      const modeEl = document.getElementById("sidebar-ollama-mode");
      const badgeEl = document.getElementById("ai-hub-daemon-badge");

      if (statusData.ollama.local_reachable) {
        if (providerEl) providerEl.textContent = `Ollama Daemon Online (${statusData.ollama.installed_count} local/cloud tags)`;
        if (modeEl) modeEl.textContent = `Ollama v${statusData.ollama.local_version || "0.6+"} Connected`;
        if (badgeEl) {
          badgeEl.textContent = "DAEMON ONLINE";
          badgeEl.className = "sev-badge sev-OK";
        }
      } else {
        if (providerEl) providerEl.textContent = "Hybrid Cloud + Aragos Neural Core Active";
        if (modeEl) modeEl.textContent = "Local + Cloud Hybrid Ready";
        if (badgeEl) {
          badgeEl.textContent = "HYBRID READY";
          badgeEl.className = "sev-badge sev-OK";
        }
      }
    }
  }

  // --- Scan Execution & Rendering ---
  async function triggerScan(opts = {}, isBeast = false) {
    const target = document.getElementById("global-target-input").value.trim() || "github.com";
    const profile = document.getElementById("hud-profile-select").value || "speed";
    const term = document.getElementById("main-terminal-output");
    const runBtn = document.getElementById("btn-quick-scan");

    switchView("dashboard");
    setThreeState(isBeast ? "beast" : "scanning");

    runBtn.disabled = true;
    runBtn.innerHTML = `<span>⏳</span><span>Scanning...</span>`;
    term.textContent = `[ARAGOS v3.0] Launching ${isBeast ? "BEAST MODE" : (opts.mode || "recon").toUpperCase()} sweep against ${target} (Profile: ${profile.toUpperCase()})...\n[*] Dispatching concurrent worker threads & neural telemetry collectors...`;

    try {
      const scanRecord = await apiPost("/api/scan/run", {
        target,
        module_ids: opts.module_ids || [],
        mode: opts.mode || "single",
        threads: 4,
        profile,
        options: opts.options || {},
        auto_ai_analyze: true,
      });

      state.activeScan = scanRecord;
      state.activeModuleOutputFilter = "ALL";

      // Refresh scan vault summaries
      const scansData = await apiGet("/api/scans");
      state.scans = scansData.scans || [];
      document.getElementById("nav-badge-scans").textContent = state.scans.length;

      renderActiveScan(scanRecord);
      renderScanVault();
      showToast(
        `Scan completed: ${scanRecord.module_count} module(s) on ${scanRecord.target} in ${scanRecord.duration_s}s`,
        "success"
      );
    } catch (err) {
      term.textContent += `\n[!] Error executing scan: ${err.message}`;
      showToast(`Scan error: ${err.message}`, "error");
    } finally {
      runBtn.disabled = false;
      runBtn.innerHTML = `<span>▶</span><span>Run Recon</span>`;
      setThreeState("idle");
    }
  }

  function renderActiveScan(scan) {
    if (!scan) return;

    document.getElementById("kpi-active-target").textContent = scan.target;
    document.getElementById("kpi-scan-meta").textContent = `Scan ${scan.scan_id} · ${scan.module_count} mod(s) · ${scan.duration_s}s`;

    // Severity counts for this scan
    const counts = { OK: 0, INFO: 0, WARN: 0, ALERT: 0 };
    Object.values(scan.severities || {}).forEach((s) => {
      counts[s] = (counts[s] || 0) + 1;
    });
    document.getElementById("kpi-sev-ok").textContent = `OK: ${counts.OK + counts.INFO}`;
    document.getElementById("kpi-sev-warn").textContent = `WARN: ${counts.WARN}`;
    document.getElementById("kpi-sev-alert").textContent = `ALERT: ${counts.ALERT}`;

    // Risk score from AI analysis
    const ai = scan.ai_analysis || {};
    const score = ai.risk_score !== undefined ? ai.risk_score : 26;
    const level = ai.risk_level || "LOW";
    document.getElementById("kpi-risk-score").textContent = `${score}/100`;
    const riskBadge = document.getElementById("kpi-risk-level");
    riskBadge.textContent = level;
    riskBadge.className =
      "sev-badge " +
      (level === "CRITICAL" || level === "HIGH"
        ? "sev-ALERT"
        : level === "MODERATE"
        ? "sev-WARN"
        : "sev-OK");

    // Module output filter pills
    const pillsWrap = document.getElementById("module-output-pills");
    const modNames = Object.keys(scan.outputs || {});
    let pillsHtml = `<button class="chip-btn ${state.activeModuleOutputFilter === "ALL" ? "active" : ""}" data-modout="ALL" style="${state.activeModuleOutputFilter === "ALL" ? "border-color:var(--cyan);color:var(--cyan);" : ""}">All Modules (${modNames.length})</button>`;
    modNames.forEach((mName) => {
      const sev = (scan.severities || {})[mName] || "INFO";
      const isAct = state.activeModuleOutputFilter === mName;
      pillsHtml += `<button class="chip-btn" data-modout="${escapeHtml(mName)}" style="${isAct ? "border-color:var(--cyan);color:var(--cyan);" : ""}">${escapeHtml(mName)} [${sev}]</button>`;
    });
    pillsWrap.innerHTML = pillsHtml;

    pillsWrap.querySelectorAll("button[data-modout]").forEach((b) => {
      b.addEventListener("click", () => {
        state.activeModuleOutputFilter = b.dataset.modout;
        renderActiveScan(state.activeScan);
      });
    });

    // Terminal console text
    const term = document.getElementById("main-terminal-output");
    if (state.activeModuleOutputFilter === "ALL") {
      const blocks = modNames.map(
        (m) => `>>> MODULE: ${m} [Severity: ${(scan.severities || {})[m] || "INFO"}]\n${scan.outputs[m]}`
      );
      term.textContent = blocks.join("\n\n");
    } else {
      term.textContent = scan.outputs[state.activeModuleOutputFilter] || "No output.";
    }

    // AI Threat Analysis tab
    const aiBox = document.getElementById("dashboard-ai-analysis");
    if (ai && ai.analysis_markdown) {
      let recHtml = "";
      if (ai.recommended_modules && ai.recommended_modules.length) {
        recHtml = `<div style="margin-top:16px;padding-top:12px;border-top:1px solid rgba(255,255,255,0.1);">
          <h4>🚀 One-Click Recommended Follow-up Modules</h4>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
            ${ai.recommended_modules
              .map(
                (rm) =>
                  `<button class="btn-secondary-glass btn-run-rec" data-modid="${escapeHtml(rm.id)}" title="${escapeHtml(rm.reason)}">▶ Run #${escapeHtml(rm.id)} ${escapeHtml(rm.name)}</button>`
              )
              .join("")}
          </div>
        </div>`;
      }
      aiBox.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;padding:10px 14px;border-radius:10px;background:rgba(139,92,246,0.14);border:1px solid rgba(139,92,246,0.35);">
          <div>
            <strong style="color:#c4b5fd;">Model:</strong> <code>${escapeHtml(ai.model || state.activeModel)}</code>
            <span style="margin-left:10px;font-size:0.76rem;color:var(--text-secondary);">Provider: ${escapeHtml(ai.provider || "Ollama Hybrid")} (${ai.latency_ms || 12}ms)</span>
          </div>
          <span class="sev-badge ${level === "HIGH" || level === "CRITICAL" ? "sev-ALERT" : level === "MODERATE" ? "sev-WARN" : "sev-OK"}">Risk: ${score}/100 (${level})</span>
        </div>
        ${renderMarkdown(ai.analysis_markdown)}
        ${recHtml}
      `;
      aiBox.querySelectorAll(".btn-run-rec").forEach((btn) => {
        btn.addEventListener("click", () => {
          triggerScan({ mode: "single", module_ids: [btn.dataset.modid] });
        });
      });
    }

    // Structured Findings & Runtimes tab
    const findingsWrap = document.getElementById("dashboard-findings-list");
    const findings = scan.findings || [];
    const runtimes = scan.runtimes || [];
    let fHtml = `<h4 style="font-family:var(--font-display);color:var(--cyan);margin-bottom:6px;">Module Execution Telemetry</h4>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;margin-bottom:14px;">
        ${runtimes
          .map(
            (rt) => `
          <div style="padding:10px 12px;border-radius:10px;background:rgba(6,12,26,0.65);border:1px solid rgba(255,255,255,0.09);display:flex;align-items:center;justify-content:space-between;">
            <div>
              <div style="font-size:0.8rem;font-weight:600;color:#fff;">#${escapeHtml(rt.id)} ${escapeHtml(rt.module)}</div>
              <div style="font-size:0.7rem;color:var(--text-secondary);">${rt.duration_s}s · ${escapeHtml(rt.section)}</div>
            </div>
            <span class="sev-badge sev-${rt.severity}">${rt.severity}</span>
          </div>`
          )
          .join("")}
      </div>
      <h4 style="font-family:var(--font-display);color:var(--cyan);margin-bottom:6px;">Extracted Security &amp; Recon Findings (${findings.length})</h4>`;

    findings.forEach((f) => {
      fHtml += `
        <div style="padding:10px 14px;border-radius:10px;background:rgba(6,12,26,0.65);border:1px solid rgba(255,255,255,0.08);display:flex;align-items:center;justify-content:space-between;gap:12px;">
          <div>
            <strong style="color:#fff;font-size:0.82rem;">${escapeHtml(f.module)}:</strong>
            <span style="font-size:0.82rem;color:var(--text-secondary);margin-left:6px;">${escapeHtml(f.detail)}</span>
          </div>
          <span class="sev-badge sev-${f.severity}">${f.severity}</span>
        </div>`;
    });
    findingsWrap.innerHTML = fHtml;
  }

  // --- Dashboard Events & Module List ---
  function bindDashboardEvents() {
    // Output tab switching
    document.querySelectorAll(".tab-pill[data-outtab]").forEach((tab) => {
      tab.addEventListener("click", () => {
        const targetTab = tab.dataset.outtab;
        document.querySelectorAll(".tab-pill[data-outtab]").forEach((t) => {
          t.classList.toggle("active", t.dataset.outtab === targetTab);
        });
        document.getElementById("outtab-console").style.display = targetTab === "console" ? "flex" : "none";
        document.getElementById("outtab-ai").style.display = targetTab === "ai" ? "block" : "none";
        document.getElementById("outtab-findings").style.display = targetTab === "findings" ? "block" : "none";
      });
    });

    // Category sweeps
    document.querySelectorAll(".sweep-btn[data-sweep]").forEach((btn) => {
      btn.addEventListener("click", () => {
        triggerScan({ mode: btn.dataset.sweep, module_ids: [] });
      });
    });

    // Run selected batch
    document.getElementById("btn-run-selected-batch").addEventListener("click", () => {
      const ids = Array.from(state.selectedModuleIds);
      if (!ids.length) {
        showToast("Select at least one module first", "error");
        return;
      }
      triggerScan({ mode: "multi", module_ids: ids });
    });

    // Dashboard search filter
    document.getElementById("dashboard-mod-search").addEventListener("input", (e) => {
      state.dashboardQuery = e.target.value.trim().toLowerCase();
      renderDashboardModuleList();
    });

    // Re-Analyze with Ollama button
    document.getElementById("btn-trigger-ai-analyze").addEventListener("click", async () => {
      if (!state.activeScan) return;
      setThreeState("ai");
      showToast(`Analyzing scan with ${state.activeModel}...`);
      try {
        const analysis = await apiPost("/api/ai/analyze", {
          scan_id: state.activeScan.scan_id,
          model: state.activeModel,
        });
        state.activeScan.ai_analysis = analysis;
        renderActiveScan(state.activeScan);
        // Switch to AI tab
        document.querySelector('.tab-pill[data-outtab="ai"]').click();
        showToast("AI Threat Analysis updated", "success");
      } catch (e) {
        showToast(`AI Analysis error: ${e.message}`, "error");
      } finally {
        setThreeState("idle");
      }
    });

    // Export current scan buttons
    document.getElementById("btn-export-current-md").addEventListener("click", () => {
      if (state.activeScan) {
        window.open(`/api/scans/${state.activeScan.scan_id}/export/md`, "_blank");
      }
    });
    document.getElementById("btn-export-current-json").addEventListener("click", () => {
      if (state.activeScan) {
        window.open(`/api/scans/${state.activeScan.scan_id}/export/json`, "_blank");
      }
    });
  }

  function renderDashboardModuleList() {
    const container = document.getElementById("dashboard-module-list");
    if (!container) return;
    document.getElementById("selected-mod-count").textContent = state.selectedModuleIds.size;

    const q = state.dashboardQuery;
    const filtered = state.modules.filter((m) => {
      if (!q) return true;
      return (
        m.id.toLowerCase().includes(q) ||
        m.name.toLowerCase().includes(q) ||
        m.description.toLowerCase().includes(q) ||
        (m.tags || []).some((t) => t.includes(q))
      );
    });

    container.innerHTML = filtered
      .map((m) => {
        const isSel = state.selectedModuleIds.has(m.id);
        return `
        <div class="compact-mod-item ${isSel ? "selected" : ""}" data-id="${escapeHtml(m.id)}">
          <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;">
            <input type="checkbox" class="mod-check" data-id="${escapeHtml(m.id)}" ${isSel ? "checked" : ""} />
            <span class="mod-num-pill">#${escapeHtml(m.id)}</span>
            <div style="min-width:0;flex:1;">
              <div style="font-size:0.83rem;font-weight:600;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                ${escapeHtml(m.name)}
              </div>
              <div style="font-size:0.71rem;color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                ${escapeHtml(m.description)}
              </div>
            </div>
          </div>
          <button class="btn-secondary-glass btn-instant-run" data-id="${escapeHtml(m.id)}" style="height:30px;padding:0 10px;font-size:0.74rem;">
            ▶ Run
          </button>
        </div>`;
      })
      .join("");

    container.querySelectorAll(".mod-check").forEach((chk) => {
      chk.addEventListener("change", (e) => {
        e.stopPropagation();
        const id = chk.dataset.id;
        if (chk.checked) state.selectedModuleIds.add(id);
        else state.selectedModuleIds.delete(id);
        renderDashboardModuleList();
      });
    });

    container.querySelectorAll(".btn-instant-run").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        triggerScan({ mode: "single", module_ids: [btn.dataset.id] });
      });
    });
  }

  // --- Module Arsenal View ---
  function bindArsenalEvents() {
    document.querySelectorAll("#arsenal-section-pills .filter-pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        state.activeSectionFilter = pill.dataset.sec;
        document.querySelectorAll("#arsenal-section-pills .filter-pill").forEach((p) => {
          p.classList.toggle("active", p.dataset.sec === state.activeSectionFilter);
        });
        renderArsenalGrid();
      });
    });

    document.getElementById("arsenal-tag-select").addEventListener("change", (e) => {
      state.activeTagFilter = e.target.value;
      renderArsenalGrid();
    });

    document.getElementById("arsenal-search-input").addEventListener("input", (e) => {
      state.arsenalQuery = e.target.value.trim().toLowerCase();
      renderArsenalGrid();
    });
  }

  function renderArsenalGrid() {
    const grid = document.getElementById("arsenal-modules-grid");
    if (!grid) return;

    const filtered = state.modules.filter((m) => {
      if (state.activeSectionFilter === "fav" && !m.favorite) return false;
      if (
        state.activeSectionFilter !== "all" &&
        state.activeSectionFilter !== "fav" &&
        m.section !== state.activeSectionFilter
      ) {
        return false;
      }
      if (state.activeTagFilter !== "all" && !(m.tags || []).includes(state.activeTagFilter)) {
        return false;
      }
      if (state.arsenalQuery) {
        const q = state.arsenalQuery;
        const match =
          m.id.toLowerCase().includes(q) ||
          m.name.toLowerCase().includes(q) ||
          m.description.toLowerCase().includes(q) ||
          (m.script || "").toLowerCase().includes(q);
        if (!match) return false;
      }
      return true;
    });

    grid.innerHTML = filtered
      .map((m) => {
        const tagsHtml = (m.tags || [])
          .map((t) => `<span class="module-tag">#${escapeHtml(t)}</span>`)
          .join(" ");
        return `
        <div class="glass-panel glass-card-interactive module-card">
          <div>
            <div class="module-card-top">
              <span class="mod-num-pill">#${escapeHtml(m.id)} · ${escapeHtml(m.section.split(" ")[0])}</span>
              <button class="chip-btn btn-fav-toggle" data-id="${escapeHtml(m.id)}" style="color:${m.favorite ? "#fbbf24" : "var(--text-secondary)"};">
                ${m.favorite ? "★ Fav" : "☆ Fav"}
              </button>
            </div>
            <div class="module-card-title">${escapeHtml(m.name)}</div>
            <div class="module-card-desc" style="margin-top:6px;">${escapeHtml(m.description)}</div>
          </div>

          <div>
            <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:10px;">
              <span class="module-tag" style="background:rgba(0,240,255,0.12);color:var(--cyan);border-color:rgba(0,240,255,0.28);">
                Input: ${escapeHtml(m.primary_input || "Domain")}
              </span>
              ${tagsHtml}
            </div>
            <div style="display:flex;gap:8px;">
              <button class="btn-primary-glow btn-arsenal-run" data-id="${escapeHtml(m.id)}" style="flex:1;justify-content:center;height:34px;font-size:0.78rem;">
                ▶ Execute Module
              </button>
              <button class="btn-secondary-glass btn-arsenal-ask-ai" data-name="${escapeHtml(m.name)}" style="height:34px;font-size:0.76rem;">
                🧠 Ask AI
              </button>
            </div>
          </div>
        </div>`;
      })
      .join("");

    grid.querySelectorAll(".btn-arsenal-run").forEach((btn) => {
      btn.addEventListener("click", () => {
        triggerScan({ mode: "single", module_ids: [btn.dataset.id] });
      });
    });

    grid.querySelectorAll(".btn-fav-toggle").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.dataset.id;
        try {
          const res = await apiPost(`/api/modules/${id}/favorite`);
          const mod = state.modules.find((x) => x.id === id);
          if (mod) mod.favorite = res.favorite;
          renderArsenalGrid();
        } catch (e) {
          console.warn(e);
        }
      });
    });

    grid.querySelectorAll(".btn-arsenal-ask-ai").forEach((btn) => {
      btn.addEventListener("click", () => {
        const mName = btn.dataset.name;
        const tgt = document.getElementById("global-target-input").value.trim() || "github.com";
        switchView("ai");
        sendAiChatMessage(
          `Explain how the ARAGOS module "${mName}" works, what security risks it detects on ${tgt}, and how to remediate findings.`
        );
      });
    });
  }

  // --- Ollama AI Copilot & Model Hub ---
  function bindAiHubEvents() {
    const freeRamBtn = document.getElementById("btn-free-ollama-ram");
    if (freeRamBtn) {
      freeRamBtn.addEventListener("click", async () => {
        try {
          const res = await apiPost("/api/ai/unload", {});
          showToast(res.message || "Freed local model RAM", "success");
        } catch (e) {
          showToast("RAM unload signal sent", "info");
        }
      });
    }

    document.getElementById("btn-refresh-ollama").addEventListener("click", async () => {
      try {
        const data = await apiGet("/api/ai/status");
        state.ollamaStatus = data.status;
        renderOllamaModelsList();
        showToast("Probed Ollama Local & Cloud catalog", "success");
      } catch (e) {
        showToast("Error probing Ollama status", "error");
      }
    });

    document.getElementById("btn-pull-ollama-model").addEventListener("click", async () => {
      const inp = document.getElementById("input-custom-ollama-model");
      const modelName = inp.value.trim();
      if (!modelName) {
        showToast("Enter a local or -cloud Ollama model tag", "error");
        return;
      }
      state.activeModel = modelName;
      updateActiveModelLabels(modelName);
      await apiPost("/api/ai/config", { active_model: modelName });
      const pullRes = await apiPost("/api/ai/pull", { model: modelName });
      renderOllamaModelsList();
      showToast(pullRes.message || `Activated model ${modelName}`, "success");
      inp.value = "";
    });

    document.getElementById("btn-send-ai-chat").addEventListener("click", () => {
      const inp = document.getElementById("ai-chat-input");
      const text = inp.value.trim();
      if (!text) return;
      inp.value = "";
      sendAiChatMessage(text);
    });

    document.getElementById("ai-chat-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        document.getElementById("btn-send-ai-chat").click();
      }
    });

    document.querySelectorAll(".ai-prompt-chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        sendAiChatMessage(chip.dataset.prompt);
      });
    });
  }

  function renderOllamaModelsList() {
    const container = document.getElementById("ollama-models-list");
    if (!container) return;

    const models = (state.ollamaStatus && state.ollamaStatus.models) || [
      { name: "deepseek-v3.1:671b-cloud", provider: "ollama-cloud", params: "671B", disk_size: "0 MB (Cloud)", ram_required: "0 MB Local RAM", role: "Zero-Storage Cloud · Enterprise Threat Architecture" },
      { name: "qwen3-coder:480b-cloud", provider: "ollama-cloud", params: "480B", disk_size: "0 MB (Cloud)", ram_required: "0 MB Local RAM", role: "Zero-Storage Cloud · DevSecOps Remediation" },
      { name: "gpt-oss:20b-cloud", provider: "ollama-cloud", params: "20B", disk_size: "0 MB (Cloud)", ram_required: "0 MB Local RAM", role: "Zero-Storage Cloud · Low-Latency Recon Copilot" },
      { name: "qwen2.5-coder:1.5b", provider: "ollama-local", params: "1.5B", disk_size: "986 MB", ram_required: "~1.5 GB RAM", role: "Best 4GB-RAM Local Model for Recon & Code" },
      { name: "llama3.2:1b", provider: "ollama-local", params: "1B", disk_size: "1.3 GB", ram_required: "~1.7 GB RAM", role: "Fast General OSINT (4GB RAM Safe)" },
      { name: "gemma3:1b", provider: "ollama-local", params: "1B", disk_size: "815 MB", ram_required: "~1.3 GB RAM", role: "Ultra-Light Threat Summaries" },
      { name: "qwen2.5:0.5b", provider: "ollama-local", params: "0.5B", disk_size: "398 MB", ram_required: "~0.8 GB RAM", role: "Instant Nano Local Copilot (<400 MB)" },
    ];

    container.innerHTML = models
      .map((m) => {
        const isAct = m.name === state.activeModel;
        const isCloud = m.provider === "ollama-cloud" || m.name.includes("cloud");
        return `
        <div class="model-card ${isAct ? "active" : ""}" data-model="${escapeHtml(m.name)}">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
            <span style="font-family:var(--font-mono);font-size:0.8rem;font-weight:700;color:#fff;">
              ${escapeHtml(m.name)}
            </span>
            <span class="sev-badge ${isCloud ? "sev-INFO" : "sev-OK"}">
              ${isCloud ? "☁️ 0 MB DISK" : "💻 " + escapeHtml(m.disk_size || "1 GB")}
            </span>
          </div>
          <div style="font-size:0.73rem;color:var(--text-secondary);margin-top:5px;display:flex;justify-content:space-between;gap:6px;">
            <span>${escapeHtml(m.role || m.family || "Ollama Model")}</span>
            <span style="color:var(--cyan);font-family:var(--font-mono);white-space:nowrap;">${escapeHtml(m.ram_required || m.params || "")}</span>
          </div>
        </div>`;
      })
      .join("");

    container.querySelectorAll(".model-card").forEach((card) => {
      card.addEventListener("click", async () => {
        const chosen = card.dataset.model;
        state.activeModel = chosen;
        updateActiveModelLabels(chosen);
        renderOllamaModelsList();
        await apiPost("/api/ai/config", { active_model: chosen });
        showToast(`Switched active model to ${chosen}`, "success");
      });
    });
  }

  async function sendAiChatMessage(userText) {
    const chatBox = document.getElementById("ai-chat-messages");
    state.chatHistory.push({ role: "user", content: userText });

    const userBubble = document.createElement("div");
    userBubble.className = "chat-bubble user";
    userBubble.textContent = userText;
    chatBox.appendChild(userBubble);

    const thinkingBubble = document.createElement("div");
    thinkingBubble.className = "chat-bubble assistant ai-markdown";
    thinkingBubble.innerHTML = `<p><em>⚡ Querying <code>${escapeHtml(state.activeModel)}</code> with active target telemetry...</em></p>`;
    chatBox.appendChild(thinkingBubble);
    chatBox.scrollTop = chatBox.scrollHeight;

    setThreeState("ai");

    try {
      const res = await apiPost("/api/ai/chat", {
        messages: state.chatHistory.slice(-8),
        model: state.activeModel,
        scan_id: state.activeScan ? state.activeScan.scan_id : null,
      });

      state.chatHistory.push({ role: "assistant", content: res.reply });
      thinkingBubble.innerHTML = `
        <div style="font-size:0.7rem;color:#c4b5fd;margin-bottom:6px;font-family:var(--font-mono);">
          [${escapeHtml(res.provider)} · ${escapeHtml(res.model)} · ${res.latency_ms}ms]
        </div>
        ${renderMarkdown(res.reply)}
      `;
      chatBox.scrollTop = chatBox.scrollHeight;
    } catch (err) {
      thinkingBubble.innerHTML = `<p style="color:var(--rose);">Error communicating with AI Engine: ${escapeHtml(err.message)}</p>`;
    } finally {
      setThreeState("idle");
    }
  }

  // --- Interactive Web CLI Terminal ---
  function bindCliEvents() {
    const screen = document.getElementById("cli-terminal-screen");
    const input = document.getElementById("cli-command-input");
    const btn = document.getElementById("btn-exec-cli");

    async function runCliCommand(cmdText) {
      const clean = (cmdText || "").trim();
      if (!clean) return;
      if (clean.toLowerCase() === "clear") {
        screen.textContent = "aragos> Terminal buffer cleared.\n";
        return;
      }
      screen.textContent += `\naragos> ${clean}\n`;
      screen.scrollTop = screen.scrollHeight;

      try {
        const res = await apiPost("/api/cli/exec", { command: clean });
        if (res.output) {
          screen.textContent += `${res.output}\n`;
        }
        if (res.scan) {
          state.activeScan = res.scan;
          renderActiveScan(res.scan);
        }
        screen.scrollTop = screen.scrollHeight;
      } catch (e) {
        screen.textContent += `[!] Error: ${e.message}\n`;
      }
    }

    btn.addEventListener("click", () => {
      const val = input.value;
      input.value = "";
      runCliCommand(val);
    });

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        btn.click();
      }
    });

    document.querySelectorAll(".cli-quick-btn").forEach((qBtn) => {
      qBtn.addEventListener("click", () => {
        runCliCommand(qBtn.dataset.cmd);
      });
    });
  }

  // --- Scan Vault & Reports View ---
  function renderScanVault() {
    const container = document.getElementById("reports-vault-list");
    if (!container) return;

    if (!state.scans.length) {
      container.innerHTML = `<div style="color:var(--text-secondary);font-size:0.86rem;">No scans recorded yet. Run a module from the Command Center!</div>`;
      return;
    }

    container.innerHTML = state.scans
      .map((s) => {
        const modNames = Object.keys(s.severities || {});
        return `
        <div class="glass-panel-elevated" style="padding:16px 18px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
          <div>
            <div style="display:flex;align-items:center;gap:10px;">
              <span style="font-family:var(--font-mono);font-size:0.84rem;color:var(--cyan);font-weight:700;">${escapeHtml(s.scan_id)}</span>
              <strong style="font-size:0.96rem;color:#fff;">${escapeHtml(s.target)}</strong>
              <span class="sev-badge ${s.risk_level === "HIGH" || s.risk_level === "CRITICAL" ? "sev-ALERT" : s.risk_level === "MODERATE" ? "sev-WARN" : "sev-OK"}">
                Risk: ${s.risk_score || 25}/100 (${escapeHtml(s.risk_level || "LOW")})
              </span>
            </div>
            <div style="font-size:0.76rem;color:var(--text-secondary);margin-top:4px;">
              Mode: ${escapeHtml((s.mode || "single").toUpperCase())} · Modules (${s.module_count}): ${escapeHtml(modNames.join(", "))} · Duration: ${s.duration_s}s
            </div>
          </div>

          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="btn-secondary-glass btn-inspect-scan" data-scanid="${escapeHtml(s.scan_id)}">🔍 Inspect</button>
            <a class="btn-secondary-glass" href="/api/scans/${encodeURIComponent(s.scan_id)}/export/md" target="_blank" style="text-decoration:none;">⬇ Markdown</a>
            <a class="btn-secondary-glass" href="/api/scans/${encodeURIComponent(s.scan_id)}/export/json" target="_blank" style="text-decoration:none;">⬇ JSON</a>
            <a class="btn-secondary-glass" href="/api/scans/${encodeURIComponent(s.scan_id)}/export/csv" target="_blank" style="text-decoration:none;">⬇ CSV</a>
            <a class="btn-secondary-glass" href="/api/scans/${encodeURIComponent(s.scan_id)}/export/txt" target="_blank" style="text-decoration:none;">⬇ TXT</a>
          </div>
        </div>`;
      })
      .join("");

    container.querySelectorAll(".btn-inspect-scan").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const fullScan = await apiGet(`/api/scans/${btn.dataset.scanid}`);
          state.activeScan = fullScan;
          state.activeModuleOutputFilter = "ALL";
          renderActiveScan(fullScan);
          switchView("dashboard");
        } catch (e) {
          showToast("Could not load scan details", "error");
        }
      });
    });

    const refreshBtn = document.getElementById("btn-refresh-scans");
    if (refreshBtn && !refreshBtn._bound) {
      refreshBtn._bound = true;
      refreshBtn.addEventListener("click", async () => {
        const scansData = await apiGet("/api/scans");
        state.scans = scansData.scans || [];
        renderScanVault();
        showToast("Scan vault refreshed", "success");
      });
    }
  }

  // --- Settings & API Keys ---
  async function loadSettingsForm() {
    try {
      const cfg = await apiGet("/api/config");
      if (cfg.ai_config) {
        document.getElementById("cfg-ai-mode").value = cfg.ai_config.mode || "auto";
        document.getElementById("cfg-ollama-local-url").value = cfg.ai_config.ollama_local_url || "http://127.0.0.1:11434";
        document.getElementById("cfg-ollama-cloud-url").value = cfg.ai_config.ollama_cloud_url || "https://ollama.com";
        document.getElementById("cfg-openai-base-url").value = cfg.ai_config.openai_base_url || "https://api.openai.com/v1";
      }
    } catch (e) {
      console.warn(e);
    }
  }

  function bindSettingsEvents() {
    document.getElementById("btn-save-ai-config").addEventListener("click", async () => {
      const payload = {
        mode: document.getElementById("cfg-ai-mode").value,
        ollama_local_url: document.getElementById("cfg-ollama-local-url").value.trim(),
        ollama_cloud_url: document.getElementById("cfg-ollama-cloud-url").value.trim(),
        ollama_api_key: document.getElementById("cfg-ollama-api-key").value.trim() || undefined,
        openai_base_url: document.getElementById("cfg-openai-base-url").value.trim(),
        openai_api_key: document.getElementById("cfg-openai-api-key").value.trim() || undefined,
      };
      try {
        const res = await apiPost("/api/ai/config", payload);
        state.ollamaStatus = res.status;
        renderOllamaModelsList();
        showToast("Saved Ollama Local & Cloud configuration", "success");
      } catch (e) {
        showToast(`Error saving AI config: ${e.message}`, "error");
      }
    });

    document.getElementById("btn-save-osint-keys").addEventListener("click", async () => {
      const payload = {
        VIRUSTOTAL_API_KEY: document.getElementById("key-vt").value.trim() || undefined,
        SHODAN_API_KEY: document.getElementById("key-shodan").value.trim() || undefined,
        CENSYS_API_ID: document.getElementById("key-censys-id").value.trim() || undefined,
        CENSYS_API_SECRET: document.getElementById("key-censys-secret").value.trim() || undefined,
        HIBP_API_KEY: document.getElementById("key-hibp").value.trim() || undefined,
      };
      try {
        await apiPost("/api/config/keys", payload);
        showToast("OSINT API keys updated", "success");
      } catch (e) {
        showToast(`Error updating keys: ${e.message}`, "error");
      }
    });
  }

  window.addEventListener("DOMContentLoaded", initApp);
})();
