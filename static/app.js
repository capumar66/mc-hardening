"use strict";

(() => {
  let currentReport = null;
  let historyItems = [];

  const VIEW_TITLES = {
    overview: "Panoramica Sicurezza",
    checks: "Controlli CIS & Lynis",
    logs: "Log & Minacce",
    ports: "Porte & Servizi in Ascolto",
    history: "Storico Scansioni",
  };

  const STATUS_LABELS = { pass: "OK", warn: "Avviso", fail: "Critico", info: "Info" };
  const SEVERITY_LABELS = { high: "Alta", medium: "Media", low: "Bassa", info: "Info" };
  const EXPOSURE_LABELS = {
    public: { text: "Pubblica", cls: "pill-warn" },
    vpn_or_private: { text: "Privata / VPN", cls: "pill-info" },
    local: { text: "Solo locale", cls: "pill-pass" },
  };
  const EVENT_LABELS = {
    ssh_failed: { text: "SSH Fallito", cls: "pill-fail" },
    ssh_invalid_user: { text: "Utente Invalido", cls: "pill-warn" },
    ssh_accepted: { text: "SSH OK", cls: "pill-pass" },
    sudo: { text: "Sudo", cls: "pill-info" },
  };

  function getAuthHeaders() {
    const token = new URLSearchParams(window.location.search).get("token");
    return token ? { "X-Audit-Token": token } : {};
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clearNode(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function renderEmptyRow(tbody, colspan, msg) {
    clearNode(tbody);
    const tr = el("tr");
    const td = el("td", "empty-cell", msg);
    td.colSpan = colspan;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  function formatTs(iso) {
    if (!iso) return "--";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("it-IT");
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ---- Two-state dark mode toggle (per dark-mode-toggle guide) ---- */
  function getSystemScheme() {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function readStoredScheme() {
    try {
      const val = localStorage.getItem("color-scheme");
      return val === "light" || val === "dark" ? val : null;
    } catch {
      return null;
    }
  }

  function applySchemeMeta(stored) {
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.content = stored ?? "light dark";
  }

  function toggleTheme() {
    const system = getSystemScheme();
    const currentRendered = readStoredScheme() ?? system;
    const target = currentRendered === "dark" ? "light" : "dark";

    try {
      if (target === system) {
        localStorage.removeItem("color-scheme");
        applySchemeMeta(null);
      } else {
        localStorage.setItem("color-scheme", target);
        applySchemeMeta(target);
      }
    } catch {
      applySchemeMeta(target);
    }
  }

  window.addEventListener("storage", (e) => {
    if (e.key === "color-scheme") {
      applySchemeMeta(readStoredScheme());
    }
  });

  /* ---- Navigation ---- */
  function switchView(viewName) {
    document.querySelectorAll(".nav-item").forEach((btn) => {
      const active = btn.dataset.view === viewName;
      btn.classList.toggle("is-active", active);
      btn.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll(".view-panel").forEach((panel) => {
      panel.hidden = panel.dataset.viewPanel !== viewName;
    });
    document.getElementById("view-title").textContent = VIEW_TITLES[viewName] || "Console";
  }

  /* ---- Renderers ---- */
  function renderOverview(report) {
    document.getElementById("sidebar-host").textContent = report.hostname || "server";
    const priv = report.is_root ? "root" : "non-root";
    document.getElementById("host-meta").textContent =
      `${report.os_info} · Kernel ${report.kernel} · Privilegi: ${priv}`;
    document.getElementById("generated-at").textContent = `Aggiornato: ${formatTs(report.generated_at)}`;
    document.getElementById("mode-badge").hidden = !report.demo_mode;

    const banner = document.getElementById("alert-banner");
    if (report.demo_mode) {
      banner.hidden = false;
      banner.textContent =
        "Modalità DEMO attiva (Ubuntu 24.04 LTS di esempio). Copia il progetto sul server Ubuntu e avvialo con sudo per l'audit reale.";
    } else if (!report.is_linux) {
      banner.hidden = false;
      banner.textContent =
        "Ambiente non Linux rilevato: i controlli Ubuntu completi sono attivi solo sul server Linux (usa --demo sul Mac per l'anteprima).";
    } else if (!report.is_root) {
      banner.hidden = false;
      banner.textContent =
        "Esecuzione senza privilegi root: alcuni controlli (sshd -T, ufw, auth.log, processi ss) possono risultare parziali. Avvia con sudo.";
    } else {
      banner.hidden = true;
    }

    // Score ring (circumference 2 * pi * 34 ≈ 213.6)
    const score = Number(report.score || 0);
    const circ = 213.6;
    const fg = document.getElementById("score-ring-fg");
    fg.style.strokeDashoffset = String(circ * (1 - score / 100));
    fg.style.stroke = score >= 80 ? "var(--pass)" : score >= 55 ? "var(--warn)" : "var(--fail)";
    document.getElementById("score-value").textContent = String(score);

    const sum = report.summary || {};
    document.getElementById("count-pass").textContent = sum.pass ?? 0;
    document.getElementById("count-warn").textContent = sum.warn ?? 0;
    document.getElementById("count-fail").textContent = sum.fail ?? 0;

    const issuesCount = (sum.fail ?? 0) + (sum.warn ?? 0);
    document.getElementById("nav-count-issues").textContent = String(issuesCount);

    const logs = report.logs || {};
    const failedTotal = (logs.failed_ssh_attempts ?? 0) + (logs.invalid_user_attempts ?? 0);
    document.getElementById("ov-failed-ssh").textContent = String(failedTotal);
    document.getElementById("ov-ufw-blocks").textContent = String(logs.ufw_blocks ?? 0);
    document.getElementById("ov-accepted-ssh").textContent = String(logs.accepted_ssh_logins ?? 0);
    document.getElementById("nav-count-logs").textContent = String(failedTotal);

    const ports = report.listening_ports || [];
    const pubPorts = ports.filter((p) => p.exposure === "public").length;
    document.getElementById("ov-public-ports").textContent = String(pubPorts);
    document.getElementById("nav-count-ports").textContent = String(ports.length);

    // Category breakdown bars
    const catMap = new Map();
    for (const c of report.checks || []) {
      if (!catMap.has(c.category)) catMap.set(c.category, { pass: 0, total: 0 });
      const entry = catMap.get(c.category);
      entry.total += 1;
      if (c.status === "pass") entry.pass += 1;
    }

    const catContainer = document.getElementById("category-bars");
    clearNode(catContainer);
    for (const [cat, stats] of catMap.entries()) {
      const pct = Math.round((stats.pass / stats.total) * 100);
      const row = el("div", "cat-row");
      const head = el("div", "cat-row-head");
      head.appendChild(el("span", null, cat));
      head.appendChild(el("span", null, `${stats.pass}/${stats.total} OK (${pct}%)`));
      row.appendChild(head);

      const track = el("div", "cat-track");
      const fill = el("div", "cat-fill");
      fill.style.inlineSize = `${pct}%`;
      fill.style.background = pct >= 80 ? "var(--pass)" : pct >= 50 ? "var(--warn)" : "var(--fail)";
      track.appendChild(fill);
      row.appendChild(track);
      catContainer.appendChild(row);
    }

    // Top priority list (fails first, then warns)
    const prioList = document.getElementById("priority-list");
    clearNode(prioList);
    const prioritized = (report.checks || [])
      .filter((c) => c.status === "fail" || c.status === "warn")
      .sort((a, b) => (a.status === "fail" ? -1 : 1) - (b.status === "fail" ? -1 : 1))
      .slice(0, 6);

    if (prioritized.length === 0) {
      prioList.appendChild(el("li", "priority-item", "Nessuna criticità aperta rilevata."));
    } else {
      for (const item of prioritized) {
        const li = el("li", "priority-item");
        const left = el("div");
        left.appendChild(el("strong", null, item.title));
        left.appendChild(el("small", null, `${item.category}${item.benchmark ? " · " + item.benchmark : ""}`));
        li.appendChild(left);
        li.appendChild(el("span", `pill pill-${item.status}`, STATUS_LABELS[item.status] || item.status));
        prioList.appendChild(li);
      }
    }
  }

  function populateCategoryFilter(checks) {
    const select = document.getElementById("filter-category");
    const prev = select.value;
    const cats = Array.from(new Set(checks.map((c) => c.category))).sort();
    clearNode(select);
    const allOpt = el("option", null, "Tutte le categorie");
    allOpt.value = "all";
    select.appendChild(allOpt);
    for (const cat of cats) {
      const opt = el("option", null, cat);
      opt.value = cat;
      select.appendChild(opt);
    }
    if (cats.includes(prev)) select.value = prev;
  }

  function renderChecksTable() {
    const tbody = document.getElementById("checks-tbody");
    if (!currentReport) return;

    const status = document.getElementById("filter-status").value;
    const category = document.getElementById("filter-category").value;
    const q = document.getElementById("filter-search").value.trim().toLowerCase();

    const filtered = (currentReport.checks || []).filter((item) => {
      if (status !== "all" && item.status !== status) return false;
      if (category !== "all" && item.category !== category) return false;
      if (q) {
        const hay = `${item.title} ${item.category} ${item.benchmark || ""} ${item.details} ${item.remediation || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      renderEmptyRow(tbody, 5, "Nessun controllo corrisponde ai filtri.");
      return;
    }

    clearNode(tbody);
    for (const item of filtered) {
      const tr = el("tr");

      const th = el("th");
      th.scope = "row";
      th.appendChild(document.createTextNode(item.title));
      th.appendChild(el("span", "check-cat", item.category));
      tr.appendChild(th);

      const tdBench = el("td");
      tdBench.appendChild(
        item.benchmark ? el("span", "pill pill-bench", item.benchmark) : el("span", null, "--")
      );
      tr.appendChild(tdBench);

      const tdStatus = el("td");
      tdStatus.appendChild(el("span", `pill pill-${item.status}`, STATUS_LABELS[item.status] || item.status));
      tr.appendChild(tdStatus);

      tr.appendChild(el("td", null, SEVERITY_LABELS[item.severity] || item.severity));

      const tdDet = el("td");
      tdDet.appendChild(el("div", null, item.details));

      if (item.remediation) {
        const rem = el("div", "remediation-box");
        rem.appendChild(el("strong", null, "Rimedio: "));
        rem.appendChild(document.createTextNode(item.remediation));
        tdDet.appendChild(rem);
      }

      if (item.remediation_cmd) {
        const cmdRow = el("div", "cmd-row");
        cmdRow.appendChild(el("code", null, item.remediation_cmd));
        const copyBtn = el("button", "copy-btn", "Copia");
        copyBtn.type = "button";
        copyBtn.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(item.remediation_cmd);
            copyBtn.textContent = "Copiato!";
            setTimeout(() => { copyBtn.textContent = "Copia"; }, 1400);
          } catch {
            copyBtn.textContent = "Seleziona";
          }
        });
        cmdRow.appendChild(copyBtn);
        tdDet.appendChild(cmdRow);
      }

      if (item.evidence) {
        tdDet.appendChild(el("span", "evidence-line", item.evidence));
      }

      tr.appendChild(tdDet);
      tbody.appendChild(tr);
    }
  }

  function renderLogs(logs) {
    document.getElementById("log-sources").textContent =
      logs.sources_checked && logs.sources_checked.length
        ? `Sorgenti analizzate: ${logs.sources_checked.join(", ")}`
        : "Sorgenti analizzate: nessuna";

    const warnBox = document.getElementById("log-warnings");
    if (logs.warnings && logs.warnings.length) {
      warnBox.hidden = false;
      warnBox.textContent = logs.warnings.join(" | ");
    } else {
      warnBox.hidden = true;
    }

    document.getElementById("log-failed-ssh").textContent = logs.failed_ssh_attempts ?? 0;
    document.getElementById("log-invalid-users").textContent = logs.invalid_user_attempts ?? 0;
    document.getElementById("log-accepted-ssh").textContent = logs.accepted_ssh_logins ?? 0;
    document.getElementById("log-sudo").textContent = logs.sudo_commands ?? 0;
    document.getElementById("log-ufw-blocks").textContent = logs.ufw_blocks ?? 0;

    const ipsBody = document.getElementById("top-ips-tbody");
    if (!logs.top_failed_ips || logs.top_failed_ips.length === 0) {
      renderEmptyRow(ipsBody, 2, "Nessun tentativo SSH fallito.");
    } else {
      clearNode(ipsBody);
      for (const r of logs.top_failed_ips) {
        const tr = el("tr");
        const th = el("th", null, r.ip);
        th.scope = "row";
        tr.appendChild(th);
        tr.appendChild(el("td", null, r.count));
        ipsBody.appendChild(tr);
      }
    }

    const blkBody = document.getElementById("top-blocked-tbody");
    if (!logs.top_blocked_ports || logs.top_blocked_ports.length === 0) {
      renderEmptyRow(blkBody, 2, "Nessun blocco UFW rilevato.");
    } else {
      clearNode(blkBody);
      for (const r of logs.top_blocked_ports) {
        const tr = el("tr");
        const th = el("th", null, r.port);
        th.scope = "row";
        tr.appendChild(th);
        tr.appendChild(el("td", null, r.count));
        blkBody.appendChild(tr);
      }
    }

    const evBody = document.getElementById("events-tbody");
    if (!logs.recent_events || logs.recent_events.length === 0) {
      renderEmptyRow(evBody, 4, "Nessun evento recente.");
    } else {
      clearNode(evBody);
      for (const ev of logs.recent_events) {
        const tr = el("tr");
        const th = el("th", null, ev.timestamp || "--");
        th.scope = "row";
        tr.appendChild(th);
        const tdType = el("td");
        const meta = EVENT_LABELS[ev.type] || { text: ev.type, cls: "pill-info" };
        tdType.appendChild(el("span", `pill ${meta.cls}`, meta.text));
        tr.appendChild(tdType);
        tr.appendChild(el("td", null, ev.source || "--"));
        tr.appendChild(el("td", null, ev.summary || ""));
        evBody.appendChild(tr);
      }
    }
  }

  function renderPorts(ports) {
    const tbody = document.getElementById("ports-tbody");
    if (!ports || ports.length === 0) {
      renderEmptyRow(tbody, 5, "Nessun socket in ascolto rilevato (disponibile su Linux via ss).");
      return;
    }
    clearNode(tbody);
    for (const p of ports) {
      const tr = el("tr");
      const th = el("th", null, p.port);
      th.scope = "row";
      tr.appendChild(th);
      tr.appendChild(el("td", null, p.protocol));
      tr.appendChild(el("td", null, p.bind_address));
      tr.appendChild(el("td", null, p.process));
      const tdExp = el("td");
      const meta = EXPOSURE_LABELS[p.exposure] || { text: p.exposure, cls: "pill-info" };
      tdExp.appendChild(el("span", `pill ${meta.cls}`, meta.text));
      tr.appendChild(tdExp);
      tbody.appendChild(tr);
    }
  }

  function renderHistory(scans) {
    historyItems = scans || [];
    document.getElementById("nav-count-history").textContent = String(historyItems.length);
    const tbody = document.getElementById("history-tbody");

    if (historyItems.length === 0) {
      renderEmptyRow(tbody, 5, "Nessuna scansione salvata nello storico.");
      return;
    }

    clearNode(tbody);
    for (const item of historyItems) {
      const tr = el("tr");
      const th = el("th", null, formatTs(item.generated_at));
      th.scope = "row";
      tr.appendChild(th);

      tr.appendChild(el("td", null, item.hostname));

      const tdScore = el("td");
      tdScore.appendChild(el("strong", null, `${item.score}/100 `));
      if (item.delta > 0) {
        tdScore.appendChild(el("span", "pill pill-pass", `+${item.delta}`));
      } else if (item.delta < 0) {
        tdScore.appendChild(el("span", "pill pill-fail", String(item.delta)));
      }
      tr.appendChild(tdScore);

      const s = item.summary || {};
      tr.appendChild(el("td", null, `${s.pass ?? 0} OK · ${s.warn ?? 0} Avvisi · ${s.fail ?? 0} Critici`));

      const tdAct = el("td");
      const loadBtn = el("button", "btn btn-secondary btn-sm", "Apri");
      loadBtn.type = "button";
      loadBtn.addEventListener("click", () => loadHistoryScan(item.id));
      tdAct.appendChild(loadBtn);
      tr.appendChild(tdAct);

      tbody.appendChild(tr);
    }
  }

  function renderAll(report) {
    currentReport = report;
    renderOverview(report);
    populateCategoryFilter(report.checks || []);
    renderChecksTable();
    renderLogs(report.logs || {});
    renderPorts(report.listening_ports || []);
  }

  /* ---- API Calls ---- */
  async function fetchHistory() {
    try {
      const resp = await fetch("/api/history", { headers: getAuthHeaders() });
      if (!resp.ok) return;
      const data = await resp.json();
      renderHistory(data.scans || []);
    } catch {
      // Non-blocking
    }
  }

  async function loadHistoryScan(id) {
    try {
      const resp = await fetch(`/api/history/${id}`, { headers: getAuthHeaders() });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const report = await resp.json();
      renderAll(report);
      switchView("overview");
    } catch (err) {
      const banner = document.getElementById("alert-banner");
      banner.hidden = false;
      banner.textContent = `Impossibile caricare la scansione #${id}: ${err.message}`;
    }
  }

  async function fetchAudit(fresh = false) {
    const btn = document.getElementById("btn-rescan");
    btn.disabled = true;
    btn.textContent = "Analisi…";
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25000);
    try {
      const resp = await fetch(fresh ? "/api/audit/run" : "/api/audit", {
        method: fresh ? "POST" : "GET",
        headers: getAuthHeaders(),
        signal: controller.signal,
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: resp.statusText }));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }
      const data = await resp.json();
      renderAll(data);
      await fetchHistory();
    } catch (err) {
      const banner = document.getElementById("alert-banner");
      banner.hidden = false;
      const msg =
        err.name === "AbortError"
          ? "Timeout scansione (25s): il server non ha risposto in tempo."
          : err.message;
      banner.textContent = `Errore caricamento report: ${msg}`;
    } finally {
      clearTimeout(timer);
      btn.disabled = false;
      btn.textContent = "Nuova scansione";
    }
  }

  /* ---- Exports ---- */
  function exportJson() {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-${currentReport.hostname || "server"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportHtml() {
    if (!currentReport) return;
    const r = currentReport;
    const rows = (r.checks || [])
      .map(
        (c) => `<tr>
          <td><strong>${escapeHtml(c.title)}</strong><br><small>${escapeHtml(c.category)}</small></td>
          <td>${escapeHtml(c.benchmark || "-")}</td>
          <td>${escapeHtml(STATUS_LABELS[c.status] || c.status)}</td>
          <td>${escapeHtml(SEVERITY_LABELS[c.severity] || c.severity)}</td>
          <td>${escapeHtml(c.details)}${c.remediation ? `<br><em>Rimedio:</em> ${escapeHtml(c.remediation)}` : ""}${c.remediation_cmd ? `<br><code>${escapeHtml(c.remediation_cmd)}</code>` : ""}</td>
        </tr>`
      )
      .join("\n");

    const html = `<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8"><title>Report Hardening - ${escapeHtml(r.hostname)}</title>
<style>
  body { font-family: system-ui, sans-serif; color: #111; margin: 2rem; font-size: 13px; }
  h1 { margin-bottom: 0.2rem; } .meta { color: #555; margin-bottom: 1.2rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f3f4f6; } code { font-size: 11px; background: #f3f4f6; padding: 1px 4px; }
</style></head><body>
  <h1>Report Hardening Server: ${escapeHtml(r.hostname)}</h1>
  <div class="meta">${escapeHtml(r.os_info)} · Kernel ${escapeHtml(r.kernel)} · Punteggio: <strong>${escapeHtml(r.score)}/100</strong> · Generato: ${escapeHtml(formatTs(r.generated_at))}</div>
  <table><thead><tr><th>Controllo</th><th>Benchmark</th><th>Stato</th><th>Severità</th><th>Dettagli & Rimedio</th></tr></thead>
  <tbody>${rows}</tbody></table>
</body></html>`;

    const blob = new Blob([html], { type: "text/html; charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-hardening-${r.hostname || "server"}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.view));
    });
    document.getElementById("btn-goto-checks").addEventListener("click", () => switchView("checks"));
    document.getElementById("btn-rescan").addEventListener("click", () => fetchAudit(true));
    document.getElementById("btn-export-json").addEventListener("click", exportJson);
    document.getElementById("btn-export-html").addEventListener("click", exportHtml);
    document.getElementById("btn-theme-toggle").addEventListener("click", toggleTheme);

    document.getElementById("filter-status").addEventListener("change", renderChecksTable);
    document.getElementById("filter-category").addEventListener("change", renderChecksTable);
    document.getElementById("filter-search").addEventListener("input", renderChecksTable);

    fetchAudit(false);
  });
})();
