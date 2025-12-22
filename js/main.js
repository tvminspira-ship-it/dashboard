// /js/main.js

// Tabs must be global because HTML uses onclick=""
window.showTab = function showTab(tabName, btn) {
  document.querySelectorAll(".content-section").forEach((s) => s.classList.remove("active"));
  document.querySelectorAll(".tab-button").forEach((b) => b.classList.remove("active"));
  document.getElementById(tabName + "-tab").classList.add("active");
  btn.classList.add("active");
};

// Colors
const chartColors = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#f59e0b",
  low: "#3b82f6",
  open: "#ef4444",
  closed: "#10b981",
  purple: "#8b5cf6",
  cyan: "#06b6d4",
  emerald: "#10b981",
};

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];
const SEVERITY_RANK = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1, Unknown: 0 };

// -------------------------
// Robust parsing helpers
// -------------------------
function detectDelimiter(headerLine) {
  return headerLine.includes("\t") ? "\t" : "spaces";
}

function splitLine(line, delimiter) {
  if (delimiter === "\t") return line.split("\t");
  return line.trim().split(/ {2,}/g); // 2+ spaces
}

function normalizeLinesHandlingQuotes(raw) {
  // Fix multiline quoted cells (e.g., API UAT Outbound URLs).
  const baseLines = (raw || "").split(/\r?\n/);
  const merged = [];

  let buf = "";
  let quoteCount = 0;

  for (const ln of baseLines) {
    const line = ln ?? "";
    const q = (line.match(/"/g) || []).length;

    if (!buf) {
      buf = line;
      quoteCount = q;
    } else {
      // if inside open quote -> join with a space (keep as one record)
      buf += (quoteCount % 2 === 1 ? " " : "\n") + line;
      quoteCount += q;
    }

    if (quoteCount % 2 === 0) {
      if (buf.trim().length) merged.push(buf);
      buf = "";
      quoteCount = 0;
    }
  }

  if (buf.trim().length) merged.push(buf);
  return merged;
}

// -------------------------
// TSV parser (with carry-forward)
// -------------------------
function parseTSV(tsv) {
  const lines0 = normalizeLinesHandlingQuotes(tsv).filter((l) => l.trim().length > 0);
  if (lines0.length < 2) return [];

  const delimiter = detectDelimiter(lines0[0]);
  const header = splitLine(lines0[0], delimiter).map((h) => h.trim());

  const rows = [];

  // carry-forward values inside each application block
  let lastApp = "";
  let lastUrl = "";
  let lastTestingDate = "";
  let lastClosingDate = "";
  let lastReportedDate = "";
  let lastAgeing = "";
  let lastOwner = "";

  for (let i = 1; i < lines0.length; i++) {
    const cols = splitLine(lines0[i], delimiter);

    const get = (name) => {
      const idx = header.indexOf(name);
      if (idx < 0) return "";
      return (cols[idx] ?? "").trim();
    };

    const appCell = get("Application Name");
    const urlCell = get("Testing URL");

    const app = appCell || lastApp;
    const url = urlCell || lastUrl;

    if (appCell) {
      // new app block => reset carry-forwards for that app
      lastApp = app;
      lastUrl = urlCell || lastUrl;

      lastTestingDate = "";
      lastClosingDate = "";
      lastReportedDate = "";
      lastAgeing = "";
      lastOwner = "";
    } else {
      lastUrl = url;
    }

    const status = (get("Status") || get("Status ") || "").trim();
    const observation = get("Security observation") || "";

    // Severity
    let severity = "Unknown";
    for (const s of SEVERITY_ORDER) {
      const v = get(s);
      if (v === "1") { severity = s; break; }
    }

    // Carry-forward columns (accuracy)
    const testingPerformedDate =
      (get("Testing performed date") || get("Testing performed date ")) || lastTestingDate;

    const closingDate =
      (get("Closing Date") || get("Revlidation Date") || get("Revlidation Date ")) || lastClosingDate;

    const reportedDate =
      (get("Vulnerability Reported Date") || get("Vulnerability Reported Date ")) || lastReportedDate;

    const ageingStr =
      (get("Vulnerability Ageing") || get("Vulnerability Ageing ")) || lastAgeing;

    const owner =
      (get("Owner") || get("Owner ")) || lastOwner;

    if (testingPerformedDate) lastTestingDate = testingPerformedDate;
    if (closingDate) lastClosingDate = closingDate;
    if (reportedDate) lastReportedDate = reportedDate;
    if (ageingStr) lastAgeing = ageingStr;
    if (owner) lastOwner = owner;

    const ageingNum = ageingStr ? Number(ageingStr) : null;

    rows.push({
      app,
      url,
      status,
      observation,
      severity,
      testingPerformedDate,
      closingDate,
      reportedDate,
      ageing: Number.isFinite(ageingNum) ? ageingNum : null,
      owner,
    });
  }

  return rows;
}

// -------------------------
// SLA helpers
// -------------------------
function parseDateFlexible(d) {
  // Accepts: 5/5/2025 or 05/05/2025
  if (!d) return null;
  const s = String(d).trim();
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (!m) return null;
  const mm = Number(m[1]);
  const dd = Number(m[2]);
  const yyyy = Number(m[3]);
  const dt = new Date(yyyy, mm - 1, dd);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

function daysBetween(d1, d2) {
  const ms = d2.getTime() - d1.getTime();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

function getSlaDays(severity) {
  if (severity === "Critical") return 3;
  if (severity === "High") return 7;
  if (severity === "Medium") return 30;
  if (severity === "Low" || severity === "Informational") return 90;
  return null;
}

function computeAgeFromReportedOrFallback(row) {
  const rep = parseDateFlexible(row.reportedDate);
  if (rep) return Math.max(0, daysBetween(rep, new Date()));
  if (typeof row.ageing === "number" && !Number.isNaN(row.ageing)) return row.ageing;
  return null;
}

// -------------------------
// Stats (stores vulnerabilities per app for dropdown)
// -------------------------
function computeDomainStats(rows) {
  const stats = {
    total: rows.length,
    open: rows.filter((r) => (r.status || "").toLowerCase() === "open").length,
    closed: rows.filter((r) => (r.status || "").toLowerCase() === "closed").length,
    severity: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0, Unknown: 0 },
    apps: new Map(),
  };

  for (const r of rows) {
    stats.severity[r.severity] = (stats.severity[r.severity] ?? 0) + 1;

    if (!stats.apps.has(r.app)) {
      stats.apps.set(r.app, {
        app: r.app,
        url: r.url,
        total: 0,
        highestSeverity: "Unknown",
        highestSeverityRank: 0,
        maxAge: null,
        _ageSum: 0,
        _ageCount: 0,
        vulns: [],
      });
    }

    const a = stats.apps.get(r.app);
    a.total += 1;

    a.vulns.push({
      observation: r.observation || "—",
      severity: r.severity || "Unknown",
      status: r.status || "—",
      reportedDate: r.reportedDate || "",
      ageing: r.ageing,
    });

    const rank = SEVERITY_RANK[r.severity] ?? 0;
    if (rank > a.highestSeverityRank) {
      a.highestSeverityRank = rank;
      a.highestSeverity = r.severity;
    }

    if (typeof r.ageing === "number" && !Number.isNaN(r.ageing)) {
      a._ageSum += r.ageing;
      a._ageCount += 1;
      a.maxAge = a.maxAge === null ? r.ageing : Math.max(a.maxAge, r.ageing);
    }
  }

  return stats;
}

// -------------------------
// Aging (OPEN only) + SLA breached + overdue + per-domain counts
// -------------------------
function computeAgingOpenStats(rows) {
  const openRows = rows
    .filter(r => String(r.status).toLowerCase() === "open")
    .map(r => {
      const ageNow = computeAgeFromReportedOrFallback(r);
      const sla = getSlaDays(r.severity);
      const breached = (ageNow !== null && sla !== null) ? (ageNow > sla) : false;
      const overdue = breached ? (ageNow - sla) : 0;
      return { ...r, ageNow, sla, breached, overdue };
    })
    .filter(r => r.ageNow !== null);

  const severityLabels = ["Critical", "High", "Medium", "Low", "Informational"];
  const domains = ["Web", "API", "Mobile"];

  const sevTotal = Object.fromEntries(severityLabels.map(s => [s, 0]));
  const sevBreached = Object.fromEntries(severityLabels.map(s => [s, 0]));

  const domTotal = Object.fromEntries(domains.map(d => [d, 0]));
  const domBreached = Object.fromEntries(domains.map(d => [d, 0]));

  for (const r of openRows) {
    if (sevTotal[r.severity] !== undefined) {
      sevTotal[r.severity]++;
      if (r.breached) sevBreached[r.severity]++;
    }
    if (domTotal[r.domain] !== undefined) {
      domTotal[r.domain]++;
      if (r.breached) domBreached[r.domain]++;
    }
  }

  const breachedOnly = openRows.filter(r => r.breached);

  const ages = openRows.map(r => r.ageNow);
  const oldest = ages.length ? Math.max(...ages) : null;
  const newest = ages.length ? Math.min(...ages) : null;
  const avg = ages.length ? Math.round(ages.reduce((a,b)=>a+b,0)/ages.length) : null;

  const topOldestOpen = [...openRows].sort((a, b) => b.ageNow - a.ageNow).slice(0, 10);

  return {
    openRows,
    breachedOnly,
    oldest, newest, avg,
    severityLabels,
    sevTotal,
    sevBreached,
    domains,
    domTotal,
    domBreached,
    topOldestOpen
  };
}

// -------------------------
// UI helpers
// -------------------------
function severityBadgeHTML(sev) {
  const cls =
    sev === "Critical" ? "badge-severity-critical" :
    sev === "High" ? "badge-severity-high" :
    sev === "Medium" ? "badge-severity-medium" :
    sev === "Low" ? "badge-severity-low" :
    "badge-severity-info";
  return `<span class="badge ${cls}">${sev}</span>`;
}

function ageBadgeHTML(age) {
  const cls =
    age >= 151 ? "badge-age-critical" :
    age >= 101 ? "badge-age-warning" :
    age >= 61  ? "badge-age-moderate" :
    "badge-age-good";
  return `<span class="badge ${cls}">${age} days</span>`;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// -------------------------
// Render Domain Tabs with dropdown + SLA on OPEN
// -------------------------
function renderDomainTab(tabId, stats, { mediumCard = true, highCard = false, showSla = false } = {}) {
  const tab = document.getElementById(tabId);
  const summaryValues = tab.querySelectorAll(".summary-value");

  if (summaryValues[0]) summaryValues[0].textContent = stats.total;
  if (summaryValues[1]) summaryValues[1].textContent = stats.open;
  if (summaryValues[2]) summaryValues[2].textContent = stats.closed;

  if (summaryValues[3]) {
    if (highCard) summaryValues[3].textContent = stats.severity.High || 0;
    else if (mediumCard) summaryValues[3].textContent = stats.severity.Medium || 0;
    else summaryValues[3].textContent = "0";
  }

  const tbody = tab.querySelector("table.data-table tbody");
  tbody.innerHTML = "";

  const appsSorted = Array.from(stats.apps.values()).sort((a, b) => b.total - a.total);

  appsSorted.forEach((a, idx) => {
    const detailsId = `${tabId}-details-${idx}`;
    const age = a.maxAge;

    const trMain = document.createElement("tr");
    trMain.innerHTML = `
      <td class="app-name">
        <button class="app-toggle" type="button" data-target="${detailsId}">
          <span class="caret">▸</span>
          ${a.url ? `<a href="${a.url}" target="_blank" rel="noopener noreferrer">${escapeHtml(a.app)}</a>` : escapeHtml(a.app)}
        </button>
      </td>
      <td>${a.total}</td>
      <td>${age === null ? `<span class="badge badge-age-moderate">—</span>` : ageBadgeHTML(age)}</td>
      <td>${severityBadgeHTML(a.highestSeverity)}</td>
    `;

    const trDetails = document.createElement("tr");
    trDetails.id = detailsId;
    trDetails.className = "details-row";
    trDetails.innerHTML = `
      <td colspan="4">
        <div class="details-box">
          <div class="details-title">Vulnerabilities (${a.vulns.length})</div>
          <ul class="vuln-list">
            ${a.vulns.map(v => {
              const isOpen = String(v.status).toLowerCase() === "open";

              const ageNow = (showSla && isOpen)
                ? computeAgeFromReportedOrFallback(v)
                : null;

              const sla = (showSla && isOpen)
                ? getSlaDays(v.severity)
                : null;

              const breached = (showSla && isOpen && ageNow !== null && sla !== null && ageNow > sla);

              return `
                <li class="vuln-item">
                  <span class="vuln-name">${escapeHtml(v.observation)}</span>
                  <span class="vuln-meta">
                    ${severityBadgeHTML(v.severity)}
                    <span class="status-pill ${isOpen ? "status-open" : "status-closed"}">${escapeHtml(v.status)}</span>

                    ${showSla && isOpen ? `
                      <span class="age-pill">Age: ${ageNow === null ? "—" : ageNow + "d"}</span>
                      <span class="sla-pill ${breached ? "sla-breached" : "sla-ok"}">
                        SLA: ${sla === null ? "—" : sla + "d"} ${breached ? "BREACHED" : "OK"}
                      </span>
                    ` : ``}
                  </span>
                </li>
              `;
            }).join("")}
          </ul>
        </div>
      </td>
    `;

    tbody.appendChild(trMain);
    tbody.appendChild(trDetails);
  });

  // Attach click handler ONCE for this tab (event delegation)
  if (!tbody.dataset.dropdownBound) {
    tbody.dataset.dropdownBound = "1";
    tbody.addEventListener("click", (e) => {
      const btn = e.target.closest(".app-toggle");
      if (!btn) return;

      const targetId = btn.getAttribute("data-target");
      const row = document.getElementById(targetId);
      if (!row) return;

      const isOpen = row.classList.toggle("open");
      const caret = btn.querySelector(".caret");
      if (caret) caret.textContent = isOpen ? "▾" : "▸";
    });
  }
}

// -------------------------
// Aging Tab rendering (Open only + optional breached-only filter)
// -------------------------
function renderAgingTab(agingOpen, showOnlyBreached) {
  // Top numbers
  const oldestEl = document.getElementById("aging-oldest");
  const avgEl = document.getElementById("aging-avg");
  const newestEl = document.getElementById("aging-newest");

  if (oldestEl) oldestEl.textContent = agingOpen.oldest ?? "—";
  if (avgEl) avgEl.textContent = agingOpen.avg ?? "—";
  if (newestEl) newestEl.textContent = agingOpen.newest ?? "—";

  // SLA breached summary cards
  const webEl = document.getElementById("sla-web");
  const apiEl = document.getElementById("sla-api");
  const mobileEl = document.getElementById("sla-mobile");

  if (webEl) webEl.textContent = agingOpen.domBreached.Web || 0;
  if (apiEl) apiEl.textContent = agingOpen.domBreached.API || 0;
  if (mobileEl) mobileEl.textContent = agingOpen.domBreached.Mobile || 0;

  // Table
  const tab = document.getElementById("aging-tab");
  const tbody = tab.querySelector("table.data-table tbody");
  tbody.innerHTML = "";

  const allowedSev = new Set(["Critical", "High", "Medium"]);
  const baseRows0 = showOnlyBreached ? agingOpen.breachedOnly : agingOpen.openRows;

  const rows = baseRows0
    .filter(r => allowedSev.has(r.severity))
    .sort((a, b) => b.ageNow - a.ageNow); // ✅ ALL rows, no slice

  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="app-name">${escapeHtml(r.app)} - ${escapeHtml(r.observation)}</td>
      <td>${escapeHtml(r.domain)}</td>
      <td>
        ${ageBadgeHTML(r.ageNow)}
        <span class="sla-pill ${r.breached ? "sla-breached" : "sla-ok"}">
          SLA ${r.sla ?? "—"}d ${r.breached ? "BREACHED" : "OK"}
        </span>
      </td>
      <td>${severityBadgeHTML(r.severity)}</td>
      <td>${r.breached ? `<span class="overdue-pill">${r.overdue} days</span>` : "—"}</td>
    `;
    tbody.appendChild(tr);
  }
}




// -------------------------
// Top metrics
// -------------------------
function renderTopMetrics(webStats, apiStats, mobileStats, agingOpen) {
  const total = webStats.total + apiStats.total + mobileStats.total;
  const open = webStats.open + apiStats.open + mobileStats.open;
  const closed = webStats.closed + apiStats.closed + mobileStats.closed;
  const resolutionRate = total ? ((closed / total) * 100).toFixed(1) + "%" : "0%";

  const metricValues = document.querySelectorAll(".metrics-grid .metric-value");
  if (metricValues[0]) metricValues[0].textContent = total;
  if (metricValues[1]) metricValues[1].textContent = open;
  if (metricValues[2]) metricValues[2].textContent = closed;
  if (metricValues[3]) metricValues[3].textContent = resolutionRate;

  // Show OPEN average age (more meaningful with SLA)
  if (metricValues[4]) metricValues[4].textContent = agingOpen.avg ?? "—";
}

// -------------------------
// Chart helpers
// -------------------------
function safeDestroyChart(chart) {
  if (chart && typeof chart.destroy === "function") chart.destroy();
}

// -------------------------
// Init + Charts
// -------------------------
document.addEventListener("DOMContentLoaded", () => {
  const webTSV = window.VM_DATA?.webTSV || "";
  const apiTSV = window.VM_DATA?.apiTSV || "";
  const mobileTSV = window.VM_DATA?.mobileTSV || "";

  const webRows = parseTSV(webTSV).map((r) => ({ ...r, domain: "Web" }));
  const apiRows = parseTSV(apiTSV).map((r) => ({ ...r, domain: "API" }));
  const mobileRows = parseTSV(mobileTSV).map((r) => ({ ...r, domain: "Mobile" }));

  const webStats = computeDomainStats(webRows);
  const apiStats = computeDomainStats(apiRows);
  const mobileStats = computeDomainStats(mobileRows);

  // SLA enabled for Web, API, Mobile dropdowns
  renderDomainTab("web-tab", webStats, { mediumCard: true, showSla: true });
  renderDomainTab("api-tab", apiStats, { mediumCard: true, showSla: true });
  renderDomainTab("mobile-tab", mobileStats, { mediumCard: false, highCard: true, showSla: true });

  const allRows = [...webRows, ...apiRows, ...mobileRows];
  const agingOpen = computeAgingOpenStats(allRows);

  // Initial render of aging tab (show all open)
  let showOnlyBreached = false;
  renderAgingTab(agingOpen, showOnlyBreached);

  // Toggle: breached only
  const toggle = document.getElementById("slaOnlyToggle");
  if (toggle) {
    toggle.addEventListener("change", (e) => {
      showOnlyBreached = !!e.target.checked;
      renderAgingTab(agingOpen, showOnlyBreached);
      refreshAgingCharts();
    });
  }

  renderTopMetrics(webStats, apiStats, mobileStats, agingOpen);

  // -------------------------
  // Overview charts (unchanged)
  // -------------------------
  const totalSeverity = (s) =>
    (webStats.severity[s] || 0) + (apiStats.severity[s] || 0) + (mobileStats.severity[s] || 0);

  new Chart(document.getElementById("severityChart").getContext("2d"), {
    type: "bar",
    data: {
      labels: ["Web", "API", "Mobile"],
      datasets: [
        { label: "Critical", data: [webStats.severity.Critical||0, apiStats.severity.Critical||0, mobileStats.severity.Critical||0], backgroundColor: chartColors.critical },
        { label: "High", data: [webStats.severity.High||0, apiStats.severity.High||0, mobileStats.severity.High||0], backgroundColor: chartColors.high },
        { label: "Medium", data: [webStats.severity.Medium||0, apiStats.severity.Medium||0, mobileStats.severity.Medium||0], backgroundColor: chartColors.medium },
        { label: "Low", data: [webStats.severity.Low||0, apiStats.severity.Low||0, mobileStats.severity.Low||0], backgroundColor: chartColors.low },
      ],
    },
    options: { responsive: true, maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true } } },
  });

  new Chart(document.getElementById("statusChart").getContext("2d"), {
    type: "bar",
    data: {
      labels: ["Web", "API", "Mobile"],
      datasets: [
        { label: "Open", data: [webStats.open, apiStats.open, mobileStats.open], backgroundColor: chartColors.open },
        { label: "Closed", data: [webStats.closed, apiStats.closed, mobileStats.closed], backgroundColor: chartColors.closed },
      ],
    },
    options: { responsive: true, maintainAspectRatio: false },
  });

  new Chart(document.getElementById("severityPieChart").getContext("2d"), {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [totalSeverity("Critical"), totalSeverity("High"), totalSeverity("Medium"), totalSeverity("Low")],
        backgroundColor: [chartColors.critical, chartColors.high, chartColors.medium, chartColors.low],
      }],
    },
    options: { responsive: true, maintainAspectRatio: false },
  });

  new Chart(document.getElementById("domainPieChart").getContext("2d"), {
    type: "doughnut",
    data: {
      labels: ["Web Applications", "API", "Mobile"],
      datasets: [{
        data: [webStats.total, apiStats.total, mobileStats.total],
        backgroundColor: [chartColors.purple, chartColors.cyan, chartColors.emerald],
      }],
    },
    options: { responsive: true, maintainAspectRatio: false },
  });

  // -------------------------
  // Aging charts (open only + toggle affects dataset)
  // -------------------------
  let ageRangeChartInstance = null;
  let ageDomainChartInstance = null;

  function refreshAgingCharts() {
    const baseRows = showOnlyBreached ? agingOpen.breachedOnly : agingOpen.openRows;

    // recompute per severity/domain from filtered set
    const severityLabels = ["Critical", "High", "Medium", "Low", "Informational"];
    const domains = ["Web", "API", "Mobile"];

    const sevTotal = Object.fromEntries(severityLabels.map(s => [s, 0]));
    const sevBreached = Object.fromEntries(severityLabels.map(s => [s, 0]));
    const domTotal = Object.fromEntries(domains.map(d => [d, 0]));
    const domBreached = Object.fromEntries(domains.map(d => [d, 0]));

    for (const r of baseRows) {
      if (sevTotal[r.severity] !== undefined) {
        sevTotal[r.severity]++;
        if (r.breached) sevBreached[r.severity]++;
      }
      if (domTotal[r.domain] !== undefined) {
        domTotal[r.domain]++;
        if (r.breached) domBreached[r.domain]++;
      }
    }

    // Severity chart: Within SLA vs Breached
    safeDestroyChart(ageRangeChartInstance);
    ageRangeChartInstance = new Chart(document.getElementById("ageRangeChart").getContext("2d"), {
      type: "bar",
      data: {
        labels: severityLabels,
        datasets: [
          {
            label: showOnlyBreached ? "Open (Breached)" : "Open (Within SLA)",
            data: severityLabels.map(s => showOnlyBreached ? sevBreached[s] : (sevTotal[s] - sevBreached[s])),
          },
          ...(showOnlyBreached ? [] : [{
            label: "Open (SLA Breached)",
            data: severityLabels.map(s => sevBreached[s]),
          }]),
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
        plugins: { legend: { position: "bottom" } },
      },
    });

    // Domain chart: Within SLA vs Breached
    safeDestroyChart(ageDomainChartInstance);
    ageDomainChartInstance = new Chart(document.getElementById("ageDomainChart").getContext("2d"), {
      type: "bar",
      data: {
        labels: domains,
        datasets: [
          {
            label: showOnlyBreached ? "Open (Breached)" : "Open (Within SLA)",
            data: domains.map(d => showOnlyBreached ? domBreached[d] : (domTotal[d] - domBreached[d])),
          },
          ...(showOnlyBreached ? [] : [{
            label: "Open (SLA Breached)",
            data: domains.map(d => domBreached[d]),
          }]),
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
        plugins: { legend: { position: "bottom" } },
      },
    });
  }

  // initial chart render
  refreshAgingCharts();
});
