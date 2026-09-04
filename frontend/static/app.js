/**
 * Supabase Health Inspector - Frontend Controller (vanilla JS)
 * Zero frameworks, zero bundlers. Clean fetch calls and direct DOM updates.
 */

// API Base URL (Supports direct FastAPI or proxied Express endpoints)
const API_BASE = window.location.origin;

// State
let currentConnectionId = "11111111-1111-1111-1111-111111111111";
let activePollInterval = null;
let currentChatSessionId = "22222222-2222-2222-2222-222222222222";

// ------------------------------------------------------------------
// Auth: token storage and authenticated fetch
// ------------------------------------------------------------------
const TOKEN_KEY = "shi_access_token";

function getToken() {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch (e) {
    return null; // private mode / storage disabled
  }
}

function setToken(token) {
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
  } catch (e) {
    console.warn("Could not persist access token:", e);
  }
}

function clearToken() {
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch (e) {
    /* nothing to clear */
  }
}

/**
 * Supabase redirects a magic link back with the token in the URL fragment
 * (#access_token=...). Capture it, hand it to /auth/callback so the backend can
 * verify it and set the HTTP-only session cookie, then strip it from the address
 * bar so the token is not left sitting in history.
 */
async function captureTokenFromUrl() {
  const hash = window.location.hash || "";
  if (!hash.includes("access_token=")) return false;

  const token = new URLSearchParams(hash.slice(1)).get("access_token");
  if (!token) return false;

  setToken(token);
  try {
    await fetch(`${API_BASE}/auth/callback?access_token=${encodeURIComponent(token)}`, {
      credentials: "include",
    });
  } catch (e) {
    console.warn("Session cookie exchange failed:", e);
  }
  history.replaceState(null, "", window.location.pathname + window.location.search);
  return true;
}

/**
 * fetch() with the bearer token attached and 401 handled in one place.
 * `credentials: include` also sends the session cookie, so either auth path works.
 */
async function apiFetch(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });

  if (res.status === 401) {
    clearToken();
    if (!window.location.pathname.startsWith("/login")) {
      window.location.href = "/login?expired=1";
    }
    throw new Error("Not authenticated. Sign in to continue.");
  }
  return res;
}

// ------------------------------------------------------------------
// Active target label (real connection, not a hardcoded string)
// ------------------------------------------------------------------
async function loadActiveTarget() {
  const label = document.getElementById("activeTargetLabel");
  if (!label) return;

  try {
    const res = await apiFetch("/connections");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const connections = await res.json();
    const active =
      connections.find((c) => c.id === currentConnectionId) || connections[0];
    if (!active) {
      label.textContent = "No target registered";
      return;
    }
    currentConnectionId = active.id;
    label.textContent = `${active.label} (${active.db_user}@${active.host})`;
  } catch (err) {
    label.textContent = "Target unavailable";
  }
}

// Utility: Format date
function formatDate(isoStr) {
  if (!isoStr) return "-";
  const d = new Date(isoStr);
  return d.toLocaleTimeString() + " " + d.toLocaleDateString();
}

// Utility: Escape HTML
function escapeHtml(str) {
  if (typeof str !== "string") str = JSON.stringify(str, null, 2) || "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ------------------------------------------------------------------
// Auth Handlers (Magic Link)
// ------------------------------------------------------------------
async function handleMagicLinkSubmit(event) {
  event.preventDefault();
  const emailInput = document.getElementById("magicEmail");
  const statusBox = document.getElementById("authStatusMsg");
  const submitBtn = document.getElementById("magicSubmitBtn");

  if (!emailInput || !emailInput.value) return;

  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Sending...';
  statusBox.style.display = "none";

  try {
    const res = await fetch(`${API_BASE}/auth/magic-link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: emailInput.value.trim() }),
    });

    const data = await res.json();
    statusBox.style.display = "block";
    if (res.ok) {
      // Deliberately no redirect. Dispatching a magic link does not create a
      // session -- that happens when the emailed link returns to /auth/callback
      // and the JWT verifies. Bouncing to the dashboard here would imply a
      // sign-in that has not occurred.
      statusBox.className = "inspection-banner";
      statusBox.innerHTML = `${escapeHtml(data.message)} Open the link in that email to complete sign-in.`;
    } else {
      statusBox.className = "severity-badge severity-critical";
      statusBox.style.width = "100%";
      statusBox.innerHTML = `Error: ${escapeHtml(data.detail || "Failed to dispatch magic link")}`;
    }
  } catch (err) {
    statusBox.style.display = "block";
    statusBox.className = "severity-badge severity-critical";
    statusBox.innerHTML = `Network error: ${escapeHtml(err.message)}`;
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = "Send Magic Link";
  }
}

// ------------------------------------------------------------------
// Dashboard & Full Diagnostic Sweep (with 2-second Polling)
// ------------------------------------------------------------------
async function triggerFullScan() {
  const runBtn = document.getElementById("runSweepBtn");
  const sweepStatus = document.getElementById("sweepStatus");

  if (runBtn) {
    runBtn.disabled = true;
    runBtn.innerHTML = '<span class="spinner"></span> Running Diagnostics...';
  }

  if (sweepStatus) {
    sweepStatus.innerHTML = '<span class="mono" style="color: var(--text-mono);">Running 5 diagnostics against the target database...</span>';
  }

  try {
    const res = await apiFetch(`/scans/${currentConnectionId}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });

    if (!res.ok) {
      throw new Error(`Server returned HTTP ${res.status}`);
    }

    const scan = await res.json();
    renderScanResults(scan);

    // If status is running, initiate 2s poll
    if (scan.status === "running") {
      pollScanProgress(scan.id);
    } else {
      if (sweepStatus) {
        sweepStatus.innerHTML = sweepStatusHtml(scan);
      }
      if (runBtn) {
        runBtn.disabled = false;
        runBtn.innerHTML = "Run Full Sweep";
      }
    }
  } catch (err) {
    if (sweepStatus) {
      sweepStatus.innerHTML = `<span class="mono" style="color: var(--severity-critical-text);">Sweep failed: ${escapeHtml(err.message)}</span>`;
    }
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.innerHTML = "Run Full Sweep";
    }
  }
}

function pollScanProgress(scanId) {
  if (activePollInterval) clearInterval(activePollInterval);

  activePollInterval = setInterval(async () => {
    try {
      const res = await apiFetch(`/scans/${scanId}`);
      if (!res.ok) return;

      const scan = await res.json();
      renderScanResults(scan);

      if (scan.status !== "running") {
        clearInterval(activePollInterval);
        activePollInterval = null;
        const runBtn = document.getElementById("runSweepBtn");
        const sweepStatus = document.getElementById("sweepStatus");
        if (runBtn) {
          runBtn.disabled = false;
          runBtn.innerHTML = "Run Full Sweep";
        }
        if (sweepStatus) {
          sweepStatus.innerHTML = sweepStatusHtml(scan);
        }
      }
    } catch (e) {
      console.warn("Polling retry error:", e);
    }
  }, 2000);
}

// Whether a run was written to the control plane is part of the result, not a
// detail to hide: an in-memory-only run disappears on restart.
function sweepStatusHtml(scan) {
  const stored = scan.persisted
    ? '<span style="color: var(--accent-supabase);">saved to control plane</span>'
    : '<span style="color: var(--severity-warning-text);">not persisted (in-memory only)</span>';
  return `<span class="mono" style="color: var(--accent-supabase);">Sweep complete ${formatDate(scan.completed_at)}</span>
          <span class="mono" style="color: var(--text-secondary);"> &bull; ${stored}</span>`;
}

function renderScanResults(scan) {
  const container = document.getElementById("moduleCardsContainer");
  if (!container || !scan.results) return;

  const moduleTitles = {
    vacuum_wraparound: "1. Vacuum & XID Wraparound",
    rls_debug: "2. RLS Security & Policy Debugger",
    connection_health: "3. Connection Pool & Idle Transactions",
    storage_audit: "4. Storage Buckets & Object Policies",
    slow_queries: "5. Slow Queries (pg_stat_statements)",
  };

  const html = scan.results
    .map((res) => {
      const title = moduleTitles[res.module] || res.module;
      const severityClass = `severity-${res.severity || "info"}`;
      const rawJson = escapeHtml(JSON.stringify(res.raw_result, null, 2));

      return `
      <div class="card" id="card-${res.module}">
        <div class="card-header">
          <div class="card-title">
            <span class="mono">${title}</span>
          </div>
          <span class="severity-badge ${severityClass}">
            ${res.severity || "info"}
          </span>
        </div>

        <div class="card-summary">
          <strong>Summary:</strong> ${escapeHtml(res.summary)}
        </div>

        ${
          res.ai_explanation
            ? `
          <div class="ai-box">
            <div class="ai-box-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
              ${escapeHtml(res.ai_provider || "model")} narration &mdash; verify against the result below
            </div>
            ${escapeHtml(res.ai_explanation)}
          </div>
        `
            : `
          <div class="mono" style="font-size: 0.72rem; color: var(--text-muted); margin-top: 4px;">
            AI narration unavailable &mdash; the diagnostic result above is unaffected.
          </div>
        `
        }

        <details>
          <summary class="mono" style="cursor: pointer; font-size: 0.75rem; color: var(--text-secondary); margin-top: 4px;">
            View Structured Query Result (JSON)
          </summary>
          <pre class="raw-code-block" style="margin-top: 6px;"><code>${rawJson}</code></pre>
        </details>
      </div>
    `;
    })
    .join("");

  container.innerHTML = html;
}

// ------------------------------------------------------------------
// RLS Debugger Tester (The Centerpiece)
// ------------------------------------------------------------------
async function handleRLSTestSubmit(event) {
  event.preventDefault();
  const tableInput = document.getElementById("rlsTableName");
  const resultContainer = document.getElementById("rlsResultContainer");
  const submitBtn = document.getElementById("rlsSubmitBtn");

  if (!tableInput) return;

  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Inspecting policy metadata...';

  try {
    const res = await apiFetch("/rls-debug", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        connection_id: currentConnectionId,
        table_name: tableInput.value.trim(),
      }),
    });

    const data = await res.json();

    // An error body carries `detail`, not the result fields. Rendering it as a
    // result produced "Target: public." with no table name and "undefinedms".
    if (!res.ok) {
      renderRLSError(res.status, data.detail);
      return;
    }

    renderRLSResult(data);
  } catch (err) {
    if (resultContainer) {
      resultContainer.innerHTML = `
        <div class="card">
          <div class="severity-badge severity-critical">Error</div>
          <p style="color: var(--severity-critical-text);">${escapeHtml(err.message)}</p>
        </div>
      `;
    }
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = "Inspect RLS Policies";
  }
}

/**
 * Populates the quick-select buttons from the target's real public schema, so the
 * tool only ever offers tables that exist on the database it is pointed at.
 */
async function loadTargetTables() {
  const row = document.getElementById("tableButtonRow");
  const input = document.getElementById("rlsTableName");
  if (!row) return;

  try {
    const res = await apiFetch("/target/tables");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const tables = await res.json();

    if (!tables.length) {
      row.innerHTML =
        '<span class="mono" style="font-size: 0.75rem; color: var(--severity-warning-text);">No base tables in the target\'s public schema.</span>';
      return;
    }

    row.innerHTML = "";
    tables.forEach((name, i) => {
      const btn = document.createElement("button");
      btn.className = "btn btn-sm";
      btn.textContent = `Inspect '${name}'`;
      btn.addEventListener("click", () => {
        if (input) input.value = name;
      });
      row.appendChild(btn);
      if (i === 0 && input && !input.value) input.value = name;
    });
  } catch (err) {
    row.innerHTML = `<span class="mono" style="font-size: 0.75rem; color: var(--severity-critical-text);">Could not load table list: ${escapeHtml(
      err.message
    )}</span>`;
  }
}

function renderRLSError(statusCode, detail) {
  const container = document.getElementById("rlsResultContainer");
  if (!container) return;
  container.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div class="card-title"><span>Inspection could not run</span></div>
        <span class="severity-badge severity-warning">HTTP ${statusCode}</span>
      </div>
      <p style="font-size: 0.85rem;">${escapeHtml(detail || "No detail provided.")}</p>
    </div>
  `;
}

function renderRLSResult(data) {
  const container = document.getElementById("rlsResultContainer");
  if (!container) return;

  const policiesList = (data.policies_found || [])
    .map(
      (p) => `
      <tr>
        <td><strong>${escapeHtml(p.policyname)}</strong></td>
        <td>${escapeHtml(p.cmd)}</td>
        <td>${escapeHtml((p.roles || []).join(", ") || "ALL")}</td>
        <td class="mono" style="color: var(--text-mono);">${escapeHtml(p.qual || "-")}</td>
      </tr>
    `
    )
    .join("");

  const planJson = escapeHtml(JSON.stringify(data.plan, null, 2));

  // Which connection produced the data-shape findings decides what this result is
  // allowed to claim, so it is stated on the face of the card rather than buried.
  const sourceLabels = {
    not_run: "Data-shape checks did not run",
    read_only: "Data-shape checks ran via the read-only connection",
    elevated: "Data-shape checks ran via the opt-in elevated connection",
  };
  const shapeSource = data.data_shape_source || "not_run";
  const shapeRan = shapeSource !== "not_run";

  // Mirrors RowVisibilityEnum. The two zero-row states are different problems and
  // must not share a label: "no policy targets this role" is a property of the
  // connection, while "RLS filtered" means a policy ran and excluded these rows.
  const visibilityLabels = {
    no_privilege: "No SELECT privilege",
    no_policy_applies: "No policy targets this role",
    rls_filtered: "SELECT granted, 0 rows visible (RLS filtered)",
    readable: `${data.readable_rows_count} row(s) visible`,
    unknown: "SELECT granted, read not completed",
  };
  const readStatus =
    visibilityLabels[data.row_visibility] || "Row visibility unknown";

  const issuesHtml = (data.detected_issues || []).length
    ? `<ul style="margin: 0.25rem 0 0 1rem; padding: 0; font-size: 0.8rem;">
         ${data.detected_issues.map((i) => `<li style="margin-bottom: 0.3rem;">${escapeHtml(i)}</li>`).join("")}
       </ul>`
    : `<p class="mono" style="font-size: 0.8rem; color: var(--text-secondary);">No findings recorded.</p>`;

  container.innerHTML = `
    <div class="inspection-banner">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span>Catalog metadata &amp; query plan only &bull; ${escapeHtml(sourceLabels[shapeSource] || shapeSource)} &bull; ${data.execution_time_ms}ms</span>
    </div>

    <div class="card" style="margin-bottom: 1rem;">
      <div class="card-header">
        <div class="card-title">
          <span>Target: public.${escapeHtml(data.table_name)}</span>
        </div>
        <span class="severity-badge ${shapeRan ? "severity-ok" : "severity-warning"}">
          ${escapeHtml(readStatus)}
        </span>
      </div>

      <div style="margin-top: 0.5rem;">
        <h4 style="font-size: 0.85rem; margin-bottom: 0.25rem;">Findings (${(data.detected_issues || []).length})</h4>
        ${issuesHtml}
      </div>

      <div class="ai-box">
        <!-- Written by the backend from the catalog findings. The /rls-debug
             endpoint does not call Gemini, so labelling this as an AI verdict
             would credit an analysis that never ran. -->
        <div class="ai-box-title">Inspector Verdict</div>
        ${escapeHtml(data.ai_explanation)}
      </div>

      <div style="margin-top: 0.5rem;">
        <h4 style="font-size: 0.85rem; margin-bottom: 0.25rem;">Active Policies on Table (${data.policies_found?.length || 0})</h4>
        ${
          data.policies_found && data.policies_found.length > 0
            ? `
          <table class="tech-table">
            <thead>
              <tr>
                <th>Policy Name</th>
                <th>Command</th>
                <th>Roles</th>
                <th>USING Clause (Filter)</th>
              </tr>
            </thead>
            <tbody>${policiesList}</tbody>
          </table>
        `
            : `<p class="mono" style="color: var(--severity-warning-text); font-size: 0.8rem;">No RLS policies defined on this table (default deny applies for the authenticated role).</p>`
        }
      </div>

      <details style="margin-top: 0.5rem;">
        <summary class="mono" style="cursor: pointer; font-size: 0.75rem; color: var(--text-secondary);">
          View Full EXPLAIN (VERBOSE, FORMAT JSON) Plan
        </summary>
        <pre class="raw-code-block" style="margin-top: 6px;"><code>${planJson}</code></pre>
      </details>
    </div>
  `;
}

// ------------------------------------------------------------------
// Function-Calling Assistant (Chat UI + Tool Traces)
// ------------------------------------------------------------------
async function handleChatSubmit(event) {
  event.preventDefault();
  const input = document.getElementById("chatInput");
  const messagesBox = document.getElementById("chatMessages");
  const submitBtn = document.getElementById("chatSubmitBtn");

  if (!input || !input.value.trim()) return;

  const userText = input.value.trim();
  input.value = "";

  // Append user bubble
  appendChatBubble("user", userText);

  // Loading assistant placeholder
  const placeholderId = "msg-loading-" + Date.now();
  appendChatBubble("assistant", '<span class="spinner"></span> Inspecting target database and evaluating tool calls...', [], placeholderId);

  submitBtn.disabled = true;

  try {
    const res = await apiFetch(`/chat/${currentChatSessionId}/message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: userText,
        connection_id: currentConnectionId,
      }),
    });

    const data = await res.json();
    const loadingElem = document.getElementById(placeholderId);
    if (loadingElem) loadingElem.remove();

    if (!res.ok) {
      // Surface the server's reason. Rendering data.content here would print
      // "undefined", since an error body carries `detail`, not `content`.
      appendChatBubble(
        "assistant",
        `<strong>Request failed (HTTP ${res.status}).</strong> ${escapeHtml(
          data.detail || "No detail provided."
        )}`
      );
      return;
    }

    // Name the provider that answered, so a deterministic fallback is never
    // mistaken for a model's reasoning.
    const badge =
      data.provider && data.provider !== "none"
        ? `<div class="mono" style="font-size: 0.68rem; color: var(--text-muted); margin-bottom: 4px;">answered by ${escapeHtml(
            data.provider
          )}</div>`
        : `<div class="mono" style="font-size: 0.68rem; color: var(--severity-warning-text); margin-bottom: 4px;">no LLM answered &mdash; deterministic routing</div>`;

    appendChatBubble("assistant", badge + escapeHtml(data.content), data.tool_calls || []);
  } catch (err) {
    const loadingElem = document.getElementById(placeholderId);
    if (loadingElem) loadingElem.remove();
    appendChatBubble("assistant", `Error executing diagnostic query: ${escapeHtml(err.message)}`);
  } finally {
    submitBtn.disabled = false;
    input.focus();
  }
}

function appendChatBubble(role, content, toolCalls = [], elementId = null) {
  const container = document.getElementById("chatMessages");
  if (!container) return;

  const bubble = document.createElement("div");
  bubble.className = `chat-bubble chat-${role}`;
  if (elementId) bubble.id = elementId;

  let toolHtml = "";
  if (toolCalls && toolCalls.length > 0) {
    toolHtml = toolCalls
      .map((tc, idx) => {
        const traceId = `trace-${Date.now()}-${idx}`;
        return `
        <div class="tool-trace" id="${traceId}">
          <div class="tool-trace-header" onclick="document.getElementById('${traceId}').classList.toggle('open')">
            <span>Tool executed: <strong>${escapeHtml(tc.tool_name)}</strong></span>
            <span>▶ Click to inspect arguments and full result</span>
          </div>
          <div class="tool-trace-body">
            <div style="margin-bottom: 4px; color: var(--text-secondary);">Arguments: <code class="mono">${escapeHtml(JSON.stringify(tc.arguments))}</code></div>
            <pre class="raw-code-block"><code>${escapeHtml(JSON.stringify(tc.result, null, 2))}</code></pre>
          </div>
        </div>
      `;
      })
      .join("");
  }

  bubble.innerHTML = `
    ${toolHtml}
    <div>${content}</div>
  `;

  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
}

// ------------------------------------------------------------------
// Reports (persisted scan runs from the control plane)
// ------------------------------------------------------------------
const MODULE_TITLES = {
  vacuum_wraparound: "Vacuum & XID Wraparound",
  rls_debug: "Row Level Security",
  connection_health: "Connection Health",
  storage_audit: "Storage Audit",
  slow_queries: "Slow Queries",
};

const SEVERITY_ORDER = ["critical", "warning", "info", "ok"];

function severityBadge(sev) {
  return `<span class="severity-badge severity-${escapeHtml(sev)}">${escapeHtml(sev)}</span>`;
}

async function loadReportsIndex() {
  const container = document.getElementById("reportsContainer");
  if (!container) return;

  try {
    const res = await apiFetch("/api/reports");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    if (!data.length) {
      container.innerHTML = `<div class="card"><p>No scan runs are stored yet. Run a sweep from the dashboard and it will appear here.</p></div>`;
      return;
    }

    const rows = data
      .map((r) => {
        const when = formatDate(r.started_at);
        const target = r.target_label || r.target_connection_id;
        const host = r.target_host ? `<span class="mono" style="color: var(--text-muted); font-size: 0.72rem;">${escapeHtml(r.target_host)}</span>` : "";
        return `
        <tr>
          <td class="mono"><a href="/reports/${escapeHtml(r.id)}">${escapeHtml(when)}</a></td>
          <td>${escapeHtml(target)}<br>${host}</td>
          <td>${r.worst_severity ? severityBadge(r.worst_severity) : "-"}</td>
          <td class="mono">${r.module_count}</td>
          <td class="mono">${escapeHtml(r.status)}</td>
          <td><a class="btn btn-sm" href="/reports/${escapeHtml(r.id)}">View report &rarr;</a></td>
        </tr>`;
      })
      .join("");

    container.innerHTML = `
      <div class="card">
        <table class="tech-table">
          <thead>
            <tr><th>Started</th><th>Target connection</th><th>Worst severity</th><th>Modules</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch (err) {
    container.innerHTML = `<div class="card"><div class="severity-badge severity-critical">Error</div><p>${escapeHtml(err.message)}</p></div>`;
  }
}

function renderFinding(f) {
  const affectedRows = Object.entries(f.affected || {})
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="mono">${escapeHtml(v)}</td></tr>`)
    .join("");

  const observations = (f.observations || []).length
    ? `<div style="margin-top: 0.75rem;">
         <h4 style="font-size: 0.8rem; margin-bottom: 0.25rem;">Observations</h4>
         <ul style="margin: 0 0 0 1rem; padding: 0; font-size: 0.8rem;">
           ${f.observations.map((o) => `<li style="margin-bottom: 0.3rem;">${escapeHtml(o)}</li>`).join("")}
         </ul>
       </div>`
    : "";

  // Narration is displayed apart from every computed field and labelled unverified,
  // so it can never be mistaken for a diagnostic conclusion.
  const narration = f.ai_explanation
    ? `<details style="margin-top: 0.75rem;">
         <summary class="mono" style="cursor: pointer; font-size: 0.72rem; color: var(--text-secondary);">
           Narration &mdash; ${escapeHtml(f.ai_provider || "model")} &mdash; UNVERIFIED
         </summary>
         <div class="ai-box" style="margin-top: 6px;">
           <div class="ai-box-title">Generated commentary, not a diagnostic conclusion</div>
           ${escapeHtml(f.ai_explanation)}
         </div>
       </details>`
    : `<div class="mono" style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.6rem;">No narration was recorded for this finding.</div>`;

  return `
    <div class="card" style="margin-bottom: 1rem;">
      <div class="card-header">
        <div class="card-title"><span class="mono">${escapeHtml(MODULE_TITLES[f.module] || f.module)}</span></div>
        ${severityBadge(f.severity)}
      </div>

      <div class="card-summary"><strong>Verdict:</strong> ${escapeHtml(f.summary)}</div>

      ${
        affectedRows
          ? `<div style="margin-top: 0.75rem;">
               <h4 style="font-size: 0.8rem; margin-bottom: 0.25rem;">Affected object</h4>
               <table class="tech-table"><tbody>${affectedRows}</tbody></table>
             </div>`
          : ""
      }

      ${
        f.probable_cause
          ? `<div style="margin-top: 0.75rem;">
               <h4 style="font-size: 0.8rem; margin-bottom: 0.25rem;">Probable cause
                 <span class="mono" style="font-weight: normal; color: var(--text-muted); font-size: 0.7rem;">&mdash; computed from the diagnostic data</span>
               </h4>
               <p style="font-size: 0.85rem; margin: 0;">${escapeHtml(f.probable_cause)}</p>
             </div>`
          : ""
      }

      ${
        f.scope_caveat
          ? `<div style="margin-top: 0.75rem;">
               <h4 style="font-size: 0.8rem; margin-bottom: 0.25rem;">Scope of this check</h4>
               <p style="font-size: 0.82rem; margin: 0; color: var(--severity-warning-text);">${escapeHtml(f.scope_caveat)}</p>
             </div>`
          : ""
      }

      ${observations}
      ${narration}

      <details style="margin-top: 0.6rem;">
        <summary class="mono" style="cursor: pointer; font-size: 0.72rem; color: var(--text-secondary);">Raw query result</summary>
        <pre class="raw-code-block" style="margin-top: 6px;"><code>${escapeHtml(JSON.stringify(f.raw_result, null, 2))}</code></pre>
      </details>
    </div>`;
}

async function loadReport() {
  const container = document.getElementById("reportContainer");
  if (!container) return;

  const id = window.location.pathname.split("/").filter(Boolean).pop();
  const exportBtn = document.getElementById("exportMdBtn");
  if (exportBtn) exportBtn.href = `/api/reports/${id}/export.md`;

  try {
    const res = await apiFetch(`/api/reports/${id}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    const run = data.run;
    const subtitle = document.getElementById("reportSubtitle");
    if (subtitle) {
      subtitle.innerHTML = `${escapeHtml(run.target_label || "unknown target")} <span class="mono" style="color: var(--text-muted);">${escapeHtml(run.target_host || "")}</span> &bull; started ${escapeHtml(formatDate(run.started_at))} &bull; ${run.module_count} module(s)`;
    }

    const counts = SEVERITY_ORDER.filter((s) => data.severity_counts[s])
      .map((s) => `${severityBadge(s)} <span class="mono">${data.severity_counts[s]}</span>`)
      .join(" &nbsp; ");

    // Grouped by severity, worst first -- the server already sorted them.
    let html = counts ? `<div class="card" style="margin-bottom: 1rem;">${counts}</div>` : "";
    let current = null;
    data.findings.forEach((f) => {
      if (f.severity !== current) {
        current = f.severity;
        html += `<h2 style="font-size: 0.95rem; margin: 1.25rem 0 0.5rem;">${escapeHtml(current.toUpperCase())}</h2>`;
      }
      html += renderFinding(f);
    });

    container.innerHTML = html || `<div class="card"><p>This run recorded no findings.</p></div>`;
  } catch (err) {
    container.innerHTML = `<div class="card"><div class="severity-badge severity-critical">Error</div><p>${escapeHtml(err.message)}</p></div>`;
  }
}

// ------------------------------------------------------------------
// LLM provider toggle (Gemini / Ollama / none)
// ------------------------------------------------------------------
function renderProviderStatuses(data) {
  const select = document.getElementById("providerSelect");
  const status = document.getElementById("providerStatus");
  const detail = document.getElementById("providerDetail");
  if (!select || !status || !detail) return;

  select.value = data.selected;
  // Record what the server reports so a restored-then-fired change event can be
  // recognised as a no-op rather than pushing a switch nobody asked for.
  select.dataset.previous = data.selected;

  // Availability is probed live, so "configured" and "available" can disagree --
  // which is exactly what a rejected API key looks like. Show both.
  const parts = (data.providers || []).map((p) => {
    const state = p.available ? "available" : p.configured ? "configured, not responding" : "not configured";
    return `${p.name}: ${state}`;
  });
  status.innerHTML = `Selection: <strong>${escapeHtml(data.selected)}</strong> (${escapeHtml(
    data.source
  )}) &bull; ${escapeHtml(parts.join(" | "))}`;

  detail.innerHTML = (data.providers || [])
    .map((p) => `<div>${escapeHtml(p.name)}${p.model ? ` (${escapeHtml(p.model)})` : ""}: ${escapeHtml(p.detail)}</div>`)
    .join("");
}

async function loadProviders() {
  const status = document.getElementById("providerStatus");
  if (!status) return;
  try {
    const res = await apiFetch("/assistant/providers");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderProviderStatuses(await res.json());
  } catch (err) {
    status.textContent = `Could not load provider status: ${err.message}`;
  }
}

async function handleProviderChange(event) {
  const select = event.target;
  const status = document.getElementById("providerStatus");
  const previous = select.dataset.previous || "auto";

  // Nothing actually changed -- don't push a switch to the server.
  if (select.value === previous) return;

  select.disabled = true;
  if (status) status.textContent = "Switching provider...";

  try {
    const res = await apiFetch("/assistant/provider", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider: select.value }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    renderProviderStatuses(data);
    select.dataset.previous = select.value;
  } catch (err) {
    select.value = previous; // the switch did not take; do not show it as if it did
    if (status) status.textContent = `Switch failed: ${err.message}`;
  } finally {
    select.disabled = false;
  }
}

// ------------------------------------------------------------------
// Global Setup & Init
// ------------------------------------------------------------------
/** Shows whether this browser currently holds a token, and offers a sign-out. */
function renderAuthState() {
  const box = document.getElementById("authStateBox");
  if (!box) return;

  const token = getToken();
  if (!token) {
    const expired = new URLSearchParams(window.location.search).has("expired");
    box.innerHTML = expired
      ? '<span class="severity-badge severity-warning">Session expired or rejected &mdash; sign in again</span>'
      : '<span class="mono" style="color: var(--text-secondary);">Not signed in. Requests use demo access unless the server runs with ENVIRONMENT=production.</span>';
    return;
  }

  let subject = "unknown";
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    subject = payload.email || payload.sub || "unknown";
  } catch (e) {
    /* leave as unknown */
  }
  box.innerHTML = `
    <span class="severity-badge severity-ok">Signed in as ${escapeHtml(subject)}</span>
    <button id="signOutBtn" class="btn btn-sm" style="margin-left: 0.5rem;">Sign out</button>`;
  const btn = document.getElementById("signOutBtn");
  if (btn) {
    btn.addEventListener("click", () => {
      clearToken();
      window.location.href = "/login";
    });
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  // A magic-link return carries the token in the fragment; consume it before
  // anything else fires an authenticated request.
  await captureTokenFromUrl();
  renderAuthState();
  loadActiveTarget();

  // Bind magic link form
  const magicForm = document.getElementById("magicLinkForm");
  if (magicForm) magicForm.addEventListener("submit", handleMagicLinkSubmit);

  // Bind RLS test form
  const rlsForm = document.getElementById("rlsTestForm");
  if (rlsForm) {
    rlsForm.addEventListener("submit", handleRLSTestSubmit);
    loadTargetTables();
  }

  // Bind Chat form
  const chatForm = document.getElementById("chatForm");
  if (chatForm) chatForm.addEventListener("submit", handleChatSubmit);

  // Reports pages
  if (document.getElementById("reportsContainer")) loadReportsIndex();
  if (document.getElementById("reportContainer")) loadReport();

  // Bind LLM provider toggle
  const providerSelect = document.getElementById("providerSelect");
  if (providerSelect) {
    providerSelect.addEventListener("change", handleProviderChange);
    loadProviders();
  }

  // Bind Run Sweep button
  const sweepBtn = document.getElementById("runSweepBtn");
  if (sweepBtn) sweepBtn.addEventListener("click", triggerFullScan);

  // Auto trigger dashboard initial sweep if on dashboard
  if (document.getElementById("moduleCardsContainer")) {
    triggerFullScan();
  }
});
