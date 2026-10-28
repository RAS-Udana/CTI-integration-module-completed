
function anomalyDecisionBadge(isAnomaly) {
  return isAnomaly
    ? '<span class="badge badge--enforce">ANOMALY</span>'
    : '<span class="badge badge--discard">normal</span>';
}

function sourceBadge(source) {
  return source === "simulated"
    ? '<span class="badge badge--pending">simulated</span>'
    : '<span class="badge badge--inbound">live</span>';
}

async function loadHealthAndStats() {
  let health;
  try {
    health = await CTI.fetchJSON("/api/anomaly/health");
  } catch (e) {
    document.getElementById("server-warning").style.display = "block";
    document.getElementById("server-warning").innerHTML = `
      <div class="panel panel__body">
        <span class="badge badge--enforce">unreachable</span>
        <span style="color:var(--text-dim); font-size:12px; margin-left:8px;">
          Could not reach the anomaly server. Check ANOMALY_SERVER_URL and that monitor.py is running.
        </span>
      </div>`;
    document.getElementById("kpi-model-status").textContent = "unreachable";
    return;
  }

  const warningEl = document.getElementById("server-warning");
  if (!health.ready) {
    warningEl.style.display = "block";
    warningEl.innerHTML = `
      <div class="panel panel__body">
        <span class="badge badge--enforce">model not loaded</span>
        <span style="color:var(--text-dim); font-size:12px; margin-left:8px;">${CTI.escapeHtml(health.load_error || "unknown error")}</span>
      </div>`;
  } else if (!health.normal_reference_loaded) {
    warningEl.style.display = "block";
    warningEl.innerHTML = `
      <div class="panel panel__body">
        <span class="badge badge--pending">degraded normal-sampling</span>
        <span style="color:var(--text-dim); font-size:12px; margin-left:8px;">${CTI.escapeHtml(health.normal_reference_warning || "normal_reference.pkl not loaded — simulated normal traffic may score as anomalies")}</span>
      </div>`;
  } else {
    warningEl.style.display = "none";
  }

  document.getElementById("kpi-model-status").textContent = health.ready ? "ready" : "not ready";
  document.getElementById("kpi-model-status").className = "kpi__value " + (health.ready ? "ok" : "crit");
  document.getElementById("kpi-model-sub").textContent = `${health.num_features} features`;
  document.getElementById("kpi-threshold").textContent = health.threshold != null ? health.threshold.toFixed(5) : "—";

  const stats = await CTI.fetchJSON("/api/anomaly/stats");
  document.getElementById("kpi-total").textContent = stats.total_scored ?? "—";
  const bySource = (stats.by_source || []).map(s => `${s.source}: ${s.c}`).join(", ");
  document.getElementById("kpi-total-sub").textContent = bySource || "no events yet";
  document.getElementById("kpi-rate").textContent = stats.anomaly_rate != null ? (stats.anomaly_rate * 100).toFixed(1) + "%" : "—";

  const offenders = document.getElementById("offenders-body");
  const rows = stats.top_offending_features || [];
  offenders.innerHTML = rows.length
    ? rows.map(r => `<tr><td>${CTI.escapeHtml(r.feature)}</td><td class="mono num">${r.times_top_contributor}</td></tr>`).join("")
    : `<tr><td colspan="2" class="empty-state">No anomalies detected yet</td></tr>`;
}

async function loadRecent() {
  const filter = document.getElementById("events-filter").value;
  let body;
  try {
    body = await CTI.fetchJSON(`/api/anomaly/recent?limit=30&source=${filter}`);
  } catch (e) {
    return;
  }
  const el = document.getElementById("events-body");
  const events = body.events || [];
  if (events.length === 0) {
    el.innerHTML = `<tr><td colspan="5" class="empty-state">No events yet — try running a simulation</td></tr>`;
    return;
  }
  el.innerHTML = events.map(ev => {
    const top = (ev.top_features && ev.top_features[0]) || null;
    return `
      <tr>
        <td class="mono" style="color:var(--text-dim);">${CTI.fmtTime(ev.ts)}</td>
        <td>${sourceBadge(ev.source)}${ev.sim_mode ? ` <span style="color:var(--text-faint); font-size:11px;">(${ev.sim_mode})</span>` : ""}</td>
        <td class="mono num" style="color:${ev.is_anomaly ? "var(--crit)" : "var(--text)"}">${ev.mse.toFixed(5)}</td>
        <td>${anomalyDecisionBadge(ev.is_anomaly)}</td>
        <td class="mono" style="color:var(--text-dim); font-size:12px;">${top ? `${CTI.escapeHtml(top.feature)} (${top.pct_of_total}%)` : "—"}</td>
      </tr>
    `;
  }).join("");
}

async function refreshAll() {
  await Promise.all([loadHealthAndStats(), loadRecent()]);
}

document.getElementById("btn-simulate").addEventListener("click", async () => {
  const btn = document.getElementById("btn-simulate");
  const resultEl = document.getElementById("sim-result");
  const mode = document.getElementById("sim-mode").value;
  const count = parseInt(document.getElementById("sim-count").value, 10) || 10;
  const magnitude = parseFloat(document.getElementById("sim-magnitude").value) || 4;

  btn.textContent = "Simulating…";
  btn.disabled = true;
  resultEl.textContent = "";

  try {
    const res = await fetch("/api/anomaly/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode, count, magnitude }),
    });
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<span style="color:var(--crit);">${CTI.escapeHtml(data.error || "simulation failed")}</span>`;
    } else {
      resultEl.innerHTML = `Generated ${data.count}, ${data.anomalies_generated} flagged as anomaly.` +
        (data.degraded_normal_sampling_warning ? `<br><span style="color:var(--warn);">degraded normal-sampling in effect</span>` : "");
      await refreshAll();
    }
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${CTI.escapeHtml(String(e))}</span>`;
  } finally {
    btn.textContent = "Run Simulation";
    btn.disabled = false;
  }
});

refreshAll().catch(e => console.warn(e));
setInterval(refreshAll, 15000);
document.getElementById("events-filter").addEventListener("change", loadRecent);
