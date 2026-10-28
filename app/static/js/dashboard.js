
function severityColor(sev) {
  // interpolate: low severity -> dim green/gray, high -> crit red, mid -> amber
  if (sev >= 0.75) return "#ff5c5c";
  if (sev >= 0.45) return "#f5a623";
  if (sev >= 0.2) return "#e8c15a";
  return "#5fb890";
}

async function loadKPIs() {
  const s = await CTI.fetchJSON("/api/stats");
  document.getElementById("kpi-total").textContent = s.total_requests.toLocaleString();
  document.getElementById("kpi-total-24h").textContent = `${s.total_requests_24h.toLocaleString()} in last 24h`;
  document.getElementById("kpi-flagged").textContent = s.flagged_requests.toLocaleString();
  document.getElementById("kpi-io").textContent = `${s.inbound_requests} / ${s.outbound_requests}`;
  document.getElementById("kpi-pending").textContent = s.pending_scoring.toLocaleString();
  document.getElementById("kpi-pending-sub").textContent = `queue depth: ${s.scoring_queue_depth}`;

  const tf = document.getElementById("top-flagged-body");
  if (s.top_flagged.length === 0) {
    tf.innerHTML = `<tr><td colspan="3" class="empty-state">No flagged IOCs yet</td></tr>`;
  } else {
    tf.innerHTML = s.top_flagged.map(f => `
      <tr>
        <td><a class="mono" href="/ioc/${encodeURIComponent(f.ioc_value)}">${CTI.escapeHtml(f.ioc_value)}</a></td>
        <td class="num">${f.hits}</td>
        <td class="num" style="color:${CTI.scoreColor(f.score)}">${CTI.fmtScore(f.score)}</td>
      </tr>
    `).join("");
  }
}

async function loadLiveFeed() {
  const data = await CTI.fetchJSON("/api/requests?per_page=15");
  const body = document.getElementById("live-feed-body");
  if (data.requests.length === 0) {
    body.innerHTML = `<tr><td colspan="6" class="empty-state">Waiting for traffic…</td></tr>`;
    return;
  }
  body.innerHTML = data.requests.map(r => `
    <tr>
      <td class="mono" style="color:var(--text-dim);">${CTI.fmtTime(r.ts)}</td>
      <td>${CTI.directionBadge(r.direction)}</td>
      <td><a class="mono" href="/ioc/${encodeURIComponent(r.ioc_value || '')}">${CTI.escapeHtml(r.ioc_value || (r.src_ip + " → " + r.dst_ip))}</a></td>
      <td class="mono" style="color:var(--text-dim);">${r.request_type || r.protocol || "—"}</td>
      <td class="num" style="color:${CTI.scoreColor(r.score)}">${CTI.fmtScore(r.score)}</td>
      <td>${CTI.decisionBadge(r.decision)}</td>
    </tr>
  `).join("");
}

async function loadLadder() {
  const data = await CTI.fetchJSON("/api/mitre");
  const ladder = document.getElementById("ladder");
  const legend = document.getElementById("ladder-legend");
  const meta = document.getElementById("ladder-meta");

  const total = data.categories.reduce((acc, c) => acc + c.severity, 0);
  ladder.innerHTML = data.categories.map(c => {
    const widthPct = (c.severity / total * 100).toFixed(2);
    const color = severityColor(c.severity);
    return `<div class="ladder__seg" style="width:${widthPct}%; background:${color};" title="${c.category} — severity ${c.severity.toFixed(3)} (raw group count: ${c.raw_count})">${c.category}</div>`;
  }).join("");

  legend.innerHTML = data.categories.map(c => `
    <div class="ladder-legend__item">
      <span class="ladder-legend__swatch" style="background:${severityColor(c.severity)}"></span>
      ${c.category} <span style="color:var(--text-faint)">${c.severity.toFixed(3)}</span>
    </div>
  `).join("");

  meta.textContent = `ATT&CK Enterprise v${data.bundle.attack_bundle_version} · derived ${new Date(data.bundle.derived_at).toLocaleDateString()} · ${data.bundle.method}`;
}

async function refreshAll() {
  await Promise.all([
    loadKPIs().catch(e => console.warn(e)),
    loadLiveFeed().catch(e => console.warn(e)),
  ]);
}

document.addEventListener("DOMContentLoaded", () => {
  refreshAll();
  loadLadder().catch(e => console.warn(e));
  setInterval(refreshAll, 4000);
});
