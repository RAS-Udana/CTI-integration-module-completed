
let currentPage = 1;
let autoRefreshTimer = null;

function buildQuery() {
  const params = new URLSearchParams();
  const q = document.getElementById("f-search").value.trim();
  const direction = document.getElementById("f-direction").value;
  const decision = document.getElementById("f-decision").value;
  const flaggedOnly = document.getElementById("f-flagged-only").checked;

  if (q) params.set("q", q);
  if (direction) params.set("direction", direction);
  if (decision) params.set("decision", decision);
  if (flaggedOnly) params.set("flagged_only", "1");
  params.set("page", currentPage);
  params.set("per_page", 40);
  return params.toString();
}

async function loadRequests() {
  const data = await CTI.fetchJSON(`/api/requests?${buildQuery()}`);
  const body = document.getElementById("req-body");

  if (data.requests.length === 0) {
    body.innerHTML = `<tr><td colspan="8" class="empty-state">No requests match this filter</td></tr>`;
  } else {
    body.innerHTML = data.requests.map(r => `
      <tr>
        <td class="mono" style="color:var(--text-dim); white-space:nowrap;">${CTI.fmtTime(r.ts)}</td>
        <td>${CTI.directionBadge(r.direction)}</td>
        <td><a class="mono" href="/ioc/${encodeURIComponent(r.ioc_value || '')}">${CTI.escapeHtml(r.ioc_value || "—")}</a></td>
        <td class="mono" style="color:var(--text-dim);">${r.request_type || r.protocol || "—"}</td>
        <td class="mono ip">${CTI.escapeHtml(r.src_ip || "—")}${r.src_port ? ":" + r.src_port : ""}</td>
        <td class="mono ip">${CTI.escapeHtml(r.dst_ip || "—")}${r.dst_port ? ":" + r.dst_port : ""}</td>
        <td class="num" style="color:${CTI.scoreColor(r.score)}">${CTI.fmtScore(r.score)}</td>
        <td>${CTI.decisionBadge(r.decision)}</td>
      </tr>
    `).join("");
  }

  document.getElementById("req-count").textContent = `${data.total.toLocaleString()} total`;
  document.getElementById("page-indicator").textContent = `page ${data.page}`;
}

function applyFilters() {
  currentPage = 1;
  loadRequests().catch(e => console.warn(e));
}

document.addEventListener("DOMContentLoaded", () => {
  loadRequests().catch(e => console.warn(e));

  document.getElementById("f-apply").addEventListener("click", applyFilters);
  document.getElementById("f-search").addEventListener("keydown", e => { if (e.key === "Enter") applyFilters(); });
  document.getElementById("f-clear").addEventListener("click", () => {
    document.getElementById("f-search").value = "";
    document.getElementById("f-direction").value = "";
    document.getElementById("f-decision").value = "";
    document.getElementById("f-flagged-only").checked = false;
    applyFilters();
  });
  document.getElementById("page-prev").addEventListener("click", () => {
    if (currentPage > 1) { currentPage--; loadRequests(); }
  });
  document.getElementById("page-next").addEventListener("click", () => {
    currentPage++; loadRequests();
  });

  autoRefreshTimer = setInterval(() => {
    if (currentPage === 1) loadRequests().catch(e => console.warn(e));
  }, 5000);
});
