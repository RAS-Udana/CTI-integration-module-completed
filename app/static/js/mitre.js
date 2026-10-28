
function severityColor(sev) {
  if (sev >= 0.75) return "#ff5c5c";
  if (sev >= 0.45) return "#f5a623";
  if (sev >= 0.2) return "#e8c15a";
  return "#5fb890";
}

async function loadMitre() {
  const data = await CTI.fetchJSON("/api/mitre");
  const b = data.bundle;

  document.getElementById("bundle-meta").innerHTML = `
    source&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;mitre-attack/attack-stix-data (Enterprise)<br>
    version&nbsp;&nbsp;&nbsp;&nbsp;v${CTI.escapeHtml(b.attack_bundle_version)}<br>
    sha256&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${CTI.escapeHtml(b.attack_bundle_sha256)}<br>
    derived&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${new Date(b.derived_at).toLocaleString()}<br>
    method&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${CTI.escapeHtml(b.method)}<br>
    floor (s_min)&nbsp;${b.s_min}
  `;

  const ladder = document.getElementById("ladder");
  const legend = document.getElementById("ladder-legend");
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

  const body = document.getElementById("mitre-body");
  body.innerHTML = data.categories.map(c => `
    <tr>
      <td style="font-weight:600;">${CTI.escapeHtml(c.category)}</td>
      <td>
        <div style="display:flex; align-items:center; gap:8px;">
          <div class="score-bar" style="width:90px;">
            <div class="score-bar__fill" style="width:${(c.severity * 100).toFixed(0)}%; background:${severityColor(c.severity)};"></div>
          </div>
          <span class="mono num" style="color:${severityColor(c.severity)};">${c.severity.toFixed(4)}</span>
        </div>
      </td>
      <td class="mono num">${c.raw_count}</td>
      <td>${c.techniques.map(t => `<span class="tech-chip">${t}</span>`).join("")}</td>
    </tr>
  `).join("");
}

document.addEventListener("DOMContentLoaded", () => {
  loadMitre().catch(e => console.warn(e));
});
