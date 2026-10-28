
function componentRow(label, value, sub) {
  return `
    <div class="feed-card__row">
      <span>${label}</span>
      <span>${value}${sub ? ` <span style="color:var(--text-faint)">${sub}</span>` : ""}</span>
    </div>
  `;
}

function renderComponents(d) {
  const c = d.components;
  const el = document.getElementById("components-body");

  if (c.category_weight !== null && c.category_weight !== undefined) {
    el.innerHTML = `
      ${componentRow("Category", c.category || "unmapped", c.category_weight_defaulted ? "(defaulted)" : "")}
      ${componentRow("Severity (MITRE)", c.category_weight?.toFixed(4))}
      ${componentRow("Corroboration", c.corroboration_score?.toFixed(2), `(${d.feeds_found} feed${d.feeds_found === 1 ? "" : "s"})`)}
      ${componentRow("Freshness", c.freshness_score?.toFixed(2), d.age_days < 9000 ? `(age: ${d.age_days.toFixed(1)}d)` : "(unknown age)")}
      ${componentRow("Rule score (decision)", `${c.category_weight?.toFixed(2)} × ${c.corroboration_score?.toFixed(2)} × ${c.freshness_score?.toFixed(2)}`, `= ${c.rule_score?.toFixed(4)}`)}
      ${c.ml_score !== null && c.ml_score !== undefined ? componentRow("ML score (comparison only)", CTI.fmtScore(c.ml_score), `confidence: ${c.ml_confidence || "—"}, not used for decision`) : ""}
    `;
  } else if (c.ml_used) {
    el.innerHTML = `
      ${componentRow("Score source", "ML fallback (no feed record)")}
      ${componentRow("ML score", CTI.fmtScore(c.ml_score))}
      ${componentRow("ML confidence", c.ml_confidence || "—")}
      ${componentRow("Model agreement", c.ml_model_agreement !== null ? Math.round(c.ml_model_agreement * 100) + "%" : "—")}
    `;
  } else {
    el.innerHTML = `<div class="empty-state">No score computed yet</div>`;
  }
}

function renderMitreBasis(d) {
  const el = document.getElementById("mitre-basis");
  const techniques = d.mitre_techniques || [];
  if (techniques.length > 0) {
    el.innerHTML = `
      <div style="font-size:12px; color:var(--text-dim); margin-bottom:8px;">
        Category <strong style="color:var(--text)">${d.components.category}</strong> derives its severity
        (<span class="mono">${d.components.category_weight?.toFixed(4)}</span>) from these ATT&CK techniques'
        documented threat-group usage:
      </div>
      <div>${techniques.map(t => `<span class="tech-chip">${t}</span>`).join("")}</div>
      <div style="margin-top:10px;"><a href="/mitre">View full severity ladder →</a></div>
    `;
    return;
  }

  if (d.feeds_found > 0) {
    // A feed hit but its tags (e.g. a malware-family name like
    // "ghostpulse") didn't match any of our mapped category names —
    // this is a coverage gap in the tag→category matcher, NOT a case
    // where ML ran instead. MITRE weighting still applied; it just
    // landed on the unmapped-category baseline.
    el.innerHTML = `<div class="empty-state" style="padding:8px 0;">
      Feed hit found (tags: ${(d.combined_tags || []).slice(0, 5).join(", ") || "none"}), but none of those tags
      matched a mapped MITRE category — severity defaulted to the baseline
      "unknown" weight (${d.components.category_weight?.toFixed(2) ?? "0.25"}) rather than a technique-derived one.
      This IOC's score still comes from the rule formula, not the ML model.
    </div>`;
  } else {
    el.innerHTML = `<div class="empty-state" style="padding:8px 0;">No feed record at all — MITRE weighting not applicable (ML fallback was used instead).</div>`;
  }
}

function renderFeeds(d) {
  const el = document.getElementById("feed-cards");
  const feeds = d.feeds || {};
  const cards = [];

  const urlhaus = feeds.urlhaus;
  cards.push(`
    <div class="feed-card">
      <div class="feed-card__title">URLhaus ${urlhaus?.found ? '<span class="badge badge--enforce">HIT</span>' : '<span class="badge badge--discard">clean</span>'}</div>
      ${urlhaus?.found ? `
        ${componentRow("Tags", (urlhaus.tags || []).slice(0, 4).join(", ") || "—")}
        ${componentRow("First seen", urlhaus.first_seen || "—")}
        ${componentRow("Confidence", urlhaus.confidence?.toFixed(2) ?? "—")}
      ` : `<div class="empty-state" style="padding:8px 0;">No record</div>`}
    </div>
  `);

  const tf = feeds.threatfox;
  const feodo = feeds.feodo;
  const abusech = tf?.found ? tf : feodo;
  cards.push(`
    <div class="feed-card">
      <div class="feed-card__title">Abuse.ch (ThreatFox/Feodo) ${abusech?.found ? '<span class="badge badge--enforce">HIT</span>' : '<span class="badge badge--discard">clean</span>'}</div>
      ${abusech?.found ? `
        ${componentRow("Source", abusech.source || "—")}
        ${componentRow("Tags", (abusech.tags || []).slice(0, 4).join(", ") || "—")}
        ${componentRow("First seen", abusech.first_seen || "—")}
        ${componentRow("Confidence", abusech.confidence?.toFixed(2) ?? "—")}
      ` : `<div class="empty-state" style="padding:8px 0;">No record</div>`}
    </div>
  `);

  const ml = d.ml_details;
  const mlRan = d.components.ml_score !== null && d.components.ml_score !== undefined;
  const mlBadge = !mlRan
    ? '<span class="badge badge--discard">not run</span>'
    : d.components.ml_used
      ? '<span class="badge badge--pending">used for decision</span>'
      : '<span class="badge badge--discard">comparison only</span>';
  cards.push(`
    <div class="feed-card">
      <div class="feed-card__title">URLPredictor (ML) ${mlBadge}</div>
      ${mlRan ? `
        ${componentRow("Probability", CTI.fmtScore(d.components.ml_score))}
        ${componentRow("Decision", ml?.decision || "—")}
        ${componentRow("Confidence", d.components.ml_confidence || "—")}
      ` : `<div class="empty-state" style="padding:8px 0;">Model unavailable or not yet run</div>`}
    </div>
  `);

  el.innerHTML = cards.join("");

  const mlPanel = document.getElementById("ml-panel");
  const mlBody = document.getElementById("ml-body");
  if (ml && ml.model_scores && Object.keys(ml.model_scores).length > 0) {
    mlPanel.style.display = "block";
    const rows = Object.entries(ml.model_scores).sort((a, b) => b[1] - a[1]);
    mlBody.innerHTML = rows.map(([name, score]) => `
      <div class="model-row">
        <div class="model-row__name">${name}</div>
        <div class="model-row__bar">
          <div class="score-bar"><div class="score-bar__fill" style="width:${(score * 100).toFixed(0)}%; background:${CTI.scoreColor(score)};"></div></div>
        </div>
        <div class="model-row__score" style="color:${CTI.scoreColor(score)}">${score.toFixed(3)}</div>
      </div>
    `).join("");
  } else {
    mlPanel.style.display = "none";
  }
}

function renderRelated(requests) {
  const body = document.getElementById("related-body");
  if (!requests || requests.length === 0) {
    body.innerHTML = `<tr><td colspan="5" class="empty-state">No related requests captured</td></tr>`;
    return;
  }
  body.innerHTML = requests.map(r => `
    <tr>
      <td class="mono" style="color:var(--text-dim);">${CTI.fmtTime(r.ts)}</td>
      <td>${CTI.directionBadge(r.direction)}</td>
      <td class="mono ip">${CTI.escapeHtml(r.src_ip || "—")}</td>
      <td class="mono ip">${CTI.escapeHtml(r.dst_ip || "—")}</td>
      <td class="mono" style="color:var(--text-dim);">${r.request_type || r.protocol || "—"}</td>
    </tr>
  `).join("");
}

function renderBlockStatus(d) {
  const btn = document.getElementById("btn-block");
  const statusEl = document.getElementById("block-status");
  const b = d.block || {};

  if (b.is_blocked) {
    btn.textContent = "Unblock";
    btn.className = "btn";
    btn.dataset.action = "unblock";
  } else {
    btn.textContent = "Block";
    btn.className = "btn";
    btn.dataset.action = "block";
  }

  if (b.is_blocked || b.block_error) {
    statusEl.style.display = "block";
    statusEl.innerHTML = b.is_blocked
      ? `<div class="panel panel__body" style="border-color:var(--red-dim, #7a2e2e);">
           <span class="badge badge--enforce">BLOCKED</span>
           <span style="color:var(--text-dim); font-size:12px; margin-left:8px;">
             via firewall app since ${CTI.fmtTime(b.blocked_at)} (${b.block_source || "manual"})
             ${b.blocked_ips ? ` — rules: ${JSON.stringify(b.blocked_ips)}` : ""}
           </span>
         </div>`
      : `<div class="panel panel__body">
           <span class="badge badge--discard">not blocked</span>
           <span style="color:var(--text-dim); font-size:12px; margin-left:8px;">${CTI.escapeHtml(b.block_error)}</span>
         </div>`;
  } else {
    statusEl.style.display = "none";
  }
}

async function load() {
  const d = await CTI.fetchJSON(`/api/ioc/${encodeURIComponent(IOC_VALUE)}`);

  document.getElementById("ioc-score").textContent = CTI.fmtScore(d.final_score);
  document.getElementById("ioc-score").style.color = CTI.scoreColor(d.final_score);
  document.getElementById("ioc-decision").innerHTML = CTI.decisionBadge(d.decision);

  renderComponents(d);
  renderMitreBasis(d);
  renderFeeds(d);
  renderRelated(d.related_requests);
  renderBlockStatus(d);
}

document.getElementById("btn-rescore").addEventListener("click", async () => {
  const btn = document.getElementById("btn-rescore");
  btn.textContent = "Rescoring…";
  btn.disabled = true;
  try {
    await CTI.fetchJSON(`/api/ioc/${encodeURIComponent(IOC_VALUE)}/rescore`, { method: "POST" });
    await load();
  } finally {
    btn.textContent = "Rescore now";
    btn.disabled = false;
  }
});

document.getElementById("btn-block").addEventListener("click", async () => {
  const btn = document.getElementById("btn-block");
  const action = btn.dataset.action || "block";
  const original = btn.textContent;
  btn.textContent = action === "block" ? "Blocking…" : "Unblocking…";
  btn.disabled = true;
  try {
    // Not using CTI.fetchJSON here — it throws away the response body
    // on a non-2xx status, and we need that body (block_error / the
    // guard's refusal reason) to show the user why it failed, not just that it did.
    const res = await fetch(`/api/ioc/${encodeURIComponent(IOC_VALUE)}/${action}`, { method: "POST" });
    const body = await res.json().catch(() => ({}));
    renderBlockStatus(body);
    if (!res.ok && body.error) {
      const statusEl = document.getElementById("block-status");
      statusEl.style.display = "block";
      statusEl.innerHTML = `<div class="panel panel__body">
        <span class="badge badge--enforce">refused</span>
        <span style="color:var(--text-dim); font-size:12px; margin-left:8px;">${CTI.escapeHtml(body.error)}</span>
      </div>`;
    }
  } finally {
    btn.disabled = false;
    if (btn.textContent === (action === "block" ? "Blocking…" : "Unblocking…")) {
      btn.textContent = original;
    }
  }
});

load().catch(e => console.warn(e));
