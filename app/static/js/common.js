
const CTI = (() => {
  function decisionBadge(decision) {
    const d = decision || "PENDING";
    const cls = d === "ENFORCE" ? "badge--enforce" : d === "DISCARD" ? "badge--discard" : "badge--pending";
    return `<span class="badge ${cls}">${d}</span>`;
  }

  function directionBadge(dir) {
    const cls = dir === "inbound" ? "badge--inbound" : "badge--outbound";
    return `<span class="badge ${cls}">${dir || "—"}</span>`;
  }

  function scoreColor(score) {
    if (score === null || score === undefined) return "var(--text-faint)";
    if (score >= 0.6) return "var(--crit)";
    if (score >= 0.35) return "var(--warn)";
    return "var(--ok)";
  }

  function fmtScore(score) {
    if (score === null || score === undefined) return "—";
    return Number(score).toFixed(3);
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
    return d.toLocaleTimeString([], { hour12: false }) ;
  }

  function timeAgo(iso) {
    if (!iso) return "—";
    const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
    const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function fetchJSON(url, opts) {
    const res = await fetch(url, opts);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    return res.json();
  }

  async function pollStatus() {
    try {
      const s = await fetchJSON("/api/stats");
      const captureDot = document.getElementById("status-capture-dot");
      const captureText = document.getElementById("status-capture-text");
      const mlDot = document.getElementById("status-ml-dot");
      const mlText = document.getElementById("status-ml-text");

      if (captureDot && captureText) {
        captureText.textContent = `capture: ${s.capture_mode}`;
        captureDot.className = "pill__dot " + (s.capture_mode === "off" ? "" : "ok");
      }
      if (mlDot && mlText) {
        if (s.ml_status.loaded) {
          mlText.textContent = `model: ${s.ml_status.models.length} loaded`;
          mlDot.className = "pill__dot ok";
        } else if (s.ml_status.attempted) {
          mlText.textContent = "model: unavailable";
          mlDot.className = "pill__dot warn";
        } else {
          mlText.textContent = "model: idle";
          mlDot.className = "pill__dot";
        }
      }
      return s;
    } catch (e) {
      console.warn("status poll failed", e);
      return null;
    }
  }

  function tickClock() {
    const el = document.getElementById("status-clock");
    if (el) el.textContent = new Date().toLocaleTimeString([], { hour12: false });
  }

  document.addEventListener("DOMContentLoaded", () => {
    pollStatus();
    setInterval(pollStatus, 8000);
    tickClock();
    setInterval(tickClock, 1000);
  });

  return { decisionBadge, directionBadge, scoreColor, fmtScore, fmtTime, timeAgo, escapeHtml, fetchJSON, pollStatus };
})();
