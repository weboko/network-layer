"use strict";
// agentgw dashboard. Plain DOM, no build step. All text is inserted via
// textContent / escaped templates: destination names come from untrusted agents.

const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let token = "";
try { token = localStorage.getItem("agentgw-token") || ""; } catch (e) { /* storage unavailable */ }
let current = "activity";
let lastStatus = null;

async function api(path, opts = {}) {
  const headers = Object.assign({ "X-AgentGW": "1" }, opts.headers || {});
  if (token) headers.Authorization = "Bearer " + token;
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  if (r.status === 401) {
    token = prompt("agentgw admin token") || "";
    try { localStorage.setItem("agentgw-token", token); } catch (e) { /* ignore */ }
    return api(path, opts);
  }
  const ct = r.headers.get("Content-Type") || "";
  const body = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((body && body.error) || r.statusText);
  return body;
}

function toast(msg, ms = 4000) {
  const d = document.createElement("div");
  d.textContent = msg;
  $("#toast").appendChild(d);
  setTimeout(() => d.remove(), ms);
}

function appliedMsg(res, what) {
  if (res.applied) return toast(`${what}: applied`);
  toast(`${what}: saved, NOT applied yet — ${res.error || "gateway did not confirm"}`, 8000);
}

const ago = (t) => {
  if (!t) return "-";
  const s = Date.now() / 1000 - t;
  if (s < 60) return Math.round(s) + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
};
const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "-");
const bytes = (n) => (n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MB" : (n / 1073741824).toFixed(2) + " GB");
const statusLabel = { approved: "approved", denied: "blocked", unreviewed: "unreviewed", partial: "partially approved" };

function riskCell(intel) {
  if (!intel) return "";
  const parts = [];
  if (intel.level !== "none") parts.push(`<span class="risk-${esc(intel.level)}">${esc(intel.level)}</span> `);
  for (const h of intel.indicators || []) parts.push(`<span class="sub risk-${esc(h.strength)}">${esc(h.detail)}</span>`);
  for (const s of intel.signals || []) parts.push(`<span class="sub">${esc(s)}</span>`);
  return parts.join("");
}
function geoCell(intel) {
  if (!intel) return "";
  const c = (intel.countries || []).join(", ") || "–";
  return `${esc(c)}<span class="sub">${esc((intel.asns || []).slice(0, 2).join("; "))}</span>`;
}
function intelLine(intel) {
  if (!intel) return "";
  const parts = [(intel.countries || []).join(", ") || "no IP known", ...(intel.asns || []).slice(0, 2)];
  const risk = [...(intel.indicators || []).map((h) => `<span class="risk-${esc(h.strength)}">${esc(h.strength)}: ${esc(h.detail)}</span>`),
    ...(intel.signals || []).map(esc)];
  return parts.map(esc).join(" · ") + (risk.length ? " · " + risk.join(" · ") : "");
}

// --- status / header ---------------------------------------------------------

async function loadStatus() {
  const s = await api("/api/status");
  lastStatus = s;
  const mode = s.settings.mode;
  const m = $("#mode");
  m.textContent = mode === "enforce" ? "ENFORCING" : "OBSERVING";
  m.className = "badge " + mode;
  $("#gw").textContent = `${s.gateway_alive ? "gateway up" : "GATEWAY DOWN"} · policy v${s.applied_version}/${s.policy_version} · ${s.rules} rules`;
  $("#qcount").textContent = s.pending || "";
  const banner = [];
  if (!s.gateway_alive) banner.push(["err", "The gateway is not reporting. Existing nftables rules stay in force, but policy changes are not being applied."]);
  if (s.apply_error) banner.push(["err", "Last policy apply failed: " + s.apply_error]);
  if (s.applied_version < s.policy_version) banner.push(["warn", `Policy v${s.policy_version} saved but not applied yet.`]);
  for (const c of s.containers) for (const w of c.warnings) banner.push(["warn", `${c.name}: ${w}`]);
  $("#banner").innerHTML = banner.map(([k, t]) => `<p class="${k}">${esc(t)}</p>`).join("");
}

// --- activity ------------------------------------------------------------------

let activityRows = [];
async function loadActivity() {
  activityRows = await api(`/api/destinations?hours=${$("#hours").value}&q=${encodeURIComponent($("#q").value)}`);
  const f = $("#statusf").value;
  const selected = new Set([...document.querySelectorAll("#activity input[data-sel]:checked")].map((x) => x.dataset.sel));
  $("#activity").innerHTML = activityRows.filter((d) => !f || d.status === f).map((d) => `
    <tr>
      <td><input type="checkbox" data-sel="${esc(d.dest)}" ${selected.has(d.dest) ? "checked" : ""}></td>
      <td><a data-detail="${esc(d.dest)}">${esc(d.dest)}</a>
        <span class="sub">${d.kind === "host" ? esc(d.ips.slice(0, 3).join(", ")) + (d.ips.length > 3 ? " …" : "") : "no hostname seen"}</span></td>
      <td>${geoCell(d.intel)}</td>
      <td>${esc(d.ports.join(", ") || (d.dns_refused ? "DNS only" : "-"))}</td>
      <td>${d.conns}</td>
      <td>${d.blocked + d.denied + d.dns_refused || ""}${d.unmatched && d.status !== "approved" ? `<span class="sub">${d.unmatched} would block</span>` : ""}</td>
      <td>${bytes(d.tx_bytes)} ↑<span class="sub">${bytes(d.rx_bytes)} ↓</span></td>
      <td>${esc(d.containers.join(", "))}</td>
      <td>${riskCell(d.intel)}</td>
      <td class="st-${esc(d.status)}">${esc(statusLabel[d.status] || d.status)}<span class="sub">${esc(d.outcome)}</span></td>
      <td>${ago(d.last_seen)}</td>
      <td>${actionButtons(d.dest, d.status)}</td>
    </tr>`).join("") || `<tr><td colspan="12" class="muted">No traffic recorded in this window.</td></tr>`;
}

function actionButtons(dest, status) {
  const a = status !== "approved" ? `<button class="approve" data-act="approve" data-dest="${esc(dest)}">Approve</button>` : "";
  const b = status !== "denied" ? `<button class="block" data-act="block" data-dest="${esc(dest)}">Block</button>` : "";
  return a + " " + b;
}

async function decide(dest, action, extra = {}) {
  try {
    const res = await api("/api/decide", { method: "POST", json: Object.assign({ dest, action }, extra) });
    appliedMsg(res, `${action} ${dest}`);
  } catch (e) { toast("Error: " + e.message, 8000); }
  refresh();
}

// --- queue -------------------------------------------------------------------------

async function loadQueue() {
  const items = await api("/api/queue");
  $("#queue").innerHTML = items.map((i, n) => `
    <div class="card">
      <h3>${esc(i.dest)} <span class="nec-${esc(i.necessity)}">${i.necessity === "unknown" ? "" : esc(i.necessity)}</span>
        <span class="muted">· ${esc(statusLabel[i.status])}</span></h3>
      <div class="muted">${esc(i.ports.join(", ") || "port unknown (DNS refused)")} · ${i.attempts} attempts ·
        ${esc(i.containers.join(", "))} · first ${ago(i.first_seen)}, last ${ago(i.last_seen)} · via ${esc(i.source)}</div>
      <div>${intelLine(i.intel)}</div>
      ${i.notes.map((nt) => `<div class="note"><b>${esc(nt.container)}</b> says <span class="nec-${esc(nt.necessity)}">${esc(nt.necessity || "")}</span>
        ${nt.port ? esc(nt.port) : ""}: ${esc(nt.reason)} ${nt.task ? `<span class="muted">(task: ${esc(nt.task)})</span>` : ""}</div>`).join("")}
      <div class="actions">
        <button class="approve" data-act="approve" data-dest="${esc(i.dest)}" data-adv="adv${n}">Approve</button>
        <button class="block" data-act="block" data-dest="${esc(i.dest)}">Block</button>
        <button data-act="dismiss" data-dest="${esc(i.dest)}">Dismiss</button>
        <a data-toggle="adv${n}">advanced…</a>
        <a data-detail="${esc(i.dest)}">details</a>
      </div>
      <div class="adv" id="adv${n}">
        <input data-f="value" value="${esc(i.dest)}" title="hostname, *.domain or IP/CIDR">
        <input data-f="ports" placeholder="ports (default: observed)" value="${esc(i.ports.filter((p) => p.includes("/")).join(", "))}">
        <input data-f="expires_hours" placeholder="temporary: hours" size="14">
        <input data-f="note" placeholder="note">
      </div>
    </div>`).join("") || `<p class="muted">Nothing waiting for review.</p>`;
}

// --- rules ---------------------------------------------------------------------

async function loadRules() {
  const rules = await api("/api/rules");
  $("#rules").innerHTML = rules.map((r) => `
    <tr data-rule="${r.id}">
      <td class="${r.action === "allow" ? "st-approved" : "st-denied"}">${r.action === "allow" ? "allow" : "block"}</td>
      <td><a data-detail="${esc(r.value)}">${esc(r.value)}</a> <span class="sub">${esc(r.kind)}</span></td>
      <td><input data-edit="ports" value="${esc(r.ports.join(", "))}" ${r.action === "deny" ? "disabled" : ""}></td>
      <td><input data-edit="note" value="${esc(r.note)}"></td>
      <td>${r.expires_at ? (r.expired ? "expired" : when(r.expires_at)) : "permanent"}</td>
      <td>${esc(r.created_by)}</td>
      <td>${ago(r.updated_at)}</td>
      <td><button data-save="${r.id}" data-action="${esc(r.action)}" data-value="${esc(r.value)}">Save</button>
        <button class="block" data-del="${r.id}">Remove</button></td>
    </tr>`).join("") || `<tr><td colspan="8" class="muted">The whitelist is empty.</td></tr>`;
}

async function loadHistory() {
  const rows = await api("/api/history");
  $("#history").innerHTML = rows.map((h) => `<tr><td>${when(h.ts)}</td><td>${esc(h.actor)}</td><td>${esc(h.event)}</td>
    <td>${esc(h.value || "")}</td><td class="muted">${esc(h.detail ? JSON.stringify(h.detail) : "")}</td></tr>`).join("");
}

async function loadSnapshots() {
  const rows = await api("/api/snapshots");
  $("#snapshots").innerHTML = rows.map((s) => `<tr><td>${esc(s.name)}</td><td>${s.rule_count}</td><td>${when(s.created_at)}</td>
    <td>${esc(s.note || "")}</td><td><button data-restore="${s.id}">Restore</button>
    <button data-download="${s.id}">Download</button> <button class="block" data-delsnap="${s.id}">Delete</button></td></tr>`).join("")
    || `<tr><td colspan="5" class="muted">No snapshots yet.</td></tr>`;
}

// --- settings --------------------------------------------------------------------

const SETTINGS = [
  ["mode", "Mode", ["observe", "enforce"], "observe: record everything, block only explicit blocks. enforce: default deny — only whitelisted destinations work."],
  ["unapproved_dns", "Unapproved names (enforce)", ["refuse", "resolve"], "refuse: answer NXDOMAIN without asking upstream (prevents DNS exfiltration; port unknown until approved). resolve: resolve, then block the connection (shows the port; the query leaves the host)."],
  ["dns_min_ttl", "Minimum DNS allowance (s)", "number", "How long an IP stays admitted after an approved name resolved to it (apps cache DNS longer than TTLs)."],
  ["dns_max_ttl", "Maximum DNS allowance (s)", "number", ""],
  ["auto_block_malicious", "Auto-block verified malicious indicators", "bool", "Off by default. Blocks IPs/domains listed by the malicious feeds below. Country never blocks anything."],
  ["watch_countries", "Watched countries", "list", "ISO codes highlighted for review, e.g. CN, RU. Informational only."],
  ["geoip", "Country / ASN lookups", "bool", "DB-IP Lite databases (CC BY 4.0), refreshed every two weeks."],
  ["default_temp_hours", "Default temporary approval (h)", "number", ""],
  ["retention_days", "Keep activity for (days)", "number", ""],
];

async function loadSettings() {
  const s = await api("/api/settings");
  const f = $("#settings");
  f.innerHTML = SETTINGS.map(([k, label, type, help]) => {
    let input;
    if (Array.isArray(type)) input = `<select name="${k}">${type.map((o) => `<option ${s[k] === o ? "selected" : ""}>${o}</option>`).join("")}</select>`;
    else if (type === "bool") input = `<input type="checkbox" name="${k}" ${s[k] ? "checked" : ""}>`;
    else if (type === "list") input = `<input name="${k}" value="${esc(s[k].join(", "))}">`;
    else input = `<input name="${k}" type="number" value="${esc(s[k])}">`;
    return `<label>${esc(label)}</label>${input}${help ? `<div class="help">${esc(help)}</div>` : ""}`;
  }).join("") + `<label>Threat feeds</label><div>${Object.entries(s.intel_feeds).map(([k, v]) =>
    `<label><input type="checkbox" data-feed="${esc(k)}" ${v ? "checked" : ""}> ${esc(k)}</label>`).join(" ")}</div>
    <span></span><button class="approve">Save settings</button>`;
  const st = (lastStatus && lastStatus.intel) || {};
  $("#intelstatus").innerHTML = Object.entries(st).map(([k, v]) => `<div><b>${esc(k)}</b>: <span class="muted">${esc(v)}</span></div>`).join("")
    || `<p class="muted">No feed has been fetched yet.</p>`;
}

async function saveSettings(ev) {
  ev.preventDefault();
  const f = ev.target;
  const body = {};
  for (const [k, , type] of SETTINGS) {
    const el = f.elements[k];
    if (type === "bool") body[k] = el.checked;
    else if (type === "list") body[k] = el.value.split(",").map((x) => x.trim()).filter(Boolean);
    else if (type === "number") body[k] = Number(el.value);
    else body[k] = el.value;
  }
  body.intel_feeds = {};
  for (const el of f.querySelectorAll("[data-feed]")) body.intel_feeds[el.dataset.feed] = el.checked;
  try {
    const res = await api("/api/settings", { method: "POST", json: body });
    appliedMsg(res, "settings");
  } catch (e) { toast("Error: " + e.message, 8000); }
  refresh();
}

// --- detail drawer ---------------------------------------------------------------

async function showDetail(dest) {
  const d = await api("/api/destination?dest=" + encodeURIComponent(dest));
  $("#detailbody").innerHTML = `
    <h2>${esc(d.dest)}</h2>
    <p class="st-${esc(d.status)}">${esc(statusLabel[d.status] || d.status)} ${d.rule ? `· rule: ${esc(d.rule.action)} ${esc(d.rule.ports.join(", "))}` : ""}</p>
    <p>${actionButtons(d.dest, d.status)}</p>
    <h3>Risk</h3><div>${riskCell(d.intel) || "no indicators"}</div>
    <table><thead><tr><th>IP</th><th>Country</th><th>ASN</th></tr></thead><tbody>
      ${d.intel.geo.map((g) => `<tr><td>${esc(g.ip)}</td><td>${esc(g.country || "?")} ${esc(g.country_name || "")}</td><td>${g.asn ? "AS" + esc(g.asn) : ""} ${esc(g.as_org || "")}</td></tr>`).join("")}
    </tbody></table>
    <h3>Connections</h3><table><thead><tr><th>Container</th><th>IP</th><th>Port</th><th>Conns</th><th>Blocked</th><th>Bytes ↑/↓</th><th>Last</th></tr></thead><tbody>
      ${d.flows.map((f) => `<tr><td>${esc(f.container)}</td><td>${esc(f.dst_ip)}</td><td>${esc(f.proto)}/${f.port}</td><td>${f.conns}</td><td>${f.blocked + f.denied}</td><td>${bytes(f.tx_bytes)} / ${bytes(f.rx_bytes)}</td><td>${ago(f.last_seen)}</td></tr>`).join("")}
    </tbody></table>
    <h3>DNS</h3><table><thead><tr><th>Container</th><th>Type</th><th>Verdict</th><th>Answers</th><th>Count</th><th>Last</th></tr></thead><tbody>
      ${d.dns.map((q) => `<tr><td>${esc(q.container)}</td><td>${esc(q.qtype)}</td><td>${esc(q.verdict)}</td><td>${esc(q.answers.join(", "))}</td><td>${q.count}</td><td>${ago(q.last_seen)}</td></tr>`).join("")}
    </tbody></table>
    <h3>Agent notes</h3>${d.notes.map((n) => `<div class="note"><b>${esc(n.container)}</b> (${esc(n.necessity || "?")}): ${esc(n.reason)}</div>`).join("") || `<p class="muted">none</p>`}
    <h3>History</h3>${d.history.map((h) => `<div>${when(h.ts)} · ${esc(h.actor)} · ${esc(h.event)}</div>`).join("") || `<p class="muted">none</p>`}`;
  $("#detail").hidden = false;
}

// --- wiring ---------------------------------------------------------------------------

const loaders = { activity: loadActivity, queue: loadQueue, rules: loadRules, history: loadHistory, snapshots: loadSnapshots, settings: loadSettings };

async function refresh() {
  try {
    await loadStatus();
    if (current !== "settings") await loaders[current]();
  } catch (e) { toast("Error: " + e.message, 8000); }
}

document.addEventListener("click", async (ev) => {
  const t = ev.target;
  if (t.dataset.tab) {
    current = t.dataset.tab;
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === t));
    document.querySelectorAll("main > section").forEach((s) => (s.hidden = s.id !== "tab-" + current));
    await loadStatus().catch(() => {});
    return loaders[current]().catch((e) => toast("Error: " + e.message));
  }
  if (t.dataset.act) {
    const extra = {};
    if (t.dataset.adv) {
      const adv = document.getElementById(t.dataset.adv);
      if (adv && adv.classList.contains("open")) {
        for (const el of adv.querySelectorAll("[data-f]")) if (el.value.trim()) extra[el.dataset.f] = el.value.trim();
        if (extra.ports) extra.ports = extra.ports.split(/[\s,]+/).filter(Boolean);
      }
    }
    return decide(t.dataset.dest, t.dataset.act, extra);
  }
  if (t.dataset.toggle) return document.getElementById(t.dataset.toggle).classList.toggle("open");
  if (t.dataset.detail) return showDetail(t.dataset.detail).catch((e) => toast("Error: " + e.message));
  if (t.id === "closedetail") { $("#detail").hidden = true; return; }
  if (t.id === "selall") { document.querySelectorAll("#activity input[data-sel]").forEach((c) => (c.checked = t.checked)); return; }
  if (t.id === "bulk-approve") {
    const sel = [...document.querySelectorAll("#activity input[data-sel]:checked")].map((x) => x.dataset.sel);
    if (!sel.length) return toast("Select destinations first");
    let ok = 0;
    for (const d of sel) {
      try { const r = await api("/api/decide", { method: "POST", json: { dest: d, action: "approve" } }); if (r.applied) ok++; }
      catch (e) { toast(`${d}: ${e.message}`, 8000); }
    }
    toast(`Approved ${ok}/${sel.length}`);
    $("#selall").checked = false;
    return refresh();
  }
  if (t.dataset.save) {
    const row = t.closest("tr");
    const ports = row.querySelector("[data-edit=ports]").value.split(/[\s,]+/).filter(Boolean);
    try {
      const res = await api("/api/rules/" + t.dataset.save, { method: "PUT", json: { action: t.dataset.action, value: t.dataset.value, ports, note: row.querySelector("[data-edit=note]").value, keep_expiry: true } });
      appliedMsg(res, "rule " + t.dataset.value);
    } catch (e) { toast("Error: " + e.message, 8000); }
    return refresh();
  }
  if (t.dataset.del) {
    try { appliedMsg(await api("/api/rules/" + t.dataset.del, { method: "DELETE" }), "removed"); } catch (e) { toast("Error: " + e.message, 8000); }
    return refresh();
  }
  if (t.dataset.restore) {
    try {
      const res = await api(`/api/snapshots/${t.dataset.restore}/restore`, { method: "POST" });
      appliedMsg(res, `restored (${res.rule_count} rules; previous whitelist saved as snapshot #${res.backup_snapshot})`);
    } catch (e) { toast("Error: " + e.message, 8000); }
    return refresh();
  }
  if (t.dataset.delsnap) { await api("/api/snapshots/" + t.dataset.delsnap, { method: "DELETE" }); return refresh(); }
  if (t.dataset.download || t.id === "export") {
    const path = t.id === "export" ? "/api/policy/export" : "/api/snapshots/" + t.dataset.download;
    const text = await api(path);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "application/yaml" }));
    a.download = t.id === "export" ? "agentgw-policy.yaml" : `snapshot-${t.dataset.download}.yaml`;
    a.click();
    return;
  }
  if (t.id === "intelrefresh") { await api("/api/intel/refresh", { method: "POST" }); toast("Refreshing feeds in the background"); }
});

$("#addrule").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const body = { action: f.action.value, value: f.value.value, ports: f.ports.value.split(/[\s,]+/).filter(Boolean), note: f.note.value };
  if (f.expires_hours.value) body.expires_hours = Number(f.expires_hours.value);
  try { appliedMsg(await api("/api/rules", { method: "POST", json: body }), "rule " + body.value); f.value.value = ""; }
  catch (e) { toast("Error: " + e.message, 8000); }
  refresh();
});
$("#snapform").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  try { const r = await api("/api/snapshots", { method: "POST", json: { name: f.name.value, note: f.note.value } }); toast(`Saved snapshot '${r.name}' (${r.rule_count} rules)`); f.reset(); }
  catch (e) { toast("Error: " + e.message, 8000); }
  refresh();
});
$("#importfile").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (!file) return;
  try {
    const res = await api("/api/policy/import?mode=" + $("#importmode").value, { method: "POST", body: await file.text(), headers: { "Content-Type": "application/yaml" } });
    appliedMsg(res, `imported ${res.rule_count} rules`);
  } catch (e) { toast("Import failed: " + e.message, 8000); }
  ev.target.value = "";
  refresh();
});
$("#settings").addEventListener("submit", saveSettings);
for (const id of ["#hours", "#statusf"]) $(id).addEventListener("change", loadActivity);
let qtimer;
$("#q").addEventListener("input", () => { clearTimeout(qtimer); qtimer = setTimeout(loadActivity, 300); });

refresh();
setInterval(() => {
  // Don't redraw under the user: typing, or an open "advanced" approval form.
  if (document.hidden || document.activeElement.matches("input, select") || document.querySelector(".adv.open")) return;
  refresh();
}, 5000);
