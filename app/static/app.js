"use strict";
// All log-derived text is inserted with textContent (never innerHTML): logs are untrusted.
const $ = (id) => document.getElementById(id);
const LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"];
const SEV_RANK = { CRITICAL: 0, ERROR: 1, WARNING: 2, INFO: 3, DEBUG: 4 };
const VERDICT_LABEL = { CRITICAL: "Critical issue", ERROR: "Error found", WARNING: "Needs attention", INFO: "Note", OK: "No problems detected" };
const MAX_ROWS = 3000;
const FINDINGS_SHOWN = 8;
let current = null;
const activeLevels = new Set(LEVELS);
const activeSeverities = new Set(LEVELS);
let showAllFindings = false;

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}

/* ---------------- theme ---------------- */
function applyTheme(theme) { if (theme) document.documentElement.dataset.theme = theme; }
try { applyTheme(localStorage.getItem("flc-theme")); } catch (_) { /* storage unavailable */ }
$("theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : window.matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem("flc-theme", next); } catch (_) { /* ignore */ }
});

/* ---------------- network ---------------- */
async function request(path, init) {
  const res = await fetch(path, init);
  let data = {};
  try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
const postJson = (path, obj) => request(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) });

function setStatus(msg, isError) { const s = $("status"); s.textContent = msg; s.className = isError ? "status error" : "status"; }
const BUSY = ["parse", "analyze-path", "crashes"];
async function run(label, work) {
  setStatus(label);
  $("loading").hidden = false;
  for (const id of BUSY) $(id).disabled = true;
  for (const b of document.querySelectorAll("[data-sample]")) b.disabled = true;
  try { show(await work()); setStatus(""); }
  catch (err) { setStatus(`Error: ${err.message}`, true); }
  finally { $("loading").hidden = true; for (const id of BUSY) $(id).disabled = false; for (const b of document.querySelectorAll("[data-sample]")) b.disabled = false; }
}

/* ---------------- current file bar ---------------- */
const fmtDate = (d) => d.toLocaleString(undefined, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
function metaItem(label, value) { const s = el("span"); s.append(el("b", label + " "), document.createTextNode(value)); return s; }

function renderCurrentFile(d) {
  const box = $("current-file"); box.replaceChildren();
  const info = d.file_info;
  const icon = el("div", undefined, "cf-icon");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5");
  svg.append(path); icon.append(svg);
  const text = el("div");
  const name = info ? info.name : (d.source_name === "coredumpctl" ? "System crash records (coredumpctl)" : d.source_name);
  text.append(el("div", info ? "Analyzed file" : "Analyzed source", "cf-label"), el("div", name, "cf-name"));
  const meta = el("div", undefined, "cf-meta");
  meta.append(metaItem("Type:", d.source_type));
  if (info) {
    meta.append(metaItem("Size:", fmtSize(info.size_bytes)));
    if (info.sample) meta.append(metaItem("Source:", "built-in demo sample (synthetic data)"));
    else meta.append(metaItem("File date:", info.modified ? fmtDate(new Date(info.modified)) : "unknown"));
  }
  meta.append(metaItem("Uploaded/analyzed:", fmtDate(new Date())));
  text.append(meta);
  box.append(icon, text);
  box.hidden = false;
}

/* ---------------- verdict ---------------- */
function renderVerdict(d) {
  const box = $("verdict"); box.replaceChildren();
  const found = [...d.findings].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  let sev, title, sub;
  if (!found.length) {
    sev = "OK"; title = "The deterministic checks found nothing to flag";
    sub = `${d.total_events} events analysed.`;
  } else {
    sev = found[0].severity; title = found[0].title;
    const by = {}; for (const f of found) by[f.severity] = (by[f.severity] || 0) + 1;
    const parts = Object.keys(SEV_RANK).filter((k) => by[k]).map((k) => `${by[k]} ${k.toLowerCase()}`);
    sub = `${found.length} finding${found.length === 1 ? "" : "s"}: ${parts.join(", ")}. Most important first below.`;
  }
  box.className = `verdict sev-${sev}`;
  const icon = el("div", sev === "OK" ? "✓" : "!", "v-icon"); icon.setAttribute("aria-hidden", "true");
  const text = el("div");
  text.append(el("div", VERDICT_LABEL[sev], "v-label"), el("div", title, "v-title"), el("p", sub, "v-sub"));
  box.append(icon, text);
}

/* ---------------- overview ---------------- */
function chip(label, value) { const c = el("span", undefined, "chip"); c.append(el("b", label), document.createTextNode(String(value))); return c; }

function renderSource(d) {
  const box = $("source"); box.replaceChildren();
  const s = d.stats || {};
  box.append(chip("type", d.source_type), chip("name", d.source_name));
  if (s.duration_s !== undefined && s.duration_s !== null) box.append(chip("duration", `${s.duration_s}s`));
  if (s.armed_s !== undefined) box.append(chip("armed", `${s.armed_s}s`));
  if (s.firmware) box.append(chip("firmware", s.firmware));
  if (s.time_base) box.append(chip("time", s.time_base));
  if (s.crash_count !== undefined) box.append(chip("crashes", s.crash_count), chip("distinct locations", s.distinct_crash_sites), chip("signals", s.signals.join(", ")));
  if (s.vehicles) for (const [k, v] of Object.entries(s.vehicles)) box.append(chip(k, v.vehicle_type));
  if (s.mission_transfers) box.append(chip("mission transfers", s.mission_transfers.length));
  if (d.source_type === "text") box.append(chip("lines", d.total_lines), chip("malformed", d.malformed_lines.length));
  for (const w of s.reader_warnings || []) box.append(chip("reader note", w));
}

function renderCounts(d) {
  const box = $("counts"); box.replaceChildren();
  for (const lvl of LEVELS) {
    const n = d.counts_by_level[lvl];
    const c = el("div", undefined, `count lvl-${lvl}${n === 0 ? " zero" : ""}`);
    c.append(el("b", String(n)), el("span", lvl, `lvl-${lvl}`));
    box.append(c);
  }
}

/* ---------------- findings ---------------- */
function renderFindingFilters(d) {
  const box = $("finding-filters"); box.replaceChildren();
  const by = {}; for (const f of d.findings) by[f.severity] = (by[f.severity] || 0) + 1;
  for (const lvl of ["CRITICAL", "ERROR", "WARNING", "INFO"]) {
    if (!by[lvl]) continue;
    const label = el("label", undefined, "pill");
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.checked = activeSeverities.has(lvl);
    cb.addEventListener("change", () => { cb.checked ? activeSeverities.add(lvl) : activeSeverities.delete(lvl); renderFindings(); });
    label.append(cb, el("span", `${lvl} ${by[lvl]}`, `lvl-${lvl}`));
    box.append(label);
  }
}

function renderFindings() {
  const d = current;
  const box = $("findings"); box.replaceChildren();
  $("findings-count").textContent = String(d.findings.length);
  $("toggle-all").hidden = d.findings.length === 0;
  const sorted = [...d.findings].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]).filter((f) => activeSeverities.has(f.severity));
  $("more-findings").hidden = true;
  if (!sorted.length) { box.append(el("div", d.findings.length ? "All findings are hidden by the filters." : "No findings. Nothing suspicious was detected by the deterministic checks.", "empty")); return; }
  const visible = showAllFindings ? sorted : sorted.slice(0, FINDINGS_SHOWN);
  visible.forEach((f, i) => {
    const card = el("details", undefined, `finding sev-${f.severity}`);
    if (i < 2) card.open = true;
    const sum = el("summary");
    const head = el("div");
    head.append(el("div", f.title, "f-title"), el("div", f.kind.replaceAll("_", " "), "f-kind"));
    sum.append(el("span", f.severity, `lvl badge lvl-${f.severity}`), head);
    card.append(sum);
    if (f.detail) card.append(el("pre", f.detail));
    box.append(card);
  });
  const hidden = sorted.length - visible.length;
  if (hidden > 0) { const b = $("more-findings"); b.hidden = false; b.textContent = `Show ${hidden} more finding${hidden === 1 ? "" : "s"}`; }
}

/* ---------------- events ---------------- */
function renderFilters() {
  const box = $("filters"); box.replaceChildren();
  for (const lvl of LEVELS) {
    const label = el("label", undefined, "pill");
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.checked = activeLevels.has(lvl);
    cb.addEventListener("change", () => { cb.checked ? activeLevels.add(lvl) : activeLevels.delete(lvl); renderEvents(); });
    label.append(cb, el("span", `${lvl} ${current.counts_by_level[lvl]}`, `lvl-${lvl}`));
    box.append(label);
  }
}

function when(e) {
  if (e.timestamp) return e.timestamp.replace("T", " ").replace(/\+00:00$/, "Z");
  if (e.elapsed_s !== null && e.elapsed_s !== undefined) return `t+${e.elapsed_s}s`;
  return "–";
}

function renderEvents() {
  const body = $("events"); body.replaceChildren();
  const needle = $("search").value.trim().toLowerCase();
  let shown = 0, hidden = 0;
  for (const e of current.events) {
    if (!activeLevels.has(e.level)) continue;
    if (needle && !e.message.toLowerCase().includes(needle)) continue;
    if (shown >= MAX_ROWS) { hidden++; continue; }
    shown++;
    const tr = document.createElement("tr");
    if (e.level === "ERROR" || e.level === "CRITICAL") tr.className = "is-error";
    const lvl = el("td"); lvl.append(el("span", e.level, `lvl badge lvl-${e.level}`));
    // mission_item === null means "no item"; 0 is a real item number.
    const item = el("td", undefined, "num");
    if (e.mission_item === null) item.textContent = "–"; else item.append(el("span", String(e.mission_item), "item"));
    tr.append(el("td", String(e.line_number), "num"), el("td", when(e), "time"), lvl, el("td", e.message, "msg"), item);
    body.append(tr);
  }
  if (shown === 0) { const tr = document.createElement("tr"); const td = el("td", "No events match.", "muted"); td.colSpan = 5; tr.append(td); body.append(tr); }
  $("truncated").hidden = hidden === 0;
  $("truncated").textContent = `${hidden} more event(s) not shown; use the JSON/CLI output for the full list.`;
  const list = $("malformed"); list.replaceChildren();
  for (const m of current.malformed_lines) list.append(el("li", `line ${m.line_number}: ${JSON.stringify(m.text)}  (${m.reason})`));
  $("malformed-box").hidden = current.malformed_lines.length === 0;
}

function show(d) {
  current = d;
  showAllFindings = false; activeSeverities.clear(); for (const l of LEVELS) activeSeverities.add(l);
  $("search").value = "";
  renderCurrentFile(d); renderVerdict(d); renderSource(d); renderCounts(d); renderFindingFilters(d); renderFindings(); renderFilters(); renderEvents();
  $("toggle-all").textContent = "Expand all";
  $("results").hidden = false; $("diagnosis").hidden = true;
  $("verdict").scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------------- AI diagnosis ---------------- */
function renderDiagnosis(resp) {
  const box = $("diagnosis"); box.replaceChildren(); box.hidden = false;
  if (resp.diagnosis_error) box.append(el("div", `AI diagnosis unavailable: ${resp.diagnosis_error}`, "banner err"));
  const d = resp.diagnosis;
  if (!d) return;
  box.append(el("div", `AI-generated by ${d.provider}/${d.model}. NOT verified: causes are hypotheses, not confirmed findings.`, "banner"));
  box.append(el("h3", "Summary"), el("p", d.summary));
  box.append(el("h3", "Evidence (text from your log)"));
  const ev = el("ul");
  for (const e of d.evidence) { const li = el("li"); li.append(el("span", `#${e.line_number}: ${e.log_message}`, "ev"), el("div", `→ ${e.observation}`, "muted")); ev.append(li); }
  if (!d.evidence.length) ev.append(el("li", "none verified"));
  box.append(ev, el("h3", "Hypotheses (unconfirmed)"));
  for (const h of d.hypotheses) {
    const card = el("div", undefined, "hyp");
    const t = el("div"); t.append(el("span", h.confidence, `conf conf-${h.confidence}`), document.createTextNode(h.description));
    card.append(t, el("div", `supporting events: ${h.supporting_lines.join(", ") || "none"}. ${h.reasoning}`, "muted"));
    box.append(card);
  }
  if (!d.hypotheses.length) box.append(el("p", "none", "muted"));
  box.append(el("h3", "Recommended checks"));
  const ck = el("ul"); for (const c of d.recommended_checks) ck.append(el("li", c)); box.append(ck);
  const conf = el("p"); conf.append(el("span", d.confidence, `conf conf-${d.confidence}`), document.createTextNode(d.confidence_explanation));
  box.append(el("h3", "Confidence"), conf);
  if (d.warnings.length) { box.append(el("h3", "Safeguard warnings")); for (const x of d.warnings) box.append(el("div", x, "banner")); }
}

async function diagnose() {
  const btn = $("diagnose"); btn.disabled = true; btn.textContent = "Diagnosing…";
  try { renderDiagnosis(await postJson("/api/diagnose", { token: current.token })); }
  catch (err) { renderDiagnosis({ diagnosis: null, diagnosis_error: err.message }); }
  finally { btn.disabled = false; btn.textContent = "Diagnose with AI"; }
}

/* ---------------- wiring ---------------- */
function uploadFile(file) {
  return run(`Analyzing ${file.name}…`, () => request(`/api/analyze?name=${encodeURIComponent(file.name)}&modified=${file.lastModified}`, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file }));
}

$("parse").addEventListener("click", () => run("Analyzing…", () => postJson("/api/parse", { text: $("input").value })));
$("analyze-path").addEventListener("click", () => run("Analyzing (large logs can take a few seconds)…", () => postJson("/api/analyze-path", { path: $("path").value })));
$("crashes").addEventListener("click", () => run("Reading crash records…", () => postJson("/api/system-crashes", { name: $("crash-name").value.trim() })));
$("diagnose").addEventListener("click", diagnose);
for (const btn of document.querySelectorAll("[data-sample]")) {
  btn.addEventListener("click", () => run("Loading sample…", () => postJson("/api/demo-sample", { kind: btn.dataset.sample })));
}
$("file").addEventListener("change", (ev) => { const f = ev.target.files[0]; ev.target.value = ""; if (f) uploadFile(f); });
$("search").addEventListener("input", () => { if (current) renderEvents(); });
$("more-findings").addEventListener("click", () => { showAllFindings = true; renderFindings(); });
$("toggle-all").addEventListener("click", () => {
  const cards = document.querySelectorAll("#findings details");
  const open = $("toggle-all").textContent === "Expand all";
  cards.forEach((c) => { c.open = open; });
  $("toggle-all").textContent = open ? "Collapse all" : "Expand all";
});

const drop = $("drop");
for (const type of ["dragenter", "dragover"]) drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.add("over"); });
for (const type of ["dragleave", "drop"]) drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.remove("over"); });
drop.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) uploadFile(f); });
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file").click(); } });

/* ---------------- server mode (public demo vs full) ---------------- */
request("/api/config").then((cfg) => {
  $("drop-hint").textContent = `or click to browse (.tlog, .BIN, crash text; max ${cfg.max_upload_mb} MB)`;
  if (!cfg.demo) return;
  $("tile-crash").hidden = true;
  $("path-row").hidden = true;
  const banner = $("demo-banner");
  banner.append(el("b", "Public demo. "), document.createTextNode(
    `Try the built-in samples or upload a small file (up to ${cfg.max_upload_mb} MB). Uploads are analysed in memory and deleted; ` +
    "local paths, system crash records and AI diagnosis are turned off here."));
  banner.hidden = false;
  $("foot").textContent = "Public demo with synthetic sample data. Findings are computed by code from the file; nothing is stored.";
}).catch(() => { /* config is optional: keep the full UI */ });

// Deep links (same actions as the buttons): /?sample=1  /?crashes=PROGRAM  /?path=/some/file.tlog
{
  const q = new URLSearchParams(location.search);
  if (q.has("sample")) {
    const kind = ["tlog", "bin", "crash", "text"].includes(q.get("sample")) ? q.get("sample") : "text";
    document.querySelector(`[data-sample="${kind}"]`).click();
  }
  if (q.has("crashes")) { $("crash-name").value = q.get("crashes"); $("crashes").click(); }
  if (q.has("path")) { $("path").value = q.get("path"); $("analyze-path").click(); }
}
