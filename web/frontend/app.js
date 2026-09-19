/* NIDS dashboard — implementation of the Claude Design "NIDS Dashboard"
 * canvas against the real API.
 *
 * Where this deliberately differs from the design mock:
 *
 *  - The mock generates flows client-side and lets you toggle between
 *    "replay" and "live" data. Here the source is whatever is writing to
 *    the database, so the banner is *derived* from the data (ground truth
 *    present => replay) rather than being a switch. A control that claimed
 *    to change the data source without changing it would be a lie in the
 *    one place this dashboard cannot afford one.
 *  - The mock's "Simulate outage" button is gone for the same reason: it
 *    fakes a fault. Stall detection below is real, driven by how long it
 *    has actually been since a flow arrived.
 *  - Feature names come from the project's own 46 columns, not the mock's
 *    placeholder list, and carry the Thai labels from feature-labels.js.
 *
 * Everything reaching innerHTML goes through esc(). This is a security
 * dashboard rendering attacker-controlled strings (IPs, ports, protocol
 * names, firewall rule text); an XSS here would be delivered by the tool
 * meant to detect it.
 */
"use strict";

const $ = (sel) => document.querySelector(sel);
const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESCAPES[c]);

const POLL_MS = 2000;
const STALL_MS = 15000;
const MAX_TRACKED = 400;
const MAX_ROWS = 200;

const SERVICES = {
  20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
  80: "http", 110: "pop3", 123: "ntp", 137: "netbios", 139: "netbios", 143: "imap",
  161: "snmp", 443: "https", 445: "smb", 502: "modbus", 993: "imaps", 995: "pop3s",
  1883: "mqtt", 3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-alt", 8443: "https-alt",
};

const WINDOWS = ["5m", "10m", "30m", "1h", "4h", "8h", "12h", "24h"];
const CHART_MODES = [
  ["stacked", "Stacked bars"],
  ["split", "Split panels"],
  ["dual", "Overlay"],
];

const state = {
  tab: "live",
  paused: false,
  held: [],
  devMode: false,
  panelOpen: true,
  flows: [],
  cursor: -1,
  pinned: null,
  onlyAnom: false,
  search: "",
  protoFilter: "all",
  minRatio: 0,
  lastSeen: null,
  lastFlowAt: Date.now(),
  connected: false,
  shapState: "empty",
  shapFlow: null,
  shap: null,
  shapAllFeats: false,
  recent: [],
  win: "1h",
  chart: "stacked",
  trend: [],
  range: null,
  drill: [],
  gaps: [],
  gapOnly: false,
  meta: null,
  stats: null,
};
const shapCache = new Map();
let dragging = false;
let anchor = null;

/* ── small helpers ──────────────────────────────────────────────────── */
const f6 = (v) => Number(v).toFixed(6);
const clock = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleTimeString("en-GB", { hour12: false });
};
const ratioOf = (f) => (f.threshold_used ? f.reconstruction_error / f.threshold_used : 0);
const service = (port) => SERVICES[port] || "port " + port;
// feature-labels.js already exports `featureLabel(name) -> {th, group}`
// and `attackExpectation(cls)`. Wrap rather than redeclare -- a second
// top-level `const featureLabel` is a SyntaxError that kills the whole
// script before a single line of it runs.
const labelOf = (col) => featureLabel(col).en;
const groupOf = (col) => featureLabel(col).group;
const unitOf  = (col) => featureLabel(col).unit || "";
const hintOf  = (col) => featureLabel(col).hint || "";

/** z-score back to the quantity an analyst can act on.
 *  Exact, not approximate: the forward path was log1p (on the columns the
 *  pipeline log-transforms) then StandardScaler, and /meta hands over both
 *  constants. Frequency- and one-hot-encoded columns have no physical unit
 *  and say so rather than being dressed up as one. */
function deStandardize(col, z) {
  const m = state.meta && state.meta.features[col];
  if (!m) return null;
  const v = z * m.scale + m.mean;
  if (m.kind === "frequency") return { text: (v * 100).toFixed(2) + "%", note: "of training traffic", kind: m.kind };
  if (m.kind === "onehot") return { text: v > 0.5 ? "yes" : "no", note: "", kind: m.kind };
  // log1p was applied to a clipped, non-negative quantity, so inverting can
  // only legitimately land at or above zero. Float error at the bottom of
  // the range otherwise renders "-0.000 pkt", which reads as a measurement
  // rather than as the zero it is.
  // log1p was applied to a clipped, non-negative quantity, so inverting it
  // can only legitimately land at or above zero.
  let raw = m.log ? Math.expm1(v) : v;
  if (m.log && raw < 0) raw = 0;
  const abs = Math.abs(raw);
  const digits = abs >= 1000 ? 0 : abs >= 10 ? 1 : 3;
  let text = raw.toLocaleString("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits });
  // A value that rounds to zero must not keep a minus sign. None of the 46
  // columns can be negative -- they are counts, bytes, durations, flags --
  // so "-0.000 ms" is the linear un-scaling landing a hair below zero, and
  // rendering the sign turns a rounding artifact into a reading. A number
  // large enough to actually show digits keeps its sign, so a genuinely
  // negative value would still be visible rather than quietly hidden.
  if (/^-0(?:[.,]0+)?$/.test(text)) text = text.slice(1);
  return { text, note: unitOf(col), kind: m.kind };
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(path + " → " + res.status + " " + res.statusText);
  return res.json();
}

/* ── header, stats, status ──────────────────────────────────────────── */
function renderStats() {
  const s = state.stats;
  const thr = state.meta ? state.meta.threshold : (state.flows[0] || {}).threshold_used;
  const secs = Math.max(1, (Date.now() - startedAt) / 1000);
  // The window is named on every counter that is windowed. Without it a
  // quiet last hour reads "Total flows 0" directly above a table of forty
  // flows, and a dashboard that appears to contradict itself is worse than
  // one that is merely dense.
  const w = s ? s.window : "1h";
  const tiles = [
    [`Total flows · ${w}`, s ? s.total_flows.toLocaleString() : "—", ""],
    [`Anomalies · ${w}`, s ? s.anomalies.toLocaleString() : "—", ""],
    [`Anomaly rate · ${w}`, s ? (s.anomaly_rate * 100).toFixed(1) : "—", "%"],
    [`Avg error · ${w}`, s ? f6(s.avg_reconstruction_error) : "—", ""],
    ["Threshold", thr != null ? f6(thr) : "—", ""],
    ["Throughput", (received / secs).toFixed(1), "flow/s"],
    ["Last update", clock(new Date().toISOString()), state.paused ? "paused" : "live"],
  ];
  $("#stats").innerHTML = tiles
    .map(([label, value, unit]) =>
      `<div class="stat"><div class="kicker trunc">${esc(label)}</div>
       <div class="v"><b>${esc(value)}</b><span>${esc(unit)}</span></div></div>`)
    .join("");
}

function renderStatus() {
  const stalled = state.connected && !state.paused && Date.now() - state.lastFlowAt > STALL_MS;
  const el = $("#status");
  el.dataset.state = stalled ? "stalled" : state.paused ? "paused" : "live";
  el.textContent = !state.connected ? "Connecting" : stalled ? "Stream stalled" : state.paused ? "Paused" : "Polling 2s";

  const banner = $("#stall-banner");
  banner.hidden = !stalled;
  if (stalled) {
    const secs = Math.round((Date.now() - state.lastFlowAt) / 1000);
    $("#stall-text").textContent =
      `No flows for ${secs}s — the poller or the capture may be down. This is not a quiet network; ` +
      `the dashboard cannot tell you anything right now.`;
  }

  const anyTruth = state.flows.some((f) => f.true_label !== null && f.true_label !== undefined);
  $("#source-banner").textContent = !state.connected
    ? "Connecting…"
    : anyTruth
      ? "Replay data — labelled, not live traffic"
      : "Live capture — no ground truth available";
  $("#pause-btn").textContent = state.paused ? `Resume (${state.held.length} held)` : "Pause stream";
}

/* ── live: spotlight ────────────────────────────────────────────────── */
function spotlightFlow() {
  return state.pinned || state.flows[0] || null;
}

function renderSpotlight() {
  const f = spotlightFlow();
  if (!f) {
    $("#spot-id").textContent = "—";
    $("#spot-readout").textContent = "Waiting for the first flow.";
    return;
  }
  const r = ratioOf(f);
  const anom = !!f.is_anomaly;
  $("#spot-kicker").textContent = state.pinned ? "Pinned flow · held for inspection" : "Latest flow · spotlight";
  $("#unpin-btn").hidden = !state.pinned;
  $("#spot-id").textContent = f.flow_id;
  $("#spot-time").textContent = clock(f.timestamp) + " UTC";
  $("#spot-src").textContent = `${f.src_ip}:${f.src_port}`;
  $("#spot-dst").textContent = `${f.dst_ip}:${f.dst_port}`;
  $("#spot-proto").textContent = f.protocol;
  $("#spot-service").textContent = service(f.dst_port);
  const v = $("#spot-verdict");
  v.className = "tag-big " + (anom ? "tag-anom" : "tag-normal");
  v.textContent = anom ? "ANOMALOUS" : "NORMAL";
  $("#spot-err").textContent = f6(f.reconstruction_error);
  $("#spot-thr").textContent = f6(f.threshold_used);
  $("#spot-ratio").textContent = r.toFixed(2) + "× threshold";

  const fill = $("#spot-fill");
  fill.style.width = (Math.min(r, 3) / 3) * 100 + "%";
  fill.style.background = anom ? "var(--color-accent-300)" : "var(--color-neutral-400)";
  fill.style.borderRight = "2px solid " + (anom ? "var(--color-accent)" : "var(--color-neutral-700)");

  $("#spot-readout").textContent = anom
    ? `Reconstruction error sits ${r.toFixed(2)}× above the threshold, so this flow is flagged as unusual. ` +
      `Unusual is not the same as an attack — run SHAP to see which features carried the error.`
    : `Error is below threshold (${r.toFixed(2)}×), so the autoencoder reconstructed this flow as ordinary traffic.`;
}

/* ── live: flow table ───────────────────────────────────────────────── */
function visibleFlows() {
  const q = state.search.trim().toLowerCase();
  return state.flows.filter((f) => {
    if (state.onlyAnom && !f.is_anomaly) return false;
    if (state.protoFilter !== "all" && f.protocol !== state.protoFilter) return false;
    if (state.minRatio && ratioOf(f) < state.minRatio) return false;
    if (q) {
      const hay = `${f.src_ip}:${f.src_port} ${f.dst_ip}:${f.dst_port} ${f.flow_id}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }).slice(0, MAX_ROWS);
}

function rowHtml(f, i) {
  const r = ratioOf(f);
  const selected = state.shapFlow && state.shapFlow.flow_id === f.flow_id;
  const truth = state.devMode && f.true_label !== null && f.true_label !== undefined
    ? ((f.true_label === 1) === !!f.is_anomaly ? "✓" : "✗")
    : "";
  const divider = f._heldCount
    ? `<div class="held-divider">↑ ${esc(f._heldCount)} flows arrived while paused</div>`
    : "";
  return divider + `
    <div class="row${f._fresh ? " is-new" : ""}" data-i="${i}" data-flow="${esc(f.flow_id)}"
         data-cursor="${i === state.cursor ? 1 : 0}" data-selected="${selected ? 1 : 0}">
      <span class="num muted">${esc(clock(f.timestamp))}</span>
      <span class="mono trunc">${esc(f.src_ip)}:${esc(f.src_port)}  →  ${esc(f.dst_ip)}:${esc(f.dst_port)}</span>
      <span class="muted">${esc(f.protocol)}</span>
      <span class="num r">${esc(f6(f.reconstruction_error))}</span>
      <span class="num r" style="font-weight:600">${esc(r.toFixed(2))}×</span>
      <span class="verdict-cell"><span class="num dim">${esc(truth)}</span>
        <span class="tag ${f.is_anomaly ? "tag-anom" : "tag-normal"}">${f.is_anomaly ? "anomalous" : "normal"}</span></span>
    </div>`;
}

function renderRows() {
  const vis = visibleFlows();
  $("#rows").innerHTML = vis.map(rowHtml).join("");
  const empty = $("#rows-empty");
  empty.hidden = vis.length > 0;
  if (!vis.length) {
    empty.textContent = state.flows.length
      ? "No flow matches these filters."
      : "No flows yet. Start a feeder: web.backend.replay_demo or web.backend.live_capture.";
  }
  $("#table-note").textContent =
    `${vis.length} of ${state.flows.length} flows` + (state.paused ? " — stream paused" : "");
  vis.forEach((f) => { f._fresh = false; });
}

/* ── explanation panel ──────────────────────────────────────────────── */
function setShapView(which) {
  $("#shap-empty").hidden = which !== "empty";
  $("#shap-loading").hidden = which !== "loading";
  $("#shap-error").hidden = which !== "error";
  $("#shap-ready").hidden = which !== "ready";
}

function renderRecent() {
  const box = $("#recent");
  box.hidden = state.recent.length < 2;
  if (box.hidden) return;
  box.innerHTML = `<span class="kicker">Recent</span>` + state.recent
    .map((f) => {
      const on = state.shapFlow && state.shapFlow.flow_id === f.flow_id;
      return `<button data-flow="${esc(f.flow_id)}" aria-pressed="${on}">${esc(
        f.flow_id.replace(/^(demo|live)-/, "") + "  " + ratioOf(f).toFixed(2) + "×")}</button>`;
    }).join("");
}

function renderShap() {
  const res = state.shap;
  if (!res) return;
  const f = state.shapFlow;
  const entries = state.meta.feature_columns
    .map((col) => ({ col, val: res.shap_values[col] ?? 0, z: res.features[col] ?? 0 }))
    .sort((a, b) => Math.abs(b.val) - Math.abs(a.val));
  const shown = state.shapAllFeats ? entries : entries.slice(0, 8);
  const max = Math.max(...entries.map((e) => Math.abs(e.val))) || 1;
  const sum = entries.reduce((a, e) => a + e.val, 0);

  $("#shap-flow-id").textContent = f.flow_id;
  const v = $("#shap-verdict");
  v.className = "tag-big " + (res.is_anomaly ? "tag-anom" : "tag-normal");
  v.textContent = res.is_anomaly ? "ANOMALOUS" : "NORMAL";
  $("#shap-ratio").textContent =
    (res.reconstruction_error / res.threshold_used).toFixed(2) + "× threshold";
  $("#shap-meta").textContent = Math.round(res.computation_time_ms) + " ms";

  $("#add-base").textContent = f6(res.base_value);
  $("#add-sum").textContent = (sum >= 0 ? "+" : "−") + Math.abs(sum).toFixed(6);
  $("#add-err").textContent = f6(res.reconstruction_error);
  $("#add-res").textContent = f6(Math.abs(res.base_value + sum - res.reconstruction_error));

  $("#feats-heading").textContent = state.shapAllFeats
    ? `All ${entries.length} features` : "Top contributors";
  $("#toggle-feats").textContent = state.shapAllFeats
    ? "− Collapse to top 8" : `+ Show all ${entries.length} features`;
  $("#feats").dataset.expanded = state.shapAllFeats ? "1" : "0";

  $("#feats").innerHTML = shown.map((e) => {
    const w = (Math.abs(e.val) / max) * 50;
    const pos = e.val >= 0;
    const raw = deStandardize(e.col, e.z);
    const tip = [e.col, hintOf(e.col)].filter(Boolean).join(" — ");
    return `<div class="feat" data-group="${esc(groupOf(e.col))}">
      <div class="l">
        <span class="name trunc" title="${esc(tip)}">${esc(labelOf(e.col))}</span>
        <span class="vals">
          <span class="raw">${esc(raw ? raw.text : "—")}</span><span class="unit">${esc(raw ? raw.note : "")}</span>
          <span class="z" title="distance from normal traffic, in standard deviations">z ${esc(e.z.toFixed(2))}</span>
        </span>
      </div>
      <div class="track">
        <div class="bar"><span class="axis"></span>
          <i style="left:${pos ? 50 : 50 - w}%;width:${w}%;background:${pos ? "var(--color-accent)" : "var(--color-neutral-600)"}"></i>
        </div>
        <span class="val">${esc((pos ? "+" : "−") + Math.abs(e.val).toFixed(6))}</span>
      </div>
    </div>`;
  }).join("");

  // Ground truth only exists for replayed flows, and only shows when the
  // user has opted into dev mode. Live traffic has no label and never will.
  const hasTruth = state.devMode && res.true_label !== null && res.true_label !== undefined;
  $("#truth").hidden = !hasTruth;
  if (hasTruth) {
    const isAttack = res.true_label === 1;
    const correct = isAttack === !!res.is_anomaly;
    $("#truth-label").textContent = isAttack ? res.true_attack : "benign";
    const tv = $("#truth-verdict");
    tv.className = "tag " + (correct ? "tag-normal" : "tag-anom");
    tv.textContent = correct ? "correct" : "incorrect";
    const exp = typeof attackExpectation === "function" ? attackExpectation(res.true_attack) : null;
    $("#truth-expect").textContent = isAttack
      ? (exp
          ? (exp.expect.length
              ? `${exp.th} — ${exp.why}. Expect these to dominate: ${exp.expect.map(labelOf).join(", ")}.`
              : `${exp.th} — ${exp.why}. There is no NetFlow signature for this class, so a flag here is coincidental rather than evidence.`)
          : "Labelled as an attack; no per-class expectation recorded.")
      : "Labelled normal traffic. A flag here is a false positive — expected at roughly the measured 4.97% rate.";
  }
  setShapView("ready");
}

async function explain(flow, force) {
  if (!flow) return;
  state.pinned = flow;
  state.shapFlow = flow;
  state.recent = [flow, ...state.recent.filter((x) => x.flow_id !== flow.flow_id)].slice(0, 3);
  renderRecent();
  renderSpotlight();
  renderRows();

  if (!force && shapCache.has(flow.flow_id)) {
    state.shap = shapCache.get(flow.flow_id);
    state.shapState = "ready";
    renderShap();
    return;
  }
  state.shapState = "loading";
  $("#shap-loading-text").textContent = `Computing SHAP for ${flow.flow_id}…`;
  $("#shap-meta").textContent = "running…";
  setShapView("loading");
  try {
    const res = await api(`/explain/${encodeURIComponent(flow.flow_id)}`, { method: "POST" });
    shapCache.set(flow.flow_id, res);
    state.shap = res;
    state.shapState = "ready";
    renderShap();
  } catch (err) {
    state.shapState = "error";
    $("#shap-error-msg").textContent =
      `${err.message}. The flow itself is unaffected — the verdict above still stands.`;
    setShapView("error");
  }
}

/* ── trend chart ────────────────────────────────────────────────────── */
const W = 1000, H = 300, VOL_BASE = H - 8;

function rateY(r) { return state.chart === "split" ? 8 + (1 - r) * 175 : H - r * H * 0.92 - 8; }

function renderTrend() {
  const pts = state.trend;
  const mode = state.chart;
  const showLine = mode !== "stacked";
  const showVol = mode !== "stacked";
  const showStack = mode === "stacked";
  const showRight = mode !== "stacked";
  const maxCount = Math.max(1, ...pts.map((p) => p.count || 0));
  const bw = W / Math.max(1, pts.length);
  const volSpan = mode === "split" ? 80 : H - 40;
  const parts = [];

  // grid
  const grid = [1, 0.75, 0.5, 0.25, 0].map((r) => {
    const y = mode === "stacked" ? VOL_BASE - r * (H - 40) : rateY(r);
    return { r, y, label: mode === "stacked" ? Math.round(maxCount * r).toLocaleString() : (r * 100).toFixed(0) + "%" };
  });
  grid.forEach((g) => parts.push(
    `<line x1="0" x2="1000" y1="${g.y.toFixed(1)}" y2="${g.y.toFixed(1)}" stroke="${g.r === 0 ? "#201e1d" : "#cfcbcb"}" stroke-width="${g.r === 0 ? 2 : 1}" vector-effect="non-scaling-stroke"></line>`));

  if (showVol) pts.forEach((p, i) => {
    const h = ((p.count || 0) / maxCount) * volSpan;
    parts.push(`<rect x="${(i * bw).toFixed(1)}" y="${(VOL_BASE - h).toFixed(1)}" width="${(bw * 0.86).toFixed(1)}" height="${h.toFixed(1)}" fill="#d7d3d3"></rect>`);
  });
  if (showStack) pts.forEach((p, i) => {
    const h = ((p.count || 0) / maxCount) * (H - 40);
    const ha = h * (p.anomaly_rate || 0);
    parts.push(`<rect x="${(i * bw).toFixed(1)}" y="${(VOL_BASE - h).toFixed(1)}" width="${(bw * 0.82).toFixed(1)}" height="${h.toFixed(1)}" fill="#d7d3d3"></rect>`);
    parts.push(`<rect x="${(i * bw).toFixed(1)}" y="${(VOL_BASE - ha).toFixed(1)}" width="${(bw * 0.82).toFixed(1)}" height="${ha.toFixed(1)}" fill="#ec3013"></rect>`);
  });
  if (mode === "split") parts.push(`<line x1="0" x2="1000" y1="200" y2="200" stroke="#201e1d" stroke-width="2" vector-effect="non-scaling-stroke"></line>`);

  // A bucket with no traffic is hatched, never drawn as 0% — "nothing
  // happened" and "everything was benign" are different facts and the
  // chart must not merge them.
  pts.forEach((p, i) => {
    if (p.anomaly_rate === null) {
      const x = pts.length > 1 ? (i / (pts.length - 1)) * W : 0;
      parts.push(`<rect x="${Math.max(0, x - bw / 2).toFixed(1)}" y="0" width="${bw.toFixed(1)}" height="300" fill="url(#nidsHatch)"></rect>`);
    }
  });

  if (showLine) {
    const segs = [];
    let cur = [];
    pts.forEach((p, i) => {
      if (p.anomaly_rate === null) { if (cur.length) segs.push(cur); cur = []; return; }
      cur.push({ x: pts.length > 1 ? (i / (pts.length - 1)) * W : 0, y: rateY(p.anomaly_rate), rate: p.anomaly_rate });
    });
    if (cur.length) segs.push(cur);
    segs.forEach((g) => {
      const m = Math.max(...g.map((p) => p.rate));
      const color = m > 0.6 ? "#ec3013" : m > 0.3 ? "#c98a0f" : "#4d6b3d";
      parts.push(`<polyline points="${g.map((p) => p.x.toFixed(1) + "," + p.y.toFixed(1)).join(" ")}" fill="none" stroke="${color}" stroke-width="2.5" vector-effect="non-scaling-stroke"></polyline>`);
    });
  }
  $("#chart-body").innerHTML = parts.join("");

  // axes
  $("#axis-l-title").textContent = mode === "stacked" ? "Flows / bucket" : "Anomaly rate";
  $("#axis-l").querySelectorAll(".axis-tick").forEach((n) => n.remove());
  grid.forEach((g) => {
    const el = document.createElement("span");
    el.className = "axis-tick";
    el.dataset.major = g.r === 0 ? "1" : "0";
    el.style.top = ((g.y / H) * 100).toFixed(2) + "%";
    el.textContent = g.label;
    $("#axis-l").appendChild(el);
  });
  $("#axis-r").hidden = !showRight;
  $("#x-spacer-r").hidden = !showRight;
  if (showRight) {
    $("#axis-r").querySelectorAll(".axis-tick").forEach((n) => n.remove());
    [1, 0.5, 0].forEach((r) => {
      const y = VOL_BASE - r * volSpan;
      const el = document.createElement("span");
      el.className = "axis-tick";
      el.style.top = ((y / H) * 100).toFixed(2) + "%";
      el.textContent = Math.round(maxCount * r).toLocaleString();
      $("#axis-r").appendChild(el);
    });
  }

  // interactive columns
  const cells = $("#cells");
  cells.style.gridTemplateColumns = `repeat(${pts.length || 60},1fr)`;
  const rg = state.range;
  cells.innerHTML = pts.map((p, i) => {
    const inSel = rg && i >= rg[0] && i <= rg[1];
    const edge = inSel && i === rg[0] ? "lo" : inSel && i === rg[1] ? "hi" : "";
    return `<button data-i="${i}" data-sel="${inSel ? 1 : 0}" data-edge="${edge}" aria-label="bucket ${i + 1}"></button>`;
  }).join("");

  $("#x-ticks").innerHTML = pts.length
    ? [0, 0.2, 0.4, 0.6, 0.8, 1]
        .map((p) => `<span>${esc(clock(pts[Math.min(pts.length - 1, Math.round(p * (pts.length - 1)))].t))}</span>`)
        .join("")
    : "";

  const live = pts.filter((p) => p.anomaly_rate !== null);
  $("#trend-peak").textContent = live.length ? (Math.max(...live.map((p) => p.anomaly_rate)) * 100).toFixed(0) + "%" : "—";
  $("#trend-mean").textContent = live.length ? ((live.reduce((a, b) => a + b.anomaly_rate, 0) / live.length) * 100).toFixed(1) + "%" : "—";
  $("#trend-nulls").textContent = `${pts.length - live.length} of ${pts.length}`;

  $("#chart-caption").textContent = mode === "stacked"
    ? "One bar per bucket — height is how many flows, the red part is how many were flagged. No second axis to read."
    : mode === "split"
      ? "Rate on top, volume underneath — same time axis, nothing overlaps."
      : "Rate line over volume bars — compact, but two scales to hold in your head.";

  const legend = mode === "stacked"
    ? [["var(--color-accent)", "12px", "flagged anomalous"], ["var(--color-neutral-300)", "12px", "normal traffic"], ["hatch", "12px", "no traffic (null)"]]
    : [["var(--color-accent)", "3px", "anomaly rate (left axis)"], ["var(--color-neutral-300)", "12px", "flows per bucket (right axis)"], ["hatch", "12px", "no traffic (null)"]];
  $("#legend").innerHTML = legend.map(([c, h, label]) => {
    const bg = c === "hatch"
      ? "repeating-linear-gradient(45deg,var(--color-neutral-300) 0 3px,transparent 3px 6px)"
      : c;
    const ring = c === "hatch" ? "box-shadow:inset 0 0 0 1px var(--color-neutral-400);" : "";
    return `<span><i style="width:${c === "hatch" ? 14 : 13}px;height:${h};background:${bg};${ring}"></i>${esc(label)}</span>`;
  }).join("");
}

function renderInsights() {
  const flows = state.flows;
  const total = Math.max(1, flows.length);
  const count = (keyFn) => {
    const m = new Map();
    flows.forEach((f) => { const k = keyFn(f); m.set(k, (m.get(k) || 0) + 1); });
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  };
  const cols = [
    ["Protocol mix", count((f) => f.protocol)],
    ["Top source IPs", count((f) => f.src_ip)],
    ["Top destination ports", count((f) => `${f.dst_port} (${service(f.dst_port)})`)],
  ];
  $("#insights").innerHTML = cols.map(([title, items]) => `
    <div class="insight">
      <div class="kicker kicker-accent">${esc(title)}</div>
      <div class="items">${items.map(([k, v]) => {
        const pct = Math.round((v / total) * 100);
        return `<div><div class="kv"><span class="mono trunc">${esc(k)}</span><span class="muted">${pct}%</span></div>
                <div class="track"><i style="width:${pct}%"></i></div></div>`;
      }).join("")}</div>
    </div>`).join("");
}

/* ── trend drill-down ───────────────────────────────────────────────── */
async function applyRange(a, b) {
  const pts = state.trend;
  const lo = Math.min(a, b), hi = Math.max(a, b);
  if (!pts[lo] || !pts[hi]) return;
  state.range = [lo, hi];
  renderTrend();

  const step = pts.length > 1 ? new Date(pts[1].t) - new Date(pts[0].t) : 60000;
  const since = pts[lo].t;
  const until = new Date(new Date(pts[hi].t).getTime() + step).toISOString();
  const selected = pts.slice(lo, hi + 1);
  const liveB = selected.filter((p) => p.anomaly_rate !== null);
  const nulls = selected.length - liveB.length;
  const count = liveB.reduce((a2, b2) => a2 + b2.count, 0);
  const rate = count ? liveB.reduce((a2, b2) => a2 + b2.count * b2.anomaly_rate, 0) / count : 0;

  $("#drill").hidden = false;
  $("#drill-title").textContent = `${clock(since)} – ${clock(until)}`;
  $("#drill-meta").textContent = liveB.length
    ? `${selected.length} bucket${selected.length === 1 ? "" : "s"} · ${count.toLocaleString()} flows · ${(rate * 100).toFixed(0)}% anomalous${nulls ? ` · ${nulls} silent` : ""}`
    : selected.length === 1 ? "no traffic in this bucket" : `no traffic across ${selected.length} buckets`;
  $("#drill-note").textContent = liveB.length
    ? "Sampled across the selection, highest error first. Click a row to explain it — the flow is pinned on the Live tab."
    : "The model saw nothing here — silence, not a clean period. Nothing to inspect.";

  if (!liveB.length) { state.drill = []; $("#drill-table").hidden = true; return; }
  try {
    const res = await api(`/alerts?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}&limit=60`);
    state.drill = res.flows;
    $("#drill-table").hidden = res.flows.length === 0;
    $("#drill-rows").innerHTML = res.flows.map((f) => `
      <div class="drill-row" data-flow="${esc(f.flow_id)}">
        <span class="num muted">${esc(clock(f.timestamp))}</span>
        <span class="mono trunc">${esc(f.flow_id)}</span>
        <span class="mono trunc">${esc(f.src_ip)}:${esc(f.src_port)}  →  ${esc(f.dst_ip)}:${esc(f.dst_port)}</span>
        <span class="muted">${esc(f.protocol)}</span>
        <span class="num r">${esc(f6(f.reconstruction_error))}</span>
        <span class="num r" style="font-weight:600">${esc(ratioOf(f).toFixed(2))}×</span>
        <span class="r"><span class="tag ${f.is_anomaly ? "tag-anom" : "tag-normal"}">${f.is_anomaly ? "anomalous" : "normal"}</span></span>
      </div>`).join("");
  } catch (err) {
    state.drill = [];
    $("#drill-table").hidden = true;
    $("#drill-note").textContent = "Could not load flows for this span: " + err.message;
  }
}

/* ── firewall gaps ──────────────────────────────────────────────────── */
function renderGaps() {
  const rows = state.gapOnly ? state.gaps.filter((g) => g.gap_detected === 1) : state.gaps;
  const assess = (g) => g.gap_detected === null ? "insufficient data" : g.gap_detected ? "GAP" : "covered";
  const cls = (g) => g.gap_detected === null ? "tag-unknown" : g.gap_detected ? "tag-anom" : "tag-normal";
  $("#gap-rows").innerHTML = rows.map((g) => `
    <div class="gap-row" data-flow="${esc(g.flow_id)}"
         data-selected="${state.shapFlow && state.shapFlow.flow_id === g.flow_id ? 1 : 0}">
      <span class="num muted">${esc(clock(g.timestamp))}</span>
      <span class="mono trunc">${esc(g.flow_id)}</span>
      <span class="mono trunc">${esc(g.src_ip)} → ${esc(g.dst_ip)}</span>
      <span class="num r">${esc(f6(g.reconstruction_error))}</span>
      <span class="mono trunc muted" style="font-size:11px">${esc(g.firewall_action_logged || "—")}</span>
      <span class="r"><span class="tag ${cls(g)}">${esc(assess(g))}</span></span>
    </div>`).join("");
  const empty = $("#gaps-empty");
  empty.hidden = rows.length > 0;
  if (!rows.length) {
    empty.textContent = state.gaps.length
      ? "No GAP rows in the current set."
      : "No firewall comparison has been run yet. Produce a rule file and run " +
        "python -m source.firewall_check.ryu_log_compare.";
  }
  $("#gap-count").textContent = state.gaps.filter((g) => g.gap_detected === 1).length;
  $("#covered-count").textContent = state.gaps.filter((g) => g.gap_detected === 0).length;
  $("#unknown-count").textContent = state.gaps.filter((g) => g.gap_detected === null).length;
}

/* ── polling ────────────────────────────────────────────────────────── */
let startedAt = Date.now();
let received = 0;

function ingest(flows) {
  if (!flows.length) return;
  state.lastSeen = flows[0].timestamp;
  state.lastFlowAt = Date.now();
  received += flows.length;
  flows.forEach((f) => { f._fresh = true; });
  if (state.paused) {
    state.held = flows.concat(state.held).slice(0, MAX_TRACKED);
    return;
  }
  state.flows = flows.concat(state.flows).slice(0, MAX_TRACKED);
}

async function pollAlerts() {
  const url = state.lastSeen
    ? `/alerts?since=${encodeURIComponent(state.lastSeen)}&limit=200`
    : "/alerts?limit=50";
  const first = !state.lastSeen;
  const data = await api(url);
  if (first) {
    // The opening batch is history, not arrivals; counting it as throughput
    // would show a burst that never happened.
    state.lastSeen = data.flows.length ? data.flows[0].timestamp : new Date().toISOString();
    data.flows.forEach((f) => { f._fresh = false; });
    state.flows = data.flows.slice(0, MAX_TRACKED);
    state.lastFlowAt = Date.now();
  } else {
    ingest(data.flows);
  }
  state.connected = true;
}

async function pollStats() {
  state.stats = await api("/stats?window=1h");
}

async function pollTrend() {
  const res = await api(`/stats/trend?window=${encodeURIComponent(state.win)}&buckets=60`);
  state.trend = res.buckets;
}

async function pollGaps() {
  const res = await api("/firewall-gaps?limit=200&gaps_only=false");
  state.gaps = res.gaps;
}

async function tick() {
  try {
    await pollAlerts();
    await pollStats();
    if (state.tab === "trend" && !state.range) await pollTrend();
    if (state.tab === "gaps") await pollGaps();
  } catch (err) {
    state.connected = false;
    console.error("poll failed:", err);
  }
  renderStats();
  renderStatus();
  if (state.tab === "live") { renderSpotlight(); renderRows(); }
  if (state.tab === "trend") { renderTrend(); renderInsights(); }
  if (state.tab === "gaps") renderGaps();
}

/* ── wiring ─────────────────────────────────────────────────────────── */
function setTab(tab) {
  state.tab = tab;
  ["live", "trend", "gaps"].forEach((t) => {
    $(`#tab-${t}`).setAttribute("aria-selected", String(t === tab));
    $(`#view-${t}`).hidden = t !== tab;
  });
  $("#tab-hint").textContent = tab === "live"
    ? "Click any flow to explain it"
    : tab === "trend" ? "Silent buckets are drawn as gaps, never as 0%" : "Only this model sees these";
  if (tab === "trend") pollTrend().then(() => { renderTrend(); renderInsights(); }).catch(console.error);
  if (tab === "gaps") pollGaps().then(renderGaps).catch(console.error);
}

function flowById(id) {
  return state.flows.find((f) => f.flow_id === id)
      || state.drill.find((f) => f.flow_id === id)
      || state.recent.find((f) => f.flow_id === id)
      || null;
}

async function explainById(id) {
  let f = flowById(id);
  if (!f) {
    try { f = await api(`/flow/${encodeURIComponent(id)}`); } catch { return; }
  }
  explain(f);
}

function togglePause() {
  if (!state.paused) { state.paused = true; renderStatus(); renderStats(); return; }
  const held = state.held;
  if (held.length) {
    held[held.length - 1]._heldCount = held.length;
    state.flows = held.concat(state.flows).slice(0, MAX_TRACKED);
  }
  state.held = [];
  state.paused = false;
  renderStatus(); renderStats(); renderRows(); renderSpotlight();
}

function moveCursor(d) {
  const vis = visibleFlows();
  if (!vis.length) return;
  state.cursor = Math.max(0, Math.min(vis.length - 1, state.cursor < 0 ? 0 : state.cursor + d));
  renderRows();
  const el = $(`.row[data-i="${state.cursor}"]`);
  if (el) el.scrollIntoView({ block: "nearest" });
}

function init() {
  $("#pause-btn").addEventListener("click", togglePause);
  $("#dev-toggle").addEventListener("change", (e) => {
    state.devMode = e.target.checked;
    renderRows();
    if (state.shap) renderShap();
  });
  ["live", "trend", "gaps"].forEach((t) => $(`#tab-${t}`).addEventListener("click", () => setTab(t)));

  $("#only-anom").addEventListener("change", (e) => { state.onlyAnom = e.target.checked; state.cursor = -1; renderRows(); });
  $("#search").addEventListener("input", (e) => { state.search = e.target.value; state.cursor = -1; renderRows(); });
  $("#proto-filter").addEventListener("change", (e) => { state.protoFilter = e.target.value; state.cursor = -1; renderRows(); });
  $("#min-ratio").addEventListener("input", (e) => {
    state.minRatio = Number(e.target.value);
    $("#ratio-label").textContent = state.minRatio ? `≥ ${state.minRatio.toFixed(1)}× thr` : "any × thr";
    state.cursor = -1; renderRows();
  });
  $("#clear-filters").addEventListener("click", () => {
    Object.assign(state, { search: "", protoFilter: "all", minRatio: 0, onlyAnom: false, cursor: -1 });
    $("#search").value = ""; $("#proto-filter").value = "all";
    $("#min-ratio").value = 0; $("#only-anom").checked = false;
    $("#ratio-label").textContent = "any × thr";
    renderRows();
  });

  $("#rows").addEventListener("click", (e) => {
    const row = e.target.closest(".row");
    if (!row) return;
    state.cursor = Number(row.dataset.i);
    explainById(row.dataset.flow);
  });
  $("#explain-spot").addEventListener("click", () => explain(spotlightFlow()));
  $("#unpin-btn").addEventListener("click", () => {
    state.pinned = null; state.shapFlow = null; state.shap = null;
    state.shapState = "empty"; setShapView("empty");
    $("#shap-meta").textContent = "on request";
    renderSpotlight(); renderRows();
  });
  $("#retry-shap").addEventListener("click", () => explain(state.shapFlow, true));
  $("#recent").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-flow]");
    if (b) explainById(b.dataset.flow);
  });
  $("#toggle-feats").addEventListener("click", () => { state.shapAllFeats = !state.shapAllFeats; renderShap(); });
  $("#panel-toggle").addEventListener("click", () => setPanel(false));
  $("#panel-reopen").addEventListener("click", () => setPanel(true));

  $("#window-seg").innerHTML = WINDOWS.map((w) =>
    `<button data-w="${w}" aria-pressed="${w === state.win}">${w}</button>`).join("");
  $("#window-seg").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-w]");
    if (!b) return;
    state.win = b.dataset.w;
    state.range = null; state.drill = []; $("#drill").hidden = true;
    $("#window-seg").querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.w === state.win)));
    await pollTrend(); renderTrend();
  });

  $("#chart-seg").innerHTML = CHART_MODES.map(([id, label]) =>
    `<button data-m="${id}" aria-pressed="${id === state.chart}">${esc(label)}</button>`).join("");
  $("#chart-seg").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-m]");
    if (!b) return;
    state.chart = b.dataset.m;
    $("#chart-seg").querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.m === state.chart)));
    renderTrend();
  });

  $("#cells").addEventListener("mousedown", (e) => {
    const b = e.target.closest("button[data-i]");
    if (!b) return;
    const i = Number(b.dataset.i);
    if (e.shiftKey && state.range) { applyRange(anchor ?? state.range[0], i); return; }
    dragging = true; anchor = i; applyRange(i, i);
  });
  $("#cells").addEventListener("mouseover", (e) => {
    if (!dragging) return;
    const b = e.target.closest("button[data-i]");
    if (b) applyRange(anchor, Number(b.dataset.i));
  });
  window.addEventListener("mouseup", () => { dragging = false; });
  $("#drill-close").addEventListener("click", () => {
    state.range = null; state.drill = []; $("#drill").hidden = true; renderTrend();
  });
  $("#drill-rows").addEventListener("click", (e) => {
    const row = e.target.closest(".drill-row");
    if (!row) return;
    setTab("live");
    explainById(row.dataset.flow);
  });

  $("#gap-only").addEventListener("change", (e) => { state.gapOnly = e.target.checked; renderGaps(); });
  $("#gap-rows").addEventListener("click", (e) => {
    const row = e.target.closest(".gap-row");
    if (!row) return;
    setTab("live");
    explainById(row.dataset.flow);
  });

  window.addEventListener("keydown", (e) => {
    const tag = e.target.tagName;
    if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
    if (e.code === "Space") { e.preventDefault(); togglePause(); return; }
    if (e.key === "j" || e.key === "ArrowDown") { e.preventDefault(); moveCursor(1); return; }
    if (e.key === "k" || e.key === "ArrowUp") { e.preventDefault(); moveCursor(-1); return; }
    if (e.key === "Enter") { const v = visibleFlows(); const f = v[Math.max(0, state.cursor)]; if (f) explain(f); return; }
    if (e.key === "Escape") { $("#unpin-btn").click(); state.cursor = -1; renderRows(); }
  });

  setInterval(() => { renderStats(); renderStatus(); }, 1000);
  setInterval(tick, POLL_MS);
}

function setPanel(open) {
  state.panelOpen = open;
  $("#panel-open").hidden = !open;
  $("#panel-reopen").hidden = open;
  $("#view-live").dataset.panel = open ? "open" : "collapsed";
}

(async function start() {
  init();
  try {
    state.meta = await api("/meta");
    const m = state.meta.metrics;
    if (m) {
      $("#foot-metrics").textContent =
        `Test set ${(m.n_test_rows / 1e6).toFixed(1)}M flows — recall ${(m.recall * 100).toFixed(2)}% · ` +
        `FPR ${(m.fpr * 100).toFixed(2)}% · precision ${(m.precision * 100).toFixed(2)}%`;
    }
  } catch (err) {
    // Without /meta the SHAP panel cannot de-standardize, but everything
    // else works — degrade rather than show a blank page.
    console.error("/meta unavailable:", err);
    $("#foot-metrics").textContent = "Model metadata unavailable";
  }
  await tick();
})();
