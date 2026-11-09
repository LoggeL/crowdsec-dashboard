/* CrowdSec Defense Grid – Frontend (ohne Abhängigkeiten).
   Alle Daten aus der API gelten als nicht vertrauenswürdig: Ausgabe nur über textContent. */
"use strict";

// ------------------------------------------------------------------ Hilfsfunktionen
const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const nf = new Intl.NumberFormat("de-DE");
const fmt = (n) => nf.format(n);
const regionNames = (() => { try { return new Intl.DisplayNames(["de"], { type: "region" }); } catch { return null; } })();
const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null) continue;
    if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c) el.append(c);
  return el;
}
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* egal */ } },
  sget(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  sset(k, v) { try { sessionStorage.setItem(k, v); } catch { /* egal */ } },
};

function countryName(cc) {
  if (!cc) return "Unbekannt";
  try { return regionNames?.of(cc) || cc; } catch { return cc; }
}
function flag(cc) {
  if (!/^[A-Z]{2}$/.test(cc || "")) return "🏴";
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0)));
}
const shortScenario = (sc) => (sc || "–").replace(/^crowdsecurity\//, "");
const pad = (n) => String(n).padStart(2, "0");
function fmtTime(d, withSec = false) {
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}. ${pad(d.getHours())}:${pad(d.getMinutes())}${withSec ? ":" + pad(d.getSeconds()) : ""}`;
}
function fmtDur(sec) {
  if (sec == null) return "–";
  if (sec <= 0) return "abgelaufen";
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} T ${hh} h`;
  if (hh) return `${hh} h ${pad(m)} min`;
  return `${Math.max(m, 1)} min`;
}
function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
const ORIGINS = {
  crowdsec: { label: "Lokal erkannt", cls: "crowdsec" },
  cscli: { label: "Manuell (cscli)", cls: "cscli" },
  CAPI: { label: "Community (CAPI)", cls: "capi" },
  lists: { label: "Blocklisten", cls: "lists" },
};
const originInfo = (o) => ORIGINS[o] || { label: o || "Sonstige", cls: "other" };

// Ungefähre Schwerpunkte (Breite, Länge) – genug für die Radar-Peilung.
const CENTROIDS = {
  AE:[24,54],AF:[33,65],AL:[41,20],AM:[40,45],AO:[-12.5,18.5],AR:[-34,-64],AT:[47.5,14.5],AU:[-25,134],AZ:[40.5,47.5],BA:[44,17.8],
  BD:[24,90],BE:[50.8,4.5],BG:[42.7,25.3],BH:[26,50.5],BN:[4.5,114.7],BO:[-17,-65],BR:[-10,-52],BW:[-22,24],BY:[53.7,28],BZ:[17.2,-88.7],
  CA:[56,-106],CH:[46.8,8.2],CI:[7.5,-5.5],CL:[-33,-71],CM:[6,12.5],CN:[35,103],CO:[4,-73],CR:[10,-84],CU:[21.5,-79],CY:[35,33],
  CZ:[49.8,15.5],DE:[51,10],DK:[56,10],DO:[19,-70.5],DZ:[28,3],EC:[-1.5,-78],EE:[58.7,25.5],EG:[27,30],ES:[40,-4],ET:[9,39],
  FI:[64,26],FJ:[-17.8,178],FR:[46.5,2.5],GB:[54,-2],GE:[42,43.5],GH:[8,-1.2],GR:[39,22],GT:[15.5,-90.3],HK:[22.3,114.2],HN:[15,-86.5],
  HR:[45.1,15.5],HU:[47,19.5],ID:[-2.5,118],IE:[53.3,-8],IL:[31.5,34.8],IN:[21,78],IQ:[33,44],IR:[32.5,54],IS:[65,-18],IT:[42.8,12.5],
  JM:[18.1,-77.3],JO:[31,36],JP:[36,138],KE:[0.5,38],KG:[41.5,74.5],KH:[12.5,105],KP:[40,127],KR:[36.5,127.8],KW:[29.3,47.6],KZ:[48,67],
  LA:[18,103],LB:[33.9,35.9],LK:[7.8,80.7],LT:[55.3,24],LU:[49.8,6.1],LV:[57,25],LY:[27,17],MA:[32,-6],MD:[47,28.5],ME:[42.7,19.3],
  MG:[-19,47],MK:[41.6,21.7],MM:[21,96],MN:[46.8,103],MO:[22.2,113.5],MT:[35.9,14.4],MU:[-20.3,57.6],MX:[23.5,-102],MY:[4,102],MZ:[-18,35],
  NA:[-22,17],NG:[9,8],NI:[12.9,-85],NL:[52.2,5.5],NO:[61,9],NP:[28.2,84],NZ:[-41,174],OM:[21,57],PA:[8.5,-80],PE:[-9.5,-75],
  PG:[-6.5,145],PH:[12.5,122],PK:[30,70],PL:[52,19.5],PR:[18.2,-66.5],PT:[39.5,-8],PY:[-23,-58],QA:[25.3,51.2],RO:[45.9,25],RS:[44,21],
  RU:[55.7,37.6],SA:[24,45],SC:[-4.6,55.5],SD:[15,30],SE:[62,15],SG:[1.35,103.8],SI:[46.1,14.8],SK:[48.7,19.5],SN:[14.5,-14.5],SV:[13.7,-89],
  SY:[35,38.5],TH:[15,101],TJ:[38.8,71],TM:[39,59.5],TN:[34,9],TR:[39,35],TT:[10.7,-61.2],TW:[23.7,121],TZ:[-6,35],UA:[49,32],
  UG:[1.3,32.3],US:[39,-98],UY:[-33,-56],UZ:[41.5,64.5],VE:[7,-66],VN:[16,107],XK:[42.6,20.9],YE:[15.5,47.5],ZA:[-29,24],ZM:[-13,28],ZW:[-19,29.5],
};

// ------------------------------------------------------------------ Zustand
const state = {
  data: null,
  range: ["24h", "7d", "30d"].includes(store.get("csd.range")) ? store.get("csd.range") : "24h",
  f: { scenario: "", country: "", q: "" },
  tab: "alerts",
  seen: null,          // IDs der schon gezeigten Alerts (für "frisch"-Animation)
  freshIds: new Set(),
  loading: false,
  bootReady: false,
  timer: null,
};

// ------------------------------------------------------------------ Tooltip
const tip = $("tooltip");
function showTip(target, lines, evt) {
  tip.replaceChildren(...lines);
  tip.hidden = false;
  const r = target.getBoundingClientRect();
  const x = evt?.clientX ?? r.left + r.width / 2;
  const y = evt?.clientY ?? r.top;
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  let left = x + 14, top = y - th - 12;
  if (left + tw > innerWidth - 8) left = x - tw - 14;
  if (top < 8) top = y + 18;
  tip.style.left = `${Math.max(8, left)}px`;
  tip.style.top = `${top}px`;
}
const hideTip = () => { tip.hidden = true; };
function tipLines(value, label, sub) {
  return [h("div", { class: "tt-value", text: value }), h("div", { class: "tt-label", text: label }), sub ? h("div", { class: "tt-sub", text: sub }) : null].filter(Boolean);
}
function bindTip(el, fn) {
  el.addEventListener("pointermove", (e) => showTip(el, fn(), e));
  el.addEventListener("pointerleave", hideTip);
  el.addEventListener("focus", () => showTip(el, fn()));
  el.addEventListener("blur", hideTip);
}

// ------------------------------------------------------------------ Filter
function matchQ(a, q) {
  return a.ip.toLowerCase().includes(q) || a.as.toLowerCase().includes(q) || a.asn.includes(q) ||
    a.machine.toLowerCase().includes(q) || a.scenario.toLowerCase().includes(q);
}
/** Filtert Alerts; `skip` lässt eine Dimension aus (Kreuzfilter: eine Liste filtert sich nicht selbst weg). */
function filterAlerts(skip) {
  const { scenario, country, q } = state.f;
  const ql = q.trim().toLowerCase();
  return (state.data?.alerts || []).filter((a) =>
    (skip === "scenario" || !scenario || a.scenario === scenario) &&
    (skip === "country" || !country || a.cn === country) &&
    (!ql || matchQ(a, ql)));
}
const hasFilter = () => !!(state.f.scenario || state.f.country || state.f.q.trim());
function setFilter(patch) {
  Object.assign(state.f, patch);
  $("f-search").value = state.f.q;
  render();
}
function countBy(list, key) {
  const m = new Map();
  for (const a of list) { const k = key(a); m.set(k, (m.get(k) || 0) + 1); }
  return [...m.entries()].sort((x, y) => y[1] - x[1]);
}

// ------------------------------------------------------------------ Laden
async function load({ boot = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  $("main").classList.toggle("loading", !!state.data);
  $("refresh").classList.add("spin");
  try {
    const res = await fetch(`api/summary?range=${encodeURIComponent(state.range)}`, { headers: { Accept: "application/json" } });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    const prevSeen = state.seen;
    state.seen = new Set(body.alerts.map((a) => a.id));
    state.freshIds = prevSeen ? new Set(body.alerts.filter((a) => !prevSeen.has(a.id)).map((a) => a.id)) : new Set();
    state.data = body;
    setStatus(body.warnings?.length ? "warn" : "ok", `${body.demo ? "DEMO" : "LINK OK"} · ${fmtTime(new Date(body.generated_at), true)}`);
    showBanner(body);
    render();
  } catch (err) {
    setStatus("err", "KEINE VERBINDUNG");
    showBanner(null, err.message);
  } finally {
    state.loading = false;
    $("main").classList.remove("loading");
    $("refresh").classList.remove("spin");
    if (boot) bootFinish();
  }
}
function setStatus(kind, text) {
  $("led").className = `led ${kind}`;
  $("status-text").textContent = text;
}
function showBanner(data, error) {
  const b = $("banner");
  const lines = [];
  if (error) lines.push(["Verbindungsfehler:", ` ${error} – angezeigt werden die zuletzt geladenen Daten.`]);
  for (const w of data?.warnings || []) lines.push(["Hinweis:", ` ${w}`]);
  if (data?.alerts_truncated) lines.push(["Gekürzt:", ` Nur die neuesten ${fmt(data.alert_limit)} Alerts geladen – für mehr ALERT_LIMIT erhöhen.`]);
  b.hidden = !lines.length;
  b.className = `banner${error ? " err" : ""}`;
  b.replaceChildren(...lines.map(([s1, s2]) => h("p", {}, h("strong", { text: s1 }), s2)));
}

// ------------------------------------------------------------------ Rendering
function render() {
  const d = state.data;
  if (!d) return;
  $("host").textContent = d.source || "lapi";
  $("source").textContent = `Quelle: ${d.source} · Zeitraum ${d.range.toUpperCase()} · Stand ${fmtTime(new Date(d.generated_at), true)}`;
  for (const b of $("range").querySelectorAll("button")) b.setAttribute("aria-checked", String(b.dataset.range === state.range));
  $("k-range").textContent = `/ ${state.range.toUpperCase().replace("D", "T")}`;
  $("f-reset").hidden = !hasFilter();

  const alerts = filterAlerts();
  renderSelects();
  renderThreat();
  renderKpis(alerts);
  renderTimeline(alerts);
  renderRadar(filterAlerts("country"));
  renderLog(alerts);
  renderBars($("top-scenarios"), countBy(filterAlerts("scenario"), (a) => a.scenario).slice(0, 8), {
    name: shortScenario, title: (k) => k, active: (k) => k === state.f.scenario,
    onClick: (k) => setFilter({ scenario: state.f.scenario === k ? "" : k }),
  });
  renderBars($("top-countries"), countBy(filterAlerts("country"), (a) => a.cn).slice(0, 8), {
    name: (k) => `${flag(k)} ${countryName(k)}`, title: countryName, active: (k) => k === state.f.country,
    onClick: (k) => setFilter({ country: state.f.country === k ? "" : k }),
  });
  const asCounts = countBy(alerts, (a) => `${a.asn}\u0000${a.as}`).slice(0, 8);
  renderBars($("top-as"), asCounts, {
    name: (k) => { const [asn, n] = k.split("\u0000"); return `${n || "unbekannt"}${asn ? ` · AS${asn}` : ""}`; },
    title: (k) => k.replace("\u0000", " "), active: () => false,
    onClick: (k) => setFilter({ q: k.split("\u0000")[1] || k.split("\u0000")[0] }),
  });
  renderShield();
  renderTables(alerts);
}

function renderSelects() {
  const all = state.data.alerts;
  fillSelect($("f-scenario"), countBy(all, (a) => a.scenario), state.f.scenario, "* alle Szenarien", (k) => shortScenario(k));
  fillSelect($("f-country"), countBy(all, (a) => a.cn), state.f.country, "* alle Länder", (k) => `${flag(k)} ${countryName(k)}`);
}
function fillSelect(sel, entries, current, allLabel, label) {
  const opts = [h("option", { value: "", text: allLabel })];
  const keys = new Set(entries.map(([k]) => k));
  for (const [k, n] of entries) opts.push(h("option", { value: k, text: `${label(k)} (${fmt(n)})` }));
  if (current && !keys.has(current)) opts.push(h("option", { value: current, text: `${label(current)} (0)` }));
  sel.replaceChildren(...opts);
  sel.value = current;
  sel.classList.toggle("active", !!current);
}

const THREAT_LEVELS = [
  null,
  { text: "KRITISCH", color: "var(--critical)" },
  { text: "HOCH", color: "var(--serious)" },
  { text: "ERHÖHT", color: "var(--warning)" },
  { text: "NORMAL", color: "var(--good)" },
  { text: "RUHIG", color: "var(--good)" },
];
function renderThreat() {
  const d = state.data, now = Date.parse(d.generated_at);
  let last = 0, before = 0;
  for (const a of d.alerts) {
    const age = now - Date.parse(a.t);
    if (age <= 3600e3) last++; else before++;
  }
  const avg = before / Math.max(1, d.hours - 1);
  const ratio = avg > 0 ? last / avg : (last ? 5 : 0);
  const level = ratio >= 4 ? 1 : ratio >= 2 ? 2 : ratio >= 1.2 ? 3 : ratio >= 0.5 || last > 0 ? 4 : 5;
  const info = THREAT_LEVELS[level];
  const el = $("threat");
  el.dataset.level = level;
  el.style.setProperty("--threat", info.color);
  $("threat-level").textContent = level;
  $("threat-text").textContent = info.text;
  [...$("threat-bars").children].forEach((bar, i) => bar.classList.toggle("on", i >= level - 1));
  el.title = `Letzte Stunde: ${fmt(last)} Alerts · Durchschnitt: ${avg.toFixed(1).replace(".", ",")} pro Stunde`;
}

function renderKpis(alerts) {
  const d = state.data;
  $("k-alerts").textContent = fmt(alerts.length);
  const perHour = alerts.length / d.hours;
  const sub = $("k-alerts-sub");
  sub.replaceChildren(`Ø ${perHour.toFixed(1).replace(".", ",")} pro Stunde`, hasFilter() ? ` · gefiltert von ${fmt(d.alerts.length)}` : "");

  const ips = countBy(alerts, (a) => a.ip);
  $("k-ips").textContent = fmt(ips.length);
  $("k-ips-sub").textContent = ips.length ? `aktivste: ${ips[0][0]} (${fmt(ips[0][1])}×)` : "keine";

  const dec = d.decisions;
  $("k-bans").textContent = dec ? fmt(filterDecisions().length) : "n/a";
  const remote = dec ? dec.by_origin.filter(([o]) => o === "CAPI" || o === "lists").reduce((n, [, c]) => n + c, 0) : null;
  $("k-capi").textContent = remote == null ? "n/a" : fmt(remote);

  const cns = countBy(alerts, (a) => a.cn).filter(([k]) => k);
  $("k-countries").textContent = fmt(cns.length);
  $("k-countries-sub").textContent = cns.length ? `vorne: ${flag(cns[0][0])} ${countryName(cns[0][0])}` : "keine";
}

// --- Zeitachse (Säulen, eine Serie)
function renderTimeline(alerts) {
  const d = state.data, box = $("timeline");
  const bucket = d.bucket * 1000, now = Date.parse(d.generated_at);
  const tz = new Date(now).getTimezoneOffset() * 60e3;
  const n = Math.round((d.hours * 3600e3) / bucket);
  const end = Math.ceil((now - tz) / bucket) * bucket + tz;
  const start = end - n * bucket;
  const counts = new Array(n).fill(0);
  for (const a of alerts) {
    const i = Math.floor((Date.parse(a.t) - start) / bucket);
    if (i >= 0 && i < n) counts[i]++;
  }
  $("bucket-hint").textContent = `// pro ${d.bucket === 3600 ? "Stunde" : d.bucket === 86400 ? "Tag" : `${d.bucket / 3600} Stunden`}`;

  const W = Math.max(280, box.clientWidth), H = box.clientHeight || 220;
  const m = { l: 40, r: 8, t: 20, b: 24 };
  const pw = W - m.l - m.r, ph = H - m.t - m.b;
  const max = niceMax(Math.max(...counts, 1));
  const slot = pw / n, cw = Math.min(24, slot * 0.72);
  const y = (v) => m.t + ph - (v / max) * ph;
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Alerts über Zeit, ${n} Intervalle, Maximum ${Math.max(...counts)}` });

  for (let i = 0; i <= 4; i++) {
    const v = (max / 4) * i, yy = Math.round(y(v)) + 0.5;
    svg.append(s("line", { class: i ? "grid-line" : "base-line", x1: m.l, x2: W - m.r, y1: yy, y2: yy }));
    svg.append(s("text", { class: "tick", x: m.l - 6, y: yy + 3, "text-anchor": "end", text: fmt(v) }));
  }
  const labelEvery = Math.max(1, Math.ceil(n / Math.floor(pw / 64)));
  const peakIdx = counts.indexOf(Math.max(...counts));
  const labelFor = (t) => {
    const dt = new Date(t);
    if (d.bucket === 3600) return `${pad(dt.getHours())}:00`;
    if (d.bucket === 86400) return `${pad(dt.getDate())}.${pad(dt.getMonth() + 1)}.`;
    return dt.getHours() === 0 ? `${pad(dt.getDate())}.${pad(dt.getMonth() + 1)}.` : `${pad(dt.getHours())}h`;
  };
  const rangeLabel = (t) => {
    const a = new Date(t), b = new Date(t + bucket);
    return d.bucket === 86400 ? a.toLocaleDateString("de-DE", { weekday: "short", day: "2-digit", month: "2-digit" }) : `${fmtTime(a)} – ${pad(b.getHours())}:${pad(b.getMinutes())}`;
  };
  counts.forEach((c, i) => {
    const t = start + i * bucket, x = m.l + i * slot + (slot - cw) / 2;
    const g = s("g", { class: "col-g" });
    if (c > 0) {
      const top = y(c), hgt = m.t + ph - top, r = Math.min(4, cw / 2, hgt);
      g.append(s("path", {
        class: `col${i === peakIdx ? " peak" : ""}`,
        d: `M${x},${top + hgt}V${top + r}Q${x},${top} ${x + r},${top}H${x + cw - r}Q${x + cw},${top} ${x + cw},${top + r}V${top + hgt}Z`,
      }));
    }
    const hit = s("rect", { class: "col-hit", x: m.l + i * slot, y: m.t, width: slot, height: ph });
    bindTip(hit, () => tipLines(fmt(c), "Alerts", rangeLabel(t)));
    g.append(hit);
    svg.append(g);
    if (i % labelEvery === 0) svg.append(s("text", { class: "tick", x: m.l + i * slot + slot / 2, y: H - 6, "text-anchor": "middle", text: labelFor(t) }));
  });
  if (counts[peakIdx] > 0) {
    const px = Math.min(Math.max(m.l + peakIdx * slot + slot / 2, m.l + 30), W - 40);
    svg.append(s("text", { class: "peak-label", x: px, y: y(counts[peakIdx]) - 6, "text-anchor": "middle", text: `max ${fmt(counts[peakIdx])}` }));
  }
  box.replaceChildren(svg);

  const rows = counts.map((c, i) => [rangeLabel(start + i * bucket), c]).reverse();
  $("timeline-table").replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", { text: "Intervall" }), h("th", { class: "num", text: "Alerts" }))),
    h("tbody", {}, rows.map(([l, c]) => h("tr", {}, h("td", { text: l }), h("td", { class: "num", text: fmt(c) })))))));
}

// --- Radar: azimutabstandstreue Peilung vom eigenen Standort
function bearingDistance(home, lat, lon) {
  const r = Math.PI / 180, p1 = home.lat * r, p2 = lat * r, dl = (lon - home.lon) * r;
  const brg = Math.atan2(Math.sin(dl) * Math.cos(p2), Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(dl));
  const a = Math.sin((p2 - p1) / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) ** 2;
  return { brg, km: 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(a))) };
}
function renderRadar(alerts) {
  const d = state.data, box = $("radar");
  const S = Math.max(260, Math.min(box.clientWidth, 640));
  const R = S / 2 - 26, MAXKM = 20000;
  const rr = (km) => Math.sqrt(Math.min(km, MAXKM) / MAXKM) * R;
  const now = Date.parse(d.generated_at);
  const svg = s("svg", { viewBox: `${-S / 2} ${-S / 2} ${S} ${S}`, role: "img", "aria-label": "Radar der Angriffsherkunft nach Richtung und Entfernung" });
  const defs = s("defs", {},
    s("radialGradient", { id: "radar-grad" }, s("stop", { offset: "0%", "stop-color": "#0d2416" }), s("stop", { offset: "100%", "stop-color": "#040a06" })),
    s("linearGradient", { id: "sweep-grad", gradientUnits: "userSpaceOnUse", x1: -R * 0.64, y1: -R * 0.55, x2: 0, y2: -R },
      s("stop", { offset: "0%", "stop-color": "#3ee07f", "stop-opacity": "0" }), s("stop", { offset: "100%", "stop-color": "#3ee07f", "stop-opacity": "0.28" })));
  svg.append(defs, s("circle", { class: "r-bg", r: R }));
  for (let deg = 0; deg < 360; deg += 30) {
    const a = (deg * Math.PI) / 180;
    svg.append(s("line", { class: "r-spoke", x1: 0, y1: 0, x2: R * Math.sin(a), y2: -R * Math.cos(a) }));
  }
  for (const km of [1000, 2500, 5000, 10000, 20000]) {
    svg.append(s("circle", { class: `r-ring${km === 20000 ? " outer" : ""}`, r: rr(km) }));
    if (km < 20000) svg.append(s("text", { class: "r-label", x: 4, y: -rr(km) - 3, text: `${fmt(km)} km` }));
  }
  for (const [lbl, deg] of [["N", 0], ["O", 90], ["S", 180], ["W", 270]]) {
    const a = (deg * Math.PI) / 180;
    svg.append(s("text", { class: "r-cardinal", x: (R + 14) * Math.sin(a), y: -(R + 14) * Math.cos(a) + 4, "text-anchor": "middle", text: lbl }));
  }
  if (!REDUCED_MOTION) {
    const a0 = (-40 * Math.PI) / 180;
    svg.append(s("g", { class: "r-sweep" },
      s("path", { d: `M0,0 L${R * Math.sin(a0)},${-R * Math.cos(a0)} A${R},${R} 0 0 1 0,${-R} Z`, fill: "url(#sweep-grad)" }),
      s("line", { x1: 0, y1: 0, x2: 0, y2: -R, stroke: "#3ee07f", "stroke-width": 1.5, "stroke-opacity": 0.8 })));
  }

  // Länder aggregieren
  const byCn = new Map();
  for (const a of alerts) {
    let e = byCn.get(a.cn);
    if (!e) byCn.set(a.cn, (e = { n: 0, ips: new Set(), hot: false }));
    e.n++; e.ips.add(a.ip);
    if (now - Date.parse(a.t) <= 3600e3) e.hot = true;
  }
  const plotted = [], unplaced = [];
  for (const [cn, e] of byCn) (CENTROIDS[cn] ? plotted : unplaced).push([cn, e]);
  plotted.sort((a, b) => a[1].n - b[1].n); // große zuletzt = oben
  const max = Math.max(1, ...plotted.map(([, e]) => e.n));
  const top5 = new Set([...plotted].sort((a, b) => b[1].n - a[1].n).slice(0, 5).map(([cn]) => cn));
  const home = d.home || { lat: 50.11, lon: 8.68, label: "HOME" };

  for (const [cn, e] of plotted) {
    const [lat, lon] = CENTROIDS[cn];
    const { brg, km } = bearingDistance(home, lat, lon);
    const dist = rr(km), x = dist * Math.sin(brg), y = -dist * Math.cos(brg);
    const r = 4 + 11 * Math.sqrt(e.n / max);
    const sel = state.f.country === cn;
    const g = s("g", { class: "r-blip-g", tabindex: 0, role: "button", "aria-label": `${countryName(cn)}: ${e.n} Alerts, ${e.ips.size} IPs. Als Filter setzen` });
    if (e.hot && !REDUCED_MOTION) g.append(s("circle", { class: "r-ping", cx: x, cy: y, r }));
    g.append(s("circle", { class: "r-blip-hit", cx: x, cy: y, r: Math.max(12, r + 4) }));
    g.append(s("circle", { class: `r-blip${e.hot ? " hot" : ""}${sel ? " sel" : ""}`, cx: x, cy: y, r }));
    if (top5.has(cn) || sel) g.append(s("text", { class: "r-blip-label", x: x + r + 4, y: y + 3, text: cn }));
    const toggle = () => setFilter({ country: state.f.country === cn ? "" : cn });
    g.addEventListener("click", toggle);
    g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } });
    bindTip(g, () => tipLines(`${fmt(e.n)} Alerts`, `${flag(cn)} ${countryName(cn)}`, `${fmt(e.ips.size)} IPs · ca. ${fmt(Math.round(km / 100) * 100)} km${e.hot ? " · aktiv in der letzten Stunde" : ""}`));
    svg.append(g);
  }
  svg.append(s("circle", { class: "r-home", r: 4 }), s("text", { class: "r-home-label", x: 7, y: 14, text: home.label }));
  box.replaceChildren(svg);
  const lost = unplaced.reduce((n, [, e]) => n + e.n, 0);
  $("radar-note").textContent = `Abstand wurzelskaliert · Punktgröße = Alerts · leuchtend = aktiv in der letzten Stunde${lost ? ` · ${fmt(lost)} Alerts ohne Länderzuordnung` : ""}`;
}

// --- Live-Feed
function renderLog(alerts) {
  const list = alerts.slice(0, 80);
  $("feed-count").textContent = `${fmt(Math.min(80, alerts.length))} / ${fmt(alerts.length)}`;
  if (!list.length) { $("log").replaceChildren(h("li", { class: "empty", text: "> keine Alerts für diese Auswahl. Stille im Äther." })); return; }
  $("log").replaceChildren(...list.map((a) => {
    const act = a.decision || "alert";
    return h("li", { class: state.freshIds.has(a.id) ? "fresh" : null, title: `${a.scenario} · ${a.machine}` },
      h("span", { class: "ts", text: `[${fmtTime(new Date(a.t), true)}] ` }),
      h("span", { class: `act ${act}`, text: act.toUpperCase().padEnd(7, " ") }),
      h("span", { class: "ip", text: a.ip, onclick: () => setFilter({ q: a.ip }) }),
      ` ${a.cn || "??"}/${(a.as || "?").slice(0, 22)} `,
      h("span", { class: "dim", text: "» " }),
      `${shortScenario(a.scenario)} ×${a.events}`);
  }));
}

// --- Balkenlisten
function renderBars(box, entries, o) {
  if (!entries.length) { box.replaceChildren(h("div", { class: "empty-msg", text: "> keine Daten" })); return; }
  const max = entries[0][1], total = entries.reduce((n, [, c]) => n + c, 0);
  box.replaceChildren(...entries.map(([k, c]) => {
    const fill = h("span", { class: "bar-fill" });
    fill.style.width = `calc((100% - 4.5em) * ${c / max})`;
    const row = h("button", { type: "button", class: `bar-row${o.active(k) ? " active" : ""}`, "aria-pressed": String(o.active(k)), onclick: () => o.onClick(k) },
      h("span", { class: "bar-name", text: o.name(k), title: o.title(k) }),
      h("span", { class: "bar-track" }, fill, h("span", { class: "bar-val", text: fmt(c) })));
    bindTip(row, () => tipLines(fmt(c), o.title(k), `${((c / total) * 100).toFixed(1).replace(".", ",")} % der Top-Einträge`));
    return row;
  }));
}

// --- Schutzschild (segmentierter Balken)
function renderShield() {
  const dec = state.data.decisions, bar = $("dec-origin"), legend = $("dec-legend");
  if (!dec) {
    bar.replaceChildren(h("div", { class: "empty-msg", text: "> LAPI_BOUNCER_KEY fehlt – keine Sperren-Daten." }));
    legend.replaceChildren(); $("dec-types").textContent = ""; return;
  }
  const total = dec.total || 1;
  bar.setAttribute("aria-label", `Aktive Sperren nach Herkunft: ${dec.by_origin.map(([o, c]) => `${originInfo(o).label} ${c}`).join(", ")}`);
  const parts = dec.by_origin.map(([o, c]) => {
    const info = originInfo(o);
    const el = h("div", { class: `seg-part${info.cls === "capi" ? " dark-text" : ""}`, tabindex: 0, text: `${((c / total) * 100).toFixed(c / total < 0.1 ? 1 : 0).replace(".", ",")} %` });
    el.style.flex = `${c} 1 0`;
    el.style.background = `var(--cat-${info.cls})`;
    bindTip(el, () => tipLines(fmt(c), info.label, `${((c / total) * 100).toFixed(1).replace(".", ",")} % aller aktiven Sperren`));
    return el;
  });
  bar.replaceChildren(...parts);
  requestAnimationFrame(() => parts.forEach((p) => { if (p.scrollWidth > p.clientWidth) p.textContent = ""; }));
  legend.replaceChildren(...dec.by_origin.map(([o, c]) => {
    const info = originInfo(o), sw = h("span", { class: "sw" });
    sw.style.background = `var(--cat-${info.cls})`;
    return h("li", {}, sw, info.label, h("span", { class: "cnt", text: fmt(c) }));
  }));
  $("dec-types").textContent = dec.by_type.map(([t, c]) => `${t} ${fmt(c)}`).join(" · ");
}

// --- Tabellen
function ipCountryMap() {
  const m = new Map();
  for (const a of state.data.alerts) if (a.cn && !m.has(a.ip)) m.set(a.ip, a.cn);
  return m;
}
function filterDecisions() {
  const dec = state.data?.decisions;
  if (!dec) return [];
  const { scenario, country, q } = state.f, ql = q.trim().toLowerCase();
  const cmap = country ? ipCountryMap() : null;
  return dec.local.filter((x) =>
    (!scenario || x.scenario === scenario) &&
    (!country || cmap.get(x.value) === country) &&
    (!ql || x.value.toLowerCase().includes(ql) || x.scenario.toLowerCase().includes(ql) || x.origin.toLowerCase().includes(ql)));
}
const tag = (type) => h("span", { class: `tag ${type || "none"}`, text: type || "keine" });
function renderTables(alerts) {
  const LIMIT = 400;
  $("alerts-count").textContent = fmt(alerts.length);
  $("alerts-body").replaceChildren(...(alerts.length ? alerts.slice(0, LIMIT).map((a) => h("tr", {},
    h("td", { text: fmtTime(new Date(a.t), true) }),
    h("td", {}, h("button", { type: "button", class: "cell-ip", text: a.ip, title: "Nach dieser IP filtern", onclick: () => setFilter({ q: a.ip }) })),
    h("td", { title: countryName(a.cn), text: `${flag(a.cn)} ${a.cn || "??"}` }),
    h("td", { text: a.as ? `${a.as.slice(0, 32)}${a.asn ? ` (AS${a.asn})` : ""}` : "–" }),
    h("td", { title: a.scenario, text: shortScenario(a.scenario) }),
    h("td", { class: "num", text: fmt(a.events) }),
    h("td", {}, tag(a.decision)))) : [h("tr", {}, h("td", { colspan: 7, class: "empty-msg", text: "> keine Treffer" }))]));
  $("alerts-more").textContent = alerts.length > LIMIT ? `Zeige die neuesten ${fmt(LIMIT)} von ${fmt(alerts.length)} – Filter oder Suche eingrenzen.` : "";

  const dec = state.data.decisions;
  const rows = filterDecisions();
  $("decisions-count").textContent = dec ? fmt(rows.length) : "n/a";
  const cmap = ipCountryMap();
  if (!dec) {
    $("decisions-body").replaceChildren(h("tr", {}, h("td", { colspan: 6, class: "empty-msg", text: "> LAPI_BOUNCER_KEY fehlt – keine Sperren-Daten." })));
    $("decisions-more").textContent = "";
    return;
  }
  $("decisions-body").replaceChildren(...(rows.length ? rows.slice(0, LIMIT).map((x) => {
    const info = originInfo(x.origin), sw = h("span", { class: "sw-inline" });
    sw.style.background = `var(--cat-${info.cls})`;
    const cn = cmap.get(x.value) || "";
    return h("tr", {},
      h("td", {}, h("button", { type: "button", class: "cell-ip", text: x.value, title: "Nach diesem Ziel filtern", onclick: () => setFilter({ q: x.value }) })),
      h("td", { title: countryName(cn), text: cn ? `${flag(cn)} ${cn}` : "–" }),
      h("td", {}, tag(x.type)),
      h("td", {}, sw, info.label),
      h("td", { class: "wrap", title: x.scenario, text: shortScenario(x.scenario) }),
      h("td", { class: "num", text: fmtDur(x.remaining) }));
  }) : [h("tr", {}, h("td", { colspan: 6, class: "empty-msg", text: "> keine aktiven lokalen Sperren für diese Auswahl" }))]));
  const more = [];
  if (rows.length > LIMIT) more.push(`Zeige ${fmt(LIMIT)} von ${fmt(rows.length)}.`);
  if (dec.local_total > dec.local.length) more.push(`Server liefert nur die ersten ${fmt(dec.local.length)} von ${fmt(dec.local_total)} lokalen Sperren.`);
  more.push("Community- und Blocklisten-Sperren werden nur gezählt, nicht einzeln gelistet.");
  $("decisions-more").textContent = more.join(" ");
}

// ------------------------------------------------------------------ Boot-Sequenz
let bootDone = null;
function bootStart() {
  if (REDUCED_MOTION || store.sget("csd.booted")) return false;
  store.sset("csd.booted", "1");
  const boot = $("boot"), log = $("boot-log");
  boot.hidden = false;
  const lines = [
    "CROWDSEC DEFENSE GRID  v1.0",
    "(c) Kollektive Abwehr – one IP banned is an IP banned for all",
    "",
    "> Initialisiere Phosphor-Display .......... ",
    "> Lade Sensor-Signaturen ................... ",
    "> Verbinde mit Local API .................. ",
  ];
  let i = 0, finished = false;
  const tick = setInterval(() => {
    if (i < lines.length) {
      log.append(lines[i]);
      if (i >= 3) log.append(h("span", { class: "ok", text: i === lines.length - 1 ? "…" : "OK" }));
      log.append("\n");
      i++;
    } else if (state.bootReady) { clearInterval(tick); bootDone(); }
  }, 140);
  const close = () => {
    if (finished) return;
    finished = true; clearInterval(tick);
    boot.classList.add("done");
    setTimeout(() => { boot.hidden = true; }, 400);
    removeEventListener("keydown", close, true);
  };
  boot.addEventListener("click", close);
  addEventListener("keydown", close, true);
  bootDone = () => {
    const d = state.data;
    log.append(d ? `> Alerts empfangen ......................... ${fmt(d.alerts.length)}\n> Status: SYSTEM BEREIT\n` : "> WARNUNG: LAPI antwortet nicht\n");
    setTimeout(close, 700);
  };
  return true;
}
function bootFinish() { state.bootReady = true; }

// ------------------------------------------------------------------ Steuerung
function setRange(r) {
  if (r === state.range) return;
  state.range = r;
  store.set("csd.range", r);
  state.seen = null;
  load();
}
function schedule() {
  clearInterval(state.timer);
  if ($("auto").checked) state.timer = setInterval(() => { if (!document.hidden) load(); }, 60e3);
}
function init() {
  const crt = store.get("csd.crt") !== "0";
  $("crt-toggle").checked = crt;
  document.body.classList.toggle("crt", crt);
  $("crt-toggle").addEventListener("change", (e) => {
    document.body.classList.toggle("crt", e.target.checked);
    store.set("csd.crt", e.target.checked ? "1" : "0");
  });
  for (const b of $("range").querySelectorAll("button")) {
    b.setAttribute("aria-checked", String(b.dataset.range === state.range));
    b.addEventListener("click", () => setRange(b.dataset.range));
  }
  let qTimer;
  $("f-search").addEventListener("input", (e) => { clearTimeout(qTimer); qTimer = setTimeout(() => setFilter({ q: e.target.value }), 150); });
  $("f-scenario").addEventListener("change", (e) => setFilter({ scenario: e.target.value }));
  $("f-country").addEventListener("change", (e) => setFilter({ country: e.target.value }));
  $("f-reset").addEventListener("click", () => setFilter({ scenario: "", country: "", q: "" }));
  $("refresh").addEventListener("click", () => load());
  $("auto").addEventListener("change", schedule);
  for (const [id, pane] of [["tab-alerts", "pane-alerts"], ["tab-decisions", "pane-decisions"]]) {
    $(id).addEventListener("click", () => {
      for (const [i2, p2] of [["tab-alerts", "pane-alerts"], ["tab-decisions", "pane-decisions"]]) {
        $(i2).setAttribute("aria-selected", String(i2 === id));
        $(p2).hidden = p2 !== pane;
      }
    });
  }
  addEventListener("keydown", (e) => {
    const typing = e.target.matches("input, select, textarea");
    if (e.key === "Escape") {
      if (hasFilter()) { setFilter({ scenario: "", country: "", q: "" }); }
      if (typing) e.target.blur();
      return;
    }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "/") { e.preventDefault(); $("f-search").focus(); }
    else if (e.key === "r" || e.key === "R") load();
    else if (e.key === "1") setRange("24h");
    else if (e.key === "2") setRange("7d");
    else if (e.key === "3") setRange("30d");
  });
  let rTimer;
  addEventListener("resize", () => { clearTimeout(rTimer); rTimer = setTimeout(render, 120); });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.data && Date.now() - Date.parse(state.data.generated_at) > 60e3) load();
  });
  const clock = () => { $("clock").textContent = new Date().toLocaleTimeString("de-DE"); };
  clock(); setInterval(clock, 1000);

  const booting = bootStart();
  load({ boot: booting });
  schedule();
}
init();
