/* CrowdSec Defense Grid – 3D-Globus.
   Canvas 2D, orthografische Projektion, Landmassen als Punktraster (Natural Earth 110m, gemeinfrei).
   Keine Abhängigkeiten. API: new Globe(container, {onHover, onLeave, onClick}).setData({...}) */
"use strict";
(function () {
  const DEG = Math.PI / 180;
  const TAU = Math.PI * 2;
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const SPIN_DEG_PER_MS = 0.005; // 5°/s

  const vec = (lat, lon) => {
    const p = lat * DEG, l = lon * DEG;
    return [Math.cos(p) * Math.sin(l), Math.sin(p), Math.cos(p) * Math.cos(l)];
  };
  const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
  function slerp(a, b, t, omega) {
    if (omega < 1e-6) return a.slice();
    const s = Math.sin(omega), k1 = Math.sin((1 - t) * omega) / s, k2 = Math.sin(t * omega) / s;
    return [a[0] * k1 + b[0] * k2, a[1] * k1 + b[1] * k2, a[2] * k1 + b[2] * k2];
  }
  const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);
  const wrap = (lon) => ((((lon + 180) % 360) + 360) % 360) - 180;

  class Globe {
    constructor(box, opts = {}) {
      this.box = box;
      this.opts = opts;
      this.canvas = document.createElement("canvas");
      this.canvas.tabIndex = 0;
      this.canvas.setAttribute("role", "img");
      this.canvas.setAttribute("aria-label", "3D-Globus der Angriffsherkunft. Pfeiltasten drehen, H richtet auf den eigenen Server aus.");
      box.replaceChildren(this.canvas);
      this.ctx = this.canvas.getContext("2d");

      this.lon0 = 10; this.lat0 = 25;
      this.spin = !REDUCED;
      this.inside = false; this.drag = null; this.tween = null; this.idleUntil = 0;
      this.hover = null; this.hits = [];
      this.clusters = []; this.arcs = []; this.home = null; this.selected = "";
      this.visible = true; this.dirty = true; this.last = 0;
      this.landV = null;
      this.readColors();
      this.font = getComputedStyle(box).fontFamily || "monospace";
      this.buildGraticule();

      fetch("land.json").then((r) => r.json()).then((flat) => {
        const n = flat.length / 2, v = new Float32Array(n * 3);
        for (let i = 0; i < n; i++) v.set(vec(flat[2 * i] / 10, flat[2 * i + 1] / 10), i * 3);
        this.landV = v;
        this.dirty = true;
      }).catch(() => { /* Globus funktioniert auch ohne Landmassen */ });

      new ResizeObserver(() => this.resize()).observe(box);
      new IntersectionObserver((e) => { this.visible = e[0].isIntersecting; }).observe(box);
      this.bindInput();
      this.resize();
      this.loop = this.loop.bind(this);
      requestAnimationFrame(this.loop);
    }

    readColors() {
      const cs = getComputedStyle(document.documentElement);
      const v = (n, f) => cs.getPropertyValue(n).trim() || f;
      this.c = {
        series: v("--series-1", "#1fa85a"), hi: v("--series-1-hi", "#3ee07f"), ink: v("--ink", "#d2ffe0"),
        surface: v("--surface", "#08110b"), muted: v("--muted", "#62a078"),
      };
    }

    buildGraticule() {
      const lines = [];
      for (let lon = -180; lon < 180; lon += 30) {
        const l = []; for (let lat = -90; lat <= 90; lat += 3) l.push(vec(lat, lon)); lines.push(l);
      }
      for (let lat = -60; lat <= 60; lat += 30) {
        const l = []; for (let lon = -180; lon <= 180; lon += 3) l.push(vec(lat, lon)); lines.push(l);
      }
      this.graticule = lines;
    }

    resize() {
      const w = this.box.clientWidth, h = this.box.clientHeight || w;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      this.W = w; this.H = h; this.dpr = dpr;
      this.canvas.width = Math.round(w * dpr); this.canvas.height = Math.round(h * dpr);
      this.R = Math.min(w, h) / 2 - 22;
      this.cx = w / 2; this.cy = h / 2;
      this.dirty = true;
    }

    setSpin(on) { this.spin = on && !REDUCED; this.idleUntil = 0; }

    centerOnHome() {
      if (!this.home) return;
      const toLon = this.home.lon, toLat = Math.max(-60, Math.min(60, this.home.lat * 0.75));
      let dLon = wrap(toLon - this.lon0);
      this.tween = { t0: performance.now(), dur: REDUCED ? 1 : 900, fromLon: this.lon0, dLon, fromLat: this.lat0, dLat: toLat - this.lat0 };
      this.idleUntil = performance.now() + 8000;
      this.dirty = true;
    }

    /** clusters: [{lat, lon, n, cn, hot, approx, ...}] */
    setData({ clusters, home, selected }) {
      const first = !this.home;
      this.home = home; this.selected = selected || "";
      this.homeV = vec(home.lat, home.lon);
      this.clusters = clusters.map((c) => ({ ...c, v: vec(c.lat, c.lon) })).sort((a, b) => a.n - b.n);
      this.max = Math.max(1, ...this.clusters.map((c) => c.n));
      const top = [...this.clusters].sort((a, b) => b.n - a.n);
      this.labelled = new Set(top.slice(0, 5));
      this.arcs = top.slice(0, 45).map((c, i) => {
        const omega = Math.acos(Math.max(-1, Math.min(1, dot(c.v, this.homeV))));
        const lift = Math.min(0.32, 0.05 + omega * 0.11);
        const steps = Math.max(12, Math.round(omega * 30));
        const pts = [];
        for (let k = 0; k <= steps; k++) {
          const t = k / steps, p = slerp(c.v, this.homeV, t, omega), hgt = 1 + lift * Math.sin(Math.PI * t);
          pts.push([p[0] * hgt, p[1] * hgt, p[2] * hgt]);
        }
        return { c, pts, phase: (i * 0.137) % 1, speed: 0.00018 + 0.00012 / Math.max(0.3, omega) };
      });
      if (first) { this.lon0 = wrap(home.lon - 25); this.lat0 = Math.max(-50, Math.min(50, home.lat * 0.6)); }
      this.dirty = true;
    }

    // ---------------------------------------------------------------- Eingabe
    bindInput() {
      const cv = this.canvas;
      cv.addEventListener("pointerenter", () => { this.inside = true; });
      cv.addEventListener("pointerleave", () => {
        this.inside = false; this.setHover(null);
        this.idleUntil = performance.now() + 1500;
      });
      cv.addEventListener("pointerdown", (e) => {
        this.drag = { x: e.clientX, y: e.clientY, lon: this.lon0, lat: this.lat0, moved: 0, id: e.pointerId };
        this.tween = null;
      });
      cv.addEventListener("pointermove", (e) => {
        if (e.pointerType === "mouse") this.inside = true;
        if (this.drag && e.pointerId === this.drag.id) {
          const dx = e.clientX - this.drag.x, dy = e.clientY - this.drag.y;
          this.drag.moved = Math.max(this.drag.moved, Math.abs(dx) + Math.abs(dy));
          if (this.drag.moved > 3) {
            if (!cv.hasPointerCapture(e.pointerId)) cv.setPointerCapture(e.pointerId);
            cv.classList.add("dragging");
            const k = 1 / (this.R * DEG);
            this.lon0 = wrap(this.drag.lon - dx * k);
            this.lat0 = Math.max(-80, Math.min(80, this.drag.lat + dy * k));
            this.setHover(null);
            this.dirty = true;
            return;
          }
        }
        const r = cv.getBoundingClientRect();
        this.setHover(this.hitTest(e.clientX - r.left, e.clientY - r.top), e);
      });
      const end = (e) => {
        if (!this.drag) return;
        const click = this.drag.moved <= 3;
        cv.classList.remove("dragging");
        this.drag = null;
        this.idleUntil = performance.now() + 2500;
        if (click && e.type === "pointerup") {
          const r = cv.getBoundingClientRect();
          const hit = this.hitTest(e.clientX - r.left, e.clientY - r.top);
          if (hit) this.opts.onClick?.(hit);
        }
      };
      cv.addEventListener("pointerup", end);
      cv.addEventListener("pointercancel", end);
      cv.addEventListener("keydown", (e) => {
        const step = 10;
        const map = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] };
        if (map[e.key]) {
          e.preventDefault(); e.stopPropagation();
          this.tween = null;
          this.lon0 = wrap(this.lon0 + map[e.key][0]);
          this.lat0 = Math.max(-80, Math.min(80, this.lat0 + map[e.key][1]));
          this.idleUntil = performance.now() + 6000;
          this.dirty = true;
        } else if (e.key === "h" || e.key === "H") {
          e.preventDefault(); e.stopPropagation(); this.centerOnHome();
        }
      });
    }

    hitTest(x, y) {
      let best = null, bd = Infinity;
      for (const h of this.hits) {
        const d = Math.hypot(h.x - x, h.y - y);
        if (d <= h.r && d < bd) { best = h.c; bd = d; }
      }
      return best;
    }

    setHover(c, e) {
      if (c === this.hover && !c) return;
      this.hover = c;
      this.canvas.style.cursor = c ? "pointer" : "";
      if (c) this.opts.onHover?.(c, e); else this.opts.onLeave?.();
      this.dirty = true;
    }

    // ---------------------------------------------------------------- Rendering
    loop(ts) {
      requestAnimationFrame(this.loop);
      const dt = this.last ? Math.min(64, ts - this.last) : 16;
      this.last = ts;
      if (!this.visible || document.hidden) return;
      if (this.tween) {
        const t = Math.min(1, (ts - this.tween.t0) / this.tween.dur), k = ease(t);
        this.lon0 = wrap(this.tween.fromLon + this.tween.dLon * k);
        this.lat0 = this.tween.fromLat + this.tween.dLat * k;
        if (t >= 1) this.tween = null;
        this.dirty = true;
      } else if (this.spin && !this.inside && !this.drag && ts > this.idleUntil) {
        this.lon0 = wrap(this.lon0 + dt * SPIN_DEG_PER_MS);
        this.dirty = true;
      }
      if (REDUCED && !this.dirty) return;
      this.dirty = false;
      this.draw(ts);
    }

    draw(ts) {
      const { ctx, R, cx, cy, c } = this;
      if (!R || R < 20) return;
      const anim = !REDUCED;
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, this.W, this.H);

      const cl = Math.cos(this.lon0 * DEG), sl = Math.sin(this.lon0 * DEG);
      const cp = Math.cos(this.lat0 * DEG), sp = Math.sin(this.lat0 * DEG);
      // Rotation: erst um die Y-Achse (Länge), dann um die X-Achse (Breite); Betrachter auf +z
      const P = (x, y, z) => {
        const x1 = x * cl - z * sl, z1 = x * sl + z * cl;
        return [x1, y * cp - z1 * sp, y * sp + z1 * cp];
      };
      const sx = (p) => cx + R * p[0], sy = (p) => cy - R * p[1];

      // Atmosphäre
      let g = ctx.createRadialGradient(cx, cy, R * 0.92, cx, cy, R * 1.16);
      g.addColorStop(0, "rgba(62,224,127,0.22)"); g.addColorStop(1, "rgba(62,224,127,0)");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R * 1.16, 0, TAU); ctx.fill();
      // Kugel
      g = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.05, cx, cy, R);
      g.addColorStop(0, "#123321"); g.addColorStop(0.7, "#071209"); g.addColorStop(1, "#030805");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();

      // Gradnetz (nur Vorderseite)
      ctx.strokeStyle = "rgba(62,224,127,0.11)"; ctx.lineWidth = 1;
      ctx.beginPath();
      for (const line of this.graticule) {
        let pen = false;
        for (const v of line) {
          const p = P(v[0], v[1], v[2]);
          if (p[2] > 0) { pen ? ctx.lineTo(sx(p), sy(p)) : ctx.moveTo(sx(p), sy(p)); pen = true; } else pen = false;
        }
      }
      ctx.stroke();

      // Landmassen: Rückseite als Hologramm, Vorderseite nach Blickwinkel abgestuft
      const L = this.landV;
      if (L) {
        const size = Math.max(1.1, Math.min(2.4, R / 150));
        const buckets = [[], [], [], [], []];
        const back = [];
        for (let i = 0; i < L.length; i += 3) {
          const x = L[i], y = L[i + 1], z = L[i + 2];
          const x1 = x * cl - z * sl, z1 = x * sl + z * cl;
          const y2 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
          const px = cx + R * x1, py = cy - R * y2;
          if (z2 > 0) buckets[Math.min(4, (z2 * 5) | 0)].push(px, py); else back.push(px, py);
        }
        ctx.fillStyle = "rgba(62,224,127,0.06)";
        for (let i = 0; i < back.length; i += 2) ctx.fillRect(back[i] - size / 2, back[i + 1] - size / 2, size * 0.8, size * 0.8);
        buckets.forEach((b, k) => {
          ctx.fillStyle = `rgba(62,224,127,${(0.22 + k * 0.16).toFixed(2)})`;
          for (let i = 0; i < b.length; i += 2) ctx.fillRect(b[i] - size / 2, b[i + 1] - size / 2, size, size);
        });
      }
      // Rand
      ctx.strokeStyle = "rgba(62,224,127,0.5)"; ctx.lineWidth = 1.2;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.stroke();

      // Angriffsbögen zum eigenen Server
      const visibleArc = (p) => p[2] > 0 || p[0] * p[0] + p[1] * p[1] > 1;
      ctx.lineCap = "round";
      for (const a of this.arcs) {
        const pts = a.pts.map((q) => P(q[0], q[1], q[2]));
        const sel = this.selected && a.c.cn === this.selected;
        const strong = sel || a.c.hot || a.c === this.hover;
        ctx.strokeStyle = strong ? "rgba(62,224,127,0.75)" : "rgba(62,224,127,0.28)";
        ctx.lineWidth = sel || a.c === this.hover ? 2 : 1.2;
        ctx.beginPath();
        let pen = false;
        for (const p of pts) {
          if (visibleArc(p)) { pen ? ctx.lineTo(sx(p), sy(p)) : ctx.moveTo(sx(p), sy(p)); pen = true; } else pen = false;
        }
        ctx.stroke();
        if (anim) {
          const t = (ts * a.speed + a.phase) % 1, n = pts.length - 1, head = Math.floor(t * n);
          const tail = Math.max(0, head - Math.max(2, Math.round(n * 0.12)));
          ctx.strokeStyle = "rgba(210,255,224,0.9)"; ctx.lineWidth = 2;
          ctx.beginPath(); pen = false;
          for (let k = tail; k <= head; k++) {
            const p = pts[k];
            if (visibleArc(p)) { pen ? ctx.lineTo(sx(p), sy(p)) : ctx.moveTo(sx(p), sy(p)); pen = true; } else pen = false;
          }
          ctx.stroke();
        }
      }

      // Angriffsorte
      this.hits = [];
      ctx.font = "10px " + this.font;
      for (const cl2 of this.clusters) {
        const p = P(cl2.v[0], cl2.v[1], cl2.v[2]);
        if (p[2] <= 0.02) continue;
        const x = sx(p), y = sy(p);
        const r = 2.5 + 8 * Math.sqrt(cl2.n / this.max);
        const fade = Math.min(1, p[2] * 5);
        ctx.globalAlpha = fade;
        if (cl2.hot && anim) {
          const ph = ((ts / 2200) + cl2.n * 0.07) % 1;
          ctx.strokeStyle = `rgba(62,224,127,${(0.8 * (1 - ph)).toFixed(2)})`; ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(x, y, r + ph * 16, 0, TAU); ctx.stroke();
        }
        ctx.fillStyle = cl2.hot || cl2 === this.hover ? c.hi : c.series;
        ctx.strokeStyle = c.surface; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(x, y, r, 0, TAU); ctx.fill(); ctx.stroke();
        if ((this.selected && cl2.cn === this.selected) || cl2 === this.hover) {
          ctx.strokeStyle = c.ink; ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(x, y, r + 2.5, 0, TAU); ctx.stroke();
        }
        if (this.labelled.has(cl2)) {
          ctx.fillStyle = c.ink; ctx.fillText(cl2.cn || "??", x + r + 4, y + 3);
        }
        ctx.globalAlpha = 1;
        this.hits.push({ x, y, r: Math.max(12, r + 5), c: cl2 });
      }

      // Eigener Server
      if (this.homeV) {
        const p = P(this.homeV[0], this.homeV[1], this.homeV[2]);
        if (p[2] > 0) {
          const x = sx(p), y = sy(p);
          if (anim) {
            for (const off of [0, 0.5]) {
              const ph = ((ts / 1800) + off) % 1;
              ctx.strokeStyle = `rgba(210,255,224,${(0.7 * (1 - ph)).toFixed(2)})`; ctx.lineWidth = 1.2;
              ctx.beginPath(); ctx.arc(x, y, 5 + ph * 22, 0, TAU); ctx.stroke();
            }
          }
          ctx.fillStyle = c.ink; ctx.strokeStyle = c.surface; ctx.lineWidth = 2;
          ctx.beginPath(); ctx.moveTo(x, y - 6); ctx.lineTo(x + 6, y); ctx.lineTo(x, y + 6); ctx.lineTo(x - 6, y); ctx.closePath();
          ctx.fill(); ctx.stroke();
          ctx.font = "bold 10px " + this.font;
          ctx.fillStyle = c.ink; ctx.fillText(this.home.label || "HOME", x + 9, y - 7);
        }
      }
    }
  }

  window.Globe = Globe;
})();
