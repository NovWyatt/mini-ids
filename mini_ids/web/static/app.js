"use strict";
/* mini-IDS dashboard (vanilla JS, không cần build).
   BẢO MẬT: nội dung alert (tên miền DNS, payload HTTP...) do KẺ TẤN CÔNG kiểm soát.
   Tuyệt đối không đưa vào innerHTML; mọi thứ dựng bằng DOM + textContent qua hàm h(). */
(() => {
  const $ = (sel, el = document) => el.querySelector(sel);
  const root = document.documentElement;

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "dataset") Object.assign(el.dataset, v);
        else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? "" : v);
      }
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const icon = (name) => h("i", { class: `ph ph-${name}`, "aria-hidden": "true" });
  // replaceChildren() biến null thành chữ "null" và mảng thành chuỗi → lọc + làm phẳng trước
  const fill = (el, ...children) => el.replaceChildren(...children.flat(Infinity).filter((c) => c != null && c !== false));

  const SEV = {
    critical: { label: "Critical", icon: "warning-octagon" },
    high: { label: "High", icon: "warning" },
    medium: { label: "Medium", icon: "warning-circle" },
    low: { label: "Low", icon: "info" },
  };
  const SEV_ORDER = ["critical", "high", "medium", "low"];
  const MODE = {
    demo: { label: "DEMO", icon: "flask" },
    live: { label: "LIVE", icon: "wifi-high" },
    replay: { label: "REPLAY", icon: "file-arrow-down" },
  };
  const MAX_ALERTS = 1000;

  // ------------------------------------------------------------------ định dạng số / thời gian
  const nf = new Intl.NumberFormat("en-US");
  function compact(n) {
    n = Number(n) || 0;
    if (Math.abs(n) < 10000) return nf.format(Math.round(n));
    for (const [d, s] of [[1e9, "B"], [1e6, "M"], [1e3, "K"]]) {
      if (Math.abs(n) >= d) { const x = n / d; return (x < 100 ? x.toFixed(1) : Math.round(x)) + s; }
    }
    return String(n);
  }
  function unit(n, units) {
    n = Number(n) || 0;
    let i = 0;
    while (Math.abs(n) >= 1000 && i < units.length - 1) { n /= 1000; i++; }
    return (i === 0 ? Math.round(n) : n < 10 ? n.toFixed(2) : n < 100 ? n.toFixed(1) : Math.round(n)) + " " + units[i];
  }
  const bitsPerSec = (n) => unit(n, ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"]);
  const bytesFmt = (n) => unit(n, ["B", "KB", "MB", "GB", "TB"]);
  const pad2 = (n) => String(n).padStart(2, "0");
  function clock(ts, withDate) {
    const d = new Date(ts * 1000);
    const t = `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
    const today = new Date().toDateString() === d.toDateString();
    return withDate || !today ? `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)} ${t}` : t;
  }
  function duration(sec) {
    sec = Math.max(0, Math.floor(sec));
    const hh = Math.floor(sec / 3600), mm = Math.floor((sec % 3600) / 60), ss = sec % 60;
    if (hh) return `${hh} giờ ${mm} phút`;
    if (mm) return `${mm} phút ${ss} giây`;
    return `${ss} giây`;
  }
  function mitreUrl(tech) {
    const [base, sub] = tech.split(".");
    return `https://attack.mitre.org/techniques/${base}/${sub ? sub + "/" : ""}`;
  }
  const cssVar = (name) => getComputedStyle(root).getPropertyValue(name).trim();

  // ------------------------------------------------------------------ state
  const state = {
    status: null,
    stats: null,
    alerts: new Map(),      // id -> alert
    order: [],              // id, mới nhất trước
    filter: { sev: "", q: "", hideAcked: false },
    connected: false,
    openId: null,
    lastFocus: null,
  };

  // ------------------------------------------------------------------ theme
  function storedTheme() { try { return localStorage.getItem("mini-ids-theme"); } catch { return null; } }
  function saveTheme(t) { try { localStorage.setItem("mini-ids-theme", t); } catch { /* private mode */ } }
  const isDark = () => (root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
  function applyTheme(t) {
    if (t) root.dataset.theme = t; else delete root.dataset.theme;
    const btn = $("#theme-toggle");
    btn.replaceChildren(icon(isDark() ? "sun" : "moon"));
    btn.setAttribute("aria-label", isDark() ? "Chuyển sang giao diện sáng" : "Chuyển sang giao diện tối");
    charts.forEach((c) => c.draw());
  }
  $("#theme-toggle").addEventListener("click", () => {
    const next = isDark() ? "light" : "dark";
    saveTheme(next);
    applyTheme(next);
  });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(root.dataset.theme));

  // ------------------------------------------------------------------ biểu đồ đường (canvas)
  function niceStep(x) {
    const p = Math.pow(10, Math.floor(Math.log10(x)));
    const f = x / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
  }

  class LineChart {
    constructor(fig, { valueLabel, axisFmt, note }) {
      this.canvas = $("canvas", fig);
      this.tip = $(".tip", fig);
      this.valueLabel = valueLabel;
      this.axisFmt = axisFmt;
      this.note = note;
      this.t = [];
      this.v = [];
      this.hover = null;
      this.geom = null;
      this.canvas.addEventListener("pointermove", (e) => this.onMove(e));
      this.canvas.addEventListener("pointerleave", () => { this.hover = null; this.tip.hidden = true; this.draw(); });
      new ResizeObserver(() => this.draw()).observe(this.canvas.parentElement);
    }

    set(t, v) {
      this.t = t;
      this.v = v;
      if (this.note) this.note.textContent = v.length ? `hiện tại ${this.valueLabel(v[v.length - 1])}` : "";
      this.draw();
      if (this.hover != null) this.showTip();
    }

    markers() {
      if (!this.t.length) return [];
      const t0 = this.t[0], t1 = this.t[this.t.length - 1] + 1;
      const out = [];
      for (const id of state.order) {
        const a = state.alerts.get(id);
        if (a.ts >= t0 && a.ts <= t1) out.push(a);
        if (out.length > 300) break;
      }
      return out.reverse();
    }

    draw() {
      const box = this.canvas.parentElement;
      const w = box.clientWidth, hgt = box.clientHeight;
      if (!w || !hgt) return;
      const dpr = window.devicePixelRatio || 1;
      if (this.canvas.width !== Math.round(w * dpr) || this.canvas.height !== Math.round(hgt * dpr)) {
        this.canvas.width = Math.round(w * dpr);
        this.canvas.height = Math.round(hgt * dpr);
      }
      const ctx = this.canvas.getContext("2d");
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, hgt);
      const n = this.t.length;
      if (n < 2) return;

      const c = { grid: cssVar("--grid"), axis: cssVar("--axis"), muted: cssVar("--muted"),
                  accent: cssVar("--accent"), surface: cssVar("--surface"), ink: cssVar("--ink") };
      const pad = { l: 48, r: 14, t: 18, b: 20 };
      const pw = w - pad.l - pad.r, ph = hgt - pad.t - pad.b;
      const t0 = this.t[0], t1 = this.t[n - 1];
      const xOf = (ts) => pad.l + ((ts - t0) / (t1 - t0 || 1)) * pw;
      const maxV = Math.max(1, ...this.v);
      const step = niceStep(maxV / 3);
      const top = Math.max(step, Math.ceil(maxV / step) * step);
      const yOf = (val) => pad.t + ph - (val / top) * ph;
      this.geom = { pad, pw, xOf, yOf, w };

      ctx.font = `11px ${getComputedStyle(document.body).fontFamily}`;
      ctx.lineWidth = 1;
      // lưới ngang + nhãn trục y
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      for (let tick = 0; tick <= top + 1e-9; tick += step) {
        const y = Math.round(yOf(tick)) + 0.5;
        ctx.strokeStyle = tick === 0 ? c.axis : c.grid;
        ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(w - pad.r, y); ctx.stroke();
        ctx.fillStyle = c.muted;
        ctx.fillText(this.axisFmt(tick), pad.l - 8, y);
      }
      // nhãn trục x: khoảng cách mốc tuỳ độ dài dữ liệu
      ctx.textAlign = "center";
      ctx.textBaseline = "alphabetic";
      const span = t1 - t0;
      const every = span <= 90 ? 15 : span <= 180 ? 30 : 60;
      for (let s = Math.ceil(t0 / every) * every; s <= t1; s += every) {
        const d = new Date(s * 1000);
        const label = `${pad2(d.getHours())}:${pad2(d.getMinutes())}` + (every < 60 ? `:${pad2(d.getSeconds())}` : "");
        ctx.fillText(label, xOf(s), hgt - 5);
      }

      // vùng + đường
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = xOf(this.t[i]), y = yOf(this.v[i]);
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      }
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.lineWidth = 2;
      ctx.strokeStyle = c.accent;
      ctx.stroke();
      ctx.lineTo(xOf(this.t[n - 1]), yOf(0));
      ctx.lineTo(xOf(this.t[0]), yOf(0));
      ctx.closePath();
      ctx.globalAlpha = 0.1;
      ctx.fillStyle = c.accent;
      ctx.fill();
      ctx.globalAlpha = 1;

      // điểm đánh dấu alert (dải trên cùng), severity cao vẽ sau để nằm trên
      const rank = { low: 0, medium: 1, high: 2, critical: 3 };
      const marks = this.markers().sort((a, b) => rank[a.severity] - rank[b.severity]);
      for (const a of marks) {
        const x = xOf(Math.min(Math.max(a.ts, t0), t1));
        this.dot(ctx, x, 7, cssVar(`--sev-${a.severity}`), c.surface);
      }

      // crosshair khi hover
      if (this.hover != null) {
        const i = this.hover;
        const x = Math.round(xOf(this.t[i])) + 0.5;
        ctx.strokeStyle = c.axis;
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(x, pad.t); ctx.lineTo(x, pad.t + ph); ctx.stroke();
        this.dot(ctx, x, yOf(this.v[i]), c.accent, c.surface);
      } else {
        this.dot(ctx, xOf(this.t[n - 1]), yOf(this.v[n - 1]), c.accent, c.surface);
      }
    }

    dot(ctx, x, y, fill, ring) {
      ctx.beginPath();
      ctx.arc(x, y, 6, 0, Math.PI * 2);
      ctx.fillStyle = ring;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = fill;
      ctx.fill();
    }

    onMove(e) {
      if (!this.geom || this.t.length < 2) return;
      const rect = this.canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const { pad, pw } = this.geom;
      const frac = Math.min(1, Math.max(0, (x - pad.l) / pw));
      this.hover = Math.round(frac * (this.t.length - 1));
      this.draw();
      this.showTip();
    }

    showTip() {
      const i = this.hover;
      if (i == null || !this.geom) return;
      const ts = this.t[i];
      const near = this.markers().filter((a) => Math.abs(a.ts - ts) <= 2).slice(-4).reverse();
      fill(this.tip,
        h("div", { class: "t-time" }, clock(ts)),
        h("div", { class: "t-val" }, this.valueLabel(this.v[i])),
        near.map((a) => h("div", { class: "t-alert" },
          h("span", { class: `mk sev-bg-${a.severity}` }), `${SEV[a.severity].label}: ${a.title}`)),
      );
      this.tip.hidden = false;
      const x = this.geom.xOf(ts);
      const tw = this.tip.offsetWidth;
      this.tip.style.left = `${x + 14 + tw > this.geom.w ? x - 14 - tw : x + 14}px`;
    }
  }

  const charts = [
    new LineChart($("#chart-pps"), { valueLabel: (v) => `${nf.format(v)} gói/s`, axisFmt: compact, note: $("#pps-note") }),
    new LineChart($("#chart-bps"), { valueLabel: bitsPerSec, axisFmt: compact, note: $("#bps-note") }),
  ];

  // ------------------------------------------------------------------ render: topbar & KPI
  function renderStatus(s) {
    state.status = s;
    const mode = MODE[s.mode] || { label: String(s.mode || "").toUpperCase(), icon: "pulse" };
    $("#mode-chip").replaceChildren(icon(mode.icon), h("span", null, mode.label));
    $("#source-desc").textContent = s.source || "";
    $("#uptime").replaceChildren(icon("clock"), duration(s.uptime));

    const cap = $("#capture-state");
    cap.classList.toggle("is-bad", Boolean(s.error));
    if (s.error) cap.replaceChildren(icon("warning-octagon"), "Lỗi capture");
    else if (s.running) cap.replaceChildren(h("span", { class: "live-dot" }), s.mode === "replay" ? "Đang phân tích" : "Đang giám sát");
    else cap.replaceChildren(icon("check-circle"), s.mode === "replay" ? "Đã phân tích xong" : "Đã dừng");

    const banner = $("#banner");
    if (s.error) {
      banner.replaceChildren(icon("warning-octagon"), h("div", null, h("b", null, "Không bắt được gói tin. "), s.error));
      banner.hidden = false;
    } else banner.hidden = true;

    const a = s.alerts || { total: 0, by_severity: {} };
    $("#kpi-alerts").textContent = nf.format(a.total);
    $("#kpi-sev").replaceChildren(...SEV_ORDER.map((sev) =>
      h("li", null, h("span", { class: `mk sev-bg-${sev}` }), SEV[sev].label, h("b", null, nf.format(a.by_severity[sev] || 0)))));
    $("#kpi-speed").textContent = s.packets ? `xử lý ${s.avg_us_per_packet} µs mỗi gói` : "";
    renderDetectors(s.detectors || []);
    updateEmpty();
  }

  function renderStats(st) {
    state.stats = st;
    $("#kpi-pps").replaceChildren(nf.format(st.rate.pps), h("small", null, "gói/s"));
    const [bv, bu] = bitsPerSec(st.rate.bps).split(" ");
    $("#kpi-bps").replaceChildren(bv, h("small", null, bu));
    $("#kpi-total").textContent = compact(st.totals.packets);
    $("#kpi-bytes").textContent = `${bytesFmt(st.totals.bytes)} dữ liệu`;
    $("#kpi-hosts").textContent = nf.format(st.totals.hosts);
    charts[0].set(st.series.t, st.series.pps);
    charts[1].set(st.series.t, st.series.bps);
    renderBreakdown(st);
  }

  function renderBreakdown(st) {
    const total = st.protocols.reduce((s, p) => s + p.packets, 0) || 1;
    const maxP = Math.max(1, ...st.protocols.map((p) => p.packets));
    $("#protocols").replaceChildren(...(st.protocols.length ? st.protocols.map((p) =>
      h("li", { title: `${nf.format(p.packets)} gói` },
        h("span", { class: "b-name" }, p.name),
        h("span", { class: "b-track" },
          h("span", { class: "b-fill", style: `width:${(p.packets / maxP) * 70}%` }),
          h("span", { class: "b-val" }, `${Math.round((p.packets / total) * 100)}%`)))) : [emptyRow()]));

    $("#top-src").replaceChildren(...(st.top_src.length ? st.top_src.map((s) =>
      h("li", null,
        h("span", { class: "r-ico", title: s.internal ? "Nội bộ" : "Bên ngoài" },
          icon(s.internal ? "house-line" : "globe-hemisphere-west"),
          h("span", { class: "sr-only" }, s.internal ? "Nội bộ" : "Bên ngoài")),
        h("span", { class: "r-name mono" }, s.ip),
        h("span", { class: "r-val" }, bytesFmt(s.bytes)))) : [emptyRow()]));

    $("#top-ports").replaceChildren(...(st.top_ports.length ? st.top_ports.map((p) =>
      h("li", null,
        h("span", { class: "r-ico" }, icon("hash")),
        h("span", { class: "r-name mono" }, String(p.port), p.service ? h("small", null, p.service) : null),
        h("span", { class: "r-val" }, `${compact(p.hits)} lần`))) : [emptyRow()]));
  }
  const emptyRow = () => h("li", { class: "list-empty" }, "Chưa có dữ liệu");

  function detectorState(d) {
    if (!d.enabled) return [null, "Tắt"];
    if (d.name === "ml") {
      if (d.status === "active") return ["brain", `Hoạt động, ngưỡng ${d.threshold}`];
      if (String(d.status).startsWith("learning")) {
        const m = /(\d+)\/(\d+)/.exec(d.status);
        return ["brain", m ? `Đang học ${m[1]}/${m[2]} flow` : "Đang học"];
      }
      return ["brain", "Chưa có model"];
    }
    if (d.name === "anomaly") return d.learning ? ["pulse", "Đang học baseline"] : ["pulse", `Baseline ~${compact(d.baseline_pps)} gói/s`];
    if (d.name === "signatures") return ["cpu", `${d.rules} rule`];
    return ["check", "Hoạt động"];
  }

  let detSig = "";
  function renderDetectors(list) {
    const sig = JSON.stringify(list.map((d) => [d.name, d.fired, d.status, d.learning, d.baseline_pps, d.enabled]));
    if (sig === detSig) return;
    detSig = sig;
    $("#detectors").replaceChildren(...list.map((d) => {
      const [ico, text] = detectorState(d);
      const learning = /Đang học/.test(text);
      return h("tr", null,
        h("td", { class: "d-name" }, d.title || d.name, h("small", null, d.name)),
        h("td", { class: "d-desc" }, d.description),
        h("td", null, (d.mitre || []).length ? d.mitre.map((t) =>
          h("a", { class: "tech", href: mitreUrl(t), target: "_blank", rel: "noopener noreferrer" }, t))
          : h("span", { class: "muted" }, "Theo rule")),
        h("td", { class: `d-state${learning ? " is-learning" : ""}` }, ico ? icon(ico) : null, text),
        h("td", { class: "num" }, nf.format(d.fired || 0)));
    }));
  }

  // ------------------------------------------------------------------ alert feed
  function passes(a) {
    const f = state.filter;
    if (f.sev && a.severity !== f.sev) return false;
    if (f.hideAcked && a.acked) return false;
    if (f.q) {
      const q = f.q.toLowerCase();
      const hay = `${a.title} ${a.src || ""} ${a.dst || ""} ${a.detector} ${a.description}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function alertRow(a, isNew) {
    const peer = a.dst ? `${a.src || "nhiều nguồn"} → ${a.dst}` : (a.src || "");
    return h("li", { dataset: { id: a.id } },
      h("button", {
        type: "button",
        class: `alert sev-${a.severity}${a.acked ? " is-acked" : ""}${isNew ? " is-new" : ""}`,
        onclick: () => openDrawer(a.id),
      },
        h("span", { class: "sev-tag" }, icon(SEV[a.severity].icon), SEV[a.severity].label),
        h("span", null,
          h("span", { class: "a-title", style: "display:block" }, a.title),
          h("span", { class: "a-meta" }, peer ? h("span", { class: "mono" }, peer) : null, h("span", null, a.detector))),
        h("span", { class: "a-side" },
          h("time", { datetime: new Date(a.ts * 1000).toISOString() }, clock(a.ts)),
          a.count > 1 ? h("span", { class: "a-count", title: "Số lần phát hiện đã gộp" }, `×${compact(a.count)}`) : null)));
  }

  function renderFeed() {
    const rows = [];
    for (const id of state.order) {
      const a = state.alerts.get(id);
      if (passes(a)) rows.push(alertRow(a, false));
      if (rows.length >= 400) break;
    }
    $("#alerts").replaceChildren(...rows);
    $("#feed-count").textContent = compact(rows.length);
    updateEmpty();
  }

  function updateEmpty() {
    const empty = $("#alerts-empty");
    const hasRows = $("#alerts").children.length > 0;
    empty.hidden = hasRows;
    if (hasRows) return;
    const filtered = state.filter.sev || state.filter.q || state.filter.hideAcked;
    const body = $("#empty-body");
    if (filtered && state.alerts.size) {
      $(".empty-title", empty).textContent = "Không có cảnh báo khớp bộ lọc";
      body.textContent = "Thử bỏ bớt điều kiện lọc ở phía trên.";
    } else {
      $(".empty-title", empty).textContent = "Chưa có cảnh báo";
      body.replaceChildren("Traffic đang được giám sát. Cảnh báo xuất hiện ở đây ngay khi một detector phát hiện bất thường.");
      if (state.status && state.status.mode === "live") {
        body.append(" Muốn xem thử các kịch bản tấn công mẫu? Chạy ", h("code", null, "mini-ids demo"), ".");
      }
    }
  }

  function addAlert(a, live) {
    const known = state.alerts.has(a.id);
    state.alerts.set(a.id, a);
    if (!known) {
      state.order.unshift(a.id);
      if (state.order.length > MAX_ALERTS) state.alerts.delete(state.order.pop());
    }
    if (!live) return;
    if (passes(a)) {
      const list = $("#alerts");
      list.prepend(alertRow(a, true));
      while (list.children.length > 400) list.lastChild.remove();
      $("#feed-count").textContent = compact(list.children.length);
    }
    updateEmpty();
  }

  function updateCounts(updates) {
    for (const u of updates) {
      const a = state.alerts.get(u.id);
      if (!a) continue;
      a.count = u.count;
      a.last_seen = u.last_seen;
      const li = $(`#alerts li[data-id="${CSS.escape(u.id)}"]`);
      if (li) li.replaceWith(alertRow(a, false));
      if (state.openId === u.id) fillDrawer(a);
    }
  }

  document.querySelectorAll(".chip").forEach((chip) => chip.addEventListener("click", () => {
    document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("is-on", c === chip));
    state.filter.sev = chip.dataset.sev;
    renderFeed();
  }));
  let searchTimer;
  $("#search").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.filter.q = e.target.value.trim(); renderFeed(); }, 150);
  });
  $("#hide-acked").addEventListener("change", (e) => { state.filter.hideAcked = e.target.checked; renderFeed(); });

  // ------------------------------------------------------------------ drawer chi tiết
  const HIDDEN_EVIDENCE = new Set(["payload_snippet", "example", "flow", "top_features"]);
  function evidenceValue(v) {
    if (Array.isArray(v)) return v.join(", ");
    if (v && typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  function fillDrawer(a) {
    $("#drawer-sev").replaceChildren(
      h("span", { class: `sev-tag sev-${a.severity}` }, icon(SEV[a.severity].icon), SEV[a.severity].label),
      h("span", { class: "muted", style: "margin-left:10px;font-size:12.5px" }, a.detector));
    $("#drawer-title").textContent = a.title;

    const kv = (pairs) => h("dl", { class: "kv" }, pairs.filter(([, v]) => v != null && v !== "")
      .flatMap(([k, v]) => [h("dt", null, k), h("dd", null, v)]));
    const ev = a.evidence || {};
    const evPairs = Object.entries(ev).filter(([k]) => !HIDDEN_EVIDENCE.has(k)).map(([k, v]) => [k, evidenceValue(v)]);
    const reasons = ev.top_features ? evidenceValue(ev.top_features) : null;
    const flow = ev.example || ev.flow;

    fill($("#drawer-body"),
      a.description ? h("p", { class: "desc" }, a.description) : null,
      kv([
        ["Lần đầu", clock(a.ts, true)],
        ["Lần cuối", clock(a.last_seen || a.ts, true)],
        ["Số lần (đã gộp)", nf.format(a.count || 1)],
        ["Nguồn", a.src ? h("span", { class: "mono" }, a.src) : "nhiều nguồn / không xác định"],
        ["Đích", a.dst ? h("span", { class: "mono" }, a.dst) : null],
        ["Mã alert", h("span", { class: "mono" }, a.id)],
      ]),
      (a.mitre || []).length ? h("section", null, h("h3", null, "MITRE ATT&CK"),
        h("div", null, a.mitre.map((t) => h("a", { class: "tech", href: mitreUrl(t), target: "_blank", rel: "noopener noreferrer" },
          t, " ", icon("arrow-square-out"))))) : null,
      evPairs.length ? h("section", null, h("h3", null, "Bằng chứng"), kv(evPairs)) : null,
      reasons ? h("section", null, h("h3", null, "Vì sao model nghi ngờ"), h("p", { class: "desc" }, reasons)) : null,
      flow ? h("section", null, h("h3", null, "Flow"), h("pre", { class: "payload" }, JSON.stringify(flow, null, 2))) : null,
      ev.payload_snippet ? h("section", null, h("h3", null, "Payload (160 byte đầu)"),
        h("pre", { class: "payload" }, ev.payload_snippet)) : null,
      a.pcap ? h("p", { class: "hint" }, "File .pcap chứa các gói tin liên quan tới cảnh báo này. Mở bằng Wireshark để xem từng gói.") : null,
    );

    const actions = [];
    if (a.pcap) {
      actions.push(h("a", { class: "btn btn-primary", href: `/api/alerts/${encodeURIComponent(a.id)}/pcap`, download: "" },
        icon("download-simple"), "Tải pcap"));
    }
    actions.push(h("button", { type: "button", class: "btn", onclick: () => toggleAck(a) },
      icon(a.acked ? "x" : "check"), a.acked ? "Bỏ đánh dấu" : "Đánh dấu đã xử lý"));
    $("#drawer-actions").replaceChildren(...actions);
  }

  async function openDrawer(id) {
    const a = state.alerts.get(id);
    if (!a) return;
    state.openId = id;
    state.lastFocus = document.activeElement;
    fillDrawer(a);
    $("#scrim").hidden = false;
    $("#drawer").hidden = false;
    $("#drawer-close").focus();
    try {
      const fresh = await api(`/api/alerts/${encodeURIComponent(id)}`);
      state.alerts.set(id, fresh);
      if (state.openId === id) fillDrawer(fresh);
    } catch { /* đã có dữ liệu cục bộ */ }
  }
  function closeDrawer() {
    state.openId = null;
    $("#drawer").hidden = true;
    $("#scrim").hidden = true;
    if (state.lastFocus && document.contains(state.lastFocus)) state.lastFocus.focus();
  }
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && state.openId) closeDrawer(); });

  async function toggleAck(a) {
    const acked = !a.acked;
    try {
      await api(`/api/alerts/${encodeURIComponent(a.id)}/ack?acked=${acked}`, { method: "POST" });
      a.acked = acked;
      fillDrawer(a);
      renderFeed();
    } catch (err) {
      console.error(err);
    }
  }

  // ------------------------------------------------------------------ mạng
  async function api(path, opts) {
    const res = await fetch(path, opts);
    if (!res.ok) throw new Error(`${res.status} ${path}`);
    return res.json();
  }

  async function loadAlerts() {
    const rows = await api("/api/alerts?limit=500");
    state.alerts.clear();
    state.order = [];
    for (const a of rows) { state.alerts.set(a.id, a); state.order.push(a.id); }
    renderFeed();
  }

  function setConn(ok) {
    state.connected = ok;
    const el = $("#conn-state");
    el.classList.toggle("is-bad", !ok);
    el.replaceChildren(icon(ok ? "plugs-connected" : "plugs"), ok ? "Realtime" : "Mất kết nối, đang thử lại");
  }

  let retry = 1000;
  let everConnected = false;
  function connect() {
    const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
    ws.onopen = () => {
      retry = 1000;
      setConn(true);
      if (everConnected) loadAlerts().catch(console.error);   // bù các alert lỡ mất khi rớt kết nối
      everConnected = true;
    };
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "stats") {
        renderStatus(msg.data.status);
        renderStats(msg.data.stats);
      } else if (msg.type === "alert") {
        addAlert(msg.data, true);
        charts.forEach((c) => c.draw());
      } else if (msg.type === "alert_update") {
        updateCounts(msg.data);
      }
    };
    ws.onclose = () => {
      setConn(false);
      setTimeout(connect, retry);
      retry = Math.min(retry * 2, 10000);
    };
  }

  // ------------------------------------------------------------------ khởi động
  for (const id of ["#protocols", "#top-src", "#top-ports"]) {
    $(id).replaceChildren(...[1, 2, 3, 4].map(() => h("li", null, h("span", { class: "skeleton sk-row", style: "grid-column:1/-1;width:100%" }))));
  }
  const urlTheme = new URLSearchParams(location.search).get("theme");   // ?theme=dark|light
  applyTheme(["dark", "light"].includes(urlTheme) ? urlTheme : storedTheme());
  setConn(false);
  $("#conn-state").replaceChildren(icon("plugs"), "Đang kết nối");
  $("#conn-state").classList.remove("is-bad");
  Promise.all([api("/api/status").then(renderStatus), api("/api/stats").then(renderStats), loadAlerts()])
    .catch((err) => console.error("Tải dữ liệu ban đầu lỗi", err));
  connect();
  if (document.fonts) document.fonts.ready.then(() => charts.forEach((c) => c.draw()));
})();
