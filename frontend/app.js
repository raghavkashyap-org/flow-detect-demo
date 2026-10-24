/**
 * FlowDetect Live SOC Controller (`app.js`)
 * Modular UI controller combining the 3D Obsidian Hero UX with 100% live WebSocket
 * ONNX flow scoring, 60 FPS pipeline telemetry, score stream chart, and 27-feature sandbox.
 */

const FEATURE_NAMES = [
  "Flow Duration", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Max", "Flow IAT Std",
  "Tot Fwd Pkts", "TotLen Fwd Pkts", "Flow Byts/s", "Down/Up Ratio", "Pkt Len Mean",
  "Pkt Len Std", "Pkt Len Max", "Fwd Pkt Len Max", "Fwd Pkt Len Mean", "Bwd Pkt Len Max",
  "Bwd Pkt Len Mean", "Fwd Act Data Pkts", "Fwd IAT Std", "Bwd IAT Mean", "Bwd IAT Tot",
  "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt", "Fwd PSH Flags",
  "Idle Mean", "Active Mean",
];

const state = {
  events: [],
  selectedEventId: null,
  status: null,
  soundEnabled: false,
  scoreHistory: [],
  particles: [],
  tau: 0.921056,
  totalPkts: 0,
  logPaused: false,
  ws: null,
  toastTimer: null,
};

const CLASS_COLORS = {
  Benign: "#10b981",
  Bot: "#a855f7",
  BruteForce: "#f59e0b",
  Flood: "#ef4444",
};

/* ---------------- TOAST, LIVE STREAM LOG & WEB AUDIO SYNTH ---------------- */
function showToast(msg) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => el.classList.add("hidden"), 3200);
}

function appendStreamLog(message, level = "info") {
  const log = document.getElementById("live-log");
  if (!log) return;
  const now = new Date().toLocaleTimeString("en-GB", { hour12: false });
  const colorMap = {
    ok: "#34d399",
    warn: "#fbbf24",
    err: "#f87171",
    bot: "#c084fc",
    info: "#a1a7b3",
  };
  const line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = `<span class="log-time">[${now}]</span><span style="color:${colorMap[level] || colorMap.info}">${message}</span>`;
  log.appendChild(line);
  if (!state.logPaused) {
    log.scrollTop = log.scrollHeight;
  }
  while (log.children.length > 100) {
    log.removeChild(log.firstChild);
  }
}

function playAlertTone() {
  if (!state.soundEnabled) return;
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    const ctx = new Ctx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "triangle";
    osc.frequency.setValueAtTime(740, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(990, ctx.currentTime + 0.14);
    gain.gain.setValueAtTime(0.12, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.28);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.28);
  } catch (_) {}
}

function pulseHeroCore(cls, isAlert) {
  const coreWrap = document.getElementById("coreWrap");
  if (!coreWrap) return;
  const col = CLASS_COLORS[cls] || "#ffffff";
  coreWrap.style.filter = isAlert
    ? `brightness(1.45) drop-shadow(0 0 28px ${col})`
    : `brightness(1.18) drop-shadow(0 0 16px rgba(16,185,129,0.45))`;
  setTimeout(() => {
    coreWrap.style.filter = "";
  }, 520);
}

/* ---------------- THEME, NAV SCROLL, REVEAL & 3D HERO STAGE ---------------- */
function setColorMode(mode) {
  document.documentElement.dataset.mode = mode;
  try {
    localStorage.setItem("fd-mode", mode);
  } catch (_) {}
  const icon = document.getElementById("modeIcon");
  if (icon) {
    icon.innerHTML =
      mode === "light"
        ? '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'
        : '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>';
  }
  renderScoreChart();
}

function initChromeUX() {
  const savedMode = document.documentElement.dataset.mode || "dark";
  setColorMode(savedMode);

  const modeBtn = document.getElementById("modeBtn");
  if (modeBtn) {
    modeBtn.onclick = () => {
      const next = document.documentElement.dataset.mode === "light" ? "dark" : "light";
      setColorMode(next);
    };
  }

  // Smooth scroll & active section spy
  const nav = document.getElementById("nav");
  const prog = document.getElementById("prog");
  const topBtn = document.getElementById("top");
  const navLinks = document.getElementById("navLinks");
  const navTog = document.getElementById("navTog");

  const onScroll = () => {
    const y = window.scrollY;
    if (nav) nav.classList.toggle("small", y > 24);
    if (topBtn) topBtn.classList.toggle("on", y > 500);
    const totalH = document.documentElement.scrollHeight - window.innerHeight;
    if (prog) prog.style.width = (totalH > 0 ? (y / totalH) * 100 : 0) + "%";

    let currentId = "hero";
    document.querySelectorAll("#hero, main .sec").forEach((sec) => {
      if (sec.offsetTop - 180 <= y) currentId = sec.id;
    });
    document.querySelectorAll(".nav-link[data-go]").forEach((btn) => {
      btn.classList.toggle("on", btn.dataset.go === currentId);
    });
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  if (topBtn) topBtn.onclick = () => window.scrollTo({ top: 0, behavior: "smooth" });
  if (navTog && navLinks) navTog.onclick = () => navLinks.classList.toggle("open");

  document.querySelectorAll("[data-go]").forEach((el) => {
    el.addEventListener("click", () => {
      const target = document.getElementById(el.dataset.go);
      if (target) target.scrollIntoView({ behavior: "smooth" });
      if (navLinks) navLinks.classList.remove("open");
    });
  });

  // Scroll-reveal observer
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          io.unobserve(entry.target);
        }
      });
    },
    { rootMargin: "0px 0px -40px 0px" }
  );
  document.querySelectorAll(".rv").forEach((el) => io.observe(el));

  // Mouse spotlight glow on `.card.spot`
  window.addEventListener(
    "mousemove",
    (e) => {
      const card = e.target.closest?.(".card.spot");
      if (!card) return;
      const rect = card.getBoundingClientRect();
      card.style.setProperty("--mx", `${e.clientX - rect.left}px`);
      card.style.setProperty("--my", `${e.clientY - rect.top}px`);
    },
    { passive: true }
  );

  // 3D Hero Stage Parallax & Ambient Data Particles
  const stage = document.getElementById("infraStage");
  const coreWrap = document.getElementById("coreWrap");
  const particlesEl = document.getElementById("particles");
  if (!stage || !coreWrap || !particlesEl) return;

  stage.addEventListener("mousemove", (e) => {
    const r = stage.getBoundingClientRect();
    const mx = (e.clientX - (r.left + r.width / 2)) / r.width;
    const my = (e.clientY - (r.top + r.height / 2)) / r.height;
    coreWrap.style.transform = `translate3d(${mx * 18}px, ${my * 12}px, 0) rotateX(${my * -6}deg) rotateY(${mx * 10}deg)`;
    document.querySelectorAll(".mono-block").forEach((b, i) => {
      const factor = 0.6 + i * 0.15;
      b.style.setProperty("--px", `${mx * 26 * factor}px`);
      b.style.setProperty("--py", `${my * 16 * factor}px`);
    });
  });

  stage.addEventListener("mouseleave", () => {
    coreWrap.style.transform = "translate3d(0, 0, 0)";
    document.querySelectorAll(".mono-block").forEach((b) => {
      b.style.setProperty("--px", "0px");
      b.style.setProperty("--py", "0px");
    });
  });

  document.querySelectorAll(".mono-block").forEach((b) => {
    b.addEventListener("mouseenter", () => {
      coreWrap.style.filter = "brightness(1.4) drop-shadow(0 0 22px rgba(255,255,255,0.4))";
      coreWrap.style.setProperty("--coreScale", "1.08");
    });
    b.addEventListener("mouseleave", () => {
      coreWrap.style.filter = "";
      coreWrap.style.setProperty("--coreScale", "1");
    });
  });

  const routes = [
    { sx: 18, sy: 18, ex: 50, ey: 50 },
    { sx: 82, sy: 18, ex: 50, ey: 50 },
    { sx: 18, sy: 82, ex: 50, ey: 50 },
    { sx: 82, sy: 82, ex: 50, ey: 50 },
  ];

  function spawnHeroParticle() {
    if (document.hidden) return;
    const r = routes[Math.floor(Math.random() * routes.length)];
    const b = stage.getBoundingClientRect();
    if (b.width <= 0) return;
    const p = document.createElement("div");
    p.className = "particle";
    const x1 = (r.sx / 100) * b.width;
    const y1 = (r.sy / 100) * b.height;
    const x2 = (r.ex / 100) * b.width;
    const y2 = (r.ey / 100) * b.height;
    p.style.left = `${x1}px`;
    p.style.top = `${y1}px`;
    p.style.setProperty("--dx", `${x2 - x1}px`);
    p.style.setProperty("--dy", `${y2 - y1}px`);
    p.style.setProperty("--dur", `${(1.3 + Math.random() * 1.5).toFixed(2)}s`);
    particlesEl.appendChild(p);
    setTimeout(() => p.remove(), 2900);
  }

  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    setInterval(spawnHeroParticle, 240);
  }
}

/* ---------------- 60 FPS PIPELINE TOPOLOGY CANVAS ---------------- */
function spawnPacketParticles(cls, count = 7) {
  const color = CLASS_COLORS[cls] || "#e5e5e5";
  for (let i = 0; i < count; i++) {
    state.particles.push({
      x: 75 - i * 18,
      y: 44 + (Math.random() - 0.5) * 20,
      speed: 5.4 + Math.random() * 2.4,
      color,
      r: cls === "Benign" ? 3.2 : 4.8,
    });
  }
}

function startTopologyLoop() {
  const canvas = document.getElementById("topology-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const nodes = [
    { x: 115, label: "Live Clients / LAN", sub: "HTTP & TCP Streams" },
    { x: 430, label: "Scapy + ASGI Collector", sub: "27 Flow Features (µs)" },
    { x: 785, label: "Dual ONNX Runtime", sub: "v1 Raw + v2 Live CPU" },
    { x: 1120, label: "Live SOC Broadcast", sub: "WebSocket + Shield 403" },
  ];

  function frame() {
    const W = canvas.width;
    const H = canvas.height;
    const isLight = document.documentElement.dataset.mode === "light";
    ctx.clearRect(0, 0, W, H);

    // Connecting steel backbone wire
    ctx.strokeStyle = isLight ? "rgba(15, 17, 21, 0.18)" : "rgba(255, 255, 255, 0.16)";
    ctx.lineWidth = 1.8;
    ctx.beginPath();
    ctx.moveTo(nodes[0].x, H / 2);
    ctx.lineTo(nodes[nodes.length - 1].x, H / 2);
    ctx.stroke();

    // Moving live packet particles
    for (let i = state.particles.length - 1; i >= 0; i--) {
      const p = state.particles[i];
      p.x += p.speed;
      if (p.x > nodes[nodes.length - 1].x) {
        state.particles.splice(i, 1);
        continue;
      }
      ctx.fillStyle = p.color;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    }

    // Monochrome steel stage cards
    nodes.forEach((n) => {
      ctx.fillStyle = isLight ? "#ffffff" : "#0e1016";
      ctx.strokeStyle = isLight ? "rgba(0, 0, 0, 0.16)" : "rgba(255, 255, 255, 0.16)";
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.roundRect(n.x - 102, 15, 204, 58, 10);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = isLight ? "#0f1115" : "#f4f5f7";
      ctx.font = "700 12.5px Inter, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(n.label, n.x, 38);

      ctx.fillStyle = isLight ? "#5b6474" : "#8a8f9a";
      ctx.font = "10.5px 'JetBrains Mono', ui-monospace, monospace";
      ctx.fillText(n.sub, n.x, 56);
    });

    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

/* ---------------- UI RENDERERS ---------------- */
function renderAlertBanner(latestEvent) {
  const banner = document.getElementById("threat-banner");
  const icon = document.getElementById("banner-icon");
  const title = document.getElementById("banner-title");
  const sub = document.getElementById("banner-sub");

  if (!latestEvent || !latestEvent.alert) {
    banner.className = "banner-safe";
    icon.className = "pulse-dot dot-green";
    title.textContent = "SYSTEM PROTECTED — LIVE FLOW TELEMETRY NORMAL";
    sub.innerHTML = latestEvent
      ? `Last flow from <code>${latestEvent.client_ip}</code> classified <strong>Benign</strong> (Score: <code>${latestEvent.attack_score.toFixed(4)}</code> &lt; &tau; <code>${state.tau.toFixed(4)}</code>)`
      : `Monitoring FastAPI (:8000) streams — Gate rule: <code>(1 - P(Benign)) &ge; ${state.tau.toFixed(4)}</code>`;
    return;
  }

  banner.className = "banner-danger";
  icon.className = "pulse-dot dot-red";
  title.textContent = `ALERT: ${latestEvent.predicted_class.toUpperCase()} DETECTED FROM ${latestEvent.client_ip}`;
  sub.innerHTML =
    `Confidence: <strong>${(latestEvent.attack_score * 100).toFixed(2)}%</strong> ` +
    `(Gate &tau; = ${(latestEvent.threshold_tau * 100).toFixed(1)}%) &bull; ` +
    `Endpoint: <code>${latestEvent.path}</code> &bull; Model: <code>${latestEvent.active_model}</code>`;
}

function renderSystemStatus(snap) {
  if (!snap) return;
  state.status = snap;
  state.tau = snap.gate.tau;

  document.getElementById("os-pill").textContent = String(snap.os || "Host").replace(/^Windows\s+/, "Win ");
  const lanIp = (snap.lan_ips && snap.lan_ips[0]) || window.location.hostname;
  const sharePort = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
  const portSuffix = (sharePort === "80" || sharePort === "443") ? "" : `:${sharePort}`;
  const shareUrl = `${window.location.protocol}//${lanIp}${portSuffix}`;

  const lanEl = document.getElementById("lan-pill");
  lanEl.textContent = `Frontend URL: ${shareUrl}`;
  lanEl.dataset.shareUrl = shareUrl;
  lanEl.dataset.apiHost = lanIp;

  document.getElementById("capture-desc").textContent = snap.capture_engine.description;
  document.getElementById("tau-display").textContent = snap.gate.tau.toFixed(6);
  document.getElementById("tau-slider").value = snap.gate.tau;
  document.getElementById("hero-tau").textContent = snap.gate.tau.toFixed(4);

  const isV2 = snap.models.active_model === "v2_live";
  document.getElementById("mode-v2").classList.toggle("active", isV2);
  document.getElementById("mode-v1").classList.toggle("active", !isV2);
  document.getElementById("model-explain").innerHTML = isV2
    ? `<strong>v2 Active (Recommended):</strong> Regularized <code>HistGradientBoosting</code> (<code>l2=1.5</code>, max leaf <code>0.32</code>) + cross-flow telemetry. Detects live LAN/Wi-Fi, Cloud &amp; CICIDS2017 attacks.`
    : `<strong>v1 Raw Active (Original Wormhole model.onnx):</strong> Unregularized CICIDS2017 baseline (<code>l2=0.0</code>, max leaf <code>32,935.9</code>). Catches lab traces, demonstrates live RTT domain shift.`;

  const isEnforce = snap.gate.shield_mode === "enforce";
  document.getElementById("shield-alert").classList.toggle("active", !isEnforce);
  document.getElementById("shield-enforce").classList.toggle("active", isEnforce);

  const box = document.getElementById("blocked-container");
  const listEl = document.getElementById("blocked-list");
  if (snap.blocked_ips && snap.blocked_ips.length > 0) {
    box.classList.remove("hidden");
    listEl.innerHTML = snap.blocked_ips
      .map(
        (b) => `
        <span class="chip-block">
          <strong>${b.ip}</strong> (${b.reason} &bull; ${b.remaining_sec}s)
          <button onclick="unblockIp('${b.ip}')">Unblock</button>
        </span>`
      )
      .join("");
  } else {
    box.classList.add("hidden");
  }

  renderKpis(snap.stats, snap.total_packets_ingested);
}

function renderKpis(stats, totalPkts) {
  if (!stats) return;
  const total = stats.total_flows_scored || 0;
  const alerts = stats.total_alerts || 0;
  document.getElementById("kpi-total").textContent = total;
  document.getElementById("kpi-benign").textContent = stats.Benign || 0;
  document.getElementById("kpi-flood").textContent = stats.Flood || 0;
  document.getElementById("kpi-bf").textContent = stats.BruteForce || 0;
  document.getElementById("kpi-bot").textContent = stats.Bot || 0;

  document.getElementById("hero-flows").textContent = total;
  document.getElementById("hero-alerts").textContent = alerts;

  if (typeof totalPkts === "number") {
    state.totalPkts = totalPkts;
  }
  document.getElementById("kpi-pkts").textContent = `${state.totalPkts} segments processed`;
}

function renderScoreChart() {
  const canvas = document.getElementById("score-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width;
  const H = canvas.height;
  const isLight = document.documentElement.dataset.mode === "light";
  ctx.clearRect(0, 0, W, H);

  const tauY = H - state.tau * (H - 18) - 9;
  ctx.strokeStyle = "rgba(239, 68, 68, 0.78)";
  ctx.lineWidth = 1.4;
  ctx.setLineDash([5, 4]);
  ctx.beginPath();
  ctx.moveTo(0, tauY);
  ctx.lineTo(W, tauY);
  ctx.stroke();
  ctx.setLineDash([]);

  const pts = state.scoreHistory.slice(-50);
  if (pts.length === 0) return;

  const stepX = (W - 20) / Math.max(pts.length - 1, 11);
  ctx.lineWidth = 1.9;
  ctx.strokeStyle = isLight ? "#1f242c" : "rgba(229, 231, 235, 0.72)";
  ctx.beginPath();
  pts.forEach((item, idx) => {
    const x = idx * stepX + 10;
    const y = H - item.score * (H - 18) - 9;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  pts.forEach((item, idx) => {
    const x = idx * stepX + 10;
    const y = H - item.score * (H - 18) - 9;
    ctx.fillStyle = CLASS_COLORS[item.cls] || "#e5e5e5";
    ctx.beginPath();
    ctx.arc(x, y, item.alert ? 4.5 : 3.1, 0, Math.PI * 2);
    ctx.fill();
  });
}

function renderFlowTable() {
  const tbody = document.getElementById("flow-tbody");
  if (!tbody) return;
  if (state.events.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No flows scored yet — launch traffic above or run any external tool against Port 8000.</td></tr>`;
    return;
  }

  tbody.innerHTML = state.events
    .slice(0, 50)
    .map((ev) => {
      const sel = ev.id === state.selectedEventId ? "selected" : "";
      const v1c = ev.comparison.v1_raw.predicted_class;
      const v2c = ev.comparison.v2_live.predicted_class;
      return `
        <tr class="${sel}" onclick="selectEvent('${ev.id}')">
          <td><code>${ev.time_str}</code></td>
          <td><strong>${ev.client_ip}</strong></td>
          <td><code>${ev.path}</code></td>
          <td>${ev.total_pkts}</td>
          <td><span class="tag tag-${ev.predicted_class}">${ev.predicted_class}</span></td>
          <td><strong>${(ev.attack_score * 100).toFixed(1)}%</strong></td>
          <td>
            <div class="dual-tags">
              <span class="tag tag-${v1c}" title="Original model.onnx">v1:${v1c}</span>
              <span class="tag tag-${v2c}" title="Fixed model_v2_live.onnx">v2:${v2c}</span>
            </div>
          </td>
          <td><code>${ev.latency_ms.toFixed(2)}ms</code></td>
        </tr>`;
    })
    .join("");
}

function renderInspector(ev) {
  const emptyEl = document.getElementById("inspector-empty");
  const contentEl = document.getElementById("inspector-content");
  const editBtn = document.getElementById("btn-edit-selected");
  if (!ev) {
    emptyEl.classList.remove("hidden");
    contentEl.classList.add("hidden");
    editBtn.classList.add("hidden");
    return;
  }
  emptyEl.classList.add("hidden");
  contentEl.classList.remove("hidden");
  editBtn.classList.remove("hidden");

  document.getElementById("insp-header").innerHTML =
    `<strong>${ev.client_ip}</strong> &rarr; <code>${ev.path}</code> &bull; ` +
    `Verdict: <span class="tag tag-${ev.predicted_class}">${ev.predicted_class}</span> ` +
    `&bull; Collector: <code>${ev.source_collector}</code>`;

  const barsHtml = ["Benign", "Flood", "BruteForce", "Bot"]
    .map((cls) => {
      const p = ev.probabilities[cls] || 0;
      const pct = (p * 100).toFixed(2);
      return `
        <div class="prob-row">
          <strong>${cls}</strong>
          <div class="prob-track">
            <div class="prob-fill" style="width:${Math.max(1.2, p * 100)}%;background:${CLASS_COLORS[cls]}"></div>
          </div>
          <span>${pct}%</span>
        </div>`;
    })
    .join("");
  document.getElementById("prob-bars").innerHTML = barsHtml;

  const entries = Object.entries(ev.all_features || {});
  document.getElementById("features-grid").innerHTML = entries
    .map(
      ([k, v], i) => `
      <div class="feat-item">
        <span class="feat-name">[${i}] ${k}</span>
        <span class="feat-val">${v}</span>
      </div>`
    )
    .join("");
}

/* ---------------- MANUAL 27-FEATURE SANDBOX MODAL ---------------- */
function openManualLab(prefillMap) {
  const modal = document.getElementById("lab-modal");
  const grid = document.getElementById("lab-inputs");
  const source =
    prefillMap ||
    (state.events[0] && state.events[0].all_features) ||
    Object.fromEntries(FEATURE_NAMES.map((f) => [f, 0]));

  grid.innerHTML = FEATURE_NAMES.map(
    (name, idx) => `
    <div class="lab-field">
      <label>[${idx}] ${name}</label>
      <input type="number" step="any" data-fname="${name}" value="${source[name] ?? 0}" />
    </div>`
  ).join("");
  modal.classList.remove("hidden");
}

window.selectEvent = function selectEvent(id) {
  state.selectedEventId = id;
  const found = state.events.find((e) => e.id === id);
  renderFlowTable();
  renderInspector(found);
};

window.unblockIp = async function unblockIp(ip) {
  await fetch(`${window.FlowDetectConfig.apiBase}/api/security/unblock/${encodeURIComponent(ip)}`, {
    method: "POST",
  });
  showToast(`Unblocked IP ${ip}`);
  appendStreamLog(`Active Shield unblocked client IP ${ip} -> HTTP 200 restored`, "ok");
  await refreshStatus();
};

async function patchConfig(body) {
  const res = await fetch(`${window.FlowDetectConfig.apiBase}/api/security/config`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.ok) {
    const snap = await res.json();
    renderSystemStatus(snap);
    renderScoreChart();
  }
}

async function refreshStatus() {
  const res = await fetch(`${window.FlowDetectConfig.apiBase}/api/security/status`);
  if (!res.ok) return;
  const snap = await res.json();
  if (state.events.length === 0 && snap.recent_events && snap.recent_events.length > 0) {
    state.events = snap.recent_events;
    state.selectedEventId = state.events[0].id;
    state.scoreHistory = snap.recent_events
      .slice()
      .reverse()
      .map((e) => ({ score: e.attack_score, cls: e.predicted_class, alert: e.alert }));
    document.getElementById("hero-latency").textContent = `${state.events[0].latency_ms.toFixed(2)}ms`;
    renderFlowTable();
    renderInspector(state.events[0]);
    renderScoreChart();
    renderAlertBanner(state.events[0]);
  }
  renderSystemStatus(snap);
}

/* ---------------- REAL-TIME WEBSOCKET ENGINE ---------------- */
function connectWebSocket() {
  const pill = document.getElementById("ws-pill");
  const ws = new WebSocket(window.FlowDetectConfig.wsUrl);
  state.ws = ws;

  ws.onopen = () => {
    pill.textContent = "Live WS: Connected";
    pill.className = "nav-pill nav-pill-ok";
    appendStreamLog(`WebSocket connected -> ${window.FlowDetectConfig.wsUrl} (Dual ONNX ready)`, "ok");
  };

  ws.onmessage = (msg) => {
    const data = JSON.parse(msg.data);
    if (data.type === "hello") {
      renderSystemStatus(data.status);
    } else if (data.type === "config_updated") {
      renderSystemStatus(data.status);
      renderScoreChart();
      appendStreamLog(
        `Engine config synced -> model=${data.status.models.active_model}, shield=${data.status.gate.shield_mode}, tau=${data.status.gate.tau.toFixed(4)}`,
        "info"
      );
    } else if (data.type === "reset") {
      state.events = [];
      state.scoreHistory = [];
      state.selectedEventId = null;
      renderSystemStatus(data.status);
      renderFlowTable();
      renderInspector(null);
      renderScoreChart();
      renderAlertBanner(null);
      appendStreamLog("Stream reset -> cleared active flow sessions and counters", "ok");
      showToast("Cleared stream history and counters");
    } else if (data.type === "flow_event") {
      const ev = data.event;
      state.events.unshift(ev);
      if (state.events.length > 80) state.events.pop();
      state.scoreHistory.push({ score: ev.attack_score, cls: ev.predicted_class, alert: ev.alert });
      state.selectedEventId = ev.id;
      state.totalPkts += ev.total_pkts || 0;
      document.getElementById("hero-latency").textContent = `${ev.latency_ms.toFixed(2)}ms`;

      spawnPacketParticles(ev.predicted_class, ev.alert ? 9 : 4);
      pulseHeroCore(ev.predicted_class, ev.alert);
      if (ev.alert) playAlertTone();

      const logLevel = !ev.alert
        ? "ok"
        : ev.predicted_class === "Flood"
        ? "err"
        : ev.predicted_class === "BruteForce"
        ? "warn"
        : "bot";
      appendStreamLog(
        `${ev.alert ? "ALERT" : "FLOW"} ${ev.client_ip} -> ${ev.path} | pkts=${ev.total_pkts} | verdict=${ev.predicted_class} (${(ev.attack_score * 100).toFixed(1)}%) | v1=${ev.comparison.v1_raw.predicted_class} v2=${ev.comparison.v2_live.predicted_class} | ${ev.latency_ms.toFixed(2)}ms`,
        logLevel
      );

      renderAlertBanner(ev);
      renderKpis(data.stats);
      renderFlowTable();
      renderInspector(ev);
      renderScoreChart();

      if (state.status && state.status.gate.shield_mode === "enforce" && ev.alert) {
        refreshStatus();
      }
    }
  };

  ws.onclose = () => {
    pill.textContent = "WS Reconnecting...";
    pill.className = "nav-pill nav-pill-warn";
    setTimeout(connectWebSocket, 1800);
  };
}

/* ---------------- APPLICATION BOOTSTRAP ---------------- */
async function initApp() {
  initChromeUX();
  startTopologyLoop();
  await window.FlowDetectConfig.init();
  await refreshStatus();
  connectWebSocket();

  document.getElementById("mode-v2").onclick = () => patchConfig({ active_model: "v2_live" });
  document.getElementById("mode-v1").onclick = () => patchConfig({ active_model: "v1_raw" });
  document.getElementById("shield-alert").onclick = () => patchConfig({ shield_mode: "alert" });
  document.getElementById("shield-enforce").onclick = () => patchConfig({ shield_mode: "enforce" });

  document.getElementById("tau-slider").onchange = (e) =>
    patchConfig({ tau: parseFloat(e.target.value) });
  document.getElementById("tau-slider").oninput = (e) => {
    const v = parseFloat(e.target.value);
    document.getElementById("tau-display").textContent = v.toFixed(6);
    state.tau = v;
    renderScoreChart();
  };

  document.getElementById("btn-sound").onclick = (e) => {
    state.soundEnabled = !state.soundEnabled;
    e.target.textContent = `Sound Alert: ${state.soundEnabled ? "ON" : "OFF"}`;
    if (state.soundEnabled) playAlertTone();
  };

  document.getElementById("btn-reset").onclick = async () => {
    await fetch(`${window.FlowDetectConfig.apiBase}/api/security/reset`, { method: "POST" });
  };

  const logEl = document.getElementById("live-log");
  const logPill = document.getElementById("log-scroll-pill");
  logEl.addEventListener("mouseenter", () => {
    state.logPaused = true;
    if (logPill) {
      logPill.textContent = "Hover Paused";
      logPill.className = "chip chip-warn";
    }
  });
  logEl.addEventListener("mouseleave", () => {
    state.logPaused = false;
    logEl.scrollTop = logEl.scrollHeight;
    if (logPill) {
      logPill.textContent = "Auto-Scroll: Live";
      logPill.className = "chip chip-ok";
    }
  });

  document.getElementById("btn-clear-log").onclick = () => {
    document.getElementById("live-log").innerHTML = "";
    appendStreamLog("Event log cleared", "info");
  };

  document.getElementById("lan-pill").onclick = (e) => {
    const url = e.currentTarget.dataset.shareUrl;
    if (url && navigator.clipboard) {
      navigator.clipboard.writeText(url);
      showToast(`Copied Frontend URL: ${url}`);
    }
  };

  document.getElementById("cli-copy-btn").onclick = () => {
    const ip = document.getElementById("lan-pill").dataset.apiHost || "127.0.0.1";
    const cmd = `python attack_simulator.py --target http://${ip}:8000 --mode all`;
    if (navigator.clipboard) navigator.clipboard.writeText(cmd);
    showToast(`Copied: ${cmd}`);
  };

  document.getElementById("btn-open-lab").onclick = () => openManualLab();
  document.getElementById("hero-open-lab").onclick = () => openManualLab();
  document.getElementById("btn-edit-selected").onclick = () => {
    const cur = state.events.find((e) => e.id === state.selectedEventId);
    openManualLab(cur ? cur.all_features : null);
  };

  const closeLab = () => document.getElementById("lab-modal").classList.add("hidden");
  document.getElementById("btn-close-lab").onclick = closeLab;
  document.getElementById("btn-zero-lab").onclick = () => {
    document.querySelectorAll("#lab-inputs input").forEach((inp) => {
      inp.value = "0";
    });
    showToast("Reset all 27 sandbox inputs to 0");
  };
  document.getElementById("lab-modal").addEventListener("click", (e) => {
    if (e.target.id === "lab-modal") closeLab();
  });
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeLab();
  });

  document.getElementById("btn-run-manual").onclick = async () => {
    const features = {};
    document.querySelectorAll("#lab-inputs input").forEach((inp) => {
      features[inp.dataset.fname] = parseFloat(inp.value || "0") || 0;
    });
    const res = await fetch(`${window.FlowDetectConfig.apiBase}/api/security/score-features`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ features, client_ip: "manual-lab-test" }),
    });
    if (res.ok) {
      const ev = await res.json();
      closeLab();
      showToast(`Scored 27 features -> ${ev.predicted_class} (${(ev.attack_score * 100).toFixed(1)}%)`);
    }
  };

  document.querySelectorAll("[data-sim]").forEach((btn) => {
    btn.onclick = async () => {
      btn.disabled = true;
      try {
        await fetch(
          `${window.FlowDetectConfig.apiBase}/api/security/simulate/${btn.dataset.sim}`,
          { method: "POST" }
        );
        showToast(`Executed live scenario: ${btn.dataset.sim}`);
      } finally {
        btn.disabled = false;
      }
    };
  });

  document.getElementById("pcap-input").onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${window.FlowDetectConfig.apiBase}/api/security/pcap-upload`, {
      method: "POST",
      body: fd,
    });
    if (res.ok) {
      const out = await res.json();
      showToast(`PCAP ${out.filename}: extracted & scored ${out.flows_extracted} flows!`);
    }
    e.target.value = "";
  };
}

initApp();
