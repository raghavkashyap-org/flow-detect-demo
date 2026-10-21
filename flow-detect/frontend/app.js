/**
 * FlowDetect Live SOC Dashboard Controller (`app.js`)
 * Structured cleanly as modular UI renderers ready for 1:1 React component migration.
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
  ws: null,
  toastTimer: null,
};

const CLASS_COLORS = {
  Benign: "#10b981",
  Bot: "#a855f7",
  BruteForce: "#f59e0b",
  Flood: "#ef4444",
};

function showToast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => el.classList.add("hidden"), 3400);
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

function spawnPacketParticles(cls, count = 7) {
  const color = CLASS_COLORS[cls] || "#38bdf8";
  for (let i = 0; i < count; i++) {
    state.particles.push({
      x: 70 - i * 18,
      y: 43 + (Math.random() - 0.5) * 20,
      speed: 5.2 + Math.random() * 2.5,
      color,
      r: cls === "Benign" ? 3.2 : 4.6,
    });
  }
}

/* ---------------- 60 FPS TOPOLOGY PIPELINE ANIMATOR ---------------- */
function startTopologyLoop() {
  const canvas = document.getElementById("topology-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const nodes = [
    { x: 115, label: "Live Clients / Wi-Fi", sub: "HTTP / TCP Streams" },
    { x: 440, label: "Scapy + ASGI Collector", sub: "27 Flow Features (µs)" },
    { x: 805, label: "Dual ONNX Runtime", sub: "v1 + v2 (0.015 ms CPU)" },
    { x: 1145, label: "Live SOC Dashboard", sub: "WebSocket Broadcast" },
  ];

  function frame() {
    const W = canvas.width;
    const H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    // Connecting backbone wire
    ctx.strokeStyle = "rgba(56, 189, 248, 0.25)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(nodes[0].x, H / 2);
    ctx.lineTo(nodes[nodes.length - 1].x, H / 2);
    ctx.stroke();

    // Update & render moving flow particles
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

    // Draw stage boxes
    nodes.forEach((n) => {
      ctx.fillStyle = "#16203a";
      ctx.strokeStyle = "#314575";
      ctx.lineWidth = 1.3;
      ctx.beginPath();
      ctx.roundRect(n.x - 102, 14, 204, 58, 9);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = "#e6ecff";
      ctx.font = "bold 12.5px Inter, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(n.label, n.x, 38);

      ctx.fillStyle = "#93a3c7";
      ctx.font = "11px ui-monospace, monospace";
      ctx.fillText(n.sub, n.x, 56);
    });

    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

/* ---------------- COMPONENT 1: TOP ALERT BANNER ---------------- */
function renderAlertBanner(latestEvent) {
  const banner = document.getElementById("threat-banner");
  const icon = document.getElementById("banner-icon");
  const title = document.getElementById("banner-title");
  const sub = document.getElementById("banner-sub");

  if (!latestEvent || !latestEvent.alert) {
    banner.className = "banner banner-safe";
    icon.className = "pulse-dot dot-green";
    title.textContent = "SYSTEM PROTECTED — LIVE FLOW TELEMETRY NORMAL";
    sub.innerHTML = latestEvent
      ? `Last flow from <code>${latestEvent.client_ip}</code> classified <strong>Benign</strong> (Attack score: <code>${latestEvent.attack_score.toFixed(4)}</code> &lt; &tau; <code>${state.tau.toFixed(4)}</code>)`
      : `Monitoring FastAPI (:8000) streams — Gate rule: <code>(1 - P(Benign)) &ge; ${state.tau.toFixed(4)}</code>`;
    return;
  }

  banner.className = "banner banner-danger";
  icon.className = "pulse-dot dot-red";
  title.textContent = `WARNING: ${latestEvent.predicted_class.toUpperCase()} ATTACK DETECTED FROM ${latestEvent.client_ip}!`;
  sub.innerHTML =
    `Attack Confidence: <strong>${(latestEvent.attack_score * 100).toFixed(2)}%</strong> ` +
    `(Gate &tau; = ${(latestEvent.threshold_tau * 100).toFixed(1)}%) &bull; ` +
    `Endpoint: <code>${latestEvent.path}</code> &bull; Model: <code>${latestEvent.active_model}</code>`;
}

/* ---------------- COMPONENT 2: HEADER PILLS & CONTROLS ---------------- */
function renderSystemStatus(snap) {
  if (!snap) return;
  state.status = snap;
  state.tau = snap.gate.tau;

  document.getElementById("os-pill").textContent = `Host: ${snap.os}`;
  const lanIp = (snap.lan_ips && snap.lan_ips[0]) || window.location.hostname;
  const sharePort = window.location.port || "9012";
  const shareUrl = `http://${lanIp}:${sharePort}`;
  const lanEl = document.getElementById("lan-pill");
  lanEl.textContent = `Teacher Wi-Fi URL: ${shareUrl}`;
  lanEl.dataset.shareUrl = shareUrl;
  lanEl.dataset.apiHost = lanIp;

  document.getElementById("capture-desc").textContent = snap.capture_engine.description;
  document.getElementById("tau-display").textContent = snap.gate.tau.toFixed(6);
  document.getElementById("tau-slider").value = snap.gate.tau;

  const isV2 = snap.models.active_model === "v2_live";
  document.getElementById("mode-v2").classList.toggle("active", isV2);
  document.getElementById("mode-v1").classList.toggle("active", !isV2);
  document.getElementById("model-explain").innerHTML = isV2
    ? `<strong>v2 Active (Recommended):</strong> Regularized <code>HistGradientBoosting</code> (<code>l2=1.5</code>, max leaf <code>0.32</code>) + cross-flow telemetry. Detects live Wi-Fi, Cloud &amp; CICIDS2017 attacks.`
    : `<strong>v1 Raw Active (Original Wormhole model.onnx):</strong> Unregularized CICIDS2017 baseline (<code>l2=0.0</code>, max leaf <code>32,935.9</code>). Catches lab traces, but demonstrates live Wi-Fi RTT domain shift!`;

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
  document.getElementById("kpi-total").textContent = stats.total_flows_scored || 0;
  document.getElementById("kpi-benign").textContent = stats.Benign || 0;
  document.getElementById("kpi-flood").textContent = stats.Flood || 0;
  document.getElementById("kpi-bruteforce").textContent = stats.BruteForce || 0;
  document.getElementById("kpi-bot").textContent = stats.Bot || 0;
  if (typeof totalPkts === "number") {
    document.getElementById("kpi-pkts").textContent = `${totalPkts} segments processed`;
  }
}

/* ---------------- COMPONENT 3: LIVE SCORE CANVAS GRAPH ---------------- */
function renderScoreChart() {
  const canvas = document.getElementById("score-canvas");
  const ctx = canvas.getContext("2d");
  const W = canvas.width;
  const H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const tauY = H - state.tau * (H - 18) - 9;
  ctx.strokeStyle = "rgba(239, 68, 68, 0.7)";
  ctx.setLineDash([5, 4]);
  ctx.beginPath();
  ctx.moveTo(0, tauY);
  ctx.lineTo(W, tauY);
  ctx.stroke();
  ctx.setLineDash([]);

  const pts = state.scoreHistory.slice(-50);
  if (pts.length === 0) return;

  const stepX = W / Math.max(pts.length, 12);
  ctx.lineWidth = 2;
  ctx.strokeStyle = "#38bdf8";
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
    ctx.fillStyle = CLASS_COLORS[item.cls] || "#38bdf8";
    ctx.beginPath();
    ctx.arc(x, y, item.alert ? 4.5 : 3, 0, Math.PI * 2);
    ctx.fill();
  });
}

/* ---------------- COMPONENT 4: FLOW TABLE & 27-FEATURE INSPECTOR ---------------- */
function renderFlowTable() {
  const tbody = document.getElementById("flow-tbody");
  if (state.events.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No flows scored yet — click any traffic button above or send live requests to Port 8000!</td></tr>`;
    return;
  }

  tbody.innerHTML = state.events
    .slice(0, 45)
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
            <span class="tag tag-${v1c}" title="Original model.onnx">v1:${v1c}</span>
            <span class="tag tag-${v2c}" title="Fixed model_v2_live.onnx">v2:${v2c}</span>
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
            <div class="prob-fill" style="width:${Math.max(1, p * 100)}%;background:${CLASS_COLORS[cls]}"></div>
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

/* ---------------- MANUAL 27-FEATURE LAB TESTER ---------------- */
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
  await refreshStatus();
};

async function patchConfig(body) {
  const res = await fetch(`${window.FlowDetectConfig.apiBase}/api/security/config`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.ok) renderSystemStatus(await res.json());
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
    renderFlowTable();
    renderInspector(state.events[0]);
    renderScoreChart();
    renderAlertBanner(state.events[0]);
  }
  renderSystemStatus(snap);
}

function connectWebSocket() {
  const pill = document.getElementById("ws-pill");
  const ws = new WebSocket(window.FlowDetectConfig.wsUrl);
  state.ws = ws;

  ws.onopen = () => {
    pill.textContent = "Live WebSocket: Connected";
    pill.className = "pill pill-ok";
  };

  ws.onmessage = (msg) => {
    const data = JSON.parse(msg.data);
    if (data.type === "hello" || data.type === "config_updated") {
      renderSystemStatus(data.status);
    } else if (data.type === "reset") {
      state.events = [];
      state.scoreHistory = [];
      state.selectedEventId = null;
      renderSystemStatus(data.status);
      renderFlowTable();
      renderInspector(null);
      renderScoreChart();
      renderAlertBanner(null);
      showToast("Cleared stream history and counters");
    } else if (data.type === "flow_event") {
      const ev = data.event;
      state.events.unshift(ev);
      if (state.events.length > 80) state.events.pop();
      state.scoreHistory.push({ score: ev.attack_score, cls: ev.predicted_class, alert: ev.alert });
      state.selectedEventId = ev.id;
      spawnPacketParticles(ev.predicted_class, ev.alert ? 9 : 4);
      if (ev.alert) playAlertTone();
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
    pill.className = "pill pill-warn";
    setTimeout(connectWebSocket, 1800);
  };
}

async function initApp() {
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
    document.getElementById("tau-display").textContent = parseFloat(e.target.value).toFixed(6);
  };

  document.getElementById("btn-sound").onclick = (e) => {
    state.soundEnabled = !state.soundEnabled;
    e.target.textContent = `Sound Alert: ${state.soundEnabled ? "ON" : "OFF"}`;
    if (state.soundEnabled) playAlertTone();
  };

  document.getElementById("btn-reset").onclick = async () => {
    await fetch(`${window.FlowDetectConfig.apiBase}/api/security/reset`, { method: "POST" });
  };

  document.getElementById("lan-pill").onclick = (e) => {
    const url = e.currentTarget.dataset.shareUrl;
    if (url && navigator.clipboard) {
      navigator.clipboard.writeText(url);
      showToast(`Copied Wi-Fi Dashboard URL: ${url}`);
    }
  };

  document.getElementById("cli-copy-btn").onclick = () => {
    const ip = document.getElementById("lan-pill").dataset.apiHost || "127.0.0.1";
    const cmd = `python attack_simulator.py --target http://${ip}:8000 --mode all`;
    if (navigator.clipboard) navigator.clipboard.writeText(cmd);
    showToast(`Copied: ${cmd}`);
  };

  document.getElementById("btn-open-lab").onclick = () => openManualLab();
  document.getElementById("btn-edit-selected").onclick = () => {
    const cur = state.events.find((e) => e.id === state.selectedEventId);
    openManualLab(cur ? cur.all_features : null);
  };
  document.getElementById("btn-close-lab").onclick = () =>
    document.getElementById("lab-modal").classList.add("hidden");

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
      document.getElementById("lab-modal").classList.add("hidden");
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
        showToast(`Executed scenario: ${btn.dataset.sim}`);
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
