# FlowDetect Frontend Architecture & Design Guide (`FRONTEND.md`)

Complete technical documentation for the **FlowDetect v2.0 Live NIDS Frontend** (`frontend/index.html`, `frontend/styles.css`, `frontend/config.js`, `frontend/app.js`) — combining a Monochrome Steel & Obsidian Glass 3D interactive hero with a zero-build, sub-millisecond WebSocket Security Operations Console.

---

## 1. Design Philosophy & Architectural Mandates

1. **Strictly Modular Multi-File Architecture (Zero Build Step):**
   - Maintained cleanly across four separate files in `/home/user/flow-detect/frontend/`:
     - `index.html` — Semantic layout structure (Floating Capsule Navbar, Integrated Threat Bar, 3D Hero Stage, Telemetry & 60 FPS Pipeline Section, Engine & Traffic Launcher Section, Live Flows + 27-Feature Inspector + WebSocket Terminal Section, Minimal Footer, and 27-Feature ONNX Sandbox Modal).
     - `styles.css` — Complete **Monochrome Steel & Obsidian Glass** token system (`#050507` Dark Mode + full `[data-mode="light"]` Platinum Light Mode), 3D CSS `preserve-3d` glass core geometry, mouse-tracking `.card.spot` radial spotlights, responsive grids, and sticky data surfaces.
     - `config.js` — Automatic FastAPI backend (`:8000`) & WebSocket (`/ws/live`) endpoint discovery across Reverse Proxy (`:9012`), multi-laptop LAN/Wi-Fi (`http://<HOST-IP>:9090`), localhost, or `?api=` query override.
     - `app.js` — Real-time WebSocket event loop, 60 FPS HTML5 `<canvas>` pipeline packet renderer, `1 - P(Benign)` score stream plotter, live 3D core threat pulse, Web Audio API synthesizer, live terminal event logger, and interactive 27-feature ONNX tensor sandbox.
2. **Monochrome Steel Chrome + Semantic Live Threat Telemetry:**
   - All structural surfaces, typography, buttons, and 3D stage elements follow a clean monochrome steel palette (`#050507` / `#0b0b0f` / `#f4f5f7`), reserving color strictly for real-time classification semantics:
     - **Benign (`Class 0`):** `#10b981` (Emerald)
     - **Bot (`Class 1`):** `#a855f7` (Purple)
     - **BruteForce (`Class 2`):** `#f59e0b` (Amber)
     - **Flood (`Class 3`):** `#ef4444` (Crimson)
3. **100% Live Telemetry — Zero Static Report Clutter:**
   - Every counter, badge, chart point, table row, probability bar, and terminal log line is driven by live FastAPI + ONNX Runtime inference over `/ws/live` and `/api/security/*`.

---

## 2. Directory Structure & File Roles

```text
flow-detect/
├── frontend_server.py        # Reverse proxy serving frontend on 0.0.0.0:9012 -> backend :8000
└── frontend/
    ├── index.html            # Modular HTML5 structure & SVG vector stage streams
    ├── styles.css            # Monochrome Steel & Obsidian Glass design tokens + Dark/Light themes
    ├── config.js             # Automatic HTTP/HTTPS + WS/WSS backend discovery
    └── app.js                # Live WebSocket state, 60 FPS canvases, inspector & 27-feature modal
```

---

## 3. Component & Section Reference

### A. Floating Glass Capsule Navbar (`#nav`) & Live Threat Capsule (`#threat-banner`)
- **Capsule Navigation (`#nav`):** Fixed frosted-glass pill (`backdrop-filter: blur(16px)`) with scroll progress bar (`#prog`), smooth section spy (`Hero`, `Telemetry`, `Engine & Launcher`, `Live Flows & Inspector`), live WebSocket connection pill (`#ws-pill`), detected Host OS (`#os-pill`), one-click copyable **`Frontend URL`** pill (`#lan-pill`), and Dark/Light theme switcher (`#modeBtn`, persisted in `localStorage['fd-mode']`).
- **Integrated Live Threat Bar (`#threat-banner`):** Transitions dynamically from `.banner-safe` (`SYSTEM PROTECTED`) to `.banner-danger` (`ALERT: <CLASS> DETECTED FROM <IP>`) whenever `attack_score = 1 - P(Benign) >= τ`, exposing quick actions for **Manual 27-Feature Tester**, **Sound Alert: ON/OFF**, and **Reset Stream**.

### B. 3D Rotating Frosted-Glass Core Hero (`#hero`)
- **Interactive 3D Stage (`#infraStage`):** Six-faced CSS 3D rotating frosted-glass cube (`#coreWrap`) surrounded by four floating isometric architecture nodes (`DUAL ONNX ENGINE`, `FLOW COLLECTOR`, `ACTIVE SHIELD`, `27-FEATURE STREAM`), animated SVG vector data streams, and ambient traveling data particles (`#particles`).
- **Live Threat Core Pulse:** Incoming WebSocket flow events pulse `#coreWrap` with semantic glow intensity matching the live ONNX verdict and update the 4 live Hero telemetry counters (`Live Flows Scored`, `Threats Flagged (≥ τ)`, `Decision Gate (τ)`, and `Dual ONNX CPU Latency`).

### C. Section `01` — Live Multi-Class Flow Counters & 60 FPS Pipeline (`#telemetry`)
- **5 Spotlight KPI Cards:** Real-time counters for total scored flows & processed segments (`#kpi-total`, `#kpi-pkts`) plus individual class counters (`Benign`, `Flood`, `BruteForce`, `Bot`) and a one-click **Copy CLI Attack Command** button (`#cli-copy-btn`).
- **60 FPS Pipeline Canvas (`#topology-canvas`):** Theme-aware HTML5 `<canvas>` animating live colored packet bursts across the four NIDS stages (`Live Clients / LAN` $\rightarrow$ `Scapy + ASGI Collector` $\rightarrow$ `Dual ONNX Runtime` $\rightarrow$ `Live SOC Broadcast`).

### D. Section `02` — Detection Engine Controls & Live Attack Score Stream (`#controls`)
- **Model & Shield Controls:** Live toggle between **`v2 Fixed Live ONNX + Host Guard`** (`models/model_v2_live.onnx`) and **`v1 Original Wormhole model.onnx`** (`models/model.onnx`), live toggle between **`Alert Warning Only`** and **`Active Shield Block (HTTP 403)`** (with instant per-IP `Unblock` chips), and live **Decision Gate Threshold ($\tau$)** slider (`0.50`–`0.99`, default `0.921056`).
- **Traffic Launcher, PCAP Replay & Score Chart (`#score-canvas`):** One-click live async traffic triggers (`Benign`, `Flood`, `BruteForce`, `Bot`), authentic `CICIDS2017` reference vector replays, `.pcap`/`.pcapng` file upload, and live 50-flow `1 - P(Benign)` score chart plotted against dashed red threshold $\tau$.

### E. Section `03` — Real-Time Flows, 27-Feature Inspector & Terminal Stream (`#live-console`)
- **8-Column Live Flows Table (`#flow-tbody`):** Zero-horizontal-scroll table displaying `Time`, `Source IP`, `Endpoint`, `Pkts`, `Verdict`, `Score`, stacked `v1 / v2` model comparison badges, and sub-millisecond ONNX CPU `Lat`.
- **27-Feature & 4-Class Probability Inspector:** Displays exact `Benign`, `Flood`, `BruteForce`, and `Bot` probabilities, extracted `float32[1, 27]` features, and a **`Load into Tester`** button (`#btn-edit-selected`) that opens the **4-Column Compact 27-Feature ONNX Sandbox Modal (`#lab-modal`)** with sticky header, `Zero All Features` reset, and sticky `Score 27 Features on ONNX Now` footer (zero vertical scroll needed on standard laptop displays).
- **Live Detection Event Stream (`#live-log`):** Real-time color-coded SOC event terminal with automatic **Hover-Pause** (`Auto-Scroll: Live` $\leftrightarrow$ `Hover Paused`) so high-rate streams never jump while inspecting log lines.
- **Native Cross-Platform Dark Glass Scrollbars:** Uses `:root { color-scheme: dark }` + custom `5px` translucent pill `::-webkit-scrollbar` tracks (`::-webkit-scrollbar-button { display: none }`, transparent track, subtle edge fade masks, and `@supports not selector(::-webkit-scrollbar)` Firefox fallback) to eliminate bright white Windows Chrome/Edge scroll strips and arrow buttons everywhere.

---

## 4. Running the Redesigned Frontend

### Option 1 — Full Reverse-Proxy Mode (Recommended for Single Port / Cloud / LAN)
```bash
# Terminal 1: Start FastAPI + Dual ONNX Backend on 0.0.0.0:8000
cd flow-detect
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000

# Terminal 2: Start Frontend + WebSocket Proxy on 0.0.0.0:9012
cd flow-detect
python -m uvicorn frontend_server:proxy_app --host 0.0.0.0 --port 9012
```

### Option 2 — Direct Static Server on Any Port (Windows / Linux / macOS LAN)
```bash
# Serve modular frontend directly from flow-detect/frontend on any port (auto-discovers :8000)
cd flow-detect/frontend
python -m http.server 9090 --bind 0.0.0.0
```
Open `http://<YOUR-LAN-IP>:9012` (or `:9090`) from any browser on the network — `config.js` automatically connects HTTP & WebSocket streams to `ws://<YOUR-LAN-IP>:8000/ws/live`.
