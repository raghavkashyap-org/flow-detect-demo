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

---

---

## 5. Architecture Walkthrough (`frontend/arch.html`) — v4.1

`frontend/arch.html` (copied to the repo root as `arch.html`) is a **three-mode, self-contained, mobile-first** viewer over the whole system. No dependencies, no CDN, no runtime build — and it still carries **1 922 lines of real source**, extracted automatically from the Python and JS that actually runs.

**v4.1 — what changed since v4.0**

| Ask | What shipped |
|---|---|
| *Remove the A−/A+ zoom* | Gone — control, menu rows, keyboard bindings and the persisted `--ui` scale. Text size is the browser's own zoom again. |
| *The position map must not open another map — it should open the Overview, where you pick from → to* | The duplicate slide-up map sheet is deleted. The **⤢** button on the rail map, **`M`**, and the phone **Map** button all jump to the **Overview** canvas, centred on the block you are standing on and already marked as **A**. |
| *Put the routing features on the big Overview map* | Overview is now a picker: **click one block = A (start)**, **click a second = B (destination)** — the shortest directed route is drawn on the canvas in amber, both ends ringed, hop count in a floating bar, and **Walk this path** turns it into a walkthrough trail. Clicking a third block starts a new A; `Esc` clears. The canvas auto-fits so both ends are visible. |
| *Selecting a block blurred the whole screen* | Fixed. The scrim is now only used by real sheets, never by the desktop inspector, and it no longer blurs the page behind it — only the panel that slid up gets focus. |

### 5.1 The three modes
| Mode | Key | What it is for | What it shows |
|---|---|---|---|
| **Overview** | `O` | Spatial / printable / routing | The full Rummler–Brache map: 5 swimlanes × 8 phases × 33 blocks × 33 hops, plus the A1 legend. Click a block for its contract; click two blocks for an **A → B** route. Export SVG / PNG / A1 PDF, search, fit. |
| **Walkthrough** | `W` | Understanding | One hop at a time: a step card, the trail, a phase meter and the live position map. |
| **How to use** | `H` | Orientation | Modes, walking rules, map gestures, A→B routing, the phone layout and every shortcut — generated from the live key map. |

### 5.2 Overview: picking a route from where to where
1. Click a block → it becomes **A** and the inspector shows it.
2. Click a second block → it becomes **B**; `bfsPath` returns the shortest directed route and every edge on it is repainted amber on the canvas, with A ringed in green and B in amber.
3. The floating bar reads **A → B · N hops**, with **Walk this path**, **Details** (phones) and **Clear**. If no directed route exists it says **no forward path** and stays on B instead of failing silently.
4. **Walk this path** switches to the walkthrough with that route already walked; the rail map then shows the same hops.
5. A third click starts a new **A**; `Esc` clears A, B and the paint. The canvas zooms out (only as far as needed) so both ends are on screen.

### 5.3 Walkthrough mechanics
- **Bidirectional with real history.** `Next` follows the branch you choose; `Back` pops the trail exactly as you walked it (not graph parents); every breadcrumb is clickable. `Other ways in` lists every predecessor.
- **Fork chooser.** One card per outgoing hop, each with **Why** (why the hop exists), **How** (the implementation) and the payload label. `1`–`9` picks a branch.
- **Cycle detection.** Back-edges from a DFS at load, SCCs from Tarjan. Re-entering a walked block raises **“You are about to re-enter …”** with *Continue anyway / Exit the loop / Stay here* and the pass number; `L` exits the loop; the rail lists `LF1`–`LF4`.
- **Edge cases.** Entry point, dead end, unreachable destination, revisit (`step 22 · pass 2`), “no source extracted”.
- **Path finder.** The rail select (or `P`) previews a BFS route and lets you walk it.

### 5.4 The position map (rail)
- **Bigger.** Rail 268 → 340 px, map ~1.8× the old minimap area, first thing under the phase meter.
- **Arrows that read.** Hop geometry is clipped to the block edges so arrowheads land on the target border; where two rows almost touch a **solid chevron** is drawn in the gap; a short hop between non-adjacent rows bows outward; the newest hop is heavier.
- **Progress.** Numbered badges on the last visited blocks (colliding badges are dropped, never smudged), a pulsing ring on the current one, dashed accent strokes for back-edges, dashed amber for a preview route.
- **Focus (`Z`).** Zooms the map to the bounding box of your trail (default from the first hop); press again for the whole canvas.
- **Click-to-route.** Click any block to preview the shortest route from where you stand; `Enter` / double-click walks it. **⤢ / `M`** opens the big Overview map instead of a second copy of the map.

### 5.5 Mobile layout
| Element | Behaviour |
|---|---|
| Header | One row that never wraps: `logo · FlowDetect · Architecture` on the left (fixed, never squeezed), the three mode tabs, then search / map tools / theme / Dashboard. Below 900 px it becomes two rows: brand + menu (⋮), then a three-cell segmented mode switch. Under 1440 px the mono subtitle drops out so the brand keeps its space. |
| Bottom bar | `◀ Back · Next ▶ · Code · Map · Menu`, sticky, safe-area padded, only inside Walkthrough. |
| **Map** | Jumps to the big Overview map at the current block (no duplicate sheet). |
| Route bar | Full-width above the toolbar; **Details** slides the inspector up for the block you last touched. |
| Menu sheet | Modes, restart, micro-details, code, last fork, exit loop, theme, shortcuts, dashboard link. |
| Inspector | Slide-up sheet below 1100 px — and it opens **on demand** (`Details`), so tapping a destination never covers the canvas. |
| Map toolbar | Floating tray over the canvas (Fit, zoom, SVG/PNG/PDF, search) below 1100 px. |
| Code drawer | Full-width, rounded top, `Wrap` on by default under 900 px. |

### 5.6 Keyboard — the complete map
| Keys | Action |
|---|---|
| `O` `W` `H` | Overview / Walkthrough / How to use |
| `N` / `→` | Follow the only pathway (on a fork: jump to the branch list) |
| `←` / `B` | Retrace one step of your actual trail |
| `1`–`9` | Pick the nth outgoing pathway |
| `Enter` | Walk the previewed route (or open the selected block in Overview) |
| `R` | Restart to the four entry points |
| `F` | Back to the last fork |
| `L` | Exit the current loop |
| `D` | Toggle micro-details (constants + failure modes) |
| `C` | Open source code for the current block |
| `X` | Raw ⇄ Explain |
| `[` `]` | Previous / next section in the drawer |
| `Y` | Copy the raw source |
| `M` | Open the big map (Overview) at the current block |
| `Z` | Focus the rail map on your trail / whole canvas |
| `P` | Jump to the path-finder list |
| `Esc` | Close the topmost layer only: overlay → drawer → sheet → route → selection |
| `/` | Search blocks (Overview) |
| `T` | Light / dark |
| `?` | Shortcut cheat sheet |

Every control is a real `<button>` in DOM order, so `Tab` reaches everything with a visible focus ring.

### 5.7 Code inspector — Raw ⇄ Explain
The drawer opens for the block you are standing on (`C`, the `Code` buttons, or from Overview) and has two tabs over the *same* function:

- **Raw code** — the **verbatim** function or block, extracted by `arch_src/extract.py` using `ast` (Python, decorators included) or brace matching (JS/CSS/HTML), with the real file path, line range, line count, line-number gutter, syntax highlighting, `Copy` (with an `execCommand` fallback for `file://`) and a `Wrap` toggle.
- **Explain** — a numbered, line-by-line account of how that function works: guard clauses, constants read, counters written, and *what breaks it*.

47 sections across all 33 blocks are extracted (largest: `score_vector` 129 lines, `train_v2_model.main` 210 lines).

### 5.8 Regenerating
```bash
python arch_src/extract.py     # re-read the real source -> arch_src/code.json
python arch_src/enrich.py      # per-hop why/how + per-function explanations
python arch_src/build.py       # -> arch.html (root + frontend/)
```
`arch_src/data.json` holds the graph and copy; `arch_src/template3.html` holds the UI (`template2.backup.html` is the v3 restore point). If a function is renamed, `extract.py` fails loudly with the missing qualname instead of shipping stale code.

### 5.9 Verified behaviour (Playwright, headless Chromium)
- **Overview routing:** `traffic → gate` = 11 hops, 11 edges repainted, A/B ringed, bar `A → B · 11 hops`, `Walk this path` → walkthrough with the route as trail; `Esc` clears bar and paint; unreachable pairs show *no forward path*; the canvas re-fits to keep both ends visible.
- **Position map:** `⤢` / `M` / phone **Map** → Overview centred on the current block, marked **A**; no `#sheet-map` in the DOM any more.
- **Selection:** clicking a block leaves the canvas crisp — scrim never appears while the inspector is the desktop column.
- **Walkthrough:** fork chooser, 29-hop deep walk with 8 loop re-entries, path finder valid + invalid, map click → preview → `Enter`, drawer raw/explain with `[` `]`, `Y` copy, `Wrap`, dark mode, `Z` focus.
- **Responsive:** zero horizontal overflow and zero console/page errors at **390 / 430 / 768 / 1024 / 1440 / 1920 px**; bottom bar ≤ 1099 px, rail ≥ 1100 px.
- **No interface-scale control remains** (`#uiz` absent, `body` zoom = 1).

### 5.10 Brand mark
One logo everywhere: a **flat matte-green rounded tile (`#2e6854 → #26604a`) with a white shield-check**. It replaces the old glossy gradient tile on the walkthrough and the light/dark inverting grey tile on the dashboard, so the mark looks the same in both themes, in the navbar, in the footer and in the browser tab (inline SVG favicon, no extra file).



### Navigation corrections
- The first entry now uses the actual block name, **Traffic & attack sources**, with “A request arrives” in its description.
- Left arrow returns one visited step. Right arrow advances a single path; at a fork it focuses the first choice, and a second Right follows that focused choice. Tab selects another branch; digits choose directly. Right confirms a loop continuation or route preview.
- Digits 1–4 launch entries from the start screen; Right launches the first entry. Desktop now has an explicit Next button.
- Position-map lane names are in a separate legend, not drawn over nodes.
- Overview F (Fit) and Enter (walk selected block) no longer get intercepted by walkthrough shortcuts.
- Automated Chromium checks: 390, 768, 1024, 1440 px; navigation, branch selection, restart, theme, map, no overflow or JavaScript errors. Separate desktop click checks cover four entries, Code, Details, Back/Next, Restart, shortcut sheet and route endpoint selection. Native mobile browsers and export downloads were not re-tested in this pass.


### Short-view — compact presentation inside Overview
Use **Overview → Short-view** to explain the whole system without navigating the long map. Eight numbered blocks cover traffic, ingress/accounting, flow assembly, 27 features, inference, alert gating, live publishing and dashboard response. Each shows its job and one implementation cue. Startup and operator feedback are separate short notes. Read left-to-right, then the next row.

This is presentation-only: no animation, zoom, routing, inspector or modal. **Full map** restores the detailed canvas; Walkthrough and How to use remain unchanged. Map-navigation commands return to Full map. The layout uses four columns on desktop, two on phones, and one on very narrow screens. The current Full/Short selection is remembered only while the page remains open.

Verified in Chromium at 390/768/1280/1440 px: eight blocks, no panel overflow, theme and mode switching, full-map restoration and hidden map tools. Existing navigation/button regression checks also pass.
