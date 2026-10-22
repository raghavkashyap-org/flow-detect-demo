# FlowDetect — Complete Frontend Architecture, UI Guide & Line-by-Line Code Reference (`FRONTEND.md`)

This document explains **every single visual UI element, mathematical rule, real-time animation, WebSocket event, REST API payload, and line of code** inside `frontend/` (`config.js`, `index.html`, and `app.js` — everything except `styles.css`), using **real live values directly from your Windows 11 deployment screenshots (`http://192.168.29.150:9090`)**, followed by a **1:1 React (Vite) migration map** and **Viva Q&A cheat-sheet**.

---

## Table of Contents

1. [High-Level Frontend Architecture & Data Flow](#1-high-level-frontend-architecture--data-flow)
2. [Every Visual UI Element Explained in Detail (With Your Live Screenshot Examples)](#2-every-visual-ui-element-explained-in-detail-with-your-live-screenshot-examples)
   - [2.1 Top Sticky Threat Alert Banner (`#threat-banner`)](#21-top-sticky-threat-alert-banner-threat-banner)
   - [2.2 Header Bar & Live Telemetry Pills (`header.topbar`)](#22-header-bar--live-telemetry-pills-headertopbar)
   - [2.3 Five Real-Time Class KPI Cards (`section.kpi-grid`)](#23-five-real-time-class-kpi-cards-sectionkpi-grid)
   - [2.4 Live 60 FPS Packet-to-ONNX Pipeline Canvas (`#topology-canvas`)](#24-live-60-fps-packet-to-onnx-pipeline-canvas-topology-canvas)
   - [2.5 Panel 1: Detection Engine, Model Toggle, Active Shield & Decision Gate Threshold (`τ`)](#25-panel-1-detection-engine-model-toggle-active-shield--decision-gate-threshold-%CF%84)
   - [2.6 Panel 2: Live Traffic Launcher, Lab Trace Replayer, `.pcap` Upload & Score Graph](#26-panel-2-live-traffic-launcher-lab-trace-replayer-pcap-upload--score-graph)
   - [2.7 Panel 3: Real-Time Scored Network Flows Table (Explaining Every Column & Screenshot Row!)](#27-panel-3-real-time-scored-network-flows-table-explaining-every-column--screenshot-row)
   - [2.8 Panel 4: Live 27-Feature & Probability Inspector + All 27 Features Reference Table](#28-panel-4-live-27-feature--probability-inspector--all-27-features-reference-table)
   - [2.9 Modal: Interactive Manual 27-Feature ONNX Sandbox (`#lab-modal`)](#29-modal-interactive-manual-27-feature-onnx-sandbox-lab-modal)
3. [Complete Line-by-Line Code Walkthrough (`frontend/` Excluding CSS)](#3-complete-line-by-line-code-walkthrough-frontend-excluding-css)
   - [3.1 `frontend/config.js` (Lines `1–45` — Zero-Edit Auto-Discovery)](#31-frontendconfigjs-lines-145--zero-edit-auto-discovery)
   - [3.2 `frontend/index.html` (Lines `1–267` — Semantic DOM Structure)](#32-frontendindexhtml-lines-1267--semantic-dom-structure)
   - [3.3 `frontend/app.js` (Lines `1–433` — State, Renderers, Canvas, Audio & WebSocket)](#33-frontendappjs-lines-1433--state-renderers-canvas-audio--websocket)
4. [Exact Backend REST & WebSocket JSON Contracts Used by Frontend](#4-exact-backend-rest--websocket-json-contracts-used-by-frontend)
5. [1:1 React (Vite) Component & Hook Conversion Map (For Frontend Teammate)](#5-11-react-vite-component--hook-conversion-map-for-frontend-teammate)
6. [Top 8 Viva / Evaluator Questions & Crisp Answers](#6-top-8-viva--evaluator-questions--crisp-answers)

---

## 1. High-Level Frontend Architecture & Data Flow

`frontend/` is intentionally built as a **zero-build, zero-external-CDN real-time Security Operations Center (SOC) single-page application** split cleanly into three files:

```text
frontend/
├── index.html   (Lines 1–267)  -> Pure semantic HTML layout & DOM mount targets (zero inline JS logic)
├── config.js    (Lines 1–45)   -> Automatic REST + WebSocket backend URL discovery across ANY IP & port
├── app.js       (Lines 1–433)  -> Centralized `state` store + WebSocket engine + 6 modular UI renderers
└── styles.css                  -> Dark SOC theme, responsive grids, color-coded class badges & animations
```

### Real-Time End-to-End Browser Lifecycle
```text
[Friend runs Static Server on :9090]      [Browser loads index.html]
                │                                    │
                ▼                                    ▼
      1. config.js probes `/api/security/status` -> sees static server (no JSON API on :9090)
      2. Auto-sets apiBase = "http://192.168.29.150:8000" & wsUrl = "ws://192.168.29.150:8000/ws/live"
      3. app.js calls GET /api/security/status -> hydrates OS, Gate τ, KPIs & recent 40 flows immediately
      4. app.js opens persistent WebSocket `/ws/live` -> pushes every scored flow in < 2ms simultaneously
         to Laptop #1, Windows Laptop #2, AND Teacher's Smartphone!
```

---

## 2. Every Visual UI Element Explained in Detail (With Your Live Screenshot Examples)

---

### 2.1 Top Sticky Threat Alert Banner (`#threat-banner`)

Pinned at the very top of the viewport (`position: sticky; top: 0`) so **even if the user scrolls down to inspect table rows (just like in your first screenshot!), live security alerts are always visible across the room**.

It has **two dynamic states**:
1. **Protected / Normal State (Green — shown in your screenshots):**
   - **Pulsing green dot (`#banner-icon`)** + Headline:  
     `SYSTEM PROTECTED — LIVE FLOW TELEMETRY NORMAL`
   - **Live Subtitle (`#banner-sub`):**  
     In your screenshot:  
     `Last flow from 192.168.62.149 classified Benign (Attack score: 0.0133 < τ 0.9211)`  
     This proves to the teacher in real time **why** no alarm triggered: the computed attack probability `0.0133` (`1.33%`) is strictly below the decision gate threshold `τ = 0.9211` (`92.11%`).
2. **Active Attack State (Flashing Red — triggered whenever `attack_score >= τ`):**
   - **Pulsing red dot** + Red glowing background + Headline:  
     `WARNING: BRUTEFORCE ATTACK DETECTED FROM 192.168.62.185!`
   - **Live Subtitle:** Displays exact attack confidence `%`, active threshold `τ`, targeted endpoint (`/api/auth/login`), and active ONNX model (`v2_live` or `v1_raw`).

#### The 3 Action Buttons on the Right Side of the Banner:
| Button | DOM ID | Exact Role |
| :--- | :--- | :--- |
| **`Manual 27-Feature Tester`** | `#btn-open-lab` | Opens the interactive 27-feature sandbox modal (`#lab-modal`) pre-filled with the latest flow's exact 27 feature numbers so you can manually edit any feature and test ONNX directly. |
| **`Sound Alert: OFF / ON`** | `#btn-sound` | Synthesizes a pure hardware-accelerated warning chime in JavaScript (`Web Audio API` rising triangle wave `740 Hz -> 990 Hz` over `0.28s` — **zero `.mp3` files needed!**). Browser security requires a user click first before allowing audio playback, which is why it starts `OFF` and plays a test chime the moment you click it `ON`. |
| **`Reset Stream`** | `#btn-reset` | Sends `POST /api/security/reset` to FastAPI, clearing active flow windows, resetting KPI counters to `0`, and broadcasting `{type: "reset"}` over WebSocket so **every open browser tab clears simultaneously**. |

---

### 2.2 Header Bar & Live Telemetry Pills (`header.topbar`)

- **Left Side (`FD` Badge + Title):**
  - Displays the **`FD`** brand emblem, `FlowDetect Live NIDS Dashboard`, and architecture summary (`FastAPI (:8000) • Scapy + ASGI 27-Feature Collector • Dual ONNX Runtime`).
- **Right Side — Three Live Status Pills:**
  1. **`Live WebSocket: Connected` (`#ws-pill`):**
     - Starts yellow (`WS Connecting...`).
     - Turns **emerald green** (`Live WebSocket: Connected`) as soon as `ws://192.168.29.150:8000/ws/live` opens.
     - If the backend restarts, turns yellow (`WS Reconnecting...`) and automatically retries every **`1,800 ms`** until reconnected — no manual browser refresh required!
  2. **`Host: Windows 11` (`#os-pill`):**
     - Displays the **actual operating system of the server machine running FastAPI (`:8000`)** (`platform.system() + platform.release()`). In your screenshot, your friend's backend reported `Host: Windows 11` live!
  3. **`Teacher Wi-Fi URL: http://192.168.29.150:9090` (`#lan-pill`):**
     - Combines the backend server's detected Wi-Fi LAN IP (`192.168.29.150`) with **`window.location.port`** (`9090`, the custom port your friend picked!).
     - **Clicking this pill copies `http://192.168.29.150:9090` to your clipboard** and shows a confirmation toast so you can send the link straight to your teacher's phone on WhatsApp/QR.

---

### 2.3 Five Real-Time Class KPI Cards (`section.kpi-grid`)

Look at the exact numbers from **Screenshot #2**:

| Card Title | Screenshot Value | Internal ONNX Index | Meaning |
| :--- | :---: | :---: | :--- |
| **`FLOWS SCORED`** | **`175`** (`4 segments processed`) | Total (`sum` of all 4 classes) | Total number of real-time flow snapshots evaluated by ONNX (`29 + 5 + 8 + 133 = 175`). Subtitle shows total raw packet/HTTP segments ingested since last reset. |
| **`BENIGN (CLASS 0)`** | **`29`** *(Green top border)* | **`Class 0`** (`CLASSES[0]`) | Normal human web browsing & API calls where `1 - P(Benign) < τ`. |
| **`FLOOD (CLASS 3)`** | **`5`** *(Red top border)* | **`Class 3`** (`CLASSES[3]`) | Volumetric HTTP floods (`ab`, `wrk`, `siege`), TCP SYN floods, and DoS bursts. |
| **`BRUTEFORCE (CLASS 2)`** | **`8`** *(Amber top border)* | **`Class 2`** (`CLASSES[2]`) | Rapid failed authentication sprays (`ffuf`, `curl` login loops) on `/api/auth/login`. |
| **`BOT (CLASS 1)`** | **`133`** *(Purple top border)* | **`Class 1`** (`CLASSES[1]`) | Clockwork C2 beacon polling (`190–200ms` fixed timer intervals) & automated scrapers. |

> **Sharp Viva Detail to Notice:** Why are the class numbers ordered `0, 3, 2, 1` visually across the cards?  
> Because `scikit-learn` / `model.onnx` sorted class names **alphabetically** during training (`0 = Benign`, `1 = Bot`, `2 = BruteForce`, `3 = Flood`), whereas on a Security Dashboard we arrange cards **by operational priority** (`Benign` $\rightarrow$ `Flood` $\rightarrow$ `BruteForce` $\rightarrow$ `Bot`) while showing the exact ONNX tensor index (`CLASS 0..3`) cleanly on every card!

---

### 2.4 Live 60 FPS Packet-to-ONNX Pipeline Canvas (`#topology-canvas`)

- Renders a hardware-accelerated **60 frames-per-second HTML5 `<canvas>` pipeline diagram** showing the 4 stages every live packet travels through:
  1. **`Live Clients / Wi-Fi`** *(HTTP / TCP Streams)*
  2. **`Scapy + ASGI Collector`** *(27 Flow Features in µs)*
  3. **`Dual ONNX Runtime`** *(v1 + v2 in ~0.015 ms on CPU)*
  4. **`Live SOC Dashboard`** *(WebSocket Broadcast)*
- Every time a WebSocket `flow_event` arrives, **`spawnPacketParticles()`** injects animated glowing packets flying left-to-right across the wire:
  - **Green small dots (`r = 3.2px`, 4 dots):** `Benign`
  - **Red large dots (`r = 4.6px`, 9 dots):** `Flood`
  - **Amber large dots (`r = 4.6px`, 9 dots):** `BruteForce`
  - **Purple large dots (`r = 4.6px`, 9 dots):** `Bot`
- **Top-Right Pill (`Copy CLI Attack Command` / `#cli-copy-btn`):** Dynamically builds and copies `python attack_simulator.py --target http://192.168.29.150:8000 --mode all` using the live server IP!

---

### 2.5 Panel 1: Detection Engine, Model Toggle, Active Shield & Decision Gate Threshold (`τ`)

This panel is **the heart of your viva demonstration**. Every single control maps directly to a live `PATCH /api/security/config` backend state update:

#### Control 1 — Active ONNX Model Switch (`#mode-v2` vs `#mode-v1`)
Both models actually run **simultaneously on every single flow** (`0.04–0.85 ms` total CPU time!), and this toggle controls **which model drives the active Verdict & Shield block**:
- **`v2 Fixed Live ONNX + Host Guard` (`active_model = "v2_live"` — Default):**
  - Regularized `HistGradientBoostingClassifier` (`l2_regularization = 1.5`, maximum tree leaf value **`0.3194`**) combined with short-window cross-flow host telemetry.
  - Accurately detects **both** live Wi-Fi/Cloud attacks **AND** original CICIDS2017 lab traces (`98.35%–98.46%` accuracy).
- **`v1 Original Wormhole model.onnx` (`active_model = "v1_raw"`):**
  - Your exact unmodified original `model.onnx` (`SHA-256: 6170e1a1...`), which had `l2_regularization = 0.0` and extreme leaf weights up to **`32,935.94`**, causing it to overfit to lab microsecond LAN timings and misclassify real Wi-Fi/Internet attacks as `Benign` (`100.0%` probability collapse).
  - Switching to `v1` live in front of your teacher proves **why real-world ML deployment requires domain-shift calibration & regularization**!

---

#### Control 2 — Response Action Switch (`#shield-alert` vs `#shield-enforce`)
- **`Alert Warning Only (Live Banner)` (`shield_mode = "alert"` — IDS Mode):**
  - Acts as a passive **Intrusion Detection System (NIDS)** — logs every malicious flow, flashes red alerts, plays audio warnings, and keeps watching incoming attack packets.
- **`Active Shield Block (HTTP 403)` (`shield_mode = "enforce"` — IPS Mode):**
  - Upgrades FlowDetect into an active **Intrusion Prevention System (NIPS)**!
  - The instant any client IP crosses `attack_score >= τ`, `DualONNXDetector` adds that IP to `blocked_ips` for `45 seconds`.
  - Every subsequent HTTP request from that attacker IP is intercepted at the outermost ASGI layer in **under `5 microseconds`** and rejected with **`HTTP 403 Forbidden`**.
  - **Dynamic Blocked Chips Box (`#blocked-container`):** Automatically appears directly below the slider showing every blocked IP (`192.168.92.14 (Flood • 39.2s) [Unblock]`) so your friend can unblock you live with **one single mouse click**!

---

#### Control 3 — What Is the **Decision Gate Threshold (`τ = 0.921056`)**? *(Complete Explanation!)*

This is **one of the most important questions an examiner will ask**. Here is the exact mathematical and engineering answer:

1. **What ONNX Outputs Raw:**  
   For every network flow tensor $X \in \mathbb{R}^{1 \times 27}$, the ONNX model outputs **4 class probabilities** summing to `1.0` (`100%`):
   $$P = \big[\; P(\text{Benign}),\; P(\text{Bot}),\; P(\text{BruteForce}),\; P(\text{Flood}) \;\big]$$

2. **How the Binary Attack Score Is Computed:**  
   Instead of triggering an alarm whenever any single attack class hits `51%` (which causes high **False Positive Rates** in real networks when a normal user loads a heavy webpage with 25 images at once!), FlowDetect computes the **Total Attack Probability**:
   $$\text{AttackScore} = 1 - P(\text{Benign}) = P(\text{Bot}) + P(\text{BruteForce}) + P(\text{Flood})$$

3. **How the Decision Gate `τ` (`0.921056`) Works:**
   - **Where `0.921056` comes from:** Inside `model_metadata.json` (`decision_threshold = 0.921055988133361`), `τ` was calibrated on validation data to maximize F1-score while keeping False Alarms on normal users near **`0%`**.
   - **Rule Step 1 (Gate Check):**
     $$\text{IsAlert} = \big(\text{AttackScore} \ge \tau\big)$$
     - If **`AttackScore < 0.921056`**: The gate stays **CLOSED (Green / Safe)** $\rightarrow$ Verdict is **`Benign`**, no alarm fires, and no user gets accidentally blocked.
     - If **`AttackScore ≥ 0.921056`**: The gate **OPENS (Red Alert!)** $\rightarrow$ FlowDetect selects which specific attack family caused the surge:
       $$\text{Verdict} = \arg\max_{c \in \{\text{Bot},\,\text{BruteForce},\,\text{Flood}\}} P(c)$$
       *(Notice why that 2-step logic is so smart: suppose `P(Benign) = 0.04`, `P(Flood) = 0.49`, `P(BruteForce) = 0.47`. Even though no single class exceeded `0.50`, total attack probability is `1 - 0.04 = 0.96 >= 0.9211`, so the gate STILL catches the attack cleanly!)*

4. **What Dragging the Slider (`0.50` $\leftrightarrow$ `0.99`) Does Live:**
   - **Lowering `τ` toward `0.50`:** **Higher Sensitivity** (catches subtle/early attacks even at 2–4 packets, slightly more aggressive).
   - **Raising `τ` toward `0.99`:** **Stricter Precision** (only alerts or blocks IPs when attack certainty exceeds `99%`).
   - Dragging updates the red dashed threshold line on the **Live Attack Score Stream Graph** instantly!

---

#### Control 4 — Capture Status Box (`#capture-desc`) on Windows 11!

Look at the exact message visible on your **Windows 11 screenshots**:
> `ASGI Live Collector Active (Raw NIC disabled: RuntimeError — Install Npcap & run PowerShell as Administrator for L3 SYN capture)`

**What to tell your evaluator if they point at this box:**
- FlowDetect has **dual-layer packet collection** so it runs cross-platform everywhere:
  1. **Layer 1 — FastAPI ASGI Live Stream Collector (`Active` on Windows 11 right now!):** Runs with **zero special drivers or admin rights** and translates every live HTTP/REST request & response segment (`Fwd`/`Bwd` lengths, microsecond IATs, TCP MSS `1460B` chunking) into exact 27-feature flow vectors in real time.
  2. **Layer 2 — Scapy Raw Network Interface Sniffer (Optional Layer-3/4 upgrade):** On Linux (`sudo`) or Windows with the **Npcap packet driver + Administrator PowerShell**, Scapy also captures raw kernel Layer-3/4 packets like half-open `hping3` TCP SYN floods. Because standard Windows blocks raw socket promiscuous sniffing without Npcap + Admin, FlowDetect cleanly detects `RuntimeError`, logs this helpful diagnostic banner instead of crashing, and runs continuously via the **ASGI Live Collector**!

---

### 2.6 Panel 2: Live Traffic Launcher, Lab Trace Replayer, `.pcap` Upload & Score Graph

1. **Four 1-Click Live HTTP Stream Buttons (`data-sim="benign|flood|bruteforce|bot"`):**
   - Calls `POST /api/security/simulate/{mode}`, which opens real loopback async HTTP requests against `/api/shop/products`, `/api/target/ping`, `/api/auth/login`, or `/api/bot/poll` so they pass through the exact same ASGI middleware + ONNX pipeline as external network traffic.
2. **Three `CICIDS2017` Lab Trace Replay Buttons (`cicids_flood`, `cicids_bruteforce`, `cicids_bot`):**
   - Feeds authentic CICIDS2017 reference feature vectors (`models/cicids_reference_vectors.json`) through both `v1_raw` and `v2_live` so you can prove on screen that **`v1_raw` scores `100.0%` on lab dataset traces even though it misses live Wi-Fi attacks**!
3. **`Upload .pcap File` Button (`#pcap-input`):**
   - Uploads any `.pcap` / `.pcapng` packet capture via `multipart/form-data` to `POST /api/security/pcap-upload`, reconstructs every bidirectional flow using Scapy, scores all flows, and streams them live onto the table.
4. **Live Attack Score Stream Canvas (`#score-canvas`):**
   - Plots the **last 50 scored flows** chronologically from left (`0.0 = 0%`) to top (`1.0 = 100%`):
     - **Red Horizontal Dashed Line:** Current Decision Gate Threshold `τ` (`0.9211`).
     - **Sky-Blue Polyline:** Continuous trajectory of `1 - P(Benign)` over time.
     - **Colored Dots on Every Point:** Look right at **your Screenshot #1 & #2**!
       - That long horizontal row of **purple dots** right at the very top (`y ≈ 99.3%`, clearly **above** the red dashed line!) is your `133` **`Bot`** flows crossing the gate!
       - Then the blue line dips down to **green dots near the bottom** (`Benign`, `score ≈ 0.01`)!
       - Then it climbs back above the red dashed line with **amber dots (`BruteForce`, `score ≈ 97.6%`)**, followed by one single **green dot at the right end** (`Pkts = 2`, initial `1.3%`)!

---

### 2.7 Panel 3: Real-Time Scored Network Flows Table (Explaining Every Column & Screenshot Row!)

Look at **Screenshot #1** — there are **TWO INCREDIBLE REAL-WORLD OBSERVATIONS** visible right in your own live table that will blow your professor's mind if you point them out during Viva:

#### All 8 Columns Explained:
1. **`Time`**: Exact `HH:MM:SS` timestamp when the flow snapshot was scored (`05:09:08`, `05:09:09`).
2. **`Source IP`**: Client IP address (`192.168.62.185`, `192.168.62.149`, or your real LAN laptop IP `192.168.92.14`).
3. **`Endpoint`**: Last HTTP route accessed in that flow (`/api/auth/login`, `/api/bot/poll`, or `L4:8000` for raw Scapy packets).
4. **`Pkts`**: Cumulative forward + backward segments observed in this flow window so far (`14 -> 16 -> 18 -> 20 -> 22 -> 24`).
5. **`Verdict (Active Model)`**: Final gated classification (`Benign`, `Flood`, `BruteForce`, `Bot`).
6. **`Attack Score`**: Percentage value of `(1 - P(Benign)) * 100%` (`97.4%`, `98.0%`, `1.3%`).
7. **`v1 Raw vs v2 Fixed`**: **Simultaneous side-by-side comparison** running both ONNX models on the exact same 27-feature vector!
8. **`Latency`**: Combined execution time of **both** ONNX models + host tracker on CPU (`0.46ms – 0.86ms`, less than **1 millisecond**!).

#### Two Brilliant Insights Directly From Screenshot #1:
- **Insight #1 — Why Rows 2–7 Show `v1:Benign` AND `v2:BruteForce` (`97.4%`) Side-by-Side!**  
  Look at rows 2 through 7 (`192.168.62.185 -> /api/auth/login`, `Pkts = 14..24`):
  - Original **`v1` (`model.onnx`)** predicted **`v1:Benign`** on every single one of those live login spray packets because live network RTTs differed from offline CICIDS2017 lab RTTs!
  - Regularized **`v2` (`model_v2_live.onnx`)** simultaneously caught every single one as **`v2:BruteForce` (`97.2% – 98.0%`) in `0.46ms`**!
- **Insight #2 — Why Row #1 at `05:09:09` (`192.168.62.149 -> /api/bot/poll`, `Pkts = 2`) Shows `Benign (1.3%)`!**  
  Look right across to Panel 4 on Screenshot #1 for that exact selected row (`Pkts = 2`):
  - `Pkts = 2` means **only 1 forward request packet + 1 backward response packet** had arrived at that millisecond (`1st poll` of a brand-new flow!).
  - With only 1 request so far, look at features `[17] Fwd IAT Std = 0`, `[18] Bwd IAT Mean = 0`, `[19] Bwd IAT Tot = 0` — **you cannot measure periodic bot timing intervals until at least 3–5 polls have arrived!**  
  - So at `Pkts = 2`, FlowDetect smartly classifies the very first request as **`Benign` (`98.67%`)** instead of falsely blocking a real user's first click — and then by `Pkts = 10+` (`5` clockwork polls at `190ms`), it immediately locks onto **`Bot` (`99.3%`)**!

---

### 2.8 Panel 4: Live 27-Feature & Probability Inspector + All 27 Features Reference Table

Clicking **any row** in Panel 3 selects that flow and populates Panel 4 with:
1. **Flow Metadata Header (`#insp-header`):** Source IP $\rightarrow$ Endpoint $\bullet$ Verdict badge $\bullet$ Collector source (`fastapi_asgi_live`, `scapy_raw_nic`, `pcap_file_upload`, or `manual_sandbox`).
2. **4-Class Probability Bars (`#prob-bars`):** Visual horizontal bars showing exact softmax confidence across all 4 classes (`Benign 98.67%`, `Flood 0.03%`, `BruteForce 0.06%`, `Bot 1.24%` in Screenshot #1).
3. **`Load into Tester` Button (`#btn-edit-selected`):** Copies all 27 feature numbers of the currently inspected row straight into the interactive ONNX Sandbox Modal!
4. **Complete `float32[1, 27]` Feature Vector Grid (`#features-grid`):** Displays the exact 27 numbers passed into `ort.InferenceSession.run(None, {"X": x})`:

| Index | Feature Name | Unit | What It Measures |
| :---: | :--- | :--- | :--- |
| `[0]` | `Flow Duration` | Microseconds (`µs`) | Total elapsed time from first packet to latest packet in the flow |
| `[1]` | `Flow Pkts/s` | Packets / sec | Total packet rate (spikes `> 200` in `Flood`) |
| `[2]` | `Flow IAT Mean` | Microseconds (`µs`) | Average time gap between consecutive packets in the flow |
| `[3]` | `Flow IAT Max` | Microseconds (`µs`) | Largest single pause between any two consecutive packets |
| `[4]` | `Flow IAT Std` | Microseconds (`µs`) | Standard deviation of inter-packet gaps (near `0` in `Bot`, huge in human `Benign`) |
| `[5]` | `Tot Fwd Pkts` | Count | Number of packets sent from Client $\rightarrow$ Server |
| `[6]` | `TotLen Fwd Pkts` | Bytes | Total payload bytes sent from Client $\rightarrow$ Server |
| `[7]` | `Flow Byts/s` | Bytes / sec | Combined bidirectional throughput |
| `[8]` | `Down/Up Ratio` | Ratio | Integer download-to-upload packet ratio (`bwd_pkts // fwd_pkts`) |
| `[9]` | `Pkt Len Mean` | Bytes | Average payload size across all packets in the flow |
| `[10]` | `Pkt Len Std` | Bytes | Standard deviation of packet payload lengths (`97.5807` in Screenshot #1!) |
| `[11]` | `Pkt Len Max` | Bytes | Largest packet payload seen in either direction (`194` in Screenshot #1) |
| `[12]` | `Fwd Pkt Len Max` | Bytes | Largest client request segment length |
| `[13]` | `Fwd Pkt Len Mean` | Bytes | Average client request segment length |
| `[14]` | `Bwd Pkt Len Max` | Bytes | Largest server response segment length (up to `1460` TCP MSS) |
| `[15]` | `Bwd Pkt Len Mean` | Bytes | Average server response segment length |
| `[16]` | `Fwd Act Data Pkts` | Count | Client packets carrying non-zero payload (`payload > 0`) |
| `[17]` | `Fwd IAT Std` | Microseconds (`µs`) | Jitter between client requests (key discriminator for `Bot` vs `Benign`!) |
| `[18]` | `Bwd IAT Mean` | Microseconds (`µs`) | Average interval between server response segments |
| `[19]` | `Bwd IAT Tot` | Microseconds (`µs`) | Total span from first response packet to latest response packet |
| `[20]` | `SYN Flag Cnt` | Count | TCP `SYN` packets seen (surges in raw `hping3` SYN floods) |
| `[21]` | `RST Flag Cnt` | Count | TCP `RST` connection-reset flags seen |
| `[22]` | `PSH Flag Cnt` | Count | TCP `PSH` push flags across complete request/response frames |
| `[23]` | `ACK Flag Cnt` | Count | TCP `ACK` flags seen |
| `[24]` | `Fwd PSH Flags` | `0` or `1` | Indicator that client push data is active |
| `[25]` | `Idle Mean` | Microseconds (`µs`) | Mean idle pause duration (`> 1s` silent gaps) |
| `[26]` | `Active Mean` | Microseconds (`µs`) | Mean continuous active burst duration before an idle gap |

---

### 2.9 Modal: Interactive Manual 27-Feature ONNX Sandbox (`#lab-modal`)

- Opens when clicking **`Manual 27-Feature Tester`** (top banner) or **`Load into Tester`** (Panel 4).
- Renders 27 editable `<input type="number" step="any">` fields (`[0] Flow Duration` ... `[26] Active Mean`).
- Clicking **`Score 27 Features on ONNX Now`** sends `POST /api/security/score-features` directly to FastAPI, runs real ONNX Runtime inference on your hand-edited tensor, broadcasts the result live over WebSocket to every connected screen, and highlights the new synthetic test row at the top of Panel 3!

---

## 3. Complete Line-by-Line Code Walkthrough (`frontend/` Excluding CSS)

---

### 3.1 `frontend/config.js` (Lines `1–45` — Zero-Edit Auto-Discovery)

**Purpose:** Guarantees your friend on Windows (`192.168.29.150:9090`), your Linux laptop, cloud VMs, and HTTPS reverse proxies **all connect to FastAPI (`:8000`) automatically without editing a single hardcoded IP address**.

- **Lines `10–13` (`window.FlowDetectConfig` singleton):**  
  Exposes `apiBase` (REST prefix) and `wsUrl` (WebSocket URL) globally so `app.js` never hardcodes `localhost` or `127.0.0.1`.
- **Lines `14–22` (Priority Tier 1 — Explicit Query Override `?api=...`):**  
  Reads `new URLSearchParams(window.location.search).get("api")`.  
  *Why this exists:* If someone deploys the static frontend on **Vercel / Netlify** and the FastAPI backend on **AWS EC2 / DigitalOcean (`http://203.0.113.10:8000`)**, opening `https://my-ui.vercel.app/?api=http://203.0.113.10:8000` connects cross-cloud immediately with zero rebuild!
- **Lines `24–36` (Priority Tier 2 — Same-Origin Reverse Proxy Check):**  
  Fetches relative `"/api/security/status"` and verifies **both** `res.ok` **and** `content-type` contains `"application/json"`.  
  - If served behind `frontend_server.py` (`:9012`) or Nginx, this succeeds (`200 OK` JSON), so `apiBase = ""` (same origin) and `wsUrl` automatically picks `wss://` over HTTPS or `ws://` over HTTP.
  - When your friend ran a plain static server on Windows port **`:9090`**, `"/api/security/status"` returned `404` (or HTML), so `config.js` automatically fell through to Priority Tier 3!
- **Lines `38–44` (Priority Tier 3 — Automatic LAN/Cloud Host `:8000` Fallback):**  
  Reads `window.location.hostname` (`"192.168.29.150"`) directly from the browser URL bar and constructs:
  - `this.apiBase = "http://192.168.29.150:8000"`
  - `this.wsUrl   = "ws://192.168.29.150:8000/ws/live"`  
  That single 6-line block is why **any custom frontend port (`3000`, `5173`, `5500`, `9090`) works immediately across any Wi-Fi/LAN**!

---

### 3.2 `frontend/index.html` (Lines `1–267` — Semantic DOM Structure)

| Line Range | HTML Section | Key IDs / Attributes & Exact Purpose |
| :--- | :--- | :--- |
| **Lines `1–8`** | `<head>` | UTF-8 charset, mobile viewport scaling (so the teacher's smartphone renders crisply!), page `<title>`, and `./styles.css`. |
| **Lines `10–30`** | `#threat-banner` | Top sticky alert bar containing `#banner-icon`, `#banner-title`, `#banner-sub`, and action buttons `#btn-open-lab`, `#btn-sound`, `#btn-reset`. |
| **Line `33`** | `#toast` | Floating notification pop-up (`hidden` until `showToast()` displays clipboard/simulation feedback for `3.4s`). |
| **Lines `36–51`** | `<header class="topbar">` | Brand badge `FD` + three live status pills (`#ws-pill`, `#os-pill`, `#lan-pill`). |
| **Lines `55–82`** | `<section class="kpi-grid">` | Five metric cards bound via `#kpi-total`, `#kpi-pkts`, `#kpi-benign`, `#kpi-flood`, `#kpi-bruteforce`, `#kpi-bot`. |
| **Lines `85–92`** | `.topology-panel` | `#cli-copy-btn` helper pill + `<canvas id="topology-canvas" width="1280" height="86">` logical 2D drawing surface. |
| **Lines `96–137`** | Panel 1 (Left `.panel`) | Model buttons (`#mode-v2`, `#mode-v1`), dynamic description `#model-explain`, Shield mode buttons (`#shield-alert`, `#shield-enforce`), threshold readout `#tau-display`, range slider `#tau-slider` (`0.50`–`0.99`), NIC diagnostic box `#capture-desc`, and `#blocked-container` (`#blocked-list`). |
| **Lines `140–186`** | Panel 2 (Right `.panel`) | Four live simulator buttons (`data-sim="benign"`, `"flood"`, `"bruteforce"`, `"bot"`), three lab trace buttons (`data-sim="cicids_flood"`, `"cicids_bruteforce"`, `"cicids_bot"`), hidden `<input id="pcap-input" type="file">` wrapped inside `<label>` button, and `<canvas id="score-canvas" width="600" height="105">`. |
| **Lines `190–218`** | Panel 3 (`.table-panel`) | Scrollable 8-column `<table>` with dynamic `<tbody id="flow-tbody">`. |
| **Lines `221–239`** | Panel 4 (`.inspector-panel`) | `#btn-edit-selected`, empty placeholder `#inspector-empty`, and live detail container `#inspector-content` (`#insp-header`, `#prob-bars`, `#features-grid`). |
| **Lines `243–258`** | `#lab-modal` | Full-screen modal backdrop (`hidden` by default) containing `#lab-inputs` (populated dynamically with 27 inputs), `#btn-close-lab`, and `#btn-run-manual`. |
| **Lines `260–261`** | `<script>` tags | Loads `./config.js` **first**, then `./app.js` **at the end of `<body>`** so all DOM elements are already parsed when `initApp()` executes. |

---

### 3.3 `frontend/app.js` (Lines `1–433` — State, Renderers, Canvas, Audio & WebSocket)

Here is every single block and function in `frontend/app.js` in exact line order:

#### 1. Constants & Single-Source Reactive `state` Store (`Lines 6–34`)
- **`FEATURE_NAMES` (`Lines 6–13`):** Exact 27 feature names in canonical index order `[0..26]`, ensuring the Manual Sandbox Modal always matches the ONNX input tensor contract `X: float32[1, 27]`.
- **`state` (`Lines 15–25`):** Central in-memory store (maps 1-to-1 to React `useState` / `useReducer` hooks!):
  - `events`: Array of up to `80` newest scored flow objects (`unshift` prepends newest on top).
  - `selectedEventId`: Currently highlighted flow ID shown inside Panel 4.
  - `status`: Latest full system snapshot from `/api/security/status`.
  - `soundEnabled`: Boolean flag for Web Audio alert chime.
  - `scoreHistory`: Rolling array of `{ score, cls, alert }` plotted on `#score-canvas`.
  - `particles`: Active animated dots currently flying across `#topology-canvas`.
  - `tau`: Active decision gate threshold (`0.921056` default).
  - `ws`: Active `WebSocket` instance.
- **`CLASS_COLORS` (`Lines 27–32`):** Consistent semantic hex palette used identically across Canvas particles, Score Chart dots, and Probability Bars (`Benign: #10b981`, `Bot: #a855f7`, `BruteForce: #f59e0b`, `Flood: #ef4444`).

#### 2. UX Feedback, Web Audio Synthesizer & Particle Spawner (`Lines 34–74`)
- **`showToast(msg)` (`Lines 34–40`):** Displays non-blocking toast banner and resets `3,400 ms` auto-hide timer via `clearTimeout(state.toastTimer)`.
- **`playAlertTone()` (`Lines 42–59`):** Creates a Web Audio `OscillatorNode` (`type = "triangle"`) sweeping exponentially from `740 Hz` (`F#5`) to `990 Hz` (`B5`) with smooth exponential volume decay (`0.12 -> 0.001` in `0.28s`). Zero external sound files needed!
- **`spawnPacketParticles(cls, count)` (`Lines 61–72`):** Pushes staggered particle objects (`x = 70 - i * 18`) into `state.particles` with randomized vertical lane jitter and velocity (`5.2 – 7.7 px/frame`).

#### 3. 60 FPS Topology Pipeline Animator (`startTopologyLoop`, `Lines 75–125`)
- Defines the 4 pipeline stages (`x = 115, 440, 805, 1145`) and runs `requestAnimationFrame(frame)` continuously at display refresh rate (`60 Hz`).
- Draws the connecting wire **first**, advances and draws moving colored packet particles **second** (splicing completed particles out in reverse loop `for (let i = len - 1; i >= 0; i--)` for zero array shift bugs!), and draws rounded stage boxes **on top** so packets visually enter and exit each processing node cleanly!

#### 4. Pure UI Renderer Functions (`Lines 128–310`)
Each function updates strictly **one UI zone** from `state` (ready to become an independent React component):
- **`renderAlertBanner(latestEvent)` (`Lines 128–151`):** Switches `.banner-safe` vs `.banner-danger` based on `latestEvent.alert`.
- **`renderSystemStatus(snap)` (`Lines 154–197`):** Syncs OS pill, Teacher Wi-Fi Share URL (`lan_ips[0] + window.location.port`), NIC capture message, `τ` slider + text badge, active model button highlight + explanation text, Active Shield toggle, and dynamic `[Unblock]` IP chips.
- **`renderKpis(stats, totalPkts)` (`Lines 199–209`):** Updates all 5 KPI card counters in O(1) DOM writes.
- **`renderScoreChart()` (`Lines 212–249`):**
  - Maps score `[0.0 .. 1.0]` to canvas vertical pixels via `y = H - score * (H - 18) - 9` (`9px` top/bottom padding so `100%` and `0%` dots are never clipped!).
  - Draws the dashed red gate line at `tauY`, connects the last `50` scores with a sky-blue line, and overlays larger `4.5px` dots for alerts vs `3px` dots for normal flows.
- **`renderFlowTable()` (`Lines 252–278`):** Renders the newest `45` flows into `#flow-tbody` with clickable row selection (`onclick="selectEvent('...')"`) and side-by-side `v1:...` / `v2:...` comparison badges.
- **`renderInspector(ev)` (`Lines 280–321`):** Renders the selected flow's header, 4 color-coded percentage bars (`min width 1%` for visibility), and all 27 indexed `[0]..[26]` feature key-value cells.

#### 5. Manual Sandbox, API Actions & Live WebSocket Engine (`Lines 324–433`)
- **`openManualLab(prefillMap)` (`Lines 324–338`):** Builds all 27 numeric inputs pre-populated from either the clicked row (`Load into Tester`), the latest live flow (`state.events[0]`), or zeros.
- **`window.selectEvent` & `window.unblockIp` (`Lines 340–352`):** Row click handler and 1-click IP unblock `POST /api/security/unblock/{ip}`.
- **`patchConfig(body)` & `refreshStatus()` (`Lines 354–378`):** Sends live config patches (`active_model`, `shield_mode`, `tau`) and hydrates historical events on first page load so even a newly joined teacher phone immediately sees the previous 40 flows!
- **`connectWebSocket()` (`Lines 380–425`):** Handles all 4 real-time push message types from FastAPI:
  1. `"hello"`: Initial snapshot immediately on socket connect.
  2. `"config_updated"`: Broadcast whenever **any** connected browser changes `v1/v2`, `Alert/Shield`, `τ`, or unblocks an IP (keeps all screens synchronized!).
  3. `"reset"`: Wipes stream state cleanly across all open devices simultaneously.
  4. `"flow_event"`: Prepends new flow, triggers particles + optional audio chime, updates all 4 visual panels instantaneously, and refreshes `blocked_ips` if `shield_mode === "enforce"`.
- **`initApp()` (`Lines 427–502` / bottom boot block):** Starts the 60 FPS canvas loop, awaits `FlowDetectConfig.init()`, loads initial status, opens WebSocket, wires all click/change/upload event listeners, and executes automatically on page load.

---

## 4. Exact Backend REST & WebSocket JSON Contracts Used by Frontend

Your Windows teammate building a custom React UI only needs these **6 endpoints** on Port `8000`:

| Method & Endpoint | Request Payload | What It Does |
| :--- | :--- | :--- |
| **`GET /api/security/status`** | None | Returns full system snapshot (`os`, `lan_ips`, `capture_engine`, `models`, `gate`, `stats`, `blocked_ips`, `recent_events`). |
| **`PATCH /api/security/config`** | `{"active_model": "v2_live", "shield_mode": "enforce", "tau": 0.92}` *(any subset)* | Updates active ONNX model, Alert/Block mode, or Gate `τ` live and broadcasts `config_updated` to all WebSocket clients. |
| **`POST /api/security/unblock/{ip}`** | None | Removes `{ip}` from `blocked_ips` and flushes its flow window immediately. |
| **`POST /api/security/reset`** | None | Resets all counters, flow sessions, and host trackers; broadcasts `reset` to all browsers. |
| **`POST /api/security/simulate/{mode}`** | None (`mode` in `benign`, `flood`, `bruteforce`, `bot`, `cicids_flood`, `cicids_bruteforce`, `cicids_bot`) | Generates real live traffic or replays authentic CICIDS2017 reference vectors. |
| **`POST /api/security/pcap-upload`** | `multipart/form-data` (`file = *.pcap`) | Parses every packet in the `.pcap`, reconstructs bidirectional 27-feature flows, and streams all verdicts over WebSocket. |
| **`POST /api/security/score-features`** | `{"client_ip": "manual-lab-test", "features": {"Flow Duration": 5000, ...}}` | Scores any custom 27-feature dictionary directly through both `v1_raw` & `v2_live` ONNX models. |
| **`WS /ws/live`** | Server push messages | Pushes `{"type": "hello" \| "config_updated" \| "reset" \| "flow_event", ...}` in real time. |

---

## 5. 1:1 React (Vite) Component & Hook Conversion Map (For Frontend Teammate)

Because `app.js` was written with pure decoupled renderers and a single `state` object, converting `frontend/` into **React + Vite** is a clean 1-to-1 split:

```text
src/
├── api/
│   └── flowDetectConfig.js      <-- Copy `frontend/config.js` directly (export `getApiConfig()`)
├── hooks/
│   ├── useFlowSocket.js         <-- Moves `state`, `refreshStatus()`, `connectWebSocket()`, `patchConfig()`
│   └── useAlertAudio.js         <-- Moves `playAlertTone()` Web Audio hook
├── components/
│   ├── ThreatBanner.jsx         <-- From `renderAlertBanner()` + Sound / Manual Tester / Reset buttons
│   ├── TopBar.jsx               <-- From `<header class="topbar">` + Wi-Fi Copy Pill
│   ├── KpiGrid.jsx              <-- From `<section class="kpi-grid">` + `renderKpis()`
│   ├── PipelineCanvas.jsx       <-- `useRef` + `useEffect` wrapping `startTopologyLoop()`
│   ├── EngineControlsPanel.jsx  <-- Panel 1 (`v1/v2` toggle, `Alert/Shield` toggle, `τ` slider, Blocked chips)
│   ├── TrafficLauncherPanel.jsx <-- Panel 2 (4 Live buttons, 3 CICIDS buttons, `.pcap` upload, `ScoreChart.jsx`)
│   ├── FlowTable.jsx            <-- Panel 3 (`renderFlowTable()` with `selectedEventId` prop)
│   ├── FeatureInspector.jsx     <-- Panel 4 (`renderInspector()` showing 4 bars + 27 feature cards)
│   └── ManualSandboxModal.jsx   <-- `#lab-modal` controlled modal with 27 controlled inputs
└── App.jsx                      <-- Connects `useFlowSocket()` to all child components above
```

---

## 6. Top 8 Viva / Evaluator Questions & Crisp Answers

1. **Q: Why does your system use `1 - P(Benign) >= τ (0.921056)` instead of simply taking `argmax` of the 4 classes?**  
   **A:** Standard `argmax` fires alerts even at low confidence (e.g. `40% Flood, 35% Benign, 25% Bot`), causing false alarms on normal web page bursts. Requiring total attack probability `1 - P(Benign) >= 0.921056` guarantees **high precision (`< 1.5%` false positive rate)** before raising alerts or auto-blocking an IP with `HTTP 403`, and once opened, selects the dominant attack class (`Flood`, `BruteForce`, or `Bot`).

2. **Q: Why does a brand-new flow with `Pkts = 2` show `Benign` first before turning into `Bot` or `BruteForce`?**  
   **A:** At `Pkts = 2` (only 1 request + 1 response), inter-arrival time statistics (`Fwd IAT Std`, `Bwd IAT Mean`, `Flow Pkts/s` across multiple requests) are `0` because only a single exchange has occurred. Waiting for `3–6+` packets prevents false blocking on normal single clicks while still catching bots and brute-force attacks in **under `0.4–1.2 seconds`**!

3. **Q: Why does column 7 show `v1:Benign` right next to `v2:BruteForce (97.4%)` on live traffic?**  
   **A:** `v1` (`model.onnx`) had zero L2 regularization (`max leaf weight = 32,935.9`), overfitting to lab Ethernet RTTs in CICIDS2017. `v2` (`model_v2_live.onnx`) applies `l2_regularization = 1.5` (`max leaf weight = 0.3194`) + realistic network RTT distillation, fixing live domain shift while keeping `98.4%` validation accuracy.

4. **Q: How fast is dual-model ONNX inference in real time?**  
   **A:** Running **both** `v1_raw` and `v2_live` simultaneously in C++ `onnxruntime` takes **`0.40 – 0.85 ms` per flow on CPU** — zero GPU required!

5. **Q: How did `http://192.168.29.150:9090` connect to port `:8000` without hardcoding the IP address?**  
   **A:** `config.js` dynamically reads `window.location.hostname` (`192.168.29.150`) at runtime and binds REST calls to `http://<hostname>:8000` and WebSockets to `ws://<hostname>:8000/ws/live`.

6. **Q: Why did you choose Backend FastAPI + ONNX Runtime instead of WebAssembly / WebGL ONNX inside the browser?**  
   **A:** Browser JavaScript is sandboxed and **cannot sniff raw network packets (`Scapy`), measure true server TCP timings, share one unified security state across multiple devices simultaneously, or enforce real server-side `HTTP 403` IP blocks**.

7. **Q: What happens when multiple devices (Laptop + Windows Server + Teacher's Phone) open the Dashboard at the same time?**  
   **A:** FastAPI maintains an active `Set[WebSocket]` broadcast hub (`ws_clients`), pushing every scored flow, model switch, slider update, and reset simultaneously in `< 2 ms` to every connected screen.

8. **Q: Why does the Windows 11 status box mention `Install Npcap & run PowerShell as Administrator for L3 SYN capture`?**  
   **A:** Windows restricts raw kernel NIC packet capture unless Npcap + Admin privileges are active. Instead of crashing on Windows, FlowDetect gracefully reports NIC status and runs its zero-privilege **FastAPI ASGI Live Collector** automatically.
