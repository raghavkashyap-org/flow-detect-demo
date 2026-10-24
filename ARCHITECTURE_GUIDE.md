# FlowDetect End-to-End Architecture & Deployment Guide

---

## Architecture Walkthrough (`arch.html`) — v4.1

`frontend/arch.html` — served at `http://<HOST>:9012/arch.html` (linked from the dashboard navbar and footer) — is a self-contained, **mobile-first** viewer with three modes over one hand-built data model:

- **Overview** — the full Rummler–Brache cross-functional flowchart: 5 swimlanes (Traffic & Actors · Frontend UI & `:9012` Edge · FastAPI Ingress `:8000` · Flow Assembly & Features · Detection Core & Artifacts) × 8 phases × 33 blocks × 33 hops. It is also the **router**: click one block for **A**, a second for **B**, and the shortest directed route is painted on the canvas (hop count, *Walk this path*, *Clear*, `Esc`). Export to SVG / PNG / one-page A1 PDF.
- **Walkthrough** — one hop at a time. Fork chooser with per-hop *Why* and *How*, breadcrumb trail, phase meter, an arrowed position map, cycle detection (LOOP badges, re-entry confirmation, four named loops), dead-end and entry-point handling, and a path finder. The map's **⤢** button and `M` open the big Overview map (centred on the current block) instead of a duplicate.
- **How to use** — modes, gestures, routing, phone layout and the complete shortcut table, generated from the live key map.

**Mobile-first:** sticky bottom bar (`Back · Next · Code · Map · Menu`), inspector as an on-demand slide-up sheet, 44 px touch targets, safe-area insets, momentum scrolling, no full-screen dimming when you select a block. **Full keyboard:** `O/W/H`, `1`–`9`, `←/→`, `N`, `R`, `F`, `L`, `D`, `C`, `X`, `[`/`]`, `Y`, `M`, `Z`, `P`, `T`, `/`, `?`, layered `Esc`.

- **Code inspector** — for any block, the verbatim function extracted from the real source (`backend/*.py`, `frontend/*.js`) with file path, line range, gutter, highlighting and copy, plus a numbered *Explain* tab that walks the same function line by line.

Regenerate with `python arch_src/extract.py && python arch_src/enrich.py && python arch_src/build.py`. Details: `FRONTEND.md` §5.

## 1. Quick Start (Linux & Windows)

### Install Dependencies
```bash
cd flow-detect
pip install -r requirements.txt
```

### Option A — Linux / macOS / Cloud Ubuntu VM
```bash
chmod +x start_linux.sh
# Run without sudo (uses FastAPI Live ASGI Stream Collector automatically):
./start_linux.sh

# OR run with sudo for raw kernel TCP SYN/UDP sniffing via Scapy:
sudo ./start_linux.sh
```

### Option B — Windows 10 / 11
1. Double-click `start_windows.bat` *(works immediately as a normal user via ASGI Live Stream mode!)*
2. *(Optional for kernel raw TCP SYN flood capture on Windows)*: Install free **Npcap** (`https://npcap.com`, check *"Install Npcap in WinPcap API-compatible Mode"*), right-click PowerShell $\rightarrow$ **Run as Administrator**, and run `.\start_windows.bat`.
3. Open **Windows Defender Firewall** once if sharing across Wi-Fi:
   ```powershell
   netsh advfirewall firewall add rule name="FlowDetect Demo" dir=in action=allow protocol=TCP localport=8000,9012
   ```

---

## 2. Live Teacher Demo Over Wi-Fi (`192.168.62.52:9012`)

1. Turn on your **Phone Mobile Hotspot** (recommended over campus Wi-Fi, because campus routers often block laptop-to-phone connections via *AP Client Isolation*).
2. Connect **your laptop** and **your teacher's phone/laptop** to the hotspot.
3. Start the stack (`./start_linux.sh` or `start_windows.bat` — OR run `uvicorn backend.app:app --host 0.0.0.0 --port 8000` + `python -m http.server 9012 --bind 0.0.0.0 --directory frontend`).
4. Read the exact **Teacher Wi-Fi URL** pill at the top-right of the dashboard (e.g. `http://192.168.62.52:9012`) and open it on your teacher's device.
5. Launch real live attacks from a second terminal or second laptop:
   ```bash
   python attack_simulator.py --target http://192.168.62.52:8000 --mode all
   ```
   Both screens update simultaneously over WebSockets (`< 20 ms`), flashing crimson warning banners, live probability bars across all 4 classes (`Benign`, `Flood`, `BruteForce`, `Bot`), and all 27 extracted features!

---

## 3. Cloud VM Deployment (`AWS EC2 / DigitalOcean / Oracle / GCP Ubuntu VM`)

1. Provision any Ubuntu 22.04 / 24.04 VM (`1–2 vCPU`, `1–2 GB RAM` is plenty — inference takes `0.015 ms` on CPU!).
2. Open inbound TCP ports **`8000`** and **`9012`** (plus `22` for SSH) in the VM's Security Group / Cloud Firewall.
3. Copy your project & run inside `tmux` or `systemd`:
   ```bash
   sudo apt update && sudo apt install -y python3-pip python3-venv tmux
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   tmux new -s flow-detect './start_linux.sh'
   ```
4. Open `http://<YOUR_VM_PUBLIC_IP>:9012` from anywhere in the world, and fire live attacks from your local laptop:
   ```bash
   python attack_simulator.py --target http://<YOUR_VM_PUBLIC_IP>:8000 --mode all
   ```


### Short-view — compact presentation inside Overview
Use **Overview → Short-view** to explain the whole system without navigating the long map. Eight numbered blocks cover traffic, ingress/accounting, flow assembly, 27 features, inference, alert gating, live publishing and dashboard response. Each shows its job and one implementation cue. Startup and operator feedback are separate short notes. Read left-to-right, then the next row.

This is presentation-only: no animation, zoom, routing, inspector or modal. **Full map** restores the detailed canvas; Walkthrough and How to use remain unchanged. Map-navigation commands return to Full map. The layout uses four columns on desktop, two on phones, and one on very narrow screens. The current Full/Short selection is remembered only while the page remains open.

Verified in Chromium at 390/768/1280/1440 px: eight blocks, no panel overflow, theme and mode switching, full-map restoration and hidden map tools. Existing navigation/button regression checks also pass.
