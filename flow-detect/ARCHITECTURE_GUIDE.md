# FlowDetect End-to-End Architecture & Deployment Guide

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
