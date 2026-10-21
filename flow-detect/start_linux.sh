#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "========================================================"
echo "  FlowDetect Live NIDS Launcher (Linux / Cloud VM)"
echo "  Backend API : http://0.0.0.0:8000"
echo "  SOC UI      : http://0.0.0.0:9012"
echo "========================================================"

if [ ! -f "models/model_v2_live.onnx" ]; then
  echo "[*] Generating models/model_v2_live.onnx ..."
  python3 train_v2_model.py
fi

python3 -m uvicorn backend.app:app --host 0.0.0.0 --port 8000 &
API_PID=$!

python3 -m uvicorn frontend_server:proxy_app --host 0.0.0.0 --port 9012 &
UI_PID=$!

trap "kill $API_PID $UI_PID 2>/dev/null || true" EXIT INT TERM
echo "[+] Both servers are running! Press Ctrl+C to stop."
wait
