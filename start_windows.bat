@echo off
cd /d "%~dp0"
echo ========================================================
echo   FlowDetect Live NIDS Launcher (Windows 10 / 11)
echo   Backend API : http://0.0.0.0:8000
echo   SOC UI      : http://0.0.0.0:9012
echo   Tip: Run CMD/PowerShell as Administrator + Npcap for L3 SYN capture,
echo        or run normally for zero-admin ASGI Live Flow mode!
echo ========================================================

if not exist "models\model_v2_live.onnx" (
    echo [*] Building models\model_v2_live.onnx ...
    python train_v2_model.py
)

start "FlowDetect FastAPI (:8000)" cmd /k "python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000"
start "FlowDetect Frontend (:9012)" cmd /k "python -m uvicorn frontend_server:proxy_app --host 0.0.0.0 --port 9012"

echo [+] Started Backend (:8000) and Frontend (:9012) in separate windows!
pause
