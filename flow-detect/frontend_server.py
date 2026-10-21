"""
Port 9012 Frontend Static Server + Automatic Backend Proxy (`0.0.0.0:9012` -> `127.0.0.1:8000`).

Works in EVERY environment:
1. Local Laptop / Mobile Hotspot (`http://192.168.62.52:9012` for your Teacher's phone/laptop!)
2. Cloud Ubuntu VM (`http://<VM_PUBLIC_IP>:9012`)
3. HTTPS Browser Previews (zero CORS or Mixed-Content issues!)
4. Note: `frontend/` ALSO works directly with plain `python -m http.server 9012 --bind 0.0.0.0`!
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import httpx
import websockets
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
API_BACKEND = os.environ.get("FLOW_DETECT_BACKEND_URL", "http://127.0.0.1:8000")
WS_BACKEND = API_BACKEND.replace("http://", "ws://").replace("https://", "wss://")

proxy_app = FastAPI(title="FlowDetect Port 9012 Frontend Server")


@proxy_app.api_route(
    "/api/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_api(full_path: str, request: Request) -> Response:
    url = f"{API_BACKEND}/api/{full_path}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    body = await request.body()
    fwd_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    if request.client and "x-forwarded-for" not in {k.lower() for k in fwd_headers}:
        fwd_headers["X-Forwarded-For"] = request.client.host

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.request(
            method=request.method,
            url=url,
            content=body,
            headers=fwd_headers,
        )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers={"content-type": resp.headers.get("content-type", "application/json")},
    )


@proxy_app.websocket("/ws/live")
async def proxy_ws(client_ws: WebSocket) -> None:
    await client_ws.accept()
    try:
        async with websockets.connect(f"{WS_BACKEND}/ws/live") as upstream:
            async def c2u() -> None:
                try:
                    while True:
                        msg = await client_ws.receive_text()
                        await upstream.send(msg)
                except Exception:
                    pass

            async def u2c() -> None:
                try:
                    async for msg in upstream:
                        await client_ws.send_text(str(msg))
                except Exception:
                    pass

            done, pending = await asyncio.wait(
                [asyncio.create_task(c2u()), asyncio.create_task(u2c())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await client_ws.close()
        except Exception:
            pass


proxy_app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
