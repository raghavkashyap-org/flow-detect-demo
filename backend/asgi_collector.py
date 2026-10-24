"""
Zero-Privilege Live FastAPI ASGI Stream-to-Packet Translator & Active Shield Middleware.

Works identically on Windows 10/11, Linux, macOS, Docker, WSL2, and Cloud VMs WITHOUT requiring
`sudo` or Npcap! Converts live incoming HTTP request segments (`Fwd`) and outgoing HTTP response
segments (`Bwd`) into exact microsecond MSS-framed flow events fed into `LiveFlowTable`.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Coroutine

from .detector_engine import DualONNXDetector
from .flow_extractor import LiveFlowTable

MSS_BYTES = 1460


class FlowDetectASGIMiddleware:
    """Pure low-overhead ASGI middleware for live translation + optional Active IP Blocking."""

    def __init__(
        self,
        app: Any,
        flow_table: LiveFlowTable,
        detector: DualONNXDetector,
        on_event_scored: Callable[[dict], Coroutine[Any, Any, None]],
        server_port: int = 8000,
    ) -> None:
        self.app = app
        self.flow_table = flow_table
        self.detector = detector
        self.on_event_scored = on_event_scored
        self.server_port = server_port

    def _resolve_client_ip(self, scope: dict) -> str:
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        # Allow attack simulator & reverse proxies to specify distinct simulated attacker IPs
        if b"x-demo-client-ip" in headers:
            return headers[b"x-demo-client-ip"].decode("latin1").strip()
        if b"x-forwarded-for" in headers:
            return headers[b"x-forwarded-for"].decode("latin1").split(",")[0].strip()
        client = scope.get("client")
        return str(client[0]) if client else "127.0.0.1"

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "/")
        # Never block or pollute flow telemetry with dashboard control/health polling calls
        if path.startswith("/api/security/") or path.startswith("/docs") or path.startswith("/openapi"):
            await self.app(scope, receive, send)
            return

        client_ip = self._resolve_client_ip(scope)

        # 1. Synchronous O(1) Active Shield Block Check (< 5 microseconds)
        blocked_info = self.detector.check_blocked(client_ip)
        if blocked_info is not None:
            payload = json.dumps(
                {
                    "blocked": True,
                    "shield": "FlowDetect Active Defense",
                    "client_ip": client_ip,
                    "attack_family": blocked_info["reason"],
                    "confidence": blocked_info["attack_score"],
                    "retry_after_sec": max(1, int(blocked_info["expires_at"] - time.time())),
                }
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"access-control-allow-origin", b"*"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return

        # Estimate HTTP header frame size cleanly
        raw_hdr_len = sum(len(k) + len(v) + 4 for k, v in scope.get("headers", [])) + len(path) + 18
        req_body_bytes = 0
        resp_body_bytes = 0
        resp_status = 200
        t_req_us = float(time.perf_counter_ns() // 1000)

        async def wrapped_receive() -> dict:
            nonlocal req_body_bytes
            msg = await receive()
            if msg["type"] == "http.request":
                req_body_bytes += len(msg.get("body", b""))
            return msg

        async def wrapped_send(msg: dict) -> None:
            nonlocal resp_status, resp_body_bytes
            if msg["type"] == "http.response.start":
                resp_status = int(msg.get("status", 200))
            elif msg["type"] == "http.response.body":
                resp_body_bytes += len(msg.get("body", b""))
            await send(msg)

        await self.app(scope, wrapped_receive, wrapped_send)

        t_done_us = float(time.perf_counter_ns() // 1000)
        # Compact forward/backward L4 payload representation aligned with `FlowSession` training
        fwd_total = max(48, min(MSS_BYTES, req_body_bytes if req_body_bytes > 0 else min(raw_hdr_len, 420)))
        bwd_total = max(56, resp_body_bytes)

        # Ingest Forward segments
        self.flow_table.ingest_event(
            client_ip=client_ip,
            server_port=self.server_port,
            protocol=6,
            is_forward=True,
            payload_bytes=fwd_total,
            ts_us=t_req_us,
            syn=0,
            psh=1,
            ack=1,
            path=path,
            emit_every_n_pkts=999999,
        )

        # Ingest Backward segments (split at TCP MSS 1460 bytes just like real Ethernet/TCP!)
        rem = bwd_total
        seg_ts = t_done_us
        scored_result = None
        while rem > 0:
            chunk = min(MSS_BYTES, rem)
            rem -= chunk
            res = self.flow_table.ingest_event(
                client_ip=client_ip,
                server_port=self.server_port,
                protocol=6,
                is_forward=False,
                payload_bytes=chunk,
                ts_us=seg_ts,
                syn=0,
                psh=(1 if rem == 0 else 0),
                ack=1,
                status_code=(resp_status if rem == 0 else None),
                emit_every_n_pkts=2,
            )
            seg_ts += 120.0
            if res is not None:
                scored_result = res

        if scored_result is not None:
            sess, vec = scored_result
            event = self.detector.score_vector(
                vec,
                session=sess,
                source_mode="fastapi_asgi_live",
                last_path=path,
                last_status=resp_status,
            )
            await self.on_event_scored(event)
