#!/usr/bin/env python3
"""
Cross-Platform CLI Live Attack & Traffic Simulator (Works on Windows 10/11, Linux & macOS!).

Auto-detects your current Wi-Fi / LAN IP automatically when `--target` is omitted or unreachable!

Examples:
  python attack_simulator.py --mode all
  python attack_simulator.py --mode flood
  python attack_simulator.py --target http://192.168.29.179:8000 --mode all
  python attack_simulator.py --target http://<CLOUD_VM_IP>:8000 --mode flood
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
import time
import httpx


def detect_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


async def resolve_working_target(requested: str | None) -> str:
    local_ip = detect_local_ip()
    candidates = []
    if requested:
        candidates.append(requested.rstrip("/"))
    candidates.extend([f"http://{local_ip}:8000", "http://127.0.0.1:8000"])

    seen = set()
    probe_timeout = httpx.Timeout(2.0, connect=1.8)
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            async with httpx.AsyncClient(timeout=probe_timeout) as probe:
                r = await probe.get(f"{url}/api/security/status")
                if r.status_code == 200:
                    if requested and url != requested.rstrip("/"):
                        print(
                            f"[!] Could not reach {requested} (your Wi-Fi IP changed!)\n"
                            f"[+] Auto-switched to active FlowDetect server at: {url}"
                        )
                    return url
        except Exception:
            if requested and url == requested.rstrip("/"):
                print(f"[!] Target {requested} timed out — checking active local server IP ({local_ip})...")

    print(
        f"[ERROR] Could not connect to FlowDetect API on {requested or f'http://{local_ip}:8000'}.\n"
        f"        Check your current IP with `hostname -I` (Linux) or `ipconfig` (Windows)\n"
        f"        and ensure uvicorn backend is running on `--host 0.0.0.0 --port 8000`."
    )
    sys.exit(1)


async def run_benign(client: httpx.AsyncClient, source_ip: str) -> None:
    print(f"[BENIGN] Simulating normal human browsing from {source_ip} ...")
    for step in range(3):
        r = await client.get("/api/shop/products", headers={"X-Demo-Client-IP": source_ip})
        print(f"  -> GET /api/shop/products [{r.status_code}] ({len(r.content)} bytes)")
        if step < 2:
            await asyncio.sleep(0.85)


async def run_flood(client: httpx.AsyncClient, source_ip: str, rounds: int = 5) -> None:
    print(f"[FLOOD] Launching high-rate HTTP flood from {source_ip} ({rounds * 16} requests) ...")
    t0 = time.perf_counter()
    codes: dict[int, int] = {}
    for _ in range(rounds):
        resps = await asyncio.gather(
            *[
                client.get("/api/target/ping", headers={"X-Demo-Client-IP": source_ip})
                for _ in range(16)
            ],
            return_exceptions=True,
        )
        for r in resps:
            code = getattr(r, "status_code", 0)
            codes[code] = codes.get(code, 0) + 1
    dt = time.perf_counter() - t0
    print(f"  -> Completed in {dt:.2f}s ({rounds * 16 / max(dt, 1e-3):.1f} req/s) | HTTP status counts: {codes}")


async def run_bruteforce(client: httpx.AsyncClient, source_ip: str) -> None:
    print(f"[BRUTEFORCE] Launching automated login credential spray from {source_ip} ...")
    wordlist = [
        "123456", "admin", "password123", "qwerty", "root2026", "welcome",
        "letmein", "test1234", "ubuntu", "pass@123", "changeme", "monkey",
    ]
    codes: dict[int, int] = {}
    for pw in wordlist:
        r = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": pw},
            headers={"X-Demo-Client-IP": source_ip},
        )
        codes[r.status_code] = codes.get(r.status_code, 0) + 1
        await asyncio.sleep(0.035)
    print(f"  -> Tried {len(wordlist)} passwords | HTTP status counts: {codes}")


async def run_bot(client: httpx.AsyncClient, source_ip: str) -> None:
    print(f"[BOT] Starting periodic C2 beacon polling every 190ms from {source_ip} ...")
    codes: dict[int, int] = {}
    for _ in range(9):
        r = await client.get("/api/bot/poll", headers={"X-Demo-Client-IP": source_ip})
        codes[r.status_code] = codes.get(r.status_code, 0) + 1
        await asyncio.sleep(0.19)
    print(f"  -> Sent 9 fixed-interval beacons | HTTP status counts: {codes}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="FlowDetect Cross-Platform Attack Simulator")
    parser.add_argument(
        "--target",
        default=None,
        help="FastAPI backend URL (auto-detects your current Wi-Fi IP if omitted!)",
    )
    parser.add_argument(
        "--mode",
        choices=["benign", "flood", "bruteforce", "bot", "all"],
        default="all",
        help="Traffic scenario to generate",
    )
    args = parser.parse_args()

    target_url = await resolve_working_target(args.target)
    print(f"[*] Connected to FlowDetect API at: {target_url}")

    async with httpx.AsyncClient(base_url=target_url, timeout=15.0) as client:
        if args.mode in ("benign", "all"):
            await run_benign(client, "192.168.29.31")
            await asyncio.sleep(0.5)
        if args.mode in ("flood", "all"):
            await run_flood(client, "192.168.29.210")
            await asyncio.sleep(0.5)
        if args.mode in ("bruteforce", "all"):
            await run_bruteforce(client, "192.168.29.185")
            await asyncio.sleep(0.5)
        if args.mode in ("bot", "all"):
            await run_bot(client, "192.168.29.149")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped by user (Ctrl+C).")
