#!/usr/bin/env python3
"""
Cross-Platform CLI Live Attack & Traffic Simulator (Works on Windows 10/11, Linux & macOS!).

Handles College Campus LANs (automatic HTTP_PROXY bypass on private subnets),
Home/Hotspot Wi-Fi, Cloud VMs, and HTTPS Tunnels (`localhost.run` / `cloudflared`).

Examples:
  python attack_simulator.py --mode all
  python attack_simulator.py --target http://10.8.0.48:8000 --mode bruteforce
  python attack_simulator.py --target https://<tunnel>.lhr.life --mode all
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import socket
import sys
import time
from urllib.parse import urlparse
import httpx


def detect_local_ip(peer_host: str = "8.8.8.8") -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect((peer_host, 8000))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def is_lan_or_local_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").strip().lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


async def resolve_working_target(requested: str | None) -> tuple[str, bool]:
    """Returns (working_base_url, use_env_proxy)."""
    if requested:
        url = requested.rstrip("/")
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        local_src = detect_local_ip(host)

        # Always try direct connection first (`trust_env=False` bypasses college HTTP_PROXY on LAN!)
        proxy_modes = [False] if is_lan_or_local_url(url) else [False, True]
        last_err: Exception | None = None
        for use_proxy in proxy_modes:
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(4.0, connect=3.0),
                    trust_env=use_proxy,
                ) as probe:
                    r = await probe.get(f"{url}/api/security/status")
                    if r.status_code == 200:
                        return url, use_proxy
            except Exception as exc:
                last_err = exc

        err_name = type(last_err).__name__ if last_err else "ConnectionError"
        print(f"[ERROR] Could not reach target {url} from your interface ({local_src}) [{err_name}].")
        print("        Quick checklist for College LAN / 2-Laptop setup:")
        print(f"        1. Bypass campus HTTP proxy if using older script: env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY")
        print(f"        2. Test L3 reachability: ping -c 2 {host}")
        print(f"        3. On friend's laptop ({host}), open Inbound TCP port {port} in Firewall:")
        print(f"           - Windows (Admin PowerShell): New-NetFirewallRule -DisplayName 'FlowDetect' -Direction Inbound -Protocol TCP -LocalPort 8000,9012,9090 -Action Allow -Profile Any")
        print(f"           - Linux (UFW):                sudo ufw allow {port}/tcp")
        print(f"        4. If `ping {host}` ALSO times out (College AP/Switch Client Isolation or OpenVPN without client-to-client):")
        print(f"           Connect both laptops to a Mobile Hotspot OR run on {host}: ssh -R 80:127.0.0.1:9012 nokey@localhost.run")
        sys.exit(1)

    local_ip = detect_local_ip()
    for url in (f"http://{local_ip}:8000", "http://127.0.0.1:8000"):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(2.5, connect=2.0),
                trust_env=False,
            ) as probe:
                r = await probe.get(f"{url}/api/security/status")
                if r.status_code == 200:
                    return url, False
        except Exception:
            pass

    print(
        f"[ERROR] No local FlowDetect API found on http://{local_ip}:8000 or http://127.0.0.1:8000.\n"
        f"        Start backend with: python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000"
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
        help="FastAPI backend URL (e.g. http://10.8.0.48:8000 or https://<tunnel>.lhr.life)",
    )
    parser.add_argument(
        "--mode",
        choices=["benign", "flood", "bruteforce", "bot", "all"],
        default="all",
        help="Traffic scenario to generate",
    )
    args = parser.parse_args()

    target_url, use_proxy = await resolve_working_target(args.target)
    print(f"[*] Connected to FlowDetect API at: {target_url} (proxy={'on' if use_proxy else 'bypassed-direct'})")

    async with httpx.AsyncClient(base_url=target_url, timeout=15.0, trust_env=use_proxy) as client:
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
