#!/usr/bin/env python3
"""
Generates a real Scapy packet capture file (`sample_attacks.pcap`) containing 4 distinct
bidirectional TCP/IP flows (`Benign`, `Flood`, `BruteForce`, `Bot`) with authentic timestamps,
TCP flags, and Layer-4 payloads so you can test `.pcap` upload anytime (even offline!).
"""

from __future__ import annotations

from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore

OUT_PCAP = Path(__file__).resolve().parent / "sample_attacks.pcap"


def pkt(src_ip: str, sport: int, dst_ip: str, dport: int, flags: str, payload: bytes, ts: float):
    frame = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags)
    )
    if payload:
        frame = frame / Raw(load=payload)
    frame.time = ts
    return frame


def main() -> None:
    packets = []
    server_ip = "192.168.62.52"
    base_ts = 1_760_000_000.0

    # 1. Benign human HTTP session from 192.168.62.21
    t = base_ts
    for r in range(3):
        if r > 0:
            t += 1.25
        packets.append(pkt("192.168.62.21", 51001, server_ip, 8000, "PA", b"GET /products HTTP/1.1\r\n\r\n" * 8, t))
        t += 0.008
        packets.append(pkt(server_ip, 8000, "192.168.62.21", 51001, "PA", b"B" * 1180, t))

    # 2. High-rate TCP SYN Flood stream from 192.168.62.222
    t = base_ts + 10.0
    for i in range(60):
        t += 0.0008
        packets.append(pkt("192.168.62.222", 52002, server_ip, 8000, "S", b"", t))

    # 3. Credential BruteForce stream from 192.168.62.188
    t = base_ts + 20.0
    for i in range(22):
        t += 0.048
        packets.append(pkt("192.168.62.188", 53003, server_ip, 8000, "PA", b"L" * 195, t))
        t += 0.003
        packets.append(pkt(server_ip, 8000, "192.168.62.188", 53003, "PA", b"U" * 145, t))

    # 4. Periodic Bot C2 Beacon stream from 192.168.62.155
    t = base_ts + 30.0
    for i in range(18):
        t += 0.250
        packets.append(pkt("192.168.62.155", 54004, server_ip, 8000, "PA", b"C" * 76, t))
        t += 0.002
        packets.append(pkt(server_ip, 8000, "192.168.62.155", 54004, "PA", b"K" * 68, t))

    wrpcap(str(OUT_PCAP), packets)
    print(f"Created {OUT_PCAP} ({OUT_PCAP.stat().st_size} bytes, {len(packets)} packets across 4 flows)")


if __name__ == "__main__":
    main()
