"""
Cross-Platform Scapy Packet Sniffer & Offline PCAP Flow Extractor (Linux + Windows).

- On Linux: uses native AF_PACKET socket when run with `sudo` or `CAP_NET_RAW`.
- On Windows 10/11: uses Npcap (`https://npcap.com`) when run in Administrator terminal.
- If run without root/Admin or without Npcap installed: NEVER crashes! Gracefully reports
  diagnostic status so `AsgiLiveFlowMiddleware` handles live traffic automatically.
- Also provides `extract_flows_from_pcap_bytes()` using Scapy to score uploaded `.pcap` files!
"""

from __future__ import annotations

import io
import os
import platform
import threading
from typing import Any, Callable, Dict, List, Optional

from .flow_extractor import FlowSession, LiveFlowTable


class CrossPlatformScapySniffer:
    """Background raw packet capture worker supporting Linux, macOS, and Windows (Npcap)."""

    def __init__(
        self,
        flow_table: LiveFlowTable,
        on_flow_ready: Callable[[FlowSession, Any, str], None],
        target_port: int = 8000,
        enable_full_http_sniff: bool = False,
    ) -> None:
        self.flow_table = flow_table
        self.on_flow_ready = on_flow_ready
        self.target_port = target_port
        self.enable_full_http_sniff = enable_full_http_sniff

        self.os_name = platform.system()
        self.scapy_available = False
        self.raw_socket_active = False
        self.status_reason = "Not started"
        self.packets_seen = 0
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        try:
            import scapy.all as scapy  # noqa: F401
            self.scapy_available = True
        except Exception as exc:
            self.status_reason = f"Scapy not installed ({exc}) — ASGI Live Collector active"
            return

        # Test whether raw socket / Npcap driver permission is available without crashing
        self._thread = threading.Thread(target=self._run_loop, name="scapy-sniffer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run_loop(self) -> None:
        try:
            from scapy.all import IP, TCP, UDP, sniff  # type: ignore

            # Capture raw TCP SYN/RST bursts (e.g. `hping3 --syn --flood` which never reach HTTP!)
            # plus full TCP/UDP if `enable_full_http_sniff=True`
            bpf = (
                f"tcp port {self.target_port} or udp port {self.target_port}"
                if self.enable_full_http_sniff
                else f"tcp port {self.target_port} and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)"
            )

            def _handle_pkt(pkt: Any) -> None:
                if IP not in pkt:
                    return
                ip_layer = pkt[IP]
                ts_us = float(pkt.time) * 1_000_000.0
                self.packets_seen += 1

                if TCP in pkt:
                    tcp = pkt[TCP]
                    sport, dport = int(tcp.sport), int(tcp.dport)
                    is_fwd = dport == self.target_port
                    client_ip = str(ip_layer.src if is_fwd else ip_layer.dst)
                    payload_len = len(bytes(tcp.payload))
                    flags_int = int(tcp.flags)
                    syn = 1 if (flags_int & 0x02) else 0
                    rst = 1 if (flags_int & 0x04) else 0
                    psh = 1 if (flags_int & 0x08) else 0
                    ack = 1 if (flags_int & 0x10) else 0

                    # Skip localhost SYN handshakes that ASGI already tracks unless raw SYN flood burst
                    if not self.enable_full_http_sniff and ack == 1 and rst == 0:
                        return

                    res = self.flow_table.ingest_event(
                        client_ip=client_ip,
                        server_port=self.target_port,
                        protocol=6,
                        is_forward=is_fwd,
                        payload_bytes=payload_len,
                        ts_us=ts_us,
                        syn=syn,
                        rst=rst,
                        psh=psh,
                        ack=ack,
                        stream_key=f"raw:{client_ip}:{self.target_port}:6",
                        emit_every_n_pkts=8,
                    )
                    if res is not None:
                        sess, vec = res
                        self.on_flow_ready(sess, vec, "scapy_raw_nic")

                elif UDP in pkt and self.enable_full_http_sniff:
                    udp = pkt[UDP]
                    is_fwd = int(udp.dport) == self.target_port
                    client_ip = str(ip_layer.src if is_fwd else ip_layer.dst)
                    payload_len = len(bytes(udp.payload))
                    res = self.flow_table.ingest_event(
                        client_ip=client_ip,
                        server_port=self.target_port,
                        protocol=17,
                        is_forward=is_fwd,
                        payload_bytes=payload_len,
                        ts_us=ts_us,
                        ack=0,
                        stream_key=f"raw:{client_ip}:{self.target_port}:17",
                        emit_every_n_pkts=8,
                    )
                    if res is not None:
                        sess, vec = res
                        self.on_flow_ready(sess, vec, "scapy_raw_nic")

            self.raw_socket_active = True
            self.status_reason = (
                f"Active on {self.os_name} (Scapy BPF: `{bpf}`) + ASGI Live Stream Hybrid"
            )
            sniff(
                filter=bpf,
                prn=_handle_pkt,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as exc:
            self.raw_socket_active = False
            hint = (
                "Install Npcap & run PowerShell as Administrator for L3 SYN capture"
                if self.os_name == "Windows"
                else "Run with `sudo` for kernel L3 SYN capture"
            )
            self.status_reason = (
                f"ASGI Live Collector Active (Raw NIC disabled: {type(exc).__name__} — {hint})"
            )


def extract_flows_from_pcap_bytes(pcap_bytes: bytes, max_flows: int = 200) -> List[FlowSession]:
    """Parse an uploaded `.pcap` file using Scapy and return bidirectional 5-tuple `FlowSession`s."""
    from scapy.all import IP, TCP, UDP, PcapReader  # type: ignore

    flows: Dict[tuple, FlowSession] = {}
    with PcapReader(io.BytesIO(pcap_bytes)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip_layer = pkt[IP]
            ts_us = float(pkt.time) * 1_000_000.0
            proto = int(ip_layer.proto)
            sport, dport, payload_len = 0, 0, 0
            syn = rst = psh = ack = 0

            if TCP in pkt:
                tcp = pkt[TCP]
                sport, dport = int(tcp.sport), int(tcp.dport)
                payload_len = len(bytes(tcp.payload))
                f_int = int(tcp.flags)
                syn = 1 if (f_int & 0x02) else 0
                rst = 1 if (f_int & 0x04) else 0
                psh = 1 if (f_int & 0x08) else 0
                ack = 1 if (f_int & 0x10) else 0
            elif UDP in pkt:
                udp = pkt[UDP]
                sport, dport = int(udp.sport), int(udp.dport)
                payload_len = len(bytes(udp.payload))
            else:
                continue

            ep_a = (str(ip_layer.src), sport)
            ep_b = (str(ip_layer.dst), dport)
            # Determine canonical flow direction (first seen initiator = forward)
            fwd_key = (ep_a[0], ep_a[1], ep_b[0], ep_b[1], proto)
            rev_key = (ep_b[0], ep_b[1], ep_a[0], ep_a[1], proto)

            if fwd_key in flows:
                sess = flows[fwd_key]
                is_fwd = True
            elif rev_key in flows:
                sess = flows[rev_key]
                is_fwd = False
            else:
                if len(flows) >= max_flows:
                    continue
                sess = FlowSession(
                    flow_id=f"{ep_a[0]}:{ep_a[1]}->{ep_b[0]}:{ep_b[1]}",
                    client_ip=ep_a[0],
                    server_port=ep_b[1],
                    protocol=proto,
                    start_ts_us=ts_us,
                    last_ts_us=ts_us,
                    active_start_ts_us=ts_us,
                )
                flows[fwd_key] = sess
                is_fwd = True

            sess.update(
                ts_us=ts_us,
                is_forward=is_fwd,
                payload_bytes=payload_len,
                syn=syn,
                rst=rst,
                psh=psh,
                ack=ack,
            )

    return [s for s in flows.values() if s.total_pkts >= 2]
