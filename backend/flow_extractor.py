"""
Real-time 27-Feature CICFlowMeter-Compatible Stateful Flow Extractor.

Designed for cross-platform deployment (Linux + Windows + Cloud VM):
- Exact unit match with `model.onnx` / `model_metadata.json`:
  * All durations & inter-arrival times (IAT): MICROSECONDS (1s = 1,000,000 us)
  * Rates (`Flow Pkts/s`, `Flow Byts/s`): per SECOND
  * Packet lengths: Layer-4 TCP/UDP payload bytes (0 .. 1460 MSS)
  * `Down/Up Ratio`: integer ratio `int(bwd_pkts // max(fwd_pkts, 1))`
  * Idle / Active split threshold: 5,000,000 us (5.0 seconds)
- O(1) memory per flow using Welford online running mean & variance.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

FEATURE_NAMES: List[str] = [
    "Flow Duration",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Max",
    "Flow IAT Std",
    "Tot Fwd Pkts",
    "TotLen Fwd Pkts",
    "Flow Byts/s",
    "Down/Up Ratio",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Max",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Mean",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Mean",
    "Fwd Act Data Pkts",
    "Fwd IAT Std",
    "Bwd IAT Mean",
    "Bwd IAT Tot",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "Fwd PSH Flags",
    "Idle Mean",
    "Active Mean",
]

IDLE_THRESHOLD_US = 5_000_000.0     # 5.0 seconds in CICFlowMeter
ACTIVE_TIMEOUT_US = 120_000_000.0   # 120.0 seconds max flow lifetime
FLOW_EXPIRY_US = 15_000_000.0       # Rotate inactive live session stream after 15s


@dataclass
class RunningStats:
    """Exact Welford running count, sum, min, max, mean, and sample std."""

    n: int = 0
    total: float = 0.0
    mean: float = 0.0
    m2: float = 0.0
    min_val: float = float("inf")
    max_val: float = 0.0

    def push(self, x: float) -> None:
        self.n += 1
        self.total += x
        if x < self.min_val:
            self.min_val = x
        if x > self.max_val:
            self.max_val = x
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(max(0.0, self.m2 / (self.n - 1)))

    @property
    def safe_max(self) -> float:
        return self.max_val if self.n > 0 else 0.0


@dataclass
class FlowSession:
    """Stateful packet accumulator for a bidirectional network flow."""

    flow_id: str
    client_ip: str
    server_port: int
    protocol: int
    start_ts_us: float
    last_ts_us: float
    active_start_ts_us: float

    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_act_data_pkts: int = 0

    last_fwd_ts_us: Optional[float] = None
    first_bwd_ts_us: Optional[float] = None
    last_bwd_ts_us: Optional[float] = None

    syn_cnt: int = 0
    rst_cnt: int = 0
    psh_cnt: int = 0
    ack_cnt: int = 0
    fwd_psh_flag: int = 0

    pkt_len_stats: RunningStats = field(default_factory=RunningStats)
    fwd_len_stats: RunningStats = field(default_factory=RunningStats)
    bwd_len_stats: RunningStats = field(default_factory=RunningStats)

    flow_iat_stats: RunningStats = field(default_factory=RunningStats)
    fwd_iat_stats: RunningStats = field(default_factory=RunningStats)
    bwd_iat_stats: RunningStats = field(default_factory=RunningStats)

    idle_stats: RunningStats = field(default_factory=RunningStats)
    active_stats: RunningStats = field(default_factory=RunningStats)

    # Extra live behavioural telemetry (used alongside model.onnx)
    auth_attempts: int = 0
    auth_failures: int = 0
    distinct_paths: set = field(default_factory=set)
    last_scored_pkts: int = 0
    last_scored_ts_us: float = 0.0

    @property
    def total_pkts(self) -> int:
        return self.fwd_pkts + self.bwd_pkts

    def update(
        self,
        ts_us: float,
        is_forward: bool,
        payload_bytes: int,
        syn: int = 0,
        rst: int = 0,
        psh: int = 0,
        ack: int = 0,
        path: Optional[str] = None,
        status_code: Optional[int] = None,
    ) -> None:
        # Ensure non-decreasing timestamps within a flow
        if ts_us < self.last_ts_us:
            ts_us = self.last_ts_us

        payload = float(max(0, payload_bytes))
        if self.total_pkts > 0:
            gap = ts_us - self.last_ts_us
            self.flow_iat_stats.push(gap)
            if gap > IDLE_THRESHOLD_US:
                self.idle_stats.push(gap)
                self.active_stats.push(self.last_ts_us - self.active_start_ts_us)
                self.active_start_ts_us = ts_us

        self.last_ts_us = ts_us
        self.pkt_len_stats.push(payload)

        if is_forward:
            if self.last_fwd_ts_us is not None:
                self.fwd_iat_stats.push(ts_us - self.last_fwd_ts_us)
            self.last_fwd_ts_us = ts_us
            self.fwd_pkts += 1
            self.fwd_len_stats.push(payload)
            if payload >= 1.0:
                self.fwd_act_data_pkts += 1
            if psh:
                self.fwd_psh_flag = 1
        else:
            if self.first_bwd_ts_us is None:
                self.first_bwd_ts_us = ts_us
            if self.last_bwd_ts_us is not None:
                self.bwd_iat_stats.push(ts_us - self.last_bwd_ts_us)
            self.last_bwd_ts_us = ts_us
            self.bwd_pkts += 1
            self.bwd_len_stats.push(payload)

        self.syn_cnt += 1 if syn else 0
        self.rst_cnt += 1 if rst else 0
        self.psh_cnt += 1 if psh else 0
        self.ack_cnt += 1 if ack else 0

        if path:
            if len(self.distinct_paths) < 64:
                self.distinct_paths.add(path)
            if "login" in path.lower() or "auth" in path.lower():
                self.auth_attempts += 1
        if status_code in (401, 403):
            self.auth_failures += 1

    def to_feature_vector(self) -> np.ndarray:
        """Return exact float32[27] vector matching `model_metadata.json` contract."""
        dur_us = max(0.0, self.last_ts_us - self.start_ts_us)
        dur_sec = dur_us / 1_000_000.0
        total_pkts = float(self.total_pkts)
        total_bytes = self.pkt_len_stats.total

        pkts_per_s = (total_pkts / dur_sec) if dur_sec > 0.0 else 0.0
        byts_per_s = (total_bytes / dur_sec) if dur_sec > 0.0 else 0.0
        down_up = float(int(self.bwd_pkts // max(self.fwd_pkts, 1)))
        bwd_iat_tot = (
            max(0.0, self.last_bwd_ts_us - self.first_bwd_ts_us)
            if (self.first_bwd_ts_us is not None and self.last_bwd_ts_us is not None)
            else 0.0
        )

        vec = np.array(
            [
                dur_us,                              # 0  Flow Duration
                pkts_per_s,                          # 1  Flow Pkts/s
                self.flow_iat_stats.mean,            # 2  Flow IAT Mean
                self.flow_iat_stats.safe_max,        # 3  Flow IAT Max
                self.flow_iat_stats.std,             # 4  Flow IAT Std
                float(self.fwd_pkts),                # 5  Tot Fwd Pkts
                self.fwd_len_stats.total,            # 6  TotLen Fwd Pkts
                byts_per_s,                          # 7  Flow Byts/s
                down_up,                             # 8  Down/Up Ratio
                self.pkt_len_stats.mean,             # 9  Pkt Len Mean
                self.pkt_len_stats.std,              # 10 Pkt Len Std
                self.pkt_len_stats.safe_max,         # 11 Pkt Len Max
                self.fwd_len_stats.safe_max,         # 12 Fwd Pkt Len Max
                self.fwd_len_stats.mean,             # 13 Fwd Pkt Len Mean
                self.bwd_len_stats.safe_max,         # 14 Bwd Pkt Len Max
                self.bwd_len_stats.mean,             # 15 Bwd Pkt Len Mean
                float(self.fwd_act_data_pkts),       # 16 Fwd Act Data Pkts
                self.fwd_iat_stats.std,              # 17 Fwd IAT Std
                self.bwd_iat_stats.mean,             # 18 Bwd IAT Mean
                bwd_iat_tot,                         # 19 Bwd IAT Tot
                float(self.syn_cnt),                 # 20 SYN Flag Cnt
                float(self.rst_cnt),                 # 21 RST Flag Cnt
                float(self.psh_cnt),                 # 22 PSH Flag Cnt
                float(self.ack_cnt),                 # 23 ACK Flag Cnt
                float(self.fwd_psh_flag),            # 24 Fwd PSH Flags
                self.idle_stats.mean,                # 25 Idle Mean
                self.active_stats.mean,              # 26 Active Mean
            ],
            dtype=np.float32,
        )
        return np.nan_to_num(vec, nan=0.0, posinf=1e9, neginf=0.0)

    def to_feature_dict(self) -> Dict[str, float]:
        vec = self.to_feature_vector()
        return {name: round(float(val), 4) for name, val in zip(FEATURE_NAMES, vec)}


class LiveFlowTable:
    """Thread-safe active flow table supporting live streaming packet/request events."""

    def __init__(self, max_flows: int = 4096) -> None:
        self._lock = threading.Lock()
        self._flows: Dict[str, FlowSession] = {}
        self.max_flows = max_flows
        self.total_packets_ingested: int = 0

    def ingest_event(
        self,
        client_ip: str,
        server_port: int,
        protocol: int,
        is_forward: bool,
        payload_bytes: int,
        ts_us: Optional[float] = None,
        syn: int = 0,
        rst: int = 0,
        psh: int = 0,
        ack: int = 1,
        stream_key: Optional[str] = None,
        path: Optional[str] = None,
        status_code: Optional[int] = None,
        emit_every_n_pkts: int = 4,
    ) -> Optional[Tuple[FlowSession, np.ndarray]]:
        now_us = float(ts_us if ts_us is not None else (time.perf_counter_ns() // 1000))
        key = stream_key or f"{client_ip}:{server_port}:{protocol}"

        with self._lock:
            self.total_packets_ingested += 1
            session = self._flows.get(key)

            # Rotate stale or max-duration flow cleanly
            if session is not None:
                idle_gap = now_us - session.last_ts_us
                total_age = now_us - session.start_ts_us
                if idle_gap > FLOW_EXPIRY_US or total_age > ACTIVE_TIMEOUT_US:
                    session = None

            if session is None:
                if len(self._flows) >= self.max_flows:
                    # Evict oldest flow
                    oldest_key = min(self._flows, key=lambda k: self._flows[k].last_ts_us)
                    del self._flows[oldest_key]
                session = FlowSession(
                    flow_id=f"{client_ip}-{int(now_us) % 1000000:06d}",
                    client_ip=client_ip,
                    server_port=server_port,
                    protocol=protocol,
                    start_ts_us=now_us,
                    last_ts_us=now_us,
                    active_start_ts_us=now_us,
                )
                self._flows[key] = session

            session.update(
                ts_us=now_us,
                is_forward=is_forward,
                payload_bytes=payload_bytes,
                syn=syn,
                rst=rst,
                psh=psh,
                ack=ack,
                path=path,
                status_code=status_code,
            )

            pkts_since = session.total_pkts - session.last_scored_pkts
            time_since = now_us - session.last_scored_ts_us
            should_score = (
                session.total_pkts >= 2
                and (pkts_since >= emit_every_n_pkts or time_since >= 250_000.0)
            )
            if should_score:
                session.last_scored_pkts = session.total_pkts
                session.last_scored_ts_us = now_us
                return session, session.to_feature_vector()

            return None

    def flush_client(self, client_ip: str) -> None:
        with self._lock:
            for k in [k for k, v in self._flows.items() if v.client_ip == client_ip]:
                del self._flows[k]

    def reset_all(self) -> None:
        with self._lock:
            self._flows.clear()
            self.total_packets_ingested = 0

    def active_count(self) -> int:
        with self._lock:
            return len(self._flows)
