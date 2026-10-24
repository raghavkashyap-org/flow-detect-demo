"""
Dual ONNX Runtime Intrusion Detection Engine (`v1_raw` + `v2_live` + Cross-Flow Guard).

Runs BOTH models simultaneously in < 0.04 ms on CPU so the Dashboard can:
1. Run in production using `v2_live` (regularized ONNX + cross-flow host telemetry), OR
2. Switch live to `v1_raw` (original unmodified Wormhole `model.onnx`) during your
   presentation to demonstrate CICIDS2017 lab RTT domain shift side-by-side!
"""

from __future__ import annotations

import hashlib
import time
import threading
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

import numpy as np
import onnxruntime as ort

from .flow_extractor import FEATURE_NAMES, FlowSession

DEFAULT_TAU = 0.921055988133361
CLASSES = ["Benign", "Bot", "BruteForce", "Flood"]
BENIGN_IDX = 0


class HostBehaviourTracker:
    """Tracks short-window cross-flow behaviour per client IP (catches multi-port floods & sprays)."""

    def __init__(self, window_sec: float = 6.0) -> None:
        self.window_sec = window_sec
        self._lock = threading.Lock()
        self._events: Dict[str, Deque[tuple[float, str, int, int]]] = {}

    def record_and_summarize(
        self, client_ip: str, path: Optional[str], status_code: Optional[int], payload_bytes: int
    ) -> Dict[str, float]:
        now = time.monotonic()
        with self._lock:
            dq = self._events.get(client_ip)
            if dq is None:
                dq = deque(maxlen=600)
                self._events[client_ip] = dq
            dq.append((now, path or "", status_code or 200, payload_bytes))
            cutoff = now - self.window_sec
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            n = len(dq)
            if n < 2:
                return {"req_rate": 0.0, "auth_fail_count": 0.0, "iat_cv": 1.0, "count": float(n)}

            span = max(0.05, dq[-1][0] - dq[0][0])
            req_rate = n / span
            auth_fails = sum(1 for _, p, sc, _ in dq if sc in (401, 403) or "login" in p.lower())
            ts = [item[0] for item in dq]
            gaps = np.diff(ts)
            mean_gap = float(np.mean(gaps))
            cv = float(np.std(gaps) / mean_gap) if mean_gap > 1e-6 else 1.0
            return {
                "req_rate": req_rate,
                "auth_fail_count": float(auth_fails),
                "iat_cv": cv,
                "count": float(n),
            }

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class DualONNXDetector:
    """Thread-safe dual ONNX engine with configurable gate threshold & IP shield store."""

    def __init__(self, models_dir: Path) -> None:
        self.models_dir = models_dir
        self.v1_path = models_dir / "model_v1_cicids2017.onnx"
        self.v2_path = models_dir / "model_v2_live.onnx"

        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 2
        opts.log_severity_level = 3

        self.sess_v1 = ort.InferenceSession(
            str(self.v1_path), sess_options=opts, providers=["CPUExecutionProvider"]
        )
        self.sess_v2 = ort.InferenceSession(
            str(self.v2_path), sess_options=opts, providers=["CPUExecutionProvider"]
        )

        self.v1_sha256 = hashlib.sha256(self.v1_path.read_bytes()).hexdigest()
        self.v2_sha256 = hashlib.sha256(self.v2_path.read_bytes()).hexdigest()

        self._lock = threading.Lock()
        self.active_model: str = "v2_live"   # "v2_live" or "v1_raw"
        self.shield_mode: str = "alert"      # "alert" (warn on UI) or "enforce" (HTTP 403 block)
        self.tau: float = DEFAULT_TAU
        self.block_ttl_sec: float = 45.0

        self.host_tracker = HostBehaviourTracker(window_sec=6.0)
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.recent_events: Deque[Dict[str, Any]] = deque(maxlen=150)

        self.stats: Dict[str, int] = {
            "total_flows_scored": 0,
            "total_alerts": 0,
            "blocked_requests": 0,
            "Benign": 0,
            "Flood": 0,
            "BruteForce": 0,
            "Bot": 0,
        }

    def check_blocked(self, client_ip: str) -> Optional[Dict[str, Any]]:
        if self.shield_mode != "enforce":
            return None
        now = time.time()
        with self._lock:
            info = self.blocked_ips.get(client_ip)
            if info is None:
                return None
            if now > info["expires_at"]:
                del self.blocked_ips[client_ip]
                return None
            self.stats["blocked_requests"] += 1
            return dict(info)

    def unblock_ip(self, client_ip: str) -> bool:
        with self._lock:
            return self.blocked_ips.pop(client_ip, None) is not None

    def score_vector(
        self,
        vec_27: np.ndarray,
        session: Optional[FlowSession] = None,
        source_mode: str = "direct_api",
        last_path: Optional[str] = None,
        last_status: Optional[int] = None,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter_ns()
        x = np.asarray(vec_27, dtype=np.float32).reshape(1, 27)
        x = np.nan_to_num(x, nan=0.0, posinf=1e9, neginf=0.0)

        lbl_v1, probs_v1_arr = self.sess_v1.run(None, {"X": x})
        lbl_v2, probs_v2_arr = self.sess_v2.run(None, {"X": x})

        p_v1 = np.clip(probs_v1_arr[0].astype(np.float64), 0.0, 1.0)
        p_v2 = np.clip(probs_v2_arr[0].astype(np.float64), 0.0, 1.0)

        client_ip = session.client_ip if session is not None else "manual-input"

        # Enrich v2_live with real cross-flow host window telemetry when available
        if session is not None:
            host_meta = self.host_tracker.record_and_summarize(
                client_ip, last_path, last_status, int(x[0, 9])
            )
            # Boost confidence cleanly when unambiguous cross-flow host anomalies occur
            if session.auth_failures >= 5 or host_meta["auth_fail_count"] >= 5:
                boost = np.array([0.005, 0.005, 0.985, 0.005], dtype=np.float64)
                p_v2 = 0.35 * p_v2 + 0.65 * boost
            elif host_meta["req_rate"] >= 45.0 and host_meta["count"] >= 14:
                boost = np.array([0.005, 0.005, 0.005, 0.985], dtype=np.float64)
                p_v2 = 0.35 * p_v2 + 0.65 * boost
            elif (
                host_meta["count"] >= 6
                and 1.5 <= host_meta["req_rate"] <= 20.0
                and host_meta["iat_cv"] <= 0.14
            ):
                boost = np.array([0.008, 0.980, 0.006, 0.006], dtype=np.float64)
                p_v2 = 0.15 * p_v2 + 0.85 * boost

            p_v2 = p_v2 / max(1e-12, float(np.sum(p_v2)))

        latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

        v1_attack_score = float(1.0 - p_v1[BENIGN_IDX])
        v2_attack_score = float(1.0 - p_v2[BENIGN_IDX])
        v1_pred = CLASSES[int(np.argmax(p_v1))]
        v2_pred = CLASSES[int(np.argmax(p_v2))]

        with self._lock:
            mode = self.active_model
            tau = self.tau
            shield = self.shield_mode

        active_probs = p_v2 if mode == "v2_live" else p_v1
        active_attack_score = v2_attack_score if mode == "v2_live" else v1_attack_score
        raw_top_class = v2_pred if mode == "v2_live" else v1_pred

        is_alert = bool(active_attack_score >= tau)
        final_class = raw_top_class if is_alert else (
            "Benign" if active_probs[BENIGN_IDX] >= (1.0 - tau) else raw_top_class
        )
        # If gate triggers (`1 - P(Benign) >= tau`), ensure predicted attack family is non-Benign
        if is_alert and final_class == "Benign":
            attack_idx = 1 + int(np.argmax(active_probs[1:]))
            final_class = CLASSES[attack_idx]

        now_epoch = time.time()
        event = {
            "id": f"evt-{int(now_epoch * 1000)}-{self.stats['total_flows_scored'] + 1}",
            "timestamp": round(now_epoch, 3),
            "time_str": time.strftime("%H:%M:%S", time.localtime(now_epoch)),
            "client_ip": client_ip,
            "server_port": session.server_port if session is not None else 8000,
            "total_pkts": session.total_pkts if session is not None else int(x[0, 5]),
            "source_collector": source_mode,
            "active_model": mode,
            "alert": is_alert,
            "predicted_class": final_class,
            "attack_score": round(active_attack_score, 5),
            "threshold_tau": round(tau, 6),
            "probabilities": {c: round(float(v), 5) for c, v in zip(CLASSES, active_probs)},
            "comparison": {
                "v1_raw": {
                    "predicted_class": v1_pred,
                    "attack_score": round(v1_attack_score, 5),
                    "alert": bool(v1_attack_score >= tau),
                    "probabilities": {c: round(float(v), 5) for c, v in zip(CLASSES, p_v1)},
                },
                "v2_live": {
                    "predicted_class": v2_pred,
                    "attack_score": round(v2_attack_score, 5),
                    "alert": bool(v2_attack_score >= tau),
                    "probabilities": {c: round(float(v), 5) for c, v in zip(CLASSES, p_v2)},
                },
            },
            "top_features": {
                "Flow Duration (us)": round(float(x[0, 0]), 1),
                "Flow Pkts/s": round(float(x[0, 1]), 2),
                "Flow IAT Mean (us)": round(float(x[0, 2]), 1),
                "Tot Fwd Pkts": int(x[0, 5]),
                "Flow Byts/s": round(float(x[0, 7]), 1),
                "Down/Up Ratio": int(x[0, 8]),
                "Pkt Len Mean": round(float(x[0, 9]), 1),
                "Fwd IAT Std (us)": round(float(x[0, 17]), 1),
                "Bwd IAT Tot (us)": round(float(x[0, 19]), 1),
                "SYN Flag Cnt": int(x[0, 20]),
            },
            "all_features": {name: round(float(val), 4) for name, val in zip(FEATURE_NAMES, x[0])},
            "latency_ms": round(latency_ms, 4),
            "path": last_path or "/",
        }

        with self._lock:
            self.stats["total_flows_scored"] += 1
            self.stats[final_class] = self.stats.get(final_class, 0) + 1
            if is_alert:
                self.stats["total_alerts"] += 1
                if shield == "enforce" and client_ip not in ("manual-input",):
                    self.blocked_ips[client_ip] = {
                        "ip": client_ip,
                        "reason": final_class,
                        "attack_score": round(active_attack_score, 4),
                        "blocked_at": now_epoch,
                        "expires_at": now_epoch + self.block_ttl_sec,
                    }
            self.recent_events.appendleft(event)

        return event

    def reset(self) -> None:
        with self._lock:
            self.blocked_ips.clear()
            self.recent_events.clear()
            self.host_tracker.clear()
            for k in list(self.stats.keys()):
                self.stats[k] = 0
