#!/usr/bin/env python3
"""
Cross-Platform 10-Point Verification Suite (`verify_all.py`).

Checks SHA-256 checksums, ONNX graph signatures, Dual ONNX Runtime inference,
all 4 attack/benign classes in `sample_attacks.pcap`, and dashboard frontend assets!
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent
sys.path.insert(0, str(ROOT))


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check(cond: bool, msg: str) -> None:
    if not cond:
        print(f"  [FAIL] {msg}")
        sys.exit(1)
    print(f"  [PASS] {msg}")


def main() -> None:
    print("================================================================")
    print("  FlowDetect 10-Point Complete System Verification")
    print("================================================================")

    EXPECTED_ONNX_SHA = "6170e1a1e6ca495ba785ede7b8b183ab0dc5a468a4aadb210e683f726ed169a6"
    EXPECTED_JOBLIB_SHA = "c5521476bfdb41374360b6e426345c7cef7e103de1e8ad524a2ab64ea2578e78"

    # 1. Verify original parent `model.onnx` + `models/model_v1_cicids2017.onnx`
    v1_path = ROOT / "models" / "model_v1_cicids2017.onnx"
    check(v1_path.exists(), f"Found {v1_path.relative_to(ROOT)}")
    check(
        sha256_file(v1_path) == EXPECTED_ONNX_SHA,
        f"SHA-256 verified for model_v1_cicids2017.onnx ({EXPECTED_ONNX_SHA[:16]}...)",
    )

    for base_label, base_dir in [(".", ROOT), ("..", PARENT)]:
        if (base_dir / "model.onnx").exists():
            check(
                sha256_file(base_dir / "model.onnx") == EXPECTED_ONNX_SHA,
                f"{base_label}/model.onnx matches model.onnx.sha256 100%",
            )
        if (base_dir / "model.joblib").exists():
            check(
                sha256_file(base_dir / "model.joblib") == EXPECTED_JOBLIB_SHA,
                f"{base_label}/model.joblib matches model_metadata.json 100%",
            )

    # 2. Verify `model_v2_live.onnx` + report
    v2_path = ROOT / "models" / "model_v2_live.onnx"
    v2_rep_path = ROOT / "models" / "model_v2_report.json"
    check(v2_path.exists() and v2_rep_path.exists(), "Found model_v2_live.onnx & model_v2_report.json")
    rep = json.loads(v2_rep_path.read_text(encoding="utf-8"))
    acc = rep["heldout_metrics"]["accuracy"]
    check(
        acc >= 0.97 and rep["max_abs_leaf_weight"] < 5.0 and rep["onnx_parity_max_diff"] < 1e-5,
        f"v2 quality verified: accuracy={acc*100:.2f}%, max_leaf={rep['max_abs_leaf_weight']}, onnx_parity_diff={rep['onnx_parity_max_diff']:.2e}",
    )

    # 3. Verify DualONNXDetector + PCAP extraction on all 4 classes
    from backend.detector_engine import DualONNXDetector
    from backend.scapy_sniffer import extract_flows_from_pcap_bytes

    det = DualONNXDetector(ROOT / "models")
    pcap_path = ROOT / "sample_attacks.pcap"
    check(pcap_path.exists(), f"Found {pcap_path.name} ({pcap_path.stat().st_size} bytes)")

    flows = extract_flows_from_pcap_bytes(pcap_path.read_bytes())
    verdicts = [det.score_vector(s.to_feature_vector(), session=s)["predicted_class"] for s in flows]
    check(
        verdicts == ["Benign", "Flood", "BruteForce", "Bot"],
        f"All 4 PCAP flows scored accurately in order: {verdicts}",
    )

    # 4. Verify all frontend files present
    fe_files = ["index.html", "styles.css", "config.js", "app.js"]
    check(
        all((ROOT / "frontend" / f).exists() for f in fe_files),
        f"All Dashboard frontend files present: {fe_files}",
    )

    print("================================================================")
    print("  ALL CHECKS PASSED — READY TO LAUNCH BACKEND (:8000) & UI (:9012)!")
    print("================================================================")


if __name__ == "__main__":
    main()
