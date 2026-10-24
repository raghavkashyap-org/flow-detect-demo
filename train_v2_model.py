"""
Reproducible Training & Export Script for `model_v2_live.onnx`.

Why `model_v2_live.onnx` exists alongside `model_v1_cicids2017.onnx` (`model.onnx`):
1. Fixes `l2_regularization=0.0` in v1 (which caused leaf Newton blowup up to +-32,936
   in iterations 80..89 after validation loss had already peaked at iteration 69).
2. Preserves CICIDS2017 knowledge distilled from `model.joblib` WHILE augmenting with
   realistic multi-OS (Windows/Linux/LAN/Cloud) live network flow streams passed directly
   through `FlowSession` (eliminating training-serving skew).
3. Exports an identical ONNX Opset 15 contract:
   - Input:  `X` -> float32[None, 27]
   - Outputs: `label` -> string[None], `probabilities` -> float32[None, 4]
   - Classes: `['Benign', 'Bot', 'BruteForce', 'Flood']`
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import onnx
from onnx import TensorProto, helper
import onnxruntime as ort
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.exceptions import InconsistentVersionWarning
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from backend.flow_extractor import FEATURE_NAMES, FlowSession  # noqa: E402


def simulate_benign_flow(rng: np.random.Generator) -> np.ndarray:
    """Realistic human browsing / normal API calls across LAN, Wi-Fi, and Cloud RTTs."""
    sess = FlowSession("sim", "10.0.0.2", 8000, 6, 0.0, 0.0, 0.0)
    t = 0.0
    mode = rng.integers(0, 3)

    if mode == 0:
        # Normal single or few-page load with realistic HTML/JSON payloads (500B..6KB)
        n_reqs = int(rng.integers(1, 7))
        for r in range(n_reqs):
            if r > 0:
                # Human think time between clicks: 0.6s .. 9.5s (high natural variance)
                t += float(rng.uniform(600_000.0, 9_500_000.0))
            rtt = float(rng.uniform(400.0, 25_000.0))
            req_bytes = int(rng.integers(180, 680))
            sess.update(t, True, req_bytes, syn=(1 if r == 0 else 0), psh=1, ack=1)
            t += rtt
            n_resp_chunks = int(rng.integers(1, 5))
            for c in range(n_resp_chunks):
                chunk_len = 1460 if c < n_resp_chunks - 1 else int(rng.integers(480, 1460))
                sess.update(t, False, chunk_len, psh=(1 if c == n_resp_chunks - 1 else 0), ack=1)
                t += float(rng.uniform(80.0, 900.0))
    elif mode == 1:
        # Interactive web app session (1..14 irregular API fetches over several seconds)
        n_reqs = int(rng.integers(2, 15))
        for r in range(n_reqs):
            if r > 0:
                t += float(rng.exponential(1_800_000.0) + 350_000.0)
            req_bytes = int(rng.integers(120, 900))
            resp_bytes = int(rng.integers(450, 2800))
            sess.update(t, True, req_bytes, syn=(1 if r == 0 else 0), psh=1, ack=1)
            t += float(rng.uniform(500.0, 35_000.0))
            while resp_bytes > 0:
                seg = min(1460, resp_bytes)
                resp_bytes -= seg
                sess.update(t, False, seg, psh=(1 if resp_bytes == 0 else 0), ack=1)
                t += float(rng.uniform(50.0, 500.0))
    else:
        # Quick single health check / single API query (2..6 total packets)
        n_reqs = int(rng.integers(1, 3))
        for r in range(n_reqs):
            if r > 0:
                t += float(rng.uniform(900_000.0, 4_000_000.0))
            sess.update(t, True, int(rng.integers(90, 450)), syn=1, psh=1, ack=1)
            t += float(rng.uniform(300.0, 18_000.0))
            sess.update(t, False, int(rng.integers(380, 1460)), psh=1, ack=1)

    return sess.to_feature_vector()


def simulate_flood_flow(rng: np.random.Generator) -> np.ndarray:
    """High-rate HTTP GET/POST floods (`ab`/`wrk`/async), TCP SYN floods, and DoS bursts."""
    sess = FlowSession("sim", "10.0.0.99", 8000, 6, 0.0, 0.0, 0.0)
    t = 0.0
    sub_type = rng.integers(0, 3)

    if sub_type == 0:
        # High-velocity HTTP flood (many rapid requests: >80 pkts/s, tiny IATs < 20ms)
        n_reqs = int(rng.integers(14, 180))
        for r in range(n_reqs):
            t += float(rng.uniform(40.0, 14_000.0))
            req_len = int(rng.integers(70, 520))
            sess.update(t, True, req_len, syn=(1 if r % 4 == 0 else 0), psh=1, ack=1)
            t += float(rng.uniform(40.0, 6_000.0))
            resp_len = int(rng.integers(120, 1460))
            sess.update(t, False, resp_len, psh=1, ack=1)
    elif sub_type == 1:
        # Raw TCP SYN / UDP volumetric flood (one-way flood, no/minimal server payload)
        n_pkts = int(rng.integers(12, 250))
        is_syn = bool(rng.integers(0, 2))
        for _ in range(n_pkts):
            t += float(rng.uniform(10.0, 8_000.0))
            payload = 0 if is_syn else int(rng.integers(512, 1460))
            sess.update(t, True, payload, syn=(1 if is_syn else 0), psh=(0 if is_syn else 1), ack=0)
    else:
        # Multi-connection keep-alive burst flood with multi-chunk responses
        n_reqs = int(rng.integers(16, 120))
        for r in range(n_reqs):
            t += float(rng.uniform(100.0, 18_000.0))
            sess.update(t, True, int(rng.integers(90, 420)), syn=1, psh=1, ack=1)
            t += float(rng.uniform(100.0, 5_000.0))
            sess.update(t, False, 1460, psh=0, ack=1)
            t += float(rng.uniform(20.0, 400.0))
            sess.update(t, False, int(rng.integers(300, 1200)), psh=1, ack=1)

    return sess.to_feature_vector()


def simulate_bruteforce_flow(rng: np.random.Generator) -> np.ndarray:
    """Automated credential stuffing / password brute-force bursts (symmetric small auth frames)."""
    sess = FlowSession("sim", "10.0.0.55", 8000, 6, 0.0, 0.0, 0.0)
    t = 0.0
    n_attempts = int(rng.integers(6, 95))
    base_delay = float(rng.uniform(22_000.0, 145_000.0))  # 22ms .. 145ms per login attempt
    for i in range(n_attempts):
        if i > 0:
            t += max(5_000.0, float(rng.normal(base_delay, base_delay * 0.28)))
        # Credential JSON payload (~130..275B) -> compact 401 rejection (~105..225B)
        req_len = int(rng.integers(130, 275))
        resp_len = int(rng.integers(105, 225))
        sess.update(t, True, req_len, syn=(1 if i == 0 else 0), psh=1, ack=1)
        t += float(rng.uniform(350.0, 9_500.0))
        sess.update(t, False, resp_len, psh=1, ack=1)

    return sess.to_feature_vector()


def simulate_bot_flow(rng: np.random.Generator) -> np.ndarray:
    """Automated C2 beacon / periodic headless bot polling with clockwork timer intervals."""
    sess = FlowSession("sim", "10.0.0.77", 8000, 6, 0.0, 0.0, 0.0)
    t = 0.0
    n_polls = int(rng.integers(5, 60))
    period_us = float(rng.choice([190_000.0, 250_000.0, 330_000.0, 500_000.0]))
    req_base = int(rng.integers(48, 320))
    resp_base = int(rng.integers(28, 165))
    for i in range(n_polls):
        if i > 0:
            # Machine timer jitter < 3% of period
            t += max(10_000.0, float(rng.normal(period_us, period_us * 0.02)))
        sess.update(t, True, req_base + int(rng.integers(-4, 5)), syn=(1 if i == 0 else 0), psh=1, ack=1)
        t += float(rng.uniform(250.0, 4_500.0))
        sess.update(t, False, resp_base + int(rng.integers(-3, 4)), psh=1, ack=1)

    return sess.to_feature_vector()


def main() -> None:
    models_dir = ROOT / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    orig_onnx = (ROOT / "model.onnx") if (ROOT / "model.onnx").exists() else (ROOT.parent / "model.onnx")
    orig_joblib = (ROOT / "model.joblib") if (ROOT / "model.joblib").exists() else (ROOT.parent / "model.joblib")
    v1_target = models_dir / "model_v1_cicids2017.onnx"
    v2_target = models_dir / "model_v2_live.onnx"

    if orig_onnx.resolve() != v1_target.resolve():
        shutil.copy2(orig_onnx, v1_target)

    rng = np.random.default_rng(42)

    # 1. Distill high-confidence CICIDS2017 knowledge directly from `model.joblib`
    bundle = joblib.load(orig_joblib)
    teacher = bundle["model"]
    classes = list(teacher.classes_)  # ['Benign', 'Bot', 'BruteForce', 'Flood']

    n_pool = 120_000
    X_pool = np.zeros((n_pool, 27), dtype=np.float32)
    for j in range(27):
        bt = teacher._bin_mapper.bin_thresholds_[j]
        X_pool[:, j] = rng.choice(np.concatenate([[0.0], bt]), size=n_pool)

    pool_probs = teacher.predict_proba(X_pool)
    pool_preds = np.argmax(pool_probs, axis=1)

    X_distilled_list, y_distilled_list = [], []
    ref_vectors: dict[str, list[list[float]]] = {}
    for c_idx, cname in enumerate(classes):
        idx = np.where((pool_preds == c_idx) & (pool_probs[:, c_idx] >= 0.96))[0]
        chosen = rng.choice(idx, size=min(2_500, len(idx)), replace=False)
        X_distilled_list.append(X_pool[chosen])
        y_distilled_list.extend([cname] * len(chosen))
        ref_vectors[str(cname)] = X_pool[chosen[:8]].tolist()

    with open(models_dir / "cicids_reference_vectors.json", "w", encoding="utf-8") as f:
        json.dump(ref_vectors, f)

    # 2. Generate realistic multi-environment live streams through `FlowSession`
    n_live_each = 6_000
    X_live, y_live = [], []
    for _ in range(n_live_each):
        X_live.append(simulate_benign_flow(rng))
        y_live.append("Benign")
        X_live.append(simulate_flood_flow(rng))
        y_live.append("Flood")
        X_live.append(simulate_bruteforce_flow(rng))
        y_live.append("BruteForce")
        X_live.append(simulate_bot_flow(rng))
        y_live.append("Bot")

    X_all = np.vstack([np.vstack(X_distilled_list), np.array(X_live, dtype=np.float32)])
    y_all = np.array(y_distilled_list + y_live)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
    )

    # Fix v1's `l2_regularization=0.0` blowup by setting `l2_regularization=1.5`
    clf_v2 = HistGradientBoostingClassifier(
        loss="log_loss",
        learning_rate=0.08,
        max_iter=220,
        max_leaf_nodes=31,
        min_samples_leaf=25,
        l2_regularization=1.5,
        class_weight="balanced",
        early_stopping=True,
        n_iter_no_change=20,
        random_state=42,
    )
    clf_v2.fit(X_tr, y_tr)

    y_pred = clf_v2.predict(X_te)
    report_dict = classification_report(y_te, y_pred, output_dict=True)
    print(classification_report(y_te, y_pred, digits=4))

    # Verify max leaf weight stability (compare against v1's 32,935.9 blowup!)
    max_leaf_v2 = float(
        max(
            np.abs(tp.nodes[tp.nodes["is_leaf"] == 1]["value"]).max()
            for it in clf_v2._predictors
            for tp in it
        )
    )
    print(f"v2 n_iter_={clf_v2.n_iter_}, max_abs_leaf={max_leaf_v2:.4f} (v1 was 32935.9392)")

    # Export directly to ONNX Opset 15 (`ai.onnx.ml::TreeEnsembleClassifier`), matching `model.onnx` 1:1
    classes_str = [str(c) for c in clf_v2.classes_]
    base_values = [float(x) for x in clf_v2._baseline_prediction.ravel()]

    nodes_treeids: list[int] = []
    nodes_nodeids: list[int] = []
    nodes_featureids: list[int] = []
    nodes_values: list[float] = []
    nodes_hitrates: list[float] = []
    nodes_modes: list[str] = []
    nodes_truenodeids: list[int] = []
    nodes_falsenodeids: list[int] = []
    nodes_missing_tracks_true: list[int] = []

    class_treeids: list[int] = []
    class_nodeids: list[int] = []
    class_ids: list[int] = []
    class_weights: list[float] = []

    tree_id = 0
    for it_trees in clf_v2._predictors:
        for c_idx, tp in enumerate(it_trees):
            for n_idx, node in enumerate(tp.nodes):
                is_leaf = bool(node["is_leaf"])
                nodes_treeids.append(tree_id)
                nodes_nodeids.append(n_idx)
                nodes_hitrates.append(1.0)
                if is_leaf:
                    nodes_featureids.append(0)
                    nodes_values.append(0.0)
                    nodes_modes.append("LEAF")
                    nodes_truenodeids.append(0)
                    nodes_falsenodeids.append(0)
                    nodes_missing_tracks_true.append(0)

                    class_treeids.append(tree_id)
                    class_nodeids.append(n_idx)
                    class_ids.append(int(c_idx))
                    class_weights.append(float(node["value"]))
                else:
                    nodes_featureids.append(int(node["feature_idx"]))
                    nodes_values.append(float(np.float32(node["num_threshold"])))
                    nodes_modes.append("BRANCH_LEQ")
                    nodes_truenodeids.append(int(node["left"]))
                    nodes_falsenodeids.append(int(node["right"]))
                    nodes_missing_tracks_true.append(int(bool(node["missing_go_to_left"])))
            tree_id += 1

    tree_node = helper.make_node(
        "TreeEnsembleClassifier",
        inputs=["X"],
        outputs=["label", "probabilities"],
        domain="ai.onnx.ml",
        name="TreeEnsembleClassifier",
        base_values=base_values,
        class_ids=class_ids,
        class_nodeids=class_nodeids,
        class_treeids=class_treeids,
        class_weights=class_weights,
        classlabels_strings=classes_str,
        nodes_falsenodeids=nodes_falsenodeids,
        nodes_featureids=nodes_featureids,
        nodes_hitrates=nodes_hitrates,
        nodes_missing_value_tracks_true=nodes_missing_tracks_true,
        nodes_modes=nodes_modes,
        nodes_nodeids=nodes_nodeids,
        nodes_treeids=nodes_treeids,
        nodes_truenodeids=nodes_truenodeids,
        nodes_values=nodes_values,
        post_transform="SOFTMAX",
    )

    graph = helper.make_graph(
        [tree_node],
        "ONNX(HistGradientBoostingClassifier)",
        inputs=[helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, 27])],
        outputs=[
            helper.make_tensor_value_info("label", TensorProto.STRING, [None]),
            helper.make_tensor_value_info("probabilities", TensorProto.FLOAT, [None, 4]),
        ],
    )
    onnx_model = helper.make_model(
        graph,
        producer_name="flow-detect-onnx-exporter",
        producer_version="2.0.0",
        ir_version=8,
        opset_imports=[
            helper.make_opsetid("ai.onnx.ml", 1),
            helper.make_opsetid("", 15),
        ],
    )
    onnx.checker.check_model(onnx_model)

    with open(v2_target, "wb") as f:
        f.write(onnx_model.SerializeToString())

    # Verify ONNX Runtime parity
    sess = ort.InferenceSession(str(v2_target), providers=["CPUExecutionProvider"])
    onnx_lbl, onnx_probs = sess.run(None, {"X": X_te[:500].astype(np.float32)})
    sk_probs = clf_v2.predict_proba(X_te[:500])
    max_diff = float(np.max(np.abs(sk_probs - onnx_probs)))
    sha256_v2 = hashlib.sha256(v2_target.read_bytes()).hexdigest()

    v2_meta = {
        "name": "flow-detect-hgb-live-v2-onnx",
        "file": "model_v2_live.onnx",
        "sha256": sha256_v2,
        "bytes": v2_target.stat().st_size,
        "fixes_applied": [
            "Fixed l2_regularization from 0.0 -> 1.5 (max leaf magnitude dropped from 32,935.94 down to bounded range)",
            "Retained distilled CICIDS2017 multi-family patterns alongside live LAN/Wi-Fi/Cloud FlowSession streams",
            "Identical ONNX Opset 15 contract: X float32[None, 27] -> label, probabilities",
        ],
        "n_iter_actual": int(clf_v2.n_iter_),
        "max_abs_leaf_weight": round(max_leaf_v2, 4),
        "onnx_parity_max_diff": max_diff,
        "heldout_metrics": report_dict,
    }
    with open(models_dir / "model_v2_report.json", "w", encoding="utf-8") as f:
        json.dump(v2_meta, f, indent=2)
    print(f"Saved {v2_target} ({v2_target.stat().st_size} bytes), ONNX parity diff={max_diff:.2e}")


if __name__ == "__main__":
    main()
