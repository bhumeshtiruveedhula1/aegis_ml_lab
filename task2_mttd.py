"""
task2_mttd.py — MTTD Measurement (fixed to match proven seed_sweep path)
=========================================================================
All data synthetic. Normal records from NormalizedEventReader (same as seed_sweep).
Calibrator via load_calibrator() → predict_proba() (same as seed_sweep).
Attack events via SyntheticAttackService with seed=1337 (eval_seed, same as seed_sweep).

MTTD = simulated temporal gap: (first_alerting_event.timestamp - first_event.timestamp)
     + wall-clock processing latency (T0_wall to first alert scored above threshold)

Run: python aegis_ml_lab/task2_mttd.py
Output: runs/task2_mttd_results_<ts>.json
"""
from __future__ import annotations
import json
import pickle
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

_LAB_ROOT = Path(__file__).parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import warnings
warnings.filterwarnings("ignore")
import numpy as np
import structlog

logger = structlog.get_logger(__name__)

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"
_RUNS_DIR = _LAB_ROOT / "runs"
_BASELINE_DIR = _LAB_ROOT / "models" / "baselines"

# Same scenarios as run_e2e_suite._IT_SCENARIOS and seed_sweep
from evaluate.run_e2e_suite import _IT_SCENARIOS, _get_feature_records, _score_records, _ENTITY_DIM

EVAL_SEED = 1337   # matches manifest.seed_evaluation
N_TRIALS = 5       # seeds 0..4 (for re-trained IF, same as seed_sweep)


def _load_proven_pipeline(run_id: str):
    """Load base IF pipeline, calibrator, thresholds — exactly as seed_sweep does."""
    from calibration.fit_isotonic import load_calibrator
    from thresholds.compute_ecdf import load_thresholds

    pkl = _REGISTRY_DIR / run_id / "IT" / "isolation_forest.pkl"
    with pkl.open("rb") as f:
        det_pipeline = pickle.load(f)
    calibrator = load_calibrator(run_id, "IT")
    thresholds = load_thresholds(run_id, "IT")
    return det_pipeline, calibrator, thresholds


def _load_normal_records(det_pipeline, reader, entity_dim: str):
    """Load normal records from production JSONL — same as seed_sweep lines 194-197."""
    from backend.baseline.reader import NormalizedEventReader
    norm_path = (_CYBERSHIELD_ROOT / "data" / "normalized" / "normalized_events.jsonl").resolve()
    all_normal = list(NormalizedEventReader(input_file=norm_path).stream())
    eval_normals = all_normal[200:400] or all_normal[:200]
    return _get_feature_records(eval_normals, reader, entity_dim)


def measure_mttd(scenario_name: str, kwargs: dict, det_pipeline, calibrator, threshold: float,
                 reader, entity_dim: str, seed: int) -> dict:
    """
    Measure MTTD for one scenario trial.
    Attack scored with IF trained with random_state=seed (same as seed_sweep._train_with_seed).
    T0_wall = start of event generation.
    T1_wall = wall-clock when first record scores >= threshold.
    MTTD_simulated = first_alerting_event.timestamp - first_event.timestamp (scenario time).
    MTTD_processing_ms = T1_wall - T0_wall (wall-clock).
    """
    from backend.synthetic_attack.service import SyntheticAttackService
    from sklearn.ensemble import IsolationForest
    import copy

    # Re-train IF with this seed (same as seed_sweep._train_with_seed)
    if hasattr(det_pipeline, "_training_X"):
        new_if = IsolationForest(
            n_estimators=det_pipeline.isolation_forest.n_estimators,
            max_samples=det_pipeline.isolation_forest.max_samples,
            contamination=det_pipeline.isolation_forest.contamination,
            max_features=det_pipeline.isolation_forest.max_features,
            random_state=seed,
            n_jobs=-1,
        )
        new_if.fit(det_pipeline._training_X)
        pipeline = copy.deepcopy(det_pipeline)
        pipeline.isolation_forest = new_if
    else:
        pipeline = det_pipeline  # fallback: use base (seed variance won't appear)

    svc = SyntheticAttackService(persist=False, seed=EVAL_SEED)  # same eval seed as sweep

    t0_wall = time.perf_counter()
    report = svc.generate(scenario_name, **kwargs)
    events = svc.get_canonical_events(report)

    if not events:
        return {"scenario": scenario_name, "seed": seed, "detected": False, "n_events": 0}

    event_timestamps = sorted(e.timestamp for e in events)
    t0_simulated = event_timestamps[0]

    # Score events in temporal order (streaming simulation)
    first_alert_wall = None
    first_alert_event_ts = None
    n_alerts = 0

    for ev in sorted(events, key=lambda e: e.timestamp):
        try:
            recs = _get_feature_records([ev], reader, entity_dim)
            if not recs:
                continue
            raw = _score_records(pipeline, recs)
            cal = calibrator.predict_proba(raw)          # ← correct method
            if any(s >= threshold for s in cal):
                n_alerts += 1
                if first_alert_wall is None:
                    first_alert_wall = time.perf_counter()
                    first_alert_event_ts = ev.timestamp
        except Exception as exc:
            logger.debug("score_event_failed", scenario=scenario_name, error=str(exc))

    if first_alert_wall is None:
        return {
            "scenario": scenario_name, "seed": seed, "detected": False,
            "n_events": len(events), "n_alerts": 0,
        }

    mttd_simulated_s = (first_alert_event_ts - t0_simulated).total_seconds()
    mttd_processing_ms = (first_alert_wall - t0_wall) * 1000.0

    return {
        "scenario": scenario_name, "seed": seed,
        "detected": True,
        "n_events": len(events),
        "n_alerts": n_alerts,
        "t0_simulated": t0_simulated.isoformat(),
        "first_alert_event_ts": first_alert_event_ts.isoformat(),
        "mttd_simulated_s": round(mttd_simulated_s, 3),
        "mttd_processing_ms": round(mttd_processing_ms, 3),
    }


if __name__ == "__main__":
    import logging
    logging.disable(logging.WARNING)

    RUN = "run-20260712T160707-a72627"
    det_pipeline, calibrator, thresholds = _load_proven_pipeline(RUN)
    threshold = thresholds.type_level_fallback

    from backend.baseline.reader_api import BaselineReader
    reader = BaselineReader(baseline_dir=_BASELINE_DIR / "IT")
    entity_dim = _ENTITY_DIM["IT"]  # "user_host"

    normal_records = _load_normal_records(det_pipeline, reader, entity_dim)
    print(f"model={RUN}  threshold={threshold:.4f}  normal_records={len(normal_records)}")

    all_results = []
    for scenario_name, kwargs in _IT_SCENARIOS.items():
        for seed in range(N_TRIALS):
            print(f"  {scenario_name}  seed={seed}...", end="", flush=True)
            try:
                r = measure_mttd(scenario_name, kwargs, det_pipeline, calibrator,
                                 threshold, reader, entity_dim, seed)
                all_results.append(r)
                if r["detected"]:
                    print(f" DETECTED  simulated={r['mttd_simulated_s']:.3f}s  proc={r['mttd_processing_ms']:.1f}ms")
                else:
                    print(f" NOT_DETECTED (n_events={r.get('n_events',0)})")
            except Exception as exc:
                import traceback; traceback.print_exc()
                all_results.append({"scenario": scenario_name, "seed": seed, "error": str(exc)})
                print(f" ERROR: {exc}")

    # Aggregate
    detected = [r for r in all_results if r.get("detected")]
    not_detected = [r for r in all_results if not r.get("detected") and "error" not in r]

    print(f"\n=== MTTD RESULTS ===")
    print(f"{'Scenario':<42} {'Det%':>5} {'SimMTTD_s min':>14} {'SimMTTD_s max':>14} {'Proc_ms mean':>13}")
    for sc in _IT_SCENARIOS:
        sc_det = [r for r in detected if r["scenario"] == sc]
        sc_all = [r for r in all_results if r["scenario"] == sc and "error" not in r]
        det_pct = f"{len(sc_det)}/{len(sc_all)}"
        if sc_det:
            sims = [r["mttd_simulated_s"] for r in sc_det]
            procs = [r["mttd_processing_ms"] for r in sc_det]
            print(f"{sc:<42} {det_pct:>5} {min(sims):>14.3f} {max(sims):>14.3f} {np.mean(procs):>13.2f}")
        else:
            print(f"{sc:<42} {det_pct:>5} {'N/A':>14} {'N/A':>14} {'N/A':>13}")

    if detected:
        sims_all = [r["mttd_simulated_s"] for r in detected]
        procs_all = [r["mttd_processing_ms"] for r in detected]
        within_2min = sum(1 for s in sims_all if s <= 120) / len(sims_all) * 100
        print(f"\nOVERALL: {len(detected)}/{len(all_results)} detected")
        print(f"  SimMTTD: min={min(sims_all):.3f}s  median={np.median(sims_all):.3f}s  max={max(sims_all):.3f}s  mean={np.mean(sims_all):.3f}s")
        print(f"  ProcLatency: min={min(procs_all):.2f}ms  median={np.median(procs_all):.2f}ms  max={max(procs_all):.2f}ms")
        print(f"  Within 2-min target: {within_2min:.0f}%")
    else:
        print(f"\nOVERALL: 0/{len(all_results)} detected. Diagnose with seed_sweep to confirm IF is scoring correctly.")

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    out = _RUNS_DIR / f"task2_mttd_results_{ts}.json"
    summary = {
        "run_id": RUN, "threshold": threshold, "eval_seed": EVAL_SEED,
        "n_trials_per_scenario": N_TRIALS,
        "detected_total": len(detected), "total": len(all_results),
        "results": all_results,
    }
    if detected:
        sims_all = [r["mttd_simulated_s"] for r in detected]
        procs_all = [r["mttd_processing_ms"] for r in detected]
        summary["aggregate"] = {
            "mttd_sim_min_s": round(min(sims_all), 3),
            "mttd_sim_median_s": round(float(np.median(sims_all)), 3),
            "mttd_sim_max_s": round(max(sims_all), 3),
            "mttd_sim_mean_s": round(float(np.mean(sims_all)), 3),
            "proc_latency_mean_ms": round(float(np.mean(procs_all)), 2),
            "within_2min_pct": round(within_2min, 1),
        }
    out.write_text(json.dumps(summary, indent=2, default=str))
    print(f"\n[Task 2] Written to {out}")
