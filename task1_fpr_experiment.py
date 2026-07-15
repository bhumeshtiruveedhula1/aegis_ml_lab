"""
task1_fpr_experiment.py — FPR Corpus-Depth Experiment
======================================================
All data synthetic, generated on demand.

Hypothesis: FPR=36-40% on the existing model is due to thin normal corpus
(40 repeats * 4 templates = ~160 synthetic runs * ~10 events = ~400-1600 records,
only workstation entities, not hospital-server-01). A larger, more diverse corpus
should lower FPR by improving the calibrator's boundary.

Experiment:
  - BASELINE: Existing model run-20260712T160707-a72627 (40 repeats), FPR already measured.
  - RUN_A:   n_repeats=125  (~5× larger corpus, ~2000+ records)
  - RUN_B:   n_repeats=250  (~10× larger corpus, ~4000+ records)

For each run:
  1. Re-use existing baseline (only training data changes — baseline is production digital twin)
  2. Generate new normal training events with _generate_normal_events_it(n_repeats=N)
  3. Run FeaturePipeline → train IF → calibrate → compute threshold → run 5-seed sweep
  4. Report FPR per seed and compare to baseline FPR

NOTE: Does NOT touch cybershield/backend/. No production files modified.
NOTE: Model architecture locked (IF + isotonic calibration). This is a data experiment only.

Run: python aegis_ml_lab/task1_fpr_experiment.py
Output: runs/task1_fpr_experiment_<ts>.json
"""
from __future__ import annotations
import copy
import json
import logging
import pickle
import sys
import warnings
from datetime import UTC, datetime
from pathlib import Path

warnings.filterwarnings("ignore")
logging.disable(logging.WARNING)

_LAB_ROOT = Path(__file__).parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import numpy as np
import structlog

logger = structlog.get_logger(__name__)

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"
_BASELINE_DIR = _LAB_ROOT / "models" / "baselines"
_RUNS_DIR = _LAB_ROOT / "runs"

EVAL_SEED = 1337          # same as proven sweep
N_SWEEP_SEEDS = 5         # seeds 0..4
BASELINE_RUN = "run-20260712T160707-a72627"
BASELINE_FPR = 0.37       # known from prior 5-seed sweep (seeds 0-4 average)

EXPERIMENTS = [
    {"label": "run_a_125repeats", "n_repeats": 125},
    {"label": "run_b_250repeats", "n_repeats": 250},
]


def _generate_expanded_normal_events(n_repeats: int, seed: int) -> list:
    """
    Generate IT normal events with n_repeats — same logic as train._generate_normal_events_it
    but called explicitly with the desired n_repeats.
    """
    from models.train import _generate_normal_events_it
    return _generate_normal_events_it(seed=seed, n_repeats=n_repeats)


def _run_feature_pipeline(events: list, reader) -> list:
    from backend.features.pipeline import FeaturePipeline
    pipeline = FeaturePipeline(baseline_reader=reader, primary_only=False)
    records, report = pipeline.process_batch(events)
    return records


def _train_if_on_records(records: list, seed: int, run_id: str) -> object:
    """Train an IF model on the provided feature records. Returns _DetectionPipeline."""
    from backend.detection.trainer import IsolationForestTrainer
    import yaml
    model_cfg = yaml.safe_load((_LAB_ROOT / "config" / "model_config.yaml").read_text())
    cfg = model_cfg.get("IT", {})
    trainer = IsolationForestTrainer(
        contamination=cfg.get("contamination", 0.1),
        n_estimators=cfg.get("n_estimators", 175),
        random_state=seed,
        max_samples=cfg.get("max_samples", 256),
        max_features=float(cfg.get("max_features", 0.8)),
        entity_dim="user_host",
    )
    det_pipeline, metadata, _ = trainer.train(records)
    # Store training_X for seed sweep re-training
    try:
        X_train = det_pipeline.preprocessor.transform(records)
        det_pipeline._training_X = X_train
    except Exception:
        pass
    return det_pipeline, metadata


def _fit_calibrator(det_pipeline, records: list, run_id: str, label: str):
    """
    Fit IsotonicCalibrator on the training records.
    Returns (calibrator, threshold).
    """
    from calibration.fit_isotonic import IsotonicCalibrator
    from evaluate.run_e2e_suite import _score_records, _IT_SCENARIOS, _get_feature_records
    from backend.synthetic_attack.service import SyntheticAttackService
    from backend.baseline.reader_api import BaselineReader

    entity_dim = "user_host"
    entity_type = "IT"
    reader = BaselineReader(baseline_dir=_BASELINE_DIR / entity_type)

    # Normal scores (training records)
    raw_normal = _score_records(det_pipeline, records)

    # Attack scores — use 3 scenarios with eval seed for calibration
    attack_records = []
    for sc_name, kwargs in list(_IT_SCENARIOS.items())[:3]:
        svc = SyntheticAttackService(persist=False, seed=EVAL_SEED)
        rpt = svc.generate(sc_name, **kwargs)
        evts = svc.get_canonical_events(rpt)
        attack_records.extend(_get_feature_records(evts, reader, entity_dim))

    if not attack_records:
        raise RuntimeError("No attack records for calibration")

    raw_attack = _score_records(det_pipeline, attack_records)

    # Combine: labels 0=normal, 1=attack
    all_raw = np.concatenate([raw_normal, raw_attack])
    all_labels = np.concatenate([
        np.zeros(len(raw_normal)),
        np.ones(len(raw_attack)),
    ])

    # Correct constructor signature: entity_type, run_id
    calibrator = IsotonicCalibrator(entity_type=entity_type, run_id=label)
    calibrator.fit(raw_scores=all_raw, labels=all_labels)

    # Threshold: 95th percentile of calibrated normal scores
    cal_normal = calibrator.predict_proba(raw_normal)
    threshold = float(np.percentile(cal_normal, 95))
    threshold = max(0.01, min(threshold, 0.99))

    # Save to correct path: calibration/calibrators/{label}_IT.pkl (matches load_calibrator convention)
    cal_dir = _LAB_ROOT / "calibration" / "calibrators"
    cal_dir.mkdir(parents=True, exist_ok=True)
    cal_path = cal_dir / f"{label}_IT.pkl"
    with cal_path.open("wb") as f:
        pickle.dump(calibrator, f)

    return calibrator, threshold



def _measure_fpr(det_pipeline, calibrator, threshold: float, reader) -> list[float]:
    """Run 5-seed FPR sweep. Returns list of FPR per seed."""
    from evaluate.run_e2e_suite import _get_feature_records, _score_records, _IT_SCENARIOS
    from backend.baseline.reader import NormalizedEventReader
    from sklearn.ensemble import IsolationForest

    entity_dim = "user_host"
    norm_path = (_CYBERSHIELD_ROOT / "data" / "normalized" / "normalized_events.jsonl").resolve()
    all_normal = list(NormalizedEventReader(input_file=norm_path).stream())
    eval_normals = all_normal[200:400] or all_normal[:200]
    normal_records = _get_feature_records(eval_normals, reader, entity_dim)

    if not normal_records:
        return [None] * N_SWEEP_SEEDS

    fprs = []
    for seed in range(N_SWEEP_SEEDS):
        # Re-train IF with this seed if training_X available
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
            pipeline = det_pipeline

        raw_nml = _score_records(pipeline, normal_records)
        cal_nml = calibrator.predict_proba(raw_nml)
        fp = int((cal_nml >= threshold).sum())
        fpr = fp / len(normal_records)
        fprs.append(fpr)
        print(f"    seed={seed}: FPR={fpr:.1%} ({fp}/{len(normal_records)} fp)")

    return fprs


if __name__ == "__main__":
    from backend.baseline.reader_api import BaselineReader

    reader = BaselineReader(baseline_dir=_BASELINE_DIR / "IT")

    results = {
        "baseline": {
            "run_id": BASELINE_RUN,
            "n_repeats": 40,
            "fpr_per_seed": [0.38, 0.38, 0.38, 0.38, 0.38],  # from prior sweep (placeholder — actual from seed_sweep_results.json)
            "fpr_mean": BASELINE_FPR,
            "note": "prior measured value; actual per-seed in seed_sweep_results.json",
        },
        "experiments": [],
    }

    # Load actual baseline FPR from seed_sweep_results.json if available
    sweep_path = _RUNS_DIR / BASELINE_RUN / "seed_sweep_results.json"
    if sweep_path.exists():
        sweep_data = json.loads(sweep_path.read_text())
        # Get unique FPR per seed (FPR is same across all scenarios per seed)
        seen_seeds = {}
        for r in sweep_data.get("per_seed_results", []):
            s = r.get("seed")
            if s not in seen_seeds:
                seen_seeds[s] = r.get("fpr", 0)

        if seen_seeds:
            baseline_fprs = [seen_seeds[s] for s in sorted(seen_seeds)]
            results["baseline"]["fpr_per_seed"] = baseline_fprs
            results["baseline"]["fpr_mean"] = round(float(np.mean(baseline_fprs)), 4)
            print(f"Baseline ({BASELINE_RUN}): FPR per seed = {[f'{x:.1%}' for x in baseline_fprs]}  mean={np.mean(baseline_fprs):.1%}")

    for exp in EXPERIMENTS:
        label = exp["label"]
        n_repeats = exp["n_repeats"]
        print(f"\n{'='*60}")
        print(f"EXPERIMENT: {label} (n_repeats={n_repeats})")
        print(f"  Step 1: generating {n_repeats*4} synthetic training runs...")
        events = _generate_expanded_normal_events(n_repeats=n_repeats, seed=42)
        print(f"  Events generated: {len(events)}")

        print(f"  Step 2: running FeaturePipeline...")
        records = _run_feature_pipeline(events, reader)
        records_user_host = [r for r in records if r.entity_key.entity_type == "user_host"]
        print(f"  Records: {len(records)} total / {len(records_user_host)} user_host")

        print(f"  Step 3: training IF...")
        det_pipeline, metadata = _train_if_on_records(records_user_host, seed=42, run_id=label)
        print(f"  Trained: {metadata.sample_count} samples, {metadata.feature_dimension} features")

        print(f"  Step 4: fitting calibrator...")
        try:
            calibrator, threshold = _fit_calibrator(det_pipeline, records_user_host, run_id=label, label=label)
            print(f"  Threshold: {threshold:.4f}")
        except Exception as exc:
            print(f"  CALIBRATION FAILED: {exc}")
            results["experiments"].append({"label": label, "n_repeats": n_repeats, "error": str(exc)})
            continue

        print(f"  Step 5: measuring FPR (5-seed sweep)...")
        fprs = _measure_fpr(det_pipeline, calibrator, threshold, reader)
        fprs_valid = [f for f in fprs if f is not None]
        fpr_mean = float(np.mean(fprs_valid)) if fprs_valid else None
        fpr_delta = round(fpr_mean - results["baseline"]["fpr_mean"], 4) if fpr_mean is not None else None

        print(f"\n  RESULT {label}: FPR per seed = {[f'{x:.1%}' for x in fprs_valid]}  mean={fpr_mean:.1%}  delta vs baseline={fpr_delta:+.1%}")

        results["experiments"].append({
            "label": label,
            "n_repeats": n_repeats,
            "n_events": len(events),
            "n_records_total": len(records),
            "n_records_user_host": len(records_user_host),
            "threshold": round(threshold, 4),
            "fpr_per_seed": fprs_valid,
            "fpr_mean": round(fpr_mean, 4) if fpr_mean is not None else None,
            "fpr_delta_vs_baseline": fpr_delta,
        })

    print(f"\n{'='*60}")
    print("FPR EXPERIMENT SUMMARY")
    print(f"{'Label':<30} {'n_repeats':>10} {'n_records':>10} {'FPR_mean':>10} {'Delta':>10}")
    print(f"{'baseline (40 rep)':30} {'40':>10} {'~400':>10} {results['baseline']['fpr_mean']:>10.1%} {'---':>10}")
    for exp in results["experiments"]:
        if "error" not in exp:
            print(f"{exp['label']:<30} {exp['n_repeats']:>10} {exp['n_records_user_host']:>10} "
                  f"{exp['fpr_mean']:>10.1%} {exp['fpr_delta_vs_baseline']:>+10.1%}")

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    out = _RUNS_DIR / f"task1_fpr_experiment_{ts}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n[Task 1] Written to {out}")
