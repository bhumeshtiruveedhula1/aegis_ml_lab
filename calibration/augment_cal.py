"""
aegis_ml_lab/calibration/augment_cal.py
=========================================
Calibration augmentation for brute_force_auth seed-instability fix.

Problem: brute_force_auth calibration uses exactly ONE attack instance (seed=42).
The isotonic calibrator therefore sees only one cluster of IF scores from
brute_force_auth. If that cluster sits exactly at the threshold boundary, all
5 seeds of the seed sweep produce DR=0%.

Fix (Rule 9 compliant):
  - Load the existing SplitManifest for the run.
  - Score 2 additional brute_force_auth instances at calibration seeds 100, 200
    (neither touches the evaluation split at seed_b=1337).
  - Append those scored records to manifest.calibration_records ONLY.
  - Overwrite split_manifest.json with the augmented manifest.
  - The augmented manifest is then re-used by run_calibration → compute_ecdf.

Call flow:
    python cli.py calibrate --entity-type IT --augment-brute-force
Or directly:
    from calibration.augment_cal import augment_brute_force_cal
    augmented_manifest = augment_brute_force_cal(run_id, entity_type)

Design guardrails:
  - NEVER adds to evaluation_records.
  - NEVER changes evaluation seed (1337).
  - Only brute_force_auth scenario is augmented (other scenarios are stable).
  - Logs all additional seeds used for full reproducibility.
"""
from __future__ import annotations

import pickle
import sys
from dataclasses import asdict
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_LAB_ROOT = Path(__file__).parent.parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"
_RUNS_DIR = _LAB_ROOT / "runs"

# Additional calibration seeds for brute_force_auth. Must not include 1337 (evaluation seed).
_EXTRA_BFA_SEEDS = [100, 200]
_BFA_SCENARIO = "brute_force_auth"
_BFA_KWARGS = {
    "target_host": "hospital-server-01",
    "attacker_user": "svc-iis",
    "compress_time": True,
}


def augment_brute_force_cal(
    run_id: str,
    entity_type: str = "IT",
) -> "SplitManifest":  # type: ignore[name-defined]
    """
    Augment calibration manifest with additional brute_force_auth instances.

    Parameters
    ----------
    run_id       : Run ID whose manifest to augment.
    entity_type  : IT only (OT not affected, known limitation).

    Returns
    -------
    Augmented SplitManifest with extra brute_force_auth calibration records.
    """
    from calibration.splits import (
        SplitManifest, ScoredRecord, load_manifest, save_manifest,
        _score_events,
    )
    from backend.baseline.reader_api import BaselineReader
    from backend.synthetic_attack.service import SyntheticAttackService

    etype = entity_type.upper()
    if etype != "IT":
        logger.warning(
            "augment_brute_force_cal_skipped",
            reason="Only IT entity type is augmented. OT is a known limitation.",
            entity_type=etype,
        )
        return load_manifest(run_id, etype)

    entity_dim = "user_host"
    manifest = load_manifest(run_id, etype)
    baseline_dir = _LAB_ROOT / "models" / "baselines" / etype
    reader = BaselineReader(baseline_dir=baseline_dir)

    # Load the same model used for the original calibration
    run_dir = _REGISTRY_DIR / run_id
    if not run_dir.exists():
        # Try to find the latest run
        runs = sorted([d for d in _REGISTRY_DIR.iterdir() if d.is_dir()])
        run_dir = max(runs, key=lambda d: d.stat().st_mtime)
    pkl_path = run_dir / etype / "isolation_forest.pkl"
    with pkl_path.open("rb") as f:
        det_pipeline = pickle.load(f)

    eval_seed = manifest.seed_evaluation

    n_added = 0
    for extra_seed in _EXTRA_BFA_SEEDS:
        if extra_seed == eval_seed:
            logger.warning(
                "augment_brute_force_cal_seed_conflict",
                extra_seed=extra_seed,
                eval_seed=eval_seed,
                action="skipping — must not use evaluation seed for calibration",
            )
            continue

        svc = SyntheticAttackService(persist=False, seed=extra_seed)
        report = svc.generate(_BFA_SCENARIO, **_BFA_KWARGS)
        events = svc.get_canonical_events(report)
        scored = _score_events(det_pipeline, events, reader, entity_dim)

        if not scored:
            logger.warning(
                "augment_brute_force_cal_no_records",
                extra_seed=extra_seed,
                scenario=_BFA_SCENARIO,
                action="skipping seed — zero scoreable records produced",
            )
            continue

        for ek, score in scored:
            manifest.calibration_records.append(ScoredRecord(
                scenario=_BFA_SCENARIO,
                label=1,
                raw_score=score,
                entity_key=ek,
                seed=extra_seed,
                split="calibration",
            ))
            n_added += 1

        logger.info(
            "augment_brute_force_cal_seed_added",
            extra_seed=extra_seed,
            scenario=_BFA_SCENARIO,
            n_records=len(scored),
        )

    cal_bfa_count = sum(
        1 for r in manifest.calibration_records
        if r.scenario == _BFA_SCENARIO and r.label == 1
    )
    logger.info(
        "augment_brute_force_cal_complete",
        run_id=run_id,
        entity_type=etype,
        n_added=n_added,
        total_bfa_cal_records=cal_bfa_count,
        eval_split_unchanged=True,
    )

    # Save augmented manifest (overwrites split_manifest.json for this run)
    save_manifest(manifest, run_id)
    print(f"\n[augment-cal] Added {n_added} brute_force_auth calibration records")
    print(f"[augment-cal] Extra seeds used: {_EXTRA_BFA_SEEDS} (eval seed={eval_seed} untouched)")
    print(f"[augment-cal] Total brute_force_auth cal records: {cal_bfa_count}")
    print(f"[augment-cal] Evaluation split: UNCHANGED")
    return manifest
