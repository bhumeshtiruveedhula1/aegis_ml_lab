"""
aegis_ml_lab/robustness/seed_sweep.py
=======================================
Phase 6.1 — Seed Sweep Robustness Test

Re-trains the IT IsolationForest across N different random seeds (keeping all
other hyperparameters and training data fixed), then evaluates each on the SAME
holdout split (from split_manifest.json, seed_evaluation=1337).

Design contracts (AEGIS_ML_Lab_ULTIMATE.md §6):
- N ≥ 5 seeds required.
- Same split_manifest.json evaluation windows for ALL seeds — no re-splitting.
- Per-seed results reported individually — NOT averaged away.
- If detection_rate range > 10pp across seeds → stability verdict = UNSTABLE.
- If FPR range > 10pp across seeds → flagged separately.
- Variance is flagged loudly — never suppressed.

Usage (via CLI):
    python cli.py evaluate --all-scenarios --seeds 5
"""

from __future__ import annotations

import json
import pickle
import sys
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import structlog

warnings.filterwarnings("ignore")

_LAB_ROOT = Path(__file__).parent.parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logger = structlog.get_logger(__name__)

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"
_RUNS_DIR     = _LAB_ROOT / "runs"

STABILITY_DR_THRESHOLD_PP  = 10.0  # detection rate range (pp) for UNSTABLE verdict
STABILITY_FPR_THRESHOLD_PP = 10.0  # FPR range (pp) for flagged FPR instability


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SeedResult:
    seed: int
    scenario: str
    detection_rate: float
    fpr: float
    auroc: float
    n_attack: int
    n_normal: int
    threshold: float


@dataclass
class SweepSummary:
    run_id: str
    entity_type: str
    n_seeds: int
    seeds: list[int]
    scenarios: list[str]
    per_seed_results: list[SeedResult] = field(default_factory=list)
    # Stability verdict computed after all seeds run
    stability_verdict: str = "PENDING"
    dr_range_pp: float = 0.0
    fpr_range_pp: float = 0.0
    stability_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "entity_type": self.entity_type,
            "n_seeds": self.n_seeds,
            "seeds": self.seeds,
            "scenarios": self.scenarios,
            "stability_verdict": self.stability_verdict,
            "dr_range_pp": self.dr_range_pp,
            "fpr_range_pp": self.fpr_range_pp,
            "stability_notes": self.stability_notes,
            "per_seed_results": [asdict(r) for r in self.per_seed_results],
        }


# ---------------------------------------------------------------------------
# Core sweep runner
# ---------------------------------------------------------------------------

def _train_with_seed(base_pipeline, seed: int):
    """
    Clone a _DetectionPipeline with a new IsolationForest random_state.
    Re-fits the IF on the same training data (stored in the baseline).
    Returns a new pipeline with different seed.
    """
    import copy
    from sklearn.ensemble import IsolationForest

    new_pipeline = copy.deepcopy(base_pipeline)
    # Get the original IF params and swap random_state
    old_if = base_pipeline.isolation_forest
    new_if = IsolationForest(
        n_estimators=old_if.n_estimators,
        max_samples=old_if.max_samples,
        contamination=old_if.contamination,
        max_features=old_if.max_features,
        random_state=seed,
        n_jobs=-1,
    )
    # Re-fit on the same training matrix stored in the pipeline
    new_if.fit(base_pipeline._training_X)
    new_pipeline.isolation_forest = new_if
    return new_pipeline


def _get_training_X(det_pipeline):
    """
    Retrieve or reconstruct the training feature matrix from the pipeline.
    Checks for _training_X attribute (set during train.py fit).
    """
    if hasattr(det_pipeline, "_training_X"):
        return det_pipeline._training_X
    raise AttributeError(
        "_DetectionPipeline does not have _training_X attribute. "
        "Re-train with `python cli.py train --entity-type IT` — "
        "the current model artifact predates Phase 6 training-X persistence."
    )


def run_seed_sweep(
    run_id: str,
    entity_type: str,
    n_seeds: int = 5,
) -> SweepSummary:
    """
    Run the seed sweep: re-train with N seeds, evaluate each on the holdout split.

    Parameters
    ----------
    run_id      : The base run whose training data and split manifest to use.
    entity_type : "IT" (OT not evaluated — known limitation).
    n_seeds     : Number of seeds to sweep (≥5 per spec).
    """
    from backend.baseline.reader_api import BaselineReader
    from backend.baseline.reader import NormalizedEventReader
    from backend.synthetic_attack.service import SyntheticAttackService
    from calibration.splits import load_manifest
    from calibration.fit_isotonic import load_calibrator
    from thresholds.compute_ecdf import load_thresholds
    from evaluate.run_e2e_suite import (
        _IT_SCENARIOS, _ENTITY_DIM, _get_feature_records, _score_records
    )
    from sklearn.metrics import roc_auc_score

    etype = entity_type.upper()
    entity_dim = _ENTITY_DIM.get(etype, "user_host")
    scenarios = _IT_SCENARIOS if etype == "IT" else {}

    seeds = list(range(n_seeds))

    # Load base pipeline from the specific run_id (not sorted-latest, which may be different)
    pkl_path = _REGISTRY_DIR / run_id / etype / "isolation_forest.pkl"
    if not pkl_path.exists():
        raise FileNotFoundError(
            f"No trained model for run_id={run_id!r} entity_type={etype!r} at {pkl_path}. "
            "Run `python cli.py train --entity-type IT` first."
        )

    with pkl_path.open("rb") as f:
        base_pipeline = pickle.load(f)

    # Check training_X availability
    has_training_x = hasattr(base_pipeline, "_training_X")

    manifest    = load_manifest(run_id, etype)
    calibrator  = load_calibrator(run_id, etype)
    thresholds  = load_thresholds(run_id, etype)

    eval_seed   = manifest.seed_evaluation
    baseline_dir = _LAB_ROOT / "models" / "baselines" / etype
    reader = BaselineReader(baseline_dir=baseline_dir)

    # Normal evaluation records (same for all seeds)
    norm_path = (_CYBERSHIELD_ROOT / "data" / "normalized" / "normalized_events.jsonl").resolve()
    all_normal = list(NormalizedEventReader(input_file=norm_path).stream())
    eval_normals = all_normal[200:400] or all_normal[:200]
    normal_records = _get_feature_records(eval_normals, reader, entity_dim)
    cal_normal = calibrator.predict_proba(_score_records(base_pipeline, normal_records))

    summary = SweepSummary(
        run_id=run_id, entity_type=etype,
        n_seeds=n_seeds, seeds=seeds, scenarios=list(scenarios),
    )

    logger.info(
        "seed_sweep_started",
        entity_type=etype, run_id=run_id,
        n_seeds=n_seeds, has_training_x=has_training_x,
    )

    for seed in seeds:
        if has_training_x:
            pipeline = _train_with_seed(base_pipeline, seed)
        else:
            # Can't re-train without training data — use base pipeline with warning
            pipeline = base_pipeline
            logger.warning(
                "seed_sweep_no_training_x",
                seed=seed,
                note="Using base pipeline — results will be identical across seeds. "
                     "Re-train to persist _training_X.",
            )

        for scenario_name, kwargs in scenarios.items():
            svc = SyntheticAttackService(persist=False, seed=eval_seed)
            rpt = svc.generate(scenario_name, **kwargs)
            attack_events = svc.get_canonical_events(rpt)
            attack_records = _get_feature_records(attack_events, reader, entity_dim)

            if not attack_records:
                summary.per_seed_results.append(SeedResult(
                    seed=seed, scenario=scenario_name,
                    detection_rate=0.0, fpr=0.0, auroc=0.0,
                    n_attack=0, n_normal=len(normal_records),
                    threshold=thresholds.type_level_fallback,
                ))
                continue

            raw_atk  = _score_records(pipeline, attack_records)
            cal_atk  = calibrator.predict_proba(raw_atk)
            # Re-score normals with this seed's pipeline
            raw_nml  = _score_records(pipeline, normal_records)
            cal_nml  = calibrator.predict_proba(raw_nml)

            thresh = thresholds.type_level_fallback
            tp = int((cal_atk >= thresh).sum())
            fp = int((cal_nml >= thresh).sum())
            dr = tp / len(attack_records)
            fpr = fp / len(normal_records)

            try:
                labels = np.concatenate([np.zeros(len(normal_records)), np.ones(len(attack_records))])
                scores = np.concatenate([cal_nml, cal_atk])
                auroc = float(roc_auc_score(labels, scores))
            except Exception:
                auroc = 0.0

            summary.per_seed_results.append(SeedResult(
                seed=seed, scenario=scenario_name,
                detection_rate=dr, fpr=fpr, auroc=auroc,
                n_attack=len(attack_records), n_normal=len(normal_records),
                threshold=thresh,
            ))

            logger.info(
                "seed_sweep_scenario_done",
                seed=seed, scenario=scenario_name,
                detection_rate=dr, fpr=fpr, auroc=auroc,
            )

    # ── Compute stability verdict ─────────────────────────────────────────────
    all_dr  = [r.detection_rate for r in summary.per_seed_results]
    all_fpr = [r.fpr for r in summary.per_seed_results]

    dr_range  = (max(all_dr)  - min(all_dr))  * 100 if all_dr  else 0.0
    fpr_range = (max(all_fpr) - min(all_fpr)) * 100 if all_fpr else 0.0
    summary.dr_range_pp  = round(dr_range, 2)
    summary.fpr_range_pp = round(fpr_range, 2)

    notes = []
    unstable = False

    if dr_range > STABILITY_DR_THRESHOLD_PP:
        unstable = True
        notes.append(
            f"UNSTABLE: Detection rate range={dr_range:.1f}pp across {n_seeds} seeds "
            f"(threshold: {STABILITY_DR_THRESHOLD_PP}pp). "
            "Model performance depends strongly on IF random seed."
        )
    if fpr_range > STABILITY_FPR_THRESHOLD_PP:
        notes.append(
            f"FPR UNSTABLE: FPR range={fpr_range:.1f}pp across {n_seeds} seeds "
            f"(threshold: {STABILITY_FPR_THRESHOLD_PP}pp)."
        )

    if not has_training_x:
        notes.append(
            "WARNING: _training_X not persisted in model artifact — all seeds used "
            "the same base pipeline. Sweep results are NOT meaningful for seed variance. "
            "Re-train with updated train.py to persist training data."
        )
        unstable = True

    summary.stability_verdict = "UNSTABLE" if unstable else "STABLE"
    summary.stability_notes = notes

    logger.info(
        "seed_sweep_complete",
        stability_verdict=summary.stability_verdict,
        dr_range_pp=summary.dr_range_pp,
        fpr_range_pp=summary.fpr_range_pp,
    )

    return summary


def save_sweep_results(summary: SweepSummary) -> Path:
    out_dir = _RUNS_DIR / summary.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "seed_sweep_results.json"
    path.write_text(json.dumps(summary.to_dict(), indent=2))
    logger.info("seed_sweep_saved", path=str(path))
    return path


def print_sweep_report(summary: SweepSummary) -> str:
    """Generate and print a markdown section for the sweep results."""
    lines = [
        f"",
        f"## Seed Sweep Results ({summary.n_seeds} seeds)",
        f"",
        f"**Stability verdict:** `{summary.stability_verdict}`  ",
        f"**Detection rate range:** {summary.dr_range_pp:.1f}pp  ",
        f"**FPR range:** {summary.fpr_range_pp:.1f}pp",
        f"",
    ]

    if summary.stability_notes:
        for note in summary.stability_notes:
            lines.append(f"> **{note}**")
        lines.append(f"")

    lines += [
        f"| Seed | Scenario | Det Rate | FPR | AUROC |",
        f"|------|----------|----------|-----|-------|",
    ]
    for r in summary.per_seed_results:
        lines.append(
            f"| {r.seed} | {r.scenario} | {r.detection_rate:.1%} | {r.fpr:.1%} | {r.auroc:.3f} |"
        )

    report = "\n".join(lines)
    print(report)
    return report
