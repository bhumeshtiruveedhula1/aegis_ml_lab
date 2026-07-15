"""
aegis_ml_lab/robustness/adversarial_drift.py
=============================================
Phase 6.2 — Adversarial Drift Test

Simulates a "low-and-slow" baseline poisoning attack: attack-adjacent behavior
is gradually mixed into normal baseline training data, then the model is
re-trained on the poisoned baseline and re-evaluated.

Design contracts (AEGIS_ML_Lab_ULTIMATE.md §6):
- MUST NOT silently pass. If the model fails to detect drifted attacks, report.md
  MUST explicitly state: "Adversarial drift test: FAILED — ..."
- If SyntheticAttackService does not natively support drift, the limitation is
  DOCUMENTED here as a named deviation — not silently skipped.
- The drift is simulated by injecting a fraction of calibration-split attack
  records into the training data under normal labels (poisoning), then
  re-training and re-evaluating on the holdout.
- Drift fraction is parameterised: start at 10%, 25%, 50%.
- At each fraction: record detection_rate, FPR, and whether the model degraded.

Drift simulation approach (no native SyntheticAttackService drift API):
  SyntheticAttackService has NO native drift/gradual API (confirmed in Phase 6
  dependency check). Simulation is done by:
  1. Generating brute_force_auth calibration-seed (seed=42) attack feature records
  2. Injecting a fraction of those into the training feature matrix as label=0
     (treating them as if they were "normal" baseline events the model has seen)
  3. Re-fitting IsolationForest on the poisoned data
  4. Evaluating on holdout (seed=1337) to see if detection degrades

Usage (via CLI):
    python cli.py evaluate --all-scenarios --adversarial-drift
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

# Drift fractions to test: fraction of attack records injected as "normal"
DRIFT_FRACTIONS = [0.10, 0.25, 0.50]

DRIFT_SIMULATION_NOTE = (
    "SyntheticAttackService has no native gradual-drift API (confirmed in Phase 6 "
    "dependency check). Drift is simulated by injecting attack feature vectors into "
    "the training data under normal labels (baseline poisoning), then re-training."
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DriftFractionResult:
    drift_fraction: float      # fraction of attack records injected as normal
    n_injected: int            # number of attack records injected
    scenario: str
    detection_rate: float
    fpr: float
    auroc: float
    verdict: str               # "DETECTED" or "FAILED"


@dataclass
class DriftTestResult:
    run_id: str
    entity_type: str
    drift_simulation_method: str
    native_drift_api_available: bool = False
    results: list[DriftFractionResult] = field(default_factory=list)
    overall_verdict: str = "PENDING"
    limitation_note: str = ""

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "entity_type": self.entity_type,
            "drift_simulation_method": self.drift_simulation_method,
            "native_drift_api_available": self.native_drift_api_available,
            "overall_verdict": self.overall_verdict,
            "limitation_note": self.limitation_note,
            "results": [asdict(r) for r in self.results],
        }


# ---------------------------------------------------------------------------
# Core drift runner
# ---------------------------------------------------------------------------

def run_adversarial_drift(
    run_id: str,
    entity_type: str,
) -> DriftTestResult:
    """
    Run the adversarial drift test for the given entity type.

    Parameters
    ----------
    run_id      : Base run whose model and split manifest to use.
    entity_type : "IT" (OT not evaluated — known limitation).
    """
    from backend.baseline.reader_api import BaselineReader
    from backend.baseline.reader import NormalizedEventReader
    from backend.synthetic_attack.service import SyntheticAttackService
    from calibration.splits import load_manifest
    from calibration.fit_isotonic import load_calibrator
    from thresholds.compute_ecdf import load_thresholds, compute_thresholds
    from evaluate.run_e2e_suite import (
        _IT_SCENARIOS, _ENTITY_DIM, _get_feature_records, _score_records
    )
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import roc_auc_score

    etype = entity_type.upper()
    entity_dim = _ENTITY_DIM.get(etype, "user_host")

    # Load base pipeline from specific run_id (not auto-latest which may be different)
    base_pkl = _REGISTRY_DIR / run_id / etype / "isolation_forest.pkl"
    if not base_pkl.exists():
        raise FileNotFoundError(
            f"No trained model for run_id={run_id!r} entity_type={etype!r} at {base_pkl}."
        )
    with base_pkl.open("rb") as f:
        base_pipeline = pickle.load(f)

    has_training_x = hasattr(base_pipeline, "_training_X")

    manifest   = load_manifest(run_id, etype)
    calibrator = load_calibrator(run_id, etype)
    thresholds_result = load_thresholds(run_id, etype)

    eval_seed = manifest.seed_evaluation
    cal_seed  = manifest.seed_calibration
    baseline_dir = _LAB_ROOT / "models" / "baselines" / etype
    reader = BaselineReader(baseline_dir=baseline_dir)

    result = DriftTestResult(
        run_id=run_id,
        entity_type=etype,
        drift_simulation_method=(
            "baseline_poisoning: inject calibration-split attack feature vectors as "
            "normal-labeled training samples, re-fit IsolationForest, re-evaluate on "
            "holdout (eval_seed=1337)"
        ),
        native_drift_api_available=False,
        limitation_note=DRIFT_SIMULATION_NOTE,
    )

    # Normal evaluation records
    norm_path = (_CYBERSHIELD_ROOT / "data" / "normalized" / "normalized_events.jsonl").resolve()
    all_normal = list(NormalizedEventReader(input_file=norm_path).stream())
    eval_normals = all_normal[200:400] or all_normal[:200]
    normal_records = _get_feature_records(eval_normals, reader, entity_dim)

    if not has_training_x:
        logger.warning(
            "adversarial_drift_no_training_x",
            note=(
                "_training_X not persisted — cannot re-train for drift test. "
                "Result will be a documented limitation, not a meaningful test."
            ),
        )
        result.overall_verdict = (
            "DEVIATION: _training_X not persisted in model artifact. "
            "Drift re-training not possible without stored training matrix. "
            "Re-train with updated train.py (which persists _training_X) to run this test meaningfully."
        )
        result.limitation_note += (
            " | _training_X missing from artifact — drift test could not re-train. "
            "This is a known gap to fix in train.py."
        )
        return result

    training_X = base_pipeline._training_X.copy()

    # Get calibration-seed attack records to use as drift injection
    svc_cal = SyntheticAttackService(persist=False, seed=cal_seed)
    rpt_cal = svc_cal.generate(
        "brute_force_auth",
        target_host="hospital-server-01",
        attacker_user="svc-iis",
        compress_time=True,
    )
    cal_attack_events = svc_cal.get_canonical_events(rpt_cal)
    cal_attack_records = _get_feature_records(cal_attack_events, reader, entity_dim)
    cal_attack_X = base_pipeline.preprocessor.transform(cal_attack_records)

    # Evaluation holdout attack records (fixed for all drift fractions)
    svc_eval = SyntheticAttackService(persist=False, seed=eval_seed)
    rpt_eval = svc_eval.generate(
        "brute_force_auth",
        target_host="hospital-server-01",
        attacker_user="svc-iis",
        compress_time=True,
    )
    eval_attack_events = svc_eval.get_canonical_events(rpt_eval)
    eval_attack_records = _get_feature_records(eval_attack_events, reader, entity_dim)

    any_failed = False

    for fraction in DRIFT_FRACTIONS:
        n_inject = max(1, int(len(cal_attack_X) * fraction))
        inject_X = cal_attack_X[:n_inject]

        # Poison training set: inject attack vectors as normal-labeled training data
        poisoned_X = np.vstack([training_X, inject_X])

        # Re-train IF on poisoned data
        old_if = base_pipeline.isolation_forest
        new_if = IsolationForest(
            n_estimators=old_if.n_estimators,
            max_samples=old_if.max_samples,
            contamination=old_if.contamination,
            max_features=old_if.max_features,
            random_state=42,
        )
        new_if.fit(poisoned_X)

        # Evaluate on holdout
        raw_atk = new_if.decision_function(
            base_pipeline.preprocessor.transform(eval_attack_records)
        ) if eval_attack_records else np.array([])
        raw_nml = new_if.decision_function(
            base_pipeline.preprocessor.transform(normal_records)
        ) if normal_records else np.array([])

        cal_atk = calibrator.predict_proba(raw_atk) if len(raw_atk) > 0 else np.array([])
        cal_nml = calibrator.predict_proba(raw_nml) if len(raw_nml) > 0 else np.array([])

        thresh = thresholds_result.type_level_fallback
        tp  = int((cal_atk >= thresh).sum()) if len(cal_atk) > 0 else 0
        fp  = int((cal_nml >= thresh).sum()) if len(cal_nml) > 0 else 0
        dr  = tp / len(eval_attack_records) if eval_attack_records else 0.0
        fpr = fp / len(normal_records) if normal_records else 0.0

        try:
            labels = np.concatenate([np.zeros(len(normal_records)), np.ones(len(eval_attack_records))])
            scores = np.concatenate([cal_nml, cal_atk])
            auroc = float(roc_auc_score(labels, scores))
        except Exception:
            auroc = 0.0

        # Verdict: DETECTED if DR >= 0.5, else FAILED
        verdict = "DETECTED" if dr >= 0.5 else "FAILED"
        if verdict == "FAILED":
            any_failed = True

        logger.info(
            "adversarial_drift_fraction_result",
            drift_fraction=fraction,
            n_injected=n_inject,
            detection_rate=dr,
            fpr=fpr,
            auroc=auroc,
            verdict=verdict,
        )

        result.results.append(DriftFractionResult(
            drift_fraction=fraction,
            n_injected=n_inject,
            scenario="brute_force_auth",
            detection_rate=dr,
            fpr=fpr,
            auroc=auroc,
            verdict=verdict,
        ))

    # Overall verdict
    if any_failed:
        failed_fracs = [
            f"{r.drift_fraction:.0%}" for r in result.results if r.verdict == "FAILED"
        ]
        result.overall_verdict = (
            f"FAILED — Model did not detect brute_force_auth after baseline poisoning "
            f"at drift fraction(s): {', '.join(failed_fracs)}. "
            f"This is a known limitation: gradual baseline absorption degrades IF detection."
        )
    else:
        result.overall_verdict = (
            "DETECTED — Model correctly detected brute_force_auth at all drift fractions "
            f"tested ({[f'{f:.0%}' for f in DRIFT_FRACTIONS]}). "
            "Note: this is a synthetic drift simulation, not a real deployment test."
        )

    return result


def save_drift_result(result: DriftTestResult) -> Path:
    out_dir = _RUNS_DIR / result.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "adversarial_drift_result.json"
    path.write_text(json.dumps(result.to_dict(), indent=2))
    logger.info("adversarial_drift_saved", path=str(path))
    return path


def print_drift_report(result: DriftTestResult) -> str:
    """Generate and return a markdown section for the drift test."""
    lines = [
        f"",
        f"## Adversarial Drift Test",
        f"",
        f"**Method:** {result.drift_simulation_method}",
        f"**Native drift API available:** {result.native_drift_api_available}",
        f"",
        f"> **Note:** {result.limitation_note}",
        f"",
        f"**Overall verdict:** `{result.overall_verdict}`",
        f"",
        f"| Drift Fraction | N Injected | Det Rate | FPR | AUROC | Verdict |",
        f"|---------------|------------|----------|-----|-------|---------|",
    ]

    for r in result.results:
        lines.append(
            f"| {r.drift_fraction:.0%} | {r.n_injected} | {r.detection_rate:.1%} | "
            f"{r.fpr:.1%} | {r.auroc:.3f} | {r.verdict} |"
        )

    if not result.results:
        lines.append(f"| — | — | — | — | — | {result.overall_verdict[:40]}... |")

    report = "\n".join(lines)
    print(report)
    return report
