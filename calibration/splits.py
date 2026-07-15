"""
aegis_ml_lab/calibration/splits.py
====================================
Phase 3.1 — Holdout Split Implementation (Rule 9)

Generates and tracks the mandatory calibration / evaluation split for every
attack scenario used in this lab.

Design contract (Rule 9, AEGIS_ML_Lab_ULTIMATE.md §4):
- Every scenario must have ≥2 independent instances with DISTINCT seeds.
- Instance A (seed[0]) → CALIBRATION split.
- Instance B (seed[1]) → EVALUATION split.
- Instances NEVER share an underlying attack execution.
- Every window's split assignment is written to split_manifest.json so that
  downstream code can verify no cross-contamination.
- Raises loudly if only 1 seed is supplied (would break the no-share contract).

Usage
-----
    from calibration.splits import generate_splits, load_manifest

    manifest = generate_splits(
        run_id="run-20260711T...",
        entity_type="IT",
        seed_a=42,
        seed_b=1337,
    )
    # manifest.calibration_records  → list[ScoredRecord] for fitting isotonic
    # manifest.evaluation_records   → list[ScoredRecord] for evaluation harness
"""

from __future__ import annotations

import json
import pickle
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
import structlog
import yaml

_LAB_ROOT = Path(__file__).parent.parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.baseline.reader_api import BaselineReader
from backend.features.pipeline import FeaturePipeline
from backend.synthetic_attack.service import SyntheticAttackService

logger = structlog.get_logger(__name__)

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"
_BASELINE_DIR = _LAB_ROOT / "models" / "baselines"
_RUNS_DIR = _LAB_ROOT / "runs"

# IT attack scenarios (from _generate_attack_events in train.py)
_IT_SCENARIOS: dict[str, dict] = {
    "brute_force_auth": {
        "target_host": "hospital-server-01",
        "attacker_user": "svc-iis",
        "compress_time": True,
    },
    "command_execution_powershell": {
        "target_host": "hospital-server-01",
        "attacker_user": "attacker",
        "compress_time": True,
    },
    "lateral_movement_smb": {
        "target_host": "hospital-server-02",
        "attacker_user": "attacker",
        "compress_time": True,
    },
}

_OT_SCENARIOS: dict[str, dict] = {
    "ot_register_manipulation": {
        "target_host": "ot-plc-01",
        "attacker_user": "attacker",
        "compress_time": True,
    },
}


@dataclass
class ScoredRecord:
    """One event's raw score plus its label and provenance."""
    scenario: str           # scenario name or "normal"
    label: int              # 0 = normal, 1 = attack
    raw_score: float        # sklearn IF decision_function value (pre-calibration)
    entity_key: str         # e.g. "user_host__svc-iis::hospital-server-01"
    seed: int
    split: str              # "calibration" or "evaluation"


@dataclass
class SplitManifest:
    """All scored records for one run/entity_type, partitioned into splits."""
    run_id: str
    entity_type: str
    seed_calibration: int
    seed_evaluation: int
    calibration_records: list[ScoredRecord] = field(default_factory=list)
    evaluation_records: list[ScoredRecord] = field(default_factory=list)

    # ── Derived convenience views ────────────────────────────────────────────

    def calibration_scores(self) -> np.ndarray:
        return np.array([r.raw_score for r in self.calibration_records])

    def calibration_labels(self) -> np.ndarray:
        return np.array([r.label for r in self.calibration_records])

    def evaluation_scores(self) -> np.ndarray:
        return np.array([r.raw_score for r in self.evaluation_records])

    def evaluation_labels(self) -> np.ndarray:
        return np.array([r.label for r in self.evaluation_records])

    def to_json_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "entity_type": self.entity_type,
            "seed_calibration": self.seed_calibration,
            "seed_evaluation": self.seed_evaluation,
            "calibration_count": len(self.calibration_records),
            "evaluation_count": len(self.evaluation_records),
            "calibration_attack_count": sum(r.label for r in self.calibration_records),
            "evaluation_attack_count": sum(r.label for r in self.evaluation_records),
            "records": [asdict(r) for r in self.calibration_records + self.evaluation_records],
        }


def _load_latest_model(entity_type: str):
    """Load the most recent trained _DetectionPipeline for this entity type."""
    runs = sorted(_REGISTRY_DIR.iterdir())
    candidates = [d for d in runs if (d / entity_type / "isolation_forest.pkl").exists()]
    if not candidates:
        raise FileNotFoundError(
            f"No trained model for entity_type={entity_type} in {_REGISTRY_DIR}. "
            "Run `python cli.py train --entity-type <type>` first."
        )
    model_path = candidates[-1] / entity_type / "isolation_forest.pkl"
    with model_path.open("rb") as f:
        return pickle.load(f), candidates[-1].name


def _score_events(
    det_pipeline,
    events: list,
    reader: BaselineReader,
    entity_dim: str,
) -> list[tuple[str, float]]:
    """
    Feature-extract + score a list of CanonicalEvents.
    Returns [(entity_key_str, raw_decision_function_score), ...].

    Uses primary_only=False so ALL entity dimensions are produced per event,
    then filters explicitly to entity_dim (e.g. 'user_host' for IT).

    CRITICAL: primary_only=True caused lateral_movement_smb (canonical primary=
    'user') and command_execution_powershell (canonical primary='host') to yield
    zero user_host records — making the calibration split brute_force_auth-only.
    primary_only=False + explicit filter is the correct approach here.
    """
    fp = FeaturePipeline(baseline_reader=reader, primary_only=False)
    records, _ = fp.process_batch(events)
    filtered = [r for r in records if r.entity_key.entity_type == entity_dim]
    if not filtered:
        return []
    X_scaled = det_pipeline.preprocessor.transform(filtered)
    scores = det_pipeline.isolation_forest.decision_function(X_scaled)
    return [(str(r.entity_key), float(s)) for r, s in zip(filtered, scores)]


def generate_splits(
    run_id: str,
    entity_type: str,
    seed_a: int = 42,
    seed_b: int = 1337,
    normal_n: int = 200,
    max_attack_per_scenario: int | None = None,
) -> SplitManifest:
    """
    Generate calibration and evaluation splits per Rule 9.

    Parameters
    ----------
    run_id                  : The run_id to associate the manifest with.
    entity_type             : "IT" or "OT"
    seed_a                  : Seed for calibration instance of each attack scenario.
    seed_b                  : Seed for evaluation instance. Must differ from seed_a.
    normal_n                : How many normal events to score for each split (constant across runs).
    max_attack_per_scenario : If set, truncate each scenario's scored attack records to this
                              count BEFORE appending to the calibration split.  Evaluation split
                              is NEVER truncated (ground truth must remain complete).
                              This pins the total calibration attack count to a constant value
                              regardless of which IF model is in the registry, eliminating the
                              run-to-run calibration-size variance that drove the 18pp FPR swing.
                              None (default) = no cap, preserve legacy behaviour.

    Returns
    -------
    SplitManifest: Populated with calibration + evaluation records.
    """
    if seed_a == seed_b:
        raise ValueError(
            f"seed_a ({seed_a}) == seed_b ({seed_b}). Rule 9 requires DISTINCT seeds for "
            "calibration and evaluation instances. Use different seeds."
        )

    etype = entity_type.upper()
    scenarios = _IT_SCENARIOS if etype == "IT" else _OT_SCENARIOS
    entity_dim = "user_host" if etype == "IT" else "ot_node"

    baseline_dir = _BASELINE_DIR / etype
    reader = BaselineReader(baseline_dir=baseline_dir)
    det_pipeline, detected_run_id = _load_latest_model(etype)

    logger.info(
        "split_generation_started",
        entity_type=etype,
        run_id=run_id,
        seed_a=seed_a,
        seed_b=seed_b,
        normal_n=normal_n,
        max_attack_per_scenario=max_attack_per_scenario,
        scenarios=list(scenarios),
    )

    manifest = SplitManifest(
        run_id=run_id,
        entity_type=etype,
        seed_calibration=seed_a,
        seed_evaluation=seed_b,
    )

    # ── Score normal events (split equally between calibration and evaluation) ─
    from backend.baseline.reader import NormalizedEventReader
    norm_path = (_CYBERSHIELD_ROOT / "data" / "normalized" / "normalized_events.jsonl").resolve()
    all_normal = list(NormalizedEventReader(input_file=norm_path).stream())

    # Take first normal_n for calibration, next normal_n for evaluation
    cal_normal = all_normal[:normal_n]
    eval_normal = all_normal[normal_n: normal_n * 2]
    if not cal_normal:
        raise RuntimeError(
            f"No normal events available in {norm_path}. Run generate-baseline first."
        )

    for events_chunk, split_name, seed in [
        (cal_normal, "calibration", seed_a),
        (eval_normal, "evaluation", seed_b),
    ]:
        scored = _score_events(det_pipeline, events_chunk, reader, entity_dim)
        target = manifest.calibration_records if split_name == "calibration" else manifest.evaluation_records
        for ek, score in scored:
            target.append(ScoredRecord(
                scenario="normal", label=0, raw_score=score,
                entity_key=ek, seed=seed, split=split_name,
            ))

    # ── Score attack scenarios (instance A = calibration, instance B = evaluation)
    for scenario_name, kwargs in scenarios.items():
        for split_name, seed in [("calibration", seed_a), ("evaluation", seed_b)]:
            svc = SyntheticAttackService(persist=False, seed=seed)
            report = svc.generate(scenario_name, **kwargs)
            events = svc.get_canonical_events(report)
            scored = _score_events(det_pipeline, events, reader, entity_dim)
            target = manifest.calibration_records if split_name == "calibration" else manifest.evaluation_records

            # Pin calibration attack count: cap per-scenario records to max_attack_per_scenario.
            # Evaluation split is NEVER truncated — full ground truth is required.
            # This prevents calibration split size from floating with model/seed.
            if split_name == "calibration" and max_attack_per_scenario is not None:
                if len(scored) > max_attack_per_scenario:
                    logger.info(
                        "split_attack_truncated",
                        scenario=scenario_name,
                        split=split_name,
                        original_n=len(scored),
                        capped_n=max_attack_per_scenario,
                    )
                    scored = scored[:max_attack_per_scenario]

            for ek, score in scored:
                target.append(ScoredRecord(
                    scenario=scenario_name, label=1, raw_score=score,
                    entity_key=ek, seed=seed, split=split_name,
                ))

        logger.info(
            "split_scenario_scored",
            scenario=scenario_name,
            calibration_n=sum(1 for r in manifest.calibration_records if r.scenario == scenario_name),
            evaluation_n=sum(1 for r in manifest.evaluation_records if r.scenario == scenario_name),
        )

    cal_atk = sum(r.label for r in manifest.calibration_records)
    eval_atk = sum(r.label for r in manifest.evaluation_records)
    logger.info(
        "split_generation_complete",
        calibration_total=len(manifest.calibration_records),
        calibration_attacks=cal_atk,
        calibration_normal=len(manifest.calibration_records) - cal_atk,
        evaluation_total=len(manifest.evaluation_records),
        evaluation_attacks=eval_atk,
        evaluation_normal=len(manifest.evaluation_records) - eval_atk,
    )

    # ── Guard: evaluation must have ≥1 attack record ─────────────────────────
    if eval_atk == 0:
        raise RuntimeError(
            "[SPLIT FAIL] Evaluation split has zero attack records. "
            "Cannot proceed — evaluation harness has no attack ground truth. "
            "Check that SyntheticAttackService generates scoreable records for this entity_dim."
        )

    return manifest


def save_manifest(manifest: SplitManifest, run_id: str) -> Path:
    """Persist split_manifest.json to runs/<run_id>/."""
    out_dir = _RUNS_DIR / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "split_manifest.json"
    out_path.write_text(json.dumps(manifest.to_json_dict(), indent=2))
    logger.info("split_manifest_saved", path=str(out_path))
    return out_path


def load_manifest(run_id: str, entity_type: str) -> SplitManifest:
    """Load a previously saved split_manifest.json."""
    path = _RUNS_DIR / run_id / "split_manifest.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No split_manifest.json found for run_id={run_id!r}. "
            "Run `python cli.py calibrate --entity-type <type>` first."
        )
    data = json.loads(path.read_text())
    # Reconstruct
    records_raw = data.pop("records", [])
    manifest = SplitManifest(
        run_id=data["run_id"],
        entity_type=data["entity_type"],
        seed_calibration=data["seed_calibration"],
        seed_evaluation=data["seed_evaluation"],
    )
    for r in records_raw:
        rec = ScoredRecord(**r)
        if rec.split == "calibration":
            manifest.calibration_records.append(rec)
        else:
            manifest.evaluation_records.append(rec)
    return manifest
