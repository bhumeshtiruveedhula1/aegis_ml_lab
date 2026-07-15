"""
aegis_ml_lab/thresholds/compute_ecdf.py
=========================================
Phase 3.4 — ECDF-Based Per-Entity Threshold Computation

Derives per-entity alert thresholds from calibrated probability scores using
the Empirical CDF (ECDF) method.

Design contracts (AEGIS_ML_Lab_ULTIMATE.md §4, rules 7 and 10):
- For entities with ≥ cold_start_min_events scored events:
    threshold = percentile(entity_calibrated_scores, target_percentile)
    e.g. 95th percentile for IT → top 5% of entity's own calibrated scores
- For entities BELOW cold_start_min_events:
    threshold = type-level fallback (computed from ALL entities' calibrated
    scores for this entity type)
- NEVER hardcodes a raw score.
- NEVER judges silently — logs which entities used per-entity vs fallback.
- Raises if calibrated scores are unavailable for this entity type.

Output
------
thresholds/<run_id>_<entity_type>_thresholds.json  —  maps each entity_id
to its threshold value, plus a type-level fallback, plus metadata.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import structlog
import yaml

_LAB_ROOT = Path(__file__).parent.parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logger = structlog.get_logger(__name__)

_THRESHOLDS_DIR = _LAB_ROOT / "thresholds"
_THRESH_CONFIG_PATH = _LAB_ROOT / "config" / "threshold_config.yaml"


@dataclass
class EntityThreshold:
    entity_key: str
    threshold: float
    method: str        # "per_entity" or "cold_start_fallback"
    n_scored: int      # how many calibrated scores contributed


@dataclass
class ThresholdResult:
    run_id: str
    entity_type: str
    target_percentile: float
    cold_start_min_events: int
    type_level_fallback: float        # threshold for cold-start entities
    entity_thresholds: dict[str, EntityThreshold]  # entity_key → threshold

    # ── Derived ──────────────────────────────────────────────────────────────
    @property
    def per_entity_count(self) -> int:
        return sum(1 for t in self.entity_thresholds.values() if t.method == "per_entity")

    @property
    def cold_start_count(self) -> int:
        return sum(1 for t in self.entity_thresholds.values() if t.method == "cold_start_fallback")

    def get_threshold(self, entity_key: str) -> float:
        """Get threshold for entity_key; returns type-level fallback if unknown."""
        et = self.entity_thresholds.get(entity_key)
        if et is None:
            return self.type_level_fallback
        return et.threshold

    def to_json_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "entity_type": self.entity_type,
            "target_percentile": self.target_percentile,
            "cold_start_min_events": self.cold_start_min_events,
            "type_level_fallback": self.type_level_fallback,
            "per_entity_count": self.per_entity_count,
            "cold_start_count": self.cold_start_count,
            "entity_thresholds": {
                k: {
                    "threshold": v.threshold,
                    "method": v.method,
                    "n_scored": v.n_scored,
                }
                for k, v in self.entity_thresholds.items()
            },
        }


def _load_threshold_config() -> dict:
    return yaml.safe_load(_THRESH_CONFIG_PATH.read_text())


def compute_thresholds(
    calibrated_records: list[tuple[str, float]],  # (entity_key, calibrated_proba)
    run_id: str,
    entity_type: str,
    target_percentile: float | None = None,
    cold_start_min_events: int | None = None,
    normal_only_scores: list[float] | None = None,  # NEW: normal-traffic calibrated probas
) -> ThresholdResult:
    """
    Compute per-entity thresholds from calibrated probability scores.

    Parameters
    ----------
    calibrated_records  : List of (entity_key, calibrated_probability) tuples,
                          from the CALIBRATION split ONLY.
    run_id              : Run identifier for output file naming.
    entity_type         : "IT" or "OT"
    target_percentile   : Override from threshold_config.yaml if not None.
    cold_start_min_events: Override from threshold_config.yaml if not None.
    normal_only_scores  : If provided, the type-level fallback is derived from
                          THESE scores (normal-traffic only) rather than from all
                          calibrated scores. This prevents attack-proba values
                          (which may be near 1.0) from inflating the fallback
                          threshold above any detectable level.

    Returns
    -------
    ThresholdResult with per-entity and fallback thresholds.
    """
    if not calibrated_records:
        raise ValueError(
            f"[THRESHOLD FAIL] No calibrated records supplied for entity_type={entity_type!r}. "
            "Run `calibrate` before `threshold`."
        )

    cfg = _load_threshold_config()
    etype = entity_type.upper()
    pct = target_percentile if target_percentile is not None else cfg[etype]["target_percentile"]
    min_events = cold_start_min_events if cold_start_min_events is not None else cfg["cold_start_min_events"]

    # ── Group calibrated scores by entity ─────────────────────────────────────
    from collections import defaultdict
    entity_scores: dict[str, list[float]] = defaultdict(list)
    for ek, score in calibrated_records:
        entity_scores[ek].append(score)

    # ── Type-level fallback: 95th pct of NORMAL-TRAFFIC scores only ───────────
    # Using all calibrated scores (normal + attack) would let attack probas
    # (which reach 1.0) push the fallback to 1.0, making cold-start attackers
    # undetectable. The fallback governs what we consider "unusual for this
    # entity type's normal traffic" — so it must be derived from normal only.
    if normal_only_scores is not None and len(normal_only_scores) > 0:
        fallback_basis = np.array(normal_only_scores)
    else:
        # Backward-compat: if no normal_only_scores supplied, use all scores
        fallback_basis = np.array([s for scores in entity_scores.values() for s in scores])
    type_fallback = float(np.percentile(fallback_basis, pct))
    all_scores = np.array([s for scores in entity_scores.values() for s in scores])

    logger.info(
        "threshold_type_level_computed",
        entity_type=etype,
        target_percentile=pct,
        type_fallback=type_fallback,
        total_scored_events=len(all_scores),
        n_entities=len(entity_scores),
    )

    # ── Per-entity thresholds ─────────────────────────────────────────────────
    entity_thresholds: dict[str, EntityThreshold] = {}
    cold_start_entities = []
    per_entity_entities = []

    for ek, scores in entity_scores.items():
        n = len(scores)
        if n >= min_events:
            thresh = float(np.percentile(scores, pct))
            method = "per_entity"
            per_entity_entities.append(ek)
        else:
            thresh = type_fallback
            method = "cold_start_fallback"
            cold_start_entities.append(ek)

        entity_thresholds[ek] = EntityThreshold(
            entity_key=ek,
            threshold=thresh,
            method=method,
            n_scored=n,
        )

    if cold_start_entities:
        logger.warning(
            "threshold_cold_start_fallback_applied",
            entity_type=etype,
            cold_start_entities=cold_start_entities,
            n_cold_start=len(cold_start_entities),
            min_events_required=min_events,
            fallback_threshold=type_fallback,
            note=(
                f"These {len(cold_start_entities)} entities had fewer than "
                f"{min_events} calibration events. They will use the type-level "
                f"threshold ({type_fallback:.4f}) instead of a per-entity threshold."
            ),
        )

    if per_entity_entities:
        logger.info(
            "threshold_per_entity_computed",
            entity_type=etype,
            n_per_entity=len(per_entity_entities),
        )

    return ThresholdResult(
        run_id=run_id,
        entity_type=etype,
        target_percentile=pct,
        cold_start_min_events=min_events,
        type_level_fallback=type_fallback,
        entity_thresholds=entity_thresholds,
    )


def save_thresholds(result: ThresholdResult) -> Path:
    """Save thresholds JSON to thresholds/<run_id>_<entity_type>_thresholds.json."""
    _THRESHOLDS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _THRESHOLDS_DIR / f"{result.run_id}_{result.entity_type}_thresholds.json"
    out_path.write_text(json.dumps(result.to_json_dict(), indent=2))
    logger.info("thresholds_saved", path=str(out_path))
    return out_path


def load_thresholds(run_id: str, entity_type: str) -> ThresholdResult:
    """Load a previously saved ThresholdResult."""
    etype = entity_type.upper()
    path = _THRESHOLDS_DIR / f"{run_id}_{etype}_thresholds.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No thresholds file found for run_id={run_id!r} entity_type={etype!r}. "
            "Run `python cli.py threshold --entity-type <type>` first."
        )
    data = json.loads(path.read_text())
    entity_thresholds = {
        ek: EntityThreshold(
            entity_key=ek,
            threshold=v["threshold"],
            method=v["method"],
            n_scored=v["n_scored"],
        )
        for ek, v in data["entity_thresholds"].items()
    }
    return ThresholdResult(
        run_id=data["run_id"],
        entity_type=data["entity_type"],
        target_percentile=data["target_percentile"],
        cold_start_min_events=data["cold_start_min_events"],
        type_level_fallback=data["type_level_fallback"],
        entity_thresholds=entity_thresholds,
    )


def load_latest_thresholds(entity_type: str) -> ThresholdResult:
    """Load the most recently saved ThresholdResult for this entity type."""
    etype = entity_type.upper()
    if not _THRESHOLDS_DIR.exists():
        raise FileNotFoundError(
            f"No thresholds directory at {_THRESHOLDS_DIR}. "
            "Run `python cli.py threshold --entity-type <type>` first."
        )
    candidates = sorted(
        _THRESHOLDS_DIR.glob(f"*_{etype}_thresholds.json"),
        key=lambda p: p.stat().st_mtime,
    )
    if not candidates:
        raise FileNotFoundError(
            f"No threshold files found for entity_type={etype!r} in {_THRESHOLDS_DIR}."
        )
    return load_thresholds(
        run_id=candidates[-1].name.replace(f"_{etype}_thresholds.json", ""),
        entity_type=etype,
    )


# ---------------------------------------------------------------------------
# Main entry-point (called by cli.py cmd_threshold)
# ---------------------------------------------------------------------------

def run_threshold(run_id: str, entity_type: str) -> ThresholdResult:
    """
    Full threshold pipeline:
      1. Load split manifest (must already exist from calibrate step).
      2. Load calibrator.
      3. Calibrate the CALIBRATION split records.
      4. Compute per-entity ECDF thresholds.
      5. Print summary and save JSON.

    Returns ThresholdResult.
    """
    from calibration.splits import load_manifest
    from calibration.fit_isotonic import load_calibrator

    manifest = load_manifest(run_id, entity_type)
    calibrator = load_calibrator(run_id, entity_type)

    # Build (entity_key, calibrated_proba) pairs from calibration split only
    cal_records = manifest.calibration_records
    if not cal_records:
        raise RuntimeError(
            f"[THRESHOLD FAIL] No calibration records in manifest for "
            f"run_id={run_id!r} entity_type={entity_type!r}."
        )

    raw_scores = np.array([r.raw_score for r in cal_records])
    cal_probas = calibrator.predict_proba(raw_scores)
    calibrated_pairs = [
        (r.entity_key, float(p)) for r, p in zip(cal_records, cal_probas)
    ]

    # Separate normal-only calibrated probas for the fallback threshold.
    # label=0 means normal traffic; label=1 means attack.
    normal_cal_probas = [
        float(p) for r, p in zip(cal_records, cal_probas) if r.label == 0
    ]

    result = compute_thresholds(
        calibrated_records=calibrated_pairs,
        run_id=run_id,
        entity_type=entity_type,
        normal_only_scores=normal_cal_probas,
    )

    # ── Print summary ────────────────────────────────────────────────────────
    cfg = _load_threshold_config()
    etype = entity_type.upper()
    pct = cfg[etype]["target_percentile"]

    print(f"\n=== THRESHOLD RESULTS ===\n")
    print(f"  Entity type          : {entity_type}")
    print(f"  Run ID               : {run_id}")
    print(f"  Target percentile    : {pct}th")
    print(f"  Cold-start minimum   : {result.cold_start_min_events} events")
    print(f"  Type-level fallback  : {result.type_level_fallback:.4f}")
    print()
    print(f"  Entities with per-entity threshold : {result.per_entity_count}")
    print(f"  Entities on cold-start fallback    : {result.cold_start_count}")
    print()

    if result.cold_start_count > 0:
        print("  Cold-start entities (using type-level threshold):")
        for ek, et in result.entity_thresholds.items():
            if et.method == "cold_start_fallback":
                print(f"    {ek}  (n_scored={et.n_scored})")
        print()

    print("  Per-entity thresholds:")
    for ek, et in sorted(result.entity_thresholds.items()):
        marker = "(per-entity)" if et.method == "per_entity" else "(fallback)"
        print(f"    {ek:<50s}  threshold={et.threshold:.4f}  {marker}  n={et.n_scored}")
    print()

    out_path = save_thresholds(result)
    print(f"  Saved to: {out_path}")
    return result
