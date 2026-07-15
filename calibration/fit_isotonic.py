"""
aegis_ml_lab/calibration/fit_isotonic.py
==========================================
Phase 3.2 — Isotonic Regression Calibrator

Fits sklearn IsotonicRegression on the CALIBRATION split only.
Maps raw Isolation Forest decision_function values → calibrated probability
scores in [0, 1].

Design contracts (AEGIS_ML_Lab_ULTIMATE.md §4):
- NEVER sees evaluation split data.
- NEVER refits at inference time.
- Raises if calibration split is empty or too small.
- Saves calibrator to calibration/calibrators/<run_id>_<entity_type>.pkl.
- Also saves a copy into the model registry artifact for this run.

Score direction note
--------------------
sklearn IF decision_function: lower (more negative) = more anomalous.
IsotonicRegression expects monotone input → output.
We NEGATE scores before fitting so higher input → higher probability:
    negate: more anomalous → higher → higher calibrated probability
Output is in [0, 1] where 1.0 = certain anomaly.
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import structlog
from sklearn.isotonic import IsotonicRegression

_LAB_ROOT = Path(__file__).parent.parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logger = structlog.get_logger(__name__)

_CALIBRATORS_DIR = _LAB_ROOT / "calibration" / "calibrators"
_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"

# Minimum calibration samples to fit a meaningful calibrator.
# With fewer samples, isotonic regression is unreliable.
_MIN_CALIBRATION_SAMPLES = 10


class IsotonicCalibrator:
    """
    Wrapper around sklearn IsotonicRegression with score-direction handling.

    Stores the entity_type and run_id for traceability.
    All public methods work in the "negated score" space internally
    so callers never need to worry about sign convention.
    """

    def __init__(self, entity_type: str, run_id: str) -> None:
        self.entity_type = entity_type
        self.run_id = run_id
        self._iso: IsotonicRegression | None = None
        self._n_cal_samples: int = 0
        self._n_attack: int = 0
        self._n_normal: int = 0

    @property
    def is_fitted(self) -> bool:
        return self._iso is not None

    def fit(self, raw_scores: np.ndarray, labels: np.ndarray) -> "IsotonicCalibrator":
        """
        Fit on calibration split scores and labels.

        Parameters
        ----------
        raw_scores : 1-D array of raw IF decision_function values.
                     (sklearn convention: lower = more anomalous)
        labels     : 1-D int array, 0=normal, 1=attack.

        Returns self (for chaining).
        """
        if len(raw_scores) < _MIN_CALIBRATION_SAMPLES:
            raise ValueError(
                f"[CALIBRATION FAIL] Only {len(raw_scores)} calibration samples for "
                f"entity_type={self.entity_type}. Minimum is {_MIN_CALIBRATION_SAMPLES}. "
                "Cannot fit a reliable isotonic calibrator. "
                "Add more calibration data before proceeding."
            )
        if len(raw_scores) != len(labels):
            raise ValueError(
                f"raw_scores ({len(raw_scores)}) and labels ({len(labels)}) must have "
                "the same length."
            )

        n_attack = int(labels.sum())
        n_normal = int((labels == 0).sum())
        if n_attack == 0:
            raise ValueError(
                "[CALIBRATION FAIL] No attack samples in calibration split. "
                "IsotonicRegression on all-normal data produces a flat 0.0 output — "
                "meaningless for threshold derivation. Check splits.py output."
            )
        if n_normal == 0:
            raise ValueError(
                "[CALIBRATION FAIL] No normal samples in calibration split. "
                "Cannot calibrate without a normal reference distribution."
            )

        # Negate so that more anomalous → larger input → larger output
        X = -raw_scores
        self._iso = IsotonicRegression(out_of_bounds="clip", increasing=True)
        self._iso.fit(X, labels.astype(float))
        self._n_cal_samples = len(raw_scores)
        self._n_attack = n_attack
        self._n_normal = n_normal

        logger.info(
            "calibrator_fitted",
            entity_type=self.entity_type,
            run_id=self.run_id,
            n_samples=self._n_cal_samples,
            n_attack=n_attack,
            n_normal=n_normal,
        )
        return self

    def predict_proba(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        Map raw IF scores to calibrated probabilities in [0, 1].

        Parameters
        ----------
        raw_scores : Raw decision_function values (sklearn sign convention).

        Returns
        -------
        np.ndarray of floats in [0, 1], higher = more likely anomaly.
        """
        if not self.is_fitted:
            raise RuntimeError(
                "IsotonicCalibrator.predict_proba() called before fit(). "
                "Run calibrate command first."
            )
        return self._iso.predict(-raw_scores)

    def summary(self) -> dict:
        """Return a metadata dict for serialisation alongside the pickle."""
        return {
            "entity_type": self.entity_type,
            "run_id": self.run_id,
            "n_calibration_samples": self._n_cal_samples,
            "n_attack": self._n_attack,
            "n_normal": self._n_normal,
            "is_fitted": self.is_fitted,
            "sklearn_class": "IsotonicRegression",
            "increasing": True,
            "score_direction": "negated_before_fit (lower IF score = higher calibrated prob)",
        }


# ---------------------------------------------------------------------------
# Persist / load helpers
# ---------------------------------------------------------------------------

def save_calibrator(calibrator: IsotonicCalibrator, run_id: str) -> Path:
    """
    Persist calibrator to calibration/calibrators/<run_id>_<entity_type>.pkl
    and also write a JSON metadata sidecar.

    Also copies into the model registry artifact for this run.
    """
    _CALIBRATORS_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"{run_id}_{calibrator.entity_type}"

    pkl_path = _CALIBRATORS_DIR / f"{stem}.pkl"
    with pkl_path.open("wb") as f:
        pickle.dump(calibrator, f)

    meta_path = _CALIBRATORS_DIR / f"{stem}_meta.json"
    meta_path.write_text(json.dumps(calibrator.summary(), indent=2))

    # Mirror into registry artifact (registry/<run_id>/<entity_type>/)
    registry_run_dirs = sorted(_REGISTRY_DIR.iterdir()) if _REGISTRY_DIR.exists() else []
    matching = [d for d in registry_run_dirs if d.name == run_id]
    if matching:
        reg_entity_dir = matching[0] / calibrator.entity_type
        reg_entity_dir.mkdir(parents=True, exist_ok=True)
        reg_pkl = reg_entity_dir / "calibrator.pkl"
        with reg_pkl.open("wb") as f:
            pickle.dump(calibrator, f)
        (reg_entity_dir / "calibrator_meta.json").write_text(
            json.dumps(calibrator.summary(), indent=2)
        )
        logger.info("calibrator_mirrored_to_registry", path=str(reg_pkl))

    logger.info(
        "calibrator_saved",
        pkl=str(pkl_path),
        meta=str(meta_path),
    )
    return pkl_path


def load_calibrator(run_id: str, entity_type: str) -> IsotonicCalibrator:
    """Load a previously fitted calibrator by run_id and entity_type."""
    stem = f"{run_id}_{entity_type}"
    pkl_path = _CALIBRATORS_DIR / f"{stem}.pkl"
    if not pkl_path.exists():
        # Fall back to registry copy
        registry_copy = _REGISTRY_DIR / run_id / entity_type / "calibrator.pkl"
        if registry_copy.exists():
            pkl_path = registry_copy
        else:
            raise FileNotFoundError(
                f"No calibrator found for run_id={run_id!r} entity_type={entity_type!r}. "
                "Run `python cli.py calibrate --entity-type <type>` first."
            )
    with pkl_path.open("rb") as f:
        return pickle.load(f)


def load_latest_calibrator(entity_type: str) -> IsotonicCalibrator:
    """Load the most recently saved calibrator for this entity type."""
    etype = entity_type.upper()
    if not _CALIBRATORS_DIR.exists():
        raise FileNotFoundError(
            f"No calibrators directory found at {_CALIBRATORS_DIR}. "
            "Run `python cli.py calibrate --entity-type <type>` first."
        )
    candidates = sorted(
        _CALIBRATORS_DIR.glob(f"*_{etype}.pkl"),
        key=lambda p: p.stat().st_mtime,
    )
    if not candidates:
        raise FileNotFoundError(
            f"No calibrator pkl found for entity_type={etype!r} in {_CALIBRATORS_DIR}."
        )
    with candidates[-1].open("rb") as f:
        return pickle.load(f)


# ---------------------------------------------------------------------------
# Main entry-point (called by cli.py cmd_calibrate)
# ---------------------------------------------------------------------------

def run_calibration(
    run_id: str,
    entity_type: str,
    seed_a: int = 42,
    seed_b: int = 1337,
    max_attack_per_scenario: int | None = None,
) -> IsotonicCalibrator:
    """
    Full calibration pipeline:
      1. Generate splits (or reload existing manifest if present).
      2. Fit isotonic calibrator on calibration split.
      3. Save calibrator + manifest.
      4. Print summary statistics.

    Parameters
    ----------
    run_id                  : Run to calibrate.
    entity_type             : "IT" or "OT".
    seed_a                  : Calibration split seed (default 42).
    seed_b                  : Evaluation split seed (default 1337).
    max_attack_per_scenario : Optional per-scenario attack cap passed to generate_splits().
                              Pins the calibration attack count to a constant value so
                              re-runs of the same config produce identical split sizes.
                              None = no cap (legacy behaviour).

    Returns the fitted IsotonicCalibrator.
    """
    from calibration.splits import generate_splits, load_manifest, save_manifest

    # Check for existing manifest to avoid re-running the attack generator
    runs_dir = _LAB_ROOT / "runs"
    manifest_path = runs_dir / run_id / "split_manifest.json"

    if manifest_path.exists():
        logger.info("split_manifest_found_reusing", path=str(manifest_path))
        manifest = load_manifest(run_id, entity_type)
    else:
        logger.info("generating_new_splits", run_id=run_id, entity_type=entity_type)
        manifest = generate_splits(
            run_id=run_id,
            entity_type=entity_type,
            seed_a=seed_a,
            seed_b=seed_b,
            max_attack_per_scenario=max_attack_per_scenario,
        )
        save_manifest(manifest, run_id)

    # Verify manifest entity_type matches
    if manifest.entity_type.upper() != entity_type.upper():
        raise ValueError(
            f"Manifest entity_type={manifest.entity_type!r} does not match "
            f"requested entity_type={entity_type!r}."
        )

    cal_scores = manifest.calibration_scores()
    cal_labels = manifest.calibration_labels()

    calibrator = IsotonicCalibrator(entity_type=entity_type.upper(), run_id=run_id)
    calibrator.fit(cal_scores, cal_labels)

    # Print calibration stats
    cal_proba = calibrator.predict_proba(cal_scores)
    normal_proba = cal_proba[cal_labels == 0]
    attack_proba = cal_proba[cal_labels == 1]

    print("\n=== CALIBRATION RESULTS ===\n")
    print(f"  Entity type     : {entity_type}")
    print(f"  Run ID          : {run_id}")
    print(f"  Cal samples     : {len(cal_scores)} ({int(cal_labels.sum())} attack, "
          f"{int((cal_labels == 0).sum())} normal)")
    print()
    print(f"  Normal calibrated probability:")
    print(f"    mean  : {normal_proba.mean():.4f}")
    print(f"    std   : {normal_proba.std():.4f}")
    print(f"    min   : {normal_proba.min():.4f}")
    print(f"    max   : {normal_proba.max():.4f}")
    print()
    print(f"  Attack calibrated probability:")
    print(f"    mean  : {attack_proba.mean():.4f}")
    print(f"    std   : {attack_proba.std():.4f}")
    print(f"    min   : {attack_proba.min():.4f}")
    print(f"    max   : {attack_proba.max():.4f}")
    print()
    if len(attack_proba) > 0 and len(normal_proba) > 0:
        sep = float(attack_proba.mean()) - float(normal_proba.mean())
        print(f"  Calibrated separation (attack_mean - normal_mean): {sep:+.4f}")
        direction = "OK  attack > normal" if sep > 0 else "FAIL  no separation"
        print(f"  Direction: {direction}")
    print()

    save_calibrator(calibrator, run_id)
    return calibrator
