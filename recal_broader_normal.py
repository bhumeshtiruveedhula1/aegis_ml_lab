"""
recal_broader_normal.py
=======================
Re-fits the isotonic calibrator for run-20260712T160707-a72627 / IT
with broader negative-class coverage.

What it does:
  - Loads existing calibration scores + labels from split_manifest.json
  - Scores an EXTRA synthetic normal slice (events 400:600 from normalized_events.jsonl)
    through the already-trained IF model — this slice was not used for training,
    calibration, or evaluation, so there is no data leakage.
  - Appends those extra normal scores (label=0) to the calibration arrays.
  - Re-fits IsotonicCalibrator on the augmented dataset.
  - Saves over the existing calibrator pkl (same path, same run_id).
  - Exports the updated calibrator to the production ModelStore.
  - Prints before/after stats so we can verify the boundary shifted.

Does NOT touch:
  - The trained Isolation Forest model
  - The ECDF threshold (compute_ecdf will be re-run after to update it)
  - Any scenario logic, hyperparameters, or eval splits
"""
import sys, warnings, pickle, json
warnings.filterwarnings('ignore')
sys.path.insert(0, '.')
sys.path.insert(0, '../cybershield')
import logging
logging.disable(logging.WARNING)

import numpy as np
from pathlib import Path

RUN = "run-20260712T160707-a72627"
ETYPE = "IT"
EXTRA_NORMAL_START = 400   # events [400:600] — distinct from cal [0:200] and eval [200:400]
EXTRA_NORMAL_END   = 600

# ── 1. Load existing calibration data from manifest ────────────────────────
from calibration.splits import load_manifest
from calibration.fit_isotonic import IsotonicCalibrator, save_calibrator

manifest = load_manifest(RUN, ETYPE)
cal_scores = manifest.calibration_scores()   # raw IF decision_function values
cal_labels = manifest.calibration_labels()   # 0=normal, 1=attack

n_orig_normal = int((cal_labels == 0).sum())
n_orig_attack = int(cal_labels.sum())
print(f"Original calibration: {len(cal_scores)} samples "
      f"({n_orig_attack} attack, {n_orig_normal} normal)")

# ── 2. Load the trained IF model ────────────────────────────────────────────
from evaluate.run_e2e_suite import _get_feature_records, _score_records, _ENTITY_DIM

_REGISTRY_DIR = Path('models') / 'registry'
pkl_path = _REGISTRY_DIR / RUN / ETYPE / 'isolation_forest.pkl'
with pkl_path.open('rb') as f:
    det_pipeline = pickle.load(f)

# ── 3. Score extra normal events ────────────────────────────────────────────
from backend.baseline.reader import NormalizedEventReader
from backend.baseline.reader_api import BaselineReader

_CYBERSHIELD_ROOT = Path('../cybershield')
norm_path = (_CYBERSHIELD_ROOT / 'data' / 'normalized' / 'normalized_events.jsonl').resolve()
all_normal = list(NormalizedEventReader(input_file=norm_path).stream())
extra_events = all_normal[EXTRA_NORMAL_START:EXTRA_NORMAL_END]
print(f"Extra normal events loaded: {len(extra_events)} (slice [{EXTRA_NORMAL_START}:{EXTRA_NORMAL_END}])")

baseline_dir = Path('models') / 'baselines' / ETYPE
reader = BaselineReader(baseline_dir=baseline_dir)
entity_dim = _ENTITY_DIM.get(ETYPE, 'user_host')

extra_records = _get_feature_records(extra_events, reader, entity_dim)
print(f"Extra normal feature records: {len(extra_records)}")

if not extra_records:
    print("ERROR: No feature records extracted from extra normal events. Aborting.")
    sys.exit(1)

extra_scores = _score_records(det_pipeline, extra_records)
extra_labels = np.zeros(len(extra_scores), dtype=int)
print(f"Extra normal raw IF scores: mean={extra_scores.mean():.4f}  std={extra_scores.std():.4f}  "
      f"min={extra_scores.min():.4f}  max={extra_scores.max():.4f}")

# ── 4. Augment calibration arrays ───────────────────────────────────────────
aug_scores = np.concatenate([cal_scores, extra_scores])
aug_labels = np.concatenate([cal_labels, extra_labels])

n_aug_normal  = int((aug_labels == 0).sum())
n_aug_attack  = int(aug_labels.sum())
print(f"\nAugmented calibration: {len(aug_scores)} samples "
      f"({n_aug_attack} attack, {n_aug_normal} normal)")

# ── 5. Fit new calibrator ────────────────────────────────────────────────────
old_cal = pickle.load(
    open(Path('calibration') / 'calibrators' / f'{RUN}_{ETYPE}.pkl', 'rb'))

# Before stats on existing calibrator
aug_proba_old = old_cal.predict_proba(aug_scores)
old_normal_max = aug_proba_old[aug_labels == 0].max()
old_normal_mean = aug_proba_old[aug_labels == 0].mean()
print(f"\nOLD calibrator (on full aug set):")
print(f"  normal_proba: mean={old_normal_mean:.4f}  max={old_normal_max:.4f}")

new_cal = IsotonicCalibrator(entity_type=ETYPE, run_id=RUN)
new_cal.fit(aug_scores, aug_labels)

aug_proba_new = new_cal.predict_proba(aug_scores)
new_normal_max = aug_proba_new[aug_labels == 0].max()
new_normal_mean = aug_proba_new[aug_labels == 0].mean()
new_attack_mean = aug_proba_new[aug_labels == 1].mean()
print(f"\nNEW calibrator (on full aug set):")
print(f"  normal_proba: mean={new_normal_mean:.4f}  max={new_normal_max:.4f}")
print(f"  attack_proba: mean={new_attack_mean:.4f}")
print(f"  separation  : {new_attack_mean - new_normal_mean:+.4f}")

# ── 6. Save the new calibrator (overwrites existing) ────────────────────────
save_calibrator(new_cal, RUN)
print(f"\nCalibrator saved (overwritten): calibration/calibrators/{RUN}_{ETYPE}.pkl")

# ── 7. Re-run ECDF threshold on the new calibrator ──────────────────────────
print("\nRe-computing ECDF threshold on new calibrator...")
from thresholds.compute_ecdf import run_threshold, load_thresholds
thresh_result = run_threshold(run_id=RUN, entity_type=ETYPE)

# Print the new threshold
new_thresholds = load_thresholds(RUN, ETYPE)
new_threshold = new_thresholds.type_level_fallback
print(f"NEW calibrated threshold (ECDF 95th pct): {new_threshold:.6f}  "
      f"(was 0.611650)")

# ── 8. Re-export to production ──────────────────────────────────────────────
print("\nRe-exporting updated calibrator to production store...")
import importlib.util, shutil
spec = importlib.util.spec_from_file_location("exp", "export_to_production.py")
exp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exp)
exp.export_model(run_id=RUN, entity_type=ETYPE)
print("Production export done.")

print("\n=== RECALIBRATION COMPLETE ===")
print(f"  Calibration samples: {len(cal_scores)} -> {len(aug_scores)}")
print(f"  Normal samples:      {n_orig_normal} -> {n_aug_normal}")
print(f"  Attack samples:      {n_orig_attack} -> {n_aug_attack}")
print(f"  New threshold:       {new_threshold:.6f}")
print(f"\nNow run: python run_seed_sweep_9.py  to compare FPR old vs new")
