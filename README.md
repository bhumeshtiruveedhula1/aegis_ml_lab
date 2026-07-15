# AEGIS ML Lab

A config-driven ML iteration environment for **Operation AEGIS** — anomaly detection
for hospital IT and OT networks using Isolation Forest + isotonic calibration.

---

## Quick-Start Sequence

Run these commands in order for a full end-to-end evaluation:

```bash
# 1. Generate entity baselines from the normalized event stream
python cli.py generate-baseline --entity-type IT

# 2. Train the Isolation Forest model
python cli.py train --entity-type IT

# 3. Calibrate the isotonic probability calibrator (splits cal/eval by seed)
python cli.py calibrate --entity-type IT

# 4. Compute per-entity ECDF thresholds
python cli.py threshold --entity-type IT

# 5. Run the full evaluation harness across all 3 IT attack scenarios
python cli.py evaluate --all-scenarios --run-id <run_id>

# 6. Phase 6: robustness (seed sweep + adversarial drift)
python cli.py evaluate --all-scenarios --run-id <run_id> --seeds 5 --adversarial-drift

# 7. Phase 7: compare two runs or two seeds statistically
python cli.py compare seed:0 seed:1
python cli.py compare run-<id_a> run-<id_b>

# 8. Phase 4: SHAP feature audit
python cli.py shap-audit --entity-type IT

# 9. Phase 8: aggregate judge summary
python cli.py judge-summary --run-id <run_id>
```

> **Note on run IDs:** Each `train` call creates a new `run-<timestamp>-<hash>` directory
> under `models/registry/`. When you re-train, pass `--run-id` to `evaluate`, `compare`,
> and `judge-summary` to target the specific calibrated run. The most-recent-run default
> will fail if a new untrained run exists without a calibrator.

---

## Command Reference

### `generate-baseline`

```
python cli.py generate-baseline --entity-type IT|OT [--seed N]
```

Reads all normalized events from `data/normalized/normalized_events.jsonl`, runs them
through the feature pipeline, and writes per-entity baseline profiles to
`models/baselines/<entity_type>/`. The baseline is required before training — it
provides the historical frequency distributions that feature extractors compare against.
The `--seed` flag controls the RNG for any stochastic elements in baseline construction
(default: 42).

---

### `audit-baseline`

```
python cli.py audit-baseline [--check-contamination]
```

Inspects the most recently generated baseline for potential attack contamination —
checks whether any known attack-pattern features appear in the baseline at levels
inconsistent with benign normal traffic. Logs a warning per entity if the contamination
check fails. Does not modify any files. Run this after `generate-baseline` if you
suspect the normalized event stream contains unlabelled attack traffic.

---

### `train`

```
python cli.py train --entity-type IT|OT [--seed N]
```

Trains an Isolation Forest model on the IT or OT entity baseline. Reads hyperparameters
from `config/model_config.yaml` (n_estimators, max_samples, contamination, etc.).
After training, runs the **Phase 2 session gate**: prints the raw
`decision_function` distributions for normal traffic and each attack scenario side-by-side.
If the gate flags scores as flat (attack mean ≈ normal mean), training halts and you must
diagnose the feature/baseline issue before proceeding. The fitted model is saved to
`models/registry/<run_id>/<entity_type>/isolation_forest.pkl`. The preprocessed training
matrix is also saved on the pipeline object as `_training_X` for Phase 6 seed sweeps.

---

### `calibrate`

```
python cli.py calibrate --entity-type IT|OT [--run-id <id>] [--seed-a 42] [--seed-b 1337]
```

Generates calibration and evaluation splits (Rule 9: distinct seeds, no overlap), then
fits an IsotonicRegression calibrator on the calibration split only. The calibrator
converts raw Isolation Forest `decision_function` scores (lower = more anomalous) into
[0, 1] anomaly probability scores (higher = more anomalous). The evaluation split
(seed_b=1337) is never touched by the calibrator — it is reserved for Phase 5. Saves
the calibrator to `calibration/calibrators/<run_id>_<entity_type>.pkl`.

---

### `threshold`

```
python cli.py threshold --entity-type IT|OT [--run-id <id>]
```

Computes per-entity alert thresholds using the Empirical CDF (ECDF) method at the
95th percentile (IT) or configured percentile (OT) of each entity's calibrated
probability scores on the calibration split. Entities with fewer than 30 calibration
events use the type-level fallback, which is derived from **normal-traffic scores only**
(attack probas are excluded from the fallback computation to prevent inflating the
threshold to an undetectable value). Thresholds are saved to
`thresholds/<run_id>_<entity_type>_thresholds.json`.

---

### `evaluate`

```
python cli.py evaluate --all-scenarios --run-id <id> [--seeds N] [--adversarial-drift]
```

Runs the full end-to-end evaluation harness (Phase 5 + optional Phase 6) on the
**evaluation split only** (seed=1337, never seen by the calibrator). For each of the
3 IT attack scenarios (brute_force_auth, command_execution_powershell,
lateral_movement_smb), generates attack events, scores them through the trained
model, applies the calibrator and threshold, and computes detection rate, FPR, and
AUROC. Produces a structured `report.md` with 5 sections: overlap verification,
raw decision_function distributions, calibrated score distributions, DR/FPR table,
and comparison to prior run. Saves `raw_metrics.json` for machine-readable access.

**`--seeds N`** triggers Phase 6.1: re-trains the IF with N different `random_state`
values and evaluates each on the same holdout split. If DR range > 10pp across seeds,
the verdict is `UNSTABLE` (flagged loudly, not averaged away).

**`--adversarial-drift`** triggers Phase 6.2: simulates baseline poisoning by injecting
attack feature vectors as normal-labeled training data at 10%, 25%, 50% fractions, then
re-trains and re-evaluates. Reports DETECTED or FAILED per fraction. Never silently passes.

---

### `compare`

```
python cli.py compare <run_a> <run_b> [--bootstrap B] [--scenario S] [--metric M]
python cli.py compare seed:0 seed:1
```

Phase 7 statistical comparison using bootstrap resampling (B=10,000 by default).
Computes 95% confidence intervals for detection_rate, FPR, and AUROC for both runs,
then reports CI overlap/non-overlap as the verdict. **CI overlap IS the verdict** —
naive point-estimate diffs are stored for reference but are not the conclusion.

Use `seed:N` syntax to compare two seeds from the most recently saved
`seed_sweep_results.json`. When comparing two seeds of the same config, CI overlap is
the correct expected result — it confirms the bootstrap mechanism works correctly, not
that there is a bug. Results are saved to `runs/<base_run>/compare_<a>_<b>.json`.

---

### `shap-audit`

```
python cli.py shap-audit [--entity-type IT] [--run-id <id>]
```

Phase 4 feature attribution audit. Reads from `runs/<run_id>/shap_tally.json` (built
incrementally during evaluate) and reports which features appear most frequently in the
top-3 SHAP contributors across all scored alerts. Features appearing in > 80% of alerts
are flagged as DOMINANT — indicating the model is heavily reliant on a narrow set of
signals. Uses `TreeExplainer` with `feature_perturbation="tree_path_dependent"` (no
background data required for Isolation Forest).

---

### `judge-summary`

```
python cli.py judge-summary [--run-id <id>] [--entity-type IT]
```

Phase 8 aggregation. Reads all available run artifacts without any re-scoring:
`raw_metrics.json`, `seed_sweep_results.json`, `adversarial_drift_result.json`,
`shap_tally.json`. Produces a single-page markdown judge report with detection results
table, seed sweep stability verdict, drift test verdict, top SHAP features, OT limitation
note, and the three mandatory deferred items (CRC, ADWIN, SHAP-NL) with one-line reasons
each. Saves both `judge_summary.json` and `judge_summary.md` to `runs/<run_id>/`.

---

## Architecture

```
aegis_ml_lab/
├── config/
│   ├── model_config.yaml         # IF hyperparameters, session gate thresholds
│   ├── baseline_config.yaml      # Baseline generation parameters
│   ├── feature_registry.yaml     # Feature definitions, active/candidate/OT-only status
│   └── threshold_config.yaml     # ECDF percentile, cold-start min_events
├── models/
│   ├── train.py                  # Phase 2 — training + session gate
│   └── baselines/IT/, baselines/OT/
├── calibration/
│   ├── splits.py                 # Phase 3 — calibration/evaluation split generation
│   └── fit_isotonic.py           # Isotonic calibrator fitting
├── thresholds/
│   └── compute_ecdf.py           # Phase 3.4 — ECDF per-entity thresholds
├── features/
│   └── extractors.py             # Feature registry implementations
├── evaluate/
│   └── run_e2e_suite.py          # Phase 5 — full evaluation harness
├── explain/
│   └── shap_report.py            # Phase 4 — SHAP annotation + tally
├── robustness/
│   ├── seed_sweep.py             # Phase 6.1 — seed sweep
│   └── adversarial_drift.py      # Phase 6.2 — adversarial drift simulation
├── compare/
│   └── compare_runs.py           # Phase 7 — bootstrap CI comparison
├── judge/
│   └── judge_summary.py          # Phase 8 — aggregation summary
└── cli.py                        # Entry point for all commands
```

**Core design constraints (immutable — do not modify):**
- Anomaly detector: Isolation Forest only (no ensemble, no neural nets)
- Explainability: SHAP only (TreeExplainer)
- OT model not yet trained — known limitation (see Deviation Log)

---

## Deviation Log

All deviations from the original spec are logged here. These are permanent record entries,
not temporary notes.

---

### DEV-001 — `writer.py` append-mode bug (fixed)

**Date:** Phase 1  
**File:** `cybershield/backend/normalization/writer.py`  
**Issue:** The normalized event writer opened output files in append mode (`'a'`), causing
events from prior runs to accumulate in `normalized_events.jsonl` across repeated
invocations. Successive runs would train on ever-growing, contaminated datasets.  
**Fix:** Changed file open mode to `'w'` (overwrite) at the start of each normalization
run. The fix is in the production writer — not worked around in lab code.  
**Impact:** Without this fix, all training data after the first run was contaminated.

---

### DEV-002 — `auth_unexpected_failure` feature (re-implemented)

**Date:** Phase 1  
**File:** `aegis_ml_lab/features/extractors.py`  
**Issue:** The production feature extractor for `auth_unexpected_failure` (detecting
authentication failure rate spikes) was missing or incomplete in the production backend.  
**Fix:** Implemented via the feature registry as `status: candidate` initially, promoted
to `status: active` after Phase 2 gate confirmation of real separation signal. The
production backend has a corresponding gap — the lab implementation should be backported.  
**Impact:** Without this feature, brute-force authentication scenarios had weaker signal.

---

### DEV-003 — `primary_only=True` in calibration splits (fixed)

**Date:** Between Phase 5 and Phase 6  
**File:** `aegis_ml_lab/calibration/splits.py`, function `_score_events`  
**Issue:** `FeaturePipeline(primary_only=True)` caused `lateral_movement_smb` (canonical
primary entity type = `user`) and `command_execution_powershell` (primary = `host`) to
produce **zero** `user_host` feature records when processed through the calibration
pipeline. The calibration split therefore contained only `brute_force_auth` attack
samples, creating a single-scenario calibrator that failed to generalise.  
**Symptom:** Calibrated probability separation was +0.038 (all 3 scenarios mapped to the
same probability); FPR was 71.5%.  
**Fix:** Changed to `primary_only=False` + explicit `entity_type == 'user_host'` filter.
All 3 scenarios now contribute: 34 calibration attack records (21 + 4 + 9).  
**Impact:** FPR dropped from 71.5% → 14.0%. AUROC improved from 0.643 → 0.930/1.000.

---

### DEV-004 — Type-level threshold fallback computed from all scores (fixed)

**Date:** Between Phase 5 and Phase 6  
**File:** `aegis_ml_lab/thresholds/compute_ecdf.py`, function `compute_thresholds`  
**Issue:** The type-level fallback threshold (used for cold-start attacker entities) was
computed as the 95th percentile of **all** calibrated scores, including attack scores.
After the DEV-003 fix, attack calibrated probabilities reached 1.0. The 95th percentile
of the combined distribution was therefore 1.0, making cold-start attacker entities
undetectable (they would need calibrated probability = 1.0 to trigger an alert).  
**Fix:** Pass normal-only calibrated scores to `compute_thresholds` via a new
`normal_only_scores` parameter. The fallback is now derived from normal traffic only
(95th pct = 0.375), which is the correct semantics: the fallback guards against what
is "unusually high for normal traffic of this entity type."  
**Impact:** Cold-start attacker detection restored. Type-level fallback: 1.0 → 0.375.

---

### DEV-005 — OT evaluation not run (known limitation)

**Date:** Phase 2 onwards  
**Status:** Permanent known limitation — not a bug, not a fix target within the lab.  
**Issue:** OT baseline window is < 14 days. The OT model training either failed the
session gate or produced insufficient baseline depth for meaningful calibration.  
**Resolution:** Accumulate ≥ 14 days of real OT telemetry (Modbus/DNP3 events from
`ot_node` source), then re-run: `generate-baseline --entity-type OT` → `train` → 
`calibrate` → `evaluate --all-scenarios` for OT. All Phase 1-8 modules are OT-ready;
only the data is missing.

---

### DEV-006 — No native adversarial drift API in SyntheticAttackService

**Date:** Phase 6  
**Status:** Documented deviation — not a code bug.  
**Issue:** `SyntheticAttackService` has no `gradual_drift`, `absorb_baseline`, or
similar API (confirmed via grep in Phase 6 dependency check). The spec anticipated this
might be the case and required the deviation be documented rather than silently skipped.  
**Workaround:** Phase 6.2 simulates drift via baseline poisoning: injects calibration-split
attack feature vectors as normal-labeled training data at 10%, 25%, 50% fractions, then
re-trains and re-evaluates. This is a reasonable approximation of concept drift but is
not equivalent to production temporal drift.  
**Impact:** Drift test results should be interpreted as "resistance to baseline poisoning"
not "resistance to production concept drift."

---

## Mandatory Deferred Items

These items are explicitly out of scope for the ML lab layer. They require infrastructure
or data not available in the lab environment.

| Item | Reason |
|------|--------|
| **CRC — Concept Drift Detection (ADWIN/DDM)** | Requires a live production event stream with timestamps across multiple time windows. ADWIN cannot be meaningfully applied to a static synthetic baseline. |
| **ADWIN Statistical Drift Window** | Depends on CRC. Requires sequential production decision scores with timestamps — not available in the lab's static evaluation setup. |
| **SHAP-NL — Natural Language SHAP Explanations** | Requires an LLM integration layer to convert SHAP feature importance vectors into human-readable narrative explanations. Belongs in the alert rendering / SOC UI layer, not the ML lab. |

---

## Known Limitations Summary

| Limitation | Impact | Resolution |
|-----------|--------|-----------|
| OT not evaluated | OT DR/FPR/AUROC unknown | Accumulate ≥14 days OT telemetry |
| brute_force_auth seed-sensitive (DR=0% on seeds 1-4) | UNSTABLE verdict in seed sweep | Widen feature separation or use ensemble voting |
| FPR 14.0% (target <5%) | Too many false positive alerts | Richer calibration data (more scenarios, multiple instances per template) |
| No native drift API | Drift simulation only approximates real concept drift | Implement `SyntheticAttackService.generate_gradual_drift()` |
| Single-scenario seed instances (std=0 per attack scenario) | AUROC computed from single-point ROC curves | Multi-instance template generation with entity variation |
