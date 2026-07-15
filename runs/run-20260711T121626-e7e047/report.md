# AEGIS ML Lab — Evaluation Report

**Run ID:** `run-20260711T121626-e7e047`  
**Entity type:** IT  
**Generated:** 2026-07-12 00:19 UTC  
**Evaluation seed:** 1337 (distinct from calibration seed 42)

---

## 1. Calibration / Evaluation Non-Overlap Verification

> **VERIFIED:** Evaluation windows do not overlap calibration windows — confirmed against `split_manifest.json` at 2026-07-12T00:19:21.968371+00:00
>
> Calibration seed: **42**  |  Evaluation seed: **1337**  
> Each scenario was independently generated with distinct seeds. No evaluation record shares an attack instance with calibration.

---

## 2. Raw `decision_function` Distributions

_(Lower = more anomalous in sklearn IF convention)_

| Scenario | N atk | N nml | Atk mean | Atk std | Nml mean | Nml std | Raw sep |
|----------|-------|-------|----------|---------|---------|---------|---------|
| brute_force_auth | 21 | 200 | 0.0215 | 0.0000 | 0.0576 | 0.0296 | -0.0362 |
| command_execution_powershell | 4 | 200 | -0.0554 | 0.0000 | 0.0576 | 0.0296 | -0.1130 |
| lateral_movement_smb | 9 | 200 | -0.0554 | 0.0000 | 0.0576 | 0.0296 | -0.1130 |

---

## 3. Calibrated Score Distributions

_(IsotonicRegression output: 0=normal, 1=attack probability)_

| Scenario | Atk cal mean | Atk cal std | Nml cal mean | Nml cal std | Cal sep |
|----------|-------------|-------------|-------------|-------------|---------|
| brute_force_auth | 0.3750 | 0.0000 | 0.0525 | 0.1301 | +0.3225 |
| command_execution_powershell | 1.0000 | 0.0000 | 0.0525 | 0.1301 | +0.9475 |
| lateral_movement_smb | 1.0000 | 0.0000 | 0.0525 | 0.1301 | +0.9475 |

---

## 4. Detection Rate and FPR at Computed Threshold

Threshold source: per-entity ECDF at 95th percentile (IT) / cold-start type-level fallback for unseen attackers.

| Scenario | Threshold | TP | FP | n_atk | n_nml | Det Rate | FPR | AUROC |
|----------|-----------|----|----|-------|-------|----------|-----|-------|
| brute_force_auth | 0.3750 | 21 | 28 | 21 | 200 | 100.0% | 14.0% | 0.930 |
| command_execution_powershell | 0.3750 | 4 | 28 | 4 | 200 | 100.0% | 14.0% | 1.000 |
| lateral_movement_smb | 0.3750 | 9 | 28 | 9 | 200 | 100.0% | 14.0% | 1.000 |

**Detection rates (bar chart):**

  brute_force_auth                    [####################] 100.0%
  command_execution_powershell        [####################] 100.0%
  lateral_movement_smb                [####################] 100.0%

**FPR (bar chart):**

  brute_force_auth                    [###-----------------] 14.0%
  command_execution_powershell        [###-----------------] 14.0%
  lateral_movement_smb                [###-----------------] 14.0%

---

## 5. Comparison to Prior Run

_No prior run found. This is the first evaluation run._

---

## Notes

- Calibrator: IsotonicRegression fitted on calibration split (seed 42) ONLY.
- This report uses evaluation split (seed 1337) — never seen by calibration.
- OT evaluation: not run — documented known limitation (< 14-day baseline window).
- SHAP annotations: 34 alerts annotated.
- For threshold derivation details see: `thresholds/run-20260711T121626-e7e047_IT_thresholds.json`
- For calibration details see: `calibration/calibrators/run-20260711T121626-e7e047_IT_meta.json`
