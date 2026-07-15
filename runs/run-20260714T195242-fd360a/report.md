# AEGIS ML Lab — Evaluation Report

**Run ID:** `run-20260714T195242-fd360a`  
**Entity type:** IT  
**Generated:** 2026-07-14 19:53 UTC  
**Evaluation seed:** 1337 (distinct from calibration seed 42)

---

## 1. Calibration / Evaluation Non-Overlap Verification

> **VERIFIED:** Evaluation windows do not overlap calibration windows — confirmed against `split_manifest.json` at 2026-07-14T19:53:15.295355+00:00
>
> Calibration seed: **42**  |  Evaluation seed: **1337**  
> Each scenario was independently generated with distinct seeds. No evaluation record shares an attack instance with calibration.

---

## 2. Raw `decision_function` Distributions

_(Lower = more anomalous in sklearn IF convention)_

| Scenario | N atk | N nml | Atk mean | Atk std | Nml mean | Nml std | Raw sep |
|----------|-------|-------|----------|---------|---------|---------|---------|
| brute_force_auth | 21 | 200 | 0.0110 | 0.0000 | 0.0576 | 0.0296 | -0.0467 |
| command_execution_powershell | 4 | 200 | -0.0484 | 0.0000 | 0.0576 | 0.0296 | -0.1060 |
| lateral_movement_smb | 9 | 200 | -0.0484 | 0.0000 | 0.0576 | 0.0296 | -0.1060 |
| credential_stuffing | 31 | 200 | -0.0484 | 0.0000 | 0.0576 | 0.0296 | -0.1060 |
| privilege_escalation_token | 3 | 200 | -0.0484 | 0.0000 | 0.0576 | 0.0296 | -0.1060 |
| persistence_scheduled_task | 2 | 200 | -0.0484 | 0.0000 | 0.0576 | 0.0296 | -0.1060 |
| network_discovery_scan | 50 | 200 | -0.0484 | 0.0000 | 0.0576 | 0.0296 | -0.1060 |
| data_exfiltration_http | 15 | 200 | -0.0484 | 0.0000 | 0.0576 | 0.0296 | -0.1060 |
| full_kill_chain_it | 26 | 200 | -0.0484 | 0.0000 | 0.0576 | 0.0296 | -0.1060 |

---

## 3. Calibrated Score Distributions

_(IsotonicRegression output: 0=normal, 1=attack probability)_

| Scenario | Atk cal mean | Atk cal std | Nml cal mean | Nml cal std | Cal sep |
|----------|-------------|-------------|-------------|-------------|---------|
| brute_force_auth | 0.4667 | 0.0000 | 0.0443 | 0.1368 | +0.4223 |
| command_execution_powershell | 1.0000 | 0.0000 | 0.0443 | 0.1368 | +0.9557 |
| lateral_movement_smb | 1.0000 | 0.0000 | 0.0443 | 0.1368 | +0.9557 |
| credential_stuffing | 1.0000 | 0.0000 | 0.0443 | 0.1368 | +0.9557 |
| privilege_escalation_token | 1.0000 | 0.0000 | 0.0443 | 0.1368 | +0.9557 |
| persistence_scheduled_task | 1.0000 | 0.0000 | 0.0443 | 0.1368 | +0.9557 |
| network_discovery_scan | 1.0000 | 0.0000 | 0.0443 | 0.1368 | +0.9557 |
| data_exfiltration_http | 1.0000 | 0.0000 | 0.0443 | 0.1368 | +0.9557 |
| full_kill_chain_it | 1.0000 | 0.0000 | 0.0443 | 0.1368 | +0.9557 |

---

## 4. Detection Rate and FPR at Computed Threshold

Threshold source: per-entity ECDF at 95th percentile (IT) / cold-start type-level fallback for unseen attackers.

| Scenario | Threshold | TP | FP | n_atk | n_nml | Det Rate | FPR | AUROC |
|----------|-----------|----|----|-------|-------|----------|-----|-------|
| brute_force_auth | 0.4667 | 21 | 19 | 21 | 200 | 100.0% | 9.5% | 0.953 |
| command_execution_powershell | 0.4667 | 4 | 19 | 4 | 200 | 100.0% | 9.5% | 1.000 |
| lateral_movement_smb | 0.4667 | 9 | 19 | 9 | 200 | 100.0% | 9.5% | 1.000 |
| credential_stuffing | 0.4667 | 31 | 19 | 31 | 200 | 100.0% | 9.5% | 1.000 |
| privilege_escalation_token | 0.4667 | 3 | 19 | 3 | 200 | 100.0% | 9.5% | 1.000 |
| persistence_scheduled_task | 0.4667 | 2 | 19 | 2 | 200 | 100.0% | 9.5% | 1.000 |
| network_discovery_scan | 0.4667 | 50 | 19 | 50 | 200 | 100.0% | 9.5% | 1.000 |
| data_exfiltration_http | 0.4667 | 15 | 19 | 15 | 200 | 100.0% | 9.5% | 1.000 |
| full_kill_chain_it | 0.4667 | 26 | 19 | 26 | 200 | 100.0% | 9.5% | 1.000 |

**Detection rates (bar chart):**

  brute_force_auth                    [####################] 100.0%
  command_execution_powershell        [####################] 100.0%
  lateral_movement_smb                [####################] 100.0%
  credential_stuffing                 [####################] 100.0%
  privilege_escalation_token          [####################] 100.0%
  persistence_scheduled_task          [####################] 100.0%
  network_discovery_scan              [####################] 100.0%
  data_exfiltration_http              [####################] 100.0%
  full_kill_chain_it                  [####################] 100.0%

**FPR (bar chart):**

  brute_force_auth                    [##------------------] 9.5%
  command_execution_powershell        [##------------------] 9.5%
  lateral_movement_smb                [##------------------] 9.5%
  credential_stuffing                 [##------------------] 9.5%
  privilege_escalation_token          [##------------------] 9.5%
  persistence_scheduled_task          [##------------------] 9.5%
  network_discovery_scan              [##------------------] 9.5%
  data_exfiltration_http              [##------------------] 9.5%
  full_kill_chain_it                  [##------------------] 9.5%

---

## 5. Comparison to Prior Run

_No prior run found. This is the first evaluation run._

---

## Notes

- Calibrator: IsotonicRegression fitted on calibration split (seed 42) ONLY.
- This report uses evaluation split (seed 1337) — never seen by calibration.
- OT evaluation: not run — documented known limitation (< 14-day baseline window).
- SHAP annotations: 161 alerts annotated.
- For threshold derivation details see: `thresholds/run-20260714T195242-fd360a_IT_thresholds.json`
- For calibration details see: `calibration/calibrators/run-20260714T195242-fd360a_IT_meta.json`
