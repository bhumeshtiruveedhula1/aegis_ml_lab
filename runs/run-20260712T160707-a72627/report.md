# AEGIS ML Lab — Evaluation Report

**Run ID:** `run-20260712T160707-a72627`  
**Entity type:** IT  
**Generated:** 2026-07-14 03:51 UTC  
**Evaluation seed:** 1337 (distinct from calibration seed 42)

---

## 1. Calibration / Evaluation Non-Overlap Verification

> **VERIFIED:** Evaluation windows do not overlap calibration windows — confirmed against `split_manifest.json` at 2026-07-14T03:51:24.851751+00:00
>
> Calibration seed: **42**  |  Evaluation seed: **1337**  
> Each scenario was independently generated with distinct seeds. No evaluation record shares an attack instance with calibration.

---

## 2. Raw `decision_function` Distributions

_(Lower = more anomalous in sklearn IF convention)_

| Scenario | N atk | N nml | Atk mean | Atk std | Nml mean | Nml std | Raw sep |
|----------|-------|-------|----------|---------|---------|---------|---------|
| brute_force_auth | 21 | 200 | 0.0136 | 0.0000 | 0.0576 | 0.0296 | -0.0441 |
| command_execution_powershell | 4 | 200 | -0.0468 | 0.0000 | 0.0576 | 0.0296 | -0.1044 |
| lateral_movement_smb | 9 | 200 | -0.0468 | 0.0000 | 0.0576 | 0.0296 | -0.1044 |
| credential_stuffing | 31 | 200 | -0.0468 | 0.0000 | 0.0576 | 0.0296 | -0.1044 |
| privilege_escalation_token | 3 | 200 | -0.0468 | 0.0000 | 0.0576 | 0.0296 | -0.1044 |
| persistence_scheduled_task | 2 | 200 | -0.0468 | 0.0000 | 0.0576 | 0.0296 | -0.1044 |
| network_discovery_scan | 50 | 200 | -0.0468 | 0.0000 | 0.0576 | 0.0296 | -0.1044 |
| data_exfiltration_http | 15 | 200 | -0.0468 | 0.0000 | 0.0576 | 0.0296 | -0.1044 |
| full_kill_chain_it | 26 | 200 | -0.0468 | 0.0000 | 0.0576 | 0.0296 | -0.1044 |

---

## 3. Calibrated Score Distributions

_(IsotonicRegression output: 0=normal, 1=attack probability)_

| Scenario | Atk cal mean | Atk cal std | Nml cal mean | Nml cal std | Cal sep |
|----------|-------------|-------------|-------------|-------------|---------|
| brute_force_auth | 0.4599 | 0.0000 | 0.0667 | 0.1619 | +0.3932 |
| command_execution_powershell | 0.6644 | 0.0000 | 0.0667 | 0.1619 | +0.5977 |
| lateral_movement_smb | 0.6644 | 0.0000 | 0.0667 | 0.1619 | +0.5977 |
| credential_stuffing | 0.6644 | 0.0000 | 0.0667 | 0.1619 | +0.5977 |
| privilege_escalation_token | 0.6644 | 0.0000 | 0.0667 | 0.1619 | +0.5977 |
| persistence_scheduled_task | 0.6644 | 0.0000 | 0.0667 | 0.1619 | +0.5977 |
| network_discovery_scan | 0.6644 | 0.0000 | 0.0667 | 0.1619 | +0.5977 |
| data_exfiltration_http | 0.6644 | 0.0000 | 0.0667 | 0.1619 | +0.5977 |
| full_kill_chain_it | 0.6644 | 0.0000 | 0.0667 | 0.1619 | +0.5977 |

---

## 4. Detection Rate and FPR at Computed Threshold

Threshold source: per-entity ECDF at 95th percentile (IT) / cold-start type-level fallback for unseen attackers.

| Scenario | Threshold | TP | FP | n_atk | n_nml | Det Rate | FPR | AUROC |
|----------|-----------|----|----|-------|-------|----------|-----|-------|
| brute_force_auth | 0.4599 | 21 | 29 | 21 | 200 | 100.0% | 14.5% | 0.927 |
| command_execution_powershell | 0.4599 | 4 | 29 | 4 | 200 | 100.0% | 14.5% | 1.000 |
| lateral_movement_smb | 0.4599 | 9 | 29 | 9 | 200 | 100.0% | 14.5% | 1.000 |
| credential_stuffing | 0.4599 | 31 | 29 | 31 | 200 | 100.0% | 14.5% | 1.000 |
| privilege_escalation_token | 0.4599 | 3 | 29 | 3 | 200 | 100.0% | 14.5% | 1.000 |
| persistence_scheduled_task | 0.4599 | 2 | 29 | 2 | 200 | 100.0% | 14.5% | 1.000 |
| network_discovery_scan | 0.4599 | 50 | 29 | 50 | 200 | 100.0% | 14.5% | 1.000 |
| data_exfiltration_http | 0.4599 | 15 | 29 | 15 | 200 | 100.0% | 14.5% | 1.000 |
| full_kill_chain_it | 0.4599 | 26 | 29 | 26 | 200 | 100.0% | 14.5% | 1.000 |

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

  brute_force_auth                    [###-----------------] 14.5%
  command_execution_powershell        [###-----------------] 14.5%
  lateral_movement_smb                [###-----------------] 14.5%
  credential_stuffing                 [###-----------------] 14.5%
  privilege_escalation_token          [###-----------------] 14.5%
  persistence_scheduled_task          [###-----------------] 14.5%
  network_discovery_scan              [###-----------------] 14.5%
  data_exfiltration_http              [###-----------------] 14.5%
  full_kill_chain_it                  [###-----------------] 14.5%

---

## 5. Comparison to Prior Run

_No prior run found. This is the first evaluation run._

---

## Notes

- Calibrator: IsotonicRegression fitted on calibration split (seed 42) ONLY.
- This report uses evaluation split (seed 1337) — never seen by calibration.
- OT evaluation: not run — documented known limitation (< 14-day baseline window).
- SHAP annotations: 0 alerts annotated.
- For threshold derivation details see: `thresholds/run-20260712T160707-a72627_IT_thresholds.json`
- For calibration details see: `calibration/calibrators/run-20260712T160707-a72627_IT_meta.json`
