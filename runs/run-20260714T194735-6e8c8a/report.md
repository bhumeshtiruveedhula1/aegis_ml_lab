# AEGIS ML Lab — Evaluation Report

**Run ID:** `run-20260714T194735-6e8c8a`  
**Entity type:** IT  
**Generated:** 2026-07-14 19:48 UTC  
**Evaluation seed:** 1337 (distinct from calibration seed 42)

---

## 1. Calibration / Evaluation Non-Overlap Verification

> **VERIFIED:** Evaluation windows do not overlap calibration windows — confirmed against `split_manifest.json` at 2026-07-14T19:48:39.773274+00:00
>
> Calibration seed: **42**  |  Evaluation seed: **1337**  
> Each scenario was independently generated with distinct seeds. No evaluation record shares an attack instance with calibration.

---

## 2. Raw `decision_function` Distributions

_(Lower = more anomalous in sklearn IF convention)_

| Scenario | N atk | N nml | Atk mean | Atk std | Nml mean | Nml std | Raw sep |
|----------|-------|-------|----------|---------|---------|---------|---------|
| brute_force_auth | 21 | 200 | 0.0801 | 0.0000 | 0.0776 | 0.0134 | +0.0025 |
| command_execution_powershell | 4 | 200 | 0.0145 | 0.0378 | 0.0776 | 0.0134 | -0.0630 |
| lateral_movement_smb | 9 | 200 | 0.0801 | 0.0000 | 0.0776 | 0.0134 | +0.0025 |
| credential_stuffing | 31 | 200 | 0.0801 | 0.0000 | 0.0776 | 0.0134 | +0.0025 |
| privilege_escalation_token | 3 | 200 | 0.0510 | 0.0412 | 0.0776 | 0.0134 | -0.0266 |
| persistence_scheduled_task | 2 | 200 | -0.0073 | 0.0000 | 0.0776 | 0.0134 | -0.0849 |
| network_discovery_scan | 50 | 200 | 0.0801 | 0.0000 | 0.0776 | 0.0134 | +0.0025 |
| data_exfiltration_http | 15 | 200 | 0.0801 | 0.0000 | 0.0776 | 0.0134 | +0.0025 |
| full_kill_chain_it | 26 | 200 | 0.0734 | 0.0233 | 0.0776 | 0.0134 | -0.0042 |

---

## 3. Calibrated Score Distributions

_(IsotonicRegression output: 0=normal, 1=attack probability)_

| Scenario | Atk cal mean | Atk cal std | Nml cal mean | Nml cal std | Cal sep |
|----------|-------------|-------------|-------------|-------------|---------|
| brute_force_auth | 0.2480 | 0.0000 | 0.0980 | 0.1212 | +0.1500 |
| command_execution_powershell | 0.8120 | 0.3256 | 0.0980 | 0.1212 | +0.7140 |
| lateral_movement_smb | 0.2480 | 0.0000 | 0.0980 | 0.1212 | +0.1500 |
| credential_stuffing | 0.2480 | 0.0000 | 0.0980 | 0.1212 | +0.1500 |
| privilege_escalation_token | 0.4987 | 0.3545 | 0.0980 | 0.1212 | +0.4007 |
| persistence_scheduled_task | 1.0000 | 0.0000 | 0.0980 | 0.1212 | +0.9020 |
| network_discovery_scan | 0.2480 | 0.0000 | 0.0980 | 0.1212 | +0.1500 |
| data_exfiltration_http | 0.2480 | 0.0000 | 0.0980 | 0.1212 | +0.1500 |
| full_kill_chain_it | 0.3058 | 0.2004 | 0.0980 | 0.1212 | +0.2079 |

---

## 4. Detection Rate and FPR at Computed Threshold

Threshold source: per-entity ECDF at 95th percentile (IT) / cold-start type-level fallback for unseen attackers.

| Scenario | Threshold | TP | FP | n_atk | n_nml | Det Rate | FPR | AUROC |
|----------|-----------|----|----|-------|-------|----------|-----|-------|
| brute_force_auth | 0.2480 | 21 | 79 | 21 | 200 | 100.0% | 39.5% | 0.802 |
| command_execution_powershell | 0.2480 | 4 | 79 | 4 | 200 | 100.0% | 39.5% | 0.951 |
| lateral_movement_smb | 0.2480 | 9 | 79 | 9 | 200 | 100.0% | 39.5% | 0.802 |
| credential_stuffing | 0.2480 | 31 | 79 | 31 | 200 | 100.0% | 39.5% | 0.802 |
| privilege_escalation_token | 0.2480 | 3 | 79 | 3 | 200 | 100.0% | 39.5% | 0.868 |
| persistence_scheduled_task | 0.2480 | 2 | 79 | 2 | 200 | 100.0% | 39.5% | 1.000 |
| network_discovery_scan | 0.2480 | 50 | 79 | 50 | 200 | 100.0% | 39.5% | 0.802 |
| data_exfiltration_http | 0.2480 | 15 | 79 | 15 | 200 | 100.0% | 39.5% | 0.802 |
| full_kill_chain_it | 0.2480 | 26 | 79 | 26 | 200 | 100.0% | 39.5% | 0.818 |

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

  brute_force_auth                    [########------------] 39.5%
  command_execution_powershell        [########------------] 39.5%
  lateral_movement_smb                [########------------] 39.5%
  credential_stuffing                 [########------------] 39.5%
  privilege_escalation_token          [########------------] 39.5%
  persistence_scheduled_task          [########------------] 39.5%
  network_discovery_scan              [########------------] 39.5%
  data_exfiltration_http              [########------------] 39.5%
  full_kill_chain_it                  [########------------] 39.5%

---

## 5. Comparison to Prior Run

_No prior run found. This is the first evaluation run._

---

## Notes

- Calibrator: IsotonicRegression fitted on calibration split (seed 42) ONLY.
- This report uses evaluation split (seed 1337) — never seen by calibration.
- OT evaluation: not run — documented known limitation (< 14-day baseline window).
- SHAP annotations: 161 alerts annotated.
- For threshold derivation details see: `thresholds/run-20260714T194735-6e8c8a_IT_thresholds.json`
- For calibration details see: `calibration/calibrators/run-20260714T194735-6e8c8a_IT_meta.json`
