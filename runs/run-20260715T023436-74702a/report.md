# AEGIS ML Lab — Evaluation Report

**Run ID:** `run-20260715T023436-74702a`  
**Entity type:** IT  
**Generated:** 2026-07-15 02:35 UTC  
**Evaluation seed:** 1337 (distinct from calibration seed 42)

---

## 1. Calibration / Evaluation Non-Overlap Verification

> **VERIFIED:** Evaluation windows do not overlap calibration windows — confirmed against `split_manifest.json` at 2026-07-15T02:35:07.097308+00:00
>
> Calibration seed: **42**  |  Evaluation seed: **1337**  
> Each scenario was independently generated with distinct seeds. No evaluation record shares an attack instance with calibration.

---

## 2. Raw `decision_function` Distributions

_(Lower = more anomalous in sklearn IF convention)_

| Scenario | N atk | N nml | Atk mean | Atk std | Nml mean | Nml std | Raw sep |
|----------|-------|-------|----------|---------|---------|---------|---------|
| brute_force_auth | 21 | 200 | 0.0598 | 0.0000 | 0.1020 | 0.0232 | -0.0422 |
| command_execution_powershell | 4 | 200 | 0.0527 | 0.0322 | 0.1020 | 0.0232 | -0.0492 |
| lateral_movement_smb | 9 | 200 | 0.1045 | 0.0000 | 0.1020 | 0.0232 | +0.0025 |
| credential_stuffing | 31 | 200 | 0.1086 | 0.0000 | 0.1020 | 0.0232 | +0.0066 |
| privilege_escalation_token | 3 | 200 | 0.0968 | 0.0167 | 0.1020 | 0.0232 | -0.0052 |
| persistence_scheduled_task | 2 | 200 | 0.0536 | 0.0195 | 0.1020 | 0.0232 | -0.0484 |
| network_discovery_scan | 50 | 200 | 0.1086 | 0.0000 | 0.1020 | 0.0232 | +0.0066 |
| data_exfiltration_http | 15 | 200 | 0.1086 | 0.0000 | 0.1020 | 0.0232 | +0.0066 |
| full_kill_chain_it | 26 | 200 | 0.1029 | 0.0198 | 0.1020 | 0.0232 | +0.0009 |

---

## 3. Calibrated Score Distributions

_(IsotonicRegression output: 0=normal, 1=attack probability)_

| Scenario | Atk cal mean | Atk cal std | Nml cal mean | Nml cal std | Cal sep |
|----------|-------------|-------------|-------------|-------------|---------|
| brute_force_auth | 0.5263 | 0.0000 | 0.0636 | 0.1095 | +0.4627 |
| command_execution_powershell | 0.5764 | 0.3007 | 0.0636 | 0.1095 | +0.5127 |
| lateral_movement_smb | 0.0769 | 0.0000 | 0.0636 | 0.1095 | +0.0133 |
| credential_stuffing | 0.0556 | 0.0000 | 0.0636 | 0.1095 | -0.0081 |
| privilege_escalation_token | 0.0627 | 0.0101 | 0.0636 | 0.1095 | -0.0010 |
| persistence_scheduled_task | 0.4135 | 0.3365 | 0.0636 | 0.1095 | +0.3498 |
| network_discovery_scan | 0.0556 | 0.0000 | 0.0636 | 0.1095 | -0.0081 |
| data_exfiltration_http | 0.0556 | 0.0000 | 0.0636 | 0.1095 | -0.0081 |
| full_kill_chain_it | 0.1090 | 0.1850 | 0.0636 | 0.1095 | +0.0453 |

---

## 4. Detection Rate and FPR at Computed Threshold

Threshold source: per-entity ECDF at 95th percentile (IT) / cold-start type-level fallback for unseen attackers.

| Scenario | Threshold | TP | FP | n_atk | n_nml | Det Rate | FPR | AUROC |
|----------|-----------|----|----|-------|-------|----------|-----|-------|
| brute_force_auth | 0.0994 | 21 | 23 | 21 | 200 | 100.0% | 11.5% | 0.975 |
| command_execution_powershell | 0.0994 | 3 | 23 | 4 | 200 | 75.0% | 11.5% | 0.860 |
| lateral_movement_smb | 0.0994 | 0 | 23 | 9 | 200 | 0.0% | 11.5% | 0.728 |
| credential_stuffing | 0.0994 | 0 | 23 | 31 | 200 | 0.0% | 11.5% | 0.448 |
| privilege_escalation_token | 0.0994 | 0 | 23 | 3 | 200 | 0.0% | 11.5% | 0.541 |
| persistence_scheduled_task | 0.0994 | 1 | 23 | 2 | 200 | 50.0% | 11.5% | 0.863 |
| network_discovery_scan | 0.0994 | 0 | 23 | 50 | 200 | 0.0% | 11.5% | 0.448 |
| data_exfiltration_http | 0.0994 | 0 | 23 | 15 | 200 | 0.0% | 11.5% | 0.448 |
| full_kill_chain_it | 0.0994 | 2 | 23 | 26 | 200 | 7.7% | 11.5% | 0.490 |

**Detection rates (bar chart):**

  brute_force_auth                    [####################] 100.0%
  command_execution_powershell        [###############-----] 75.0%
  lateral_movement_smb                [--------------------] 0.0%
  credential_stuffing                 [--------------------] 0.0%
  privilege_escalation_token          [--------------------] 0.0%
  persistence_scheduled_task          [##########----------] 50.0%
  network_discovery_scan              [--------------------] 0.0%
  data_exfiltration_http              [--------------------] 0.0%
  full_kill_chain_it                  [##------------------] 7.7%

**FPR (bar chart):**

  brute_force_auth                    [##------------------] 11.5%
  command_execution_powershell        [##------------------] 11.5%
  lateral_movement_smb                [##------------------] 11.5%
  credential_stuffing                 [##------------------] 11.5%
  privilege_escalation_token          [##------------------] 11.5%
  persistence_scheduled_task          [##------------------] 11.5%
  network_discovery_scan              [##------------------] 11.5%
  data_exfiltration_http              [##------------------] 11.5%
  full_kill_chain_it                  [##------------------] 11.5%

---

## 5. Comparison to Prior Run

_No prior run found. This is the first evaluation run._

---

## Notes

- Calibrator: IsotonicRegression fitted on calibration split (seed 42) ONLY.
- This report uses evaluation split (seed 1337) — never seen by calibration.
- OT evaluation: not run — documented known limitation (< 14-day baseline window).
- SHAP annotations: 27 alerts annotated.
- For threshold derivation details see: `thresholds/run-20260715T023436-74702a_IT_thresholds.json`
- For calibration details see: `calibration/calibrators/run-20260715T023436-74702a_IT_meta.json`
