# AEGIS ML Lab — Evaluation Report

**Run ID:** `run-20260714T195613-f4bcaa`  
**Entity type:** IT  
**Generated:** 2026-07-14 19:57 UTC  
**Evaluation seed:** 1337 (distinct from calibration seed 42)

---

## 1. Calibration / Evaluation Non-Overlap Verification

> **VERIFIED:** Evaluation windows do not overlap calibration windows — confirmed against `split_manifest.json` at 2026-07-14T19:57:19.987167+00:00
>
> Calibration seed: **42**  |  Evaluation seed: **1337**  
> Each scenario was independently generated with distinct seeds. No evaluation record shares an attack instance with calibration.

---

## 2. Raw `decision_function` Distributions

_(Lower = more anomalous in sklearn IF convention)_

| Scenario | N atk | N nml | Atk mean | Atk std | Nml mean | Nml std | Raw sep |
|----------|-------|-------|----------|---------|---------|---------|---------|
| brute_force_auth | 21 | 200 | 0.0470 | 0.0000 | 0.1017 | 0.0150 | -0.0547 |
| command_execution_powershell | 4 | 200 | 0.0336 | 0.0318 | 0.1017 | 0.0150 | -0.0682 |
| lateral_movement_smb | 9 | 200 | 0.0916 | 0.0000 | 0.1017 | 0.0150 | -0.0101 |
| credential_stuffing | 31 | 200 | 0.0886 | 0.0000 | 0.1017 | 0.0150 | -0.0131 |
| privilege_escalation_token | 3 | 200 | 0.0788 | 0.0138 | 0.1017 | 0.0150 | -0.0229 |
| persistence_scheduled_task | 2 | 200 | 0.0372 | 0.0220 | 0.1017 | 0.0150 | -0.0645 |
| network_discovery_scan | 50 | 200 | 0.0886 | 0.0000 | 0.1017 | 0.0150 | -0.0131 |
| data_exfiltration_http | 15 | 200 | 0.0886 | 0.0000 | 0.1017 | 0.0150 | -0.0131 |
| full_kill_chain_it | 26 | 200 | 0.0830 | 0.0196 | 0.1017 | 0.0150 | -0.0188 |

---

## 3. Calibrated Score Distributions

_(IsotonicRegression output: 0=normal, 1=attack probability)_

| Scenario | Atk cal mean | Atk cal std | Nml cal mean | Nml cal std | Cal sep |
|----------|-------------|-------------|-------------|-------------|---------|
| brute_force_auth | 1.0000 | 0.0000 | 0.0432 | 0.0684 | +0.9568 |
| command_execution_powershell | 0.7879 | 0.3674 | 0.0432 | 0.0684 | +0.7447 |
| lateral_movement_smb | 0.1515 | 0.0000 | 0.0432 | 0.0684 | +0.1083 |
| credential_stuffing | 0.1515 | 0.0000 | 0.0432 | 0.0684 | +0.1083 |
| privilege_escalation_token | 0.2522 | 0.1424 | 0.0432 | 0.0684 | +0.2091 |
| persistence_scheduled_task | 0.7268 | 0.2732 | 0.0432 | 0.0684 | +0.6837 |
| network_discovery_scan | 0.1515 | 0.0000 | 0.0432 | 0.0684 | +0.1083 |
| data_exfiltration_http | 0.1515 | 0.0000 | 0.0432 | 0.0684 | +0.1083 |
| full_kill_chain_it | 0.2168 | 0.2261 | 0.0432 | 0.0684 | +0.1736 |

---

## 4. Detection Rate and FPR at Computed Threshold

Threshold source: per-entity ECDF at 95th percentile (IT) / cold-start type-level fallback for unseen attackers.

| Scenario | Threshold | TP | FP | n_atk | n_nml | Det Rate | FPR | AUROC |
|----------|-----------|----|----|-------|-------|----------|-----|-------|
| brute_force_auth | 0.1515 | 21 | 50 | 21 | 200 | 100.0% | 25.0% | 1.000 |
| command_execution_powershell | 0.1515 | 4 | 50 | 4 | 200 | 100.0% | 25.0% | 0.964 |
| lateral_movement_smb | 0.1515 | 9 | 50 | 9 | 200 | 100.0% | 25.0% | 0.858 |
| credential_stuffing | 0.1515 | 31 | 50 | 31 | 200 | 100.0% | 25.0% | 0.858 |
| privilege_escalation_token | 0.1515 | 3 | 50 | 3 | 200 | 100.0% | 25.0% | 0.905 |
| persistence_scheduled_task | 0.1515 | 2 | 50 | 2 | 200 | 100.0% | 25.0% | 1.000 |
| network_discovery_scan | 0.1515 | 50 | 50 | 50 | 200 | 100.0% | 25.0% | 0.858 |
| data_exfiltration_http | 0.1515 | 15 | 50 | 15 | 200 | 100.0% | 25.0% | 0.858 |
| full_kill_chain_it | 0.1515 | 26 | 50 | 26 | 200 | 100.0% | 25.0% | 0.868 |

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

  brute_force_auth                    [#####---------------] 25.0%
  command_execution_powershell        [#####---------------] 25.0%
  lateral_movement_smb                [#####---------------] 25.0%
  credential_stuffing                 [#####---------------] 25.0%
  privilege_escalation_token          [#####---------------] 25.0%
  persistence_scheduled_task          [#####---------------] 25.0%
  network_discovery_scan              [#####---------------] 25.0%
  data_exfiltration_http              [#####---------------] 25.0%
  full_kill_chain_it                  [#####---------------] 25.0%

---

## 5. Comparison to Prior Run

_No prior run found. This is the first evaluation run._

---

## Notes

- Calibrator: IsotonicRegression fitted on calibration split (seed 42) ONLY.
- This report uses evaluation split (seed 1337) — never seen by calibration.
- OT evaluation: not run — documented known limitation (< 14-day baseline window).
- SHAP annotations: 161 alerts annotated.
- For threshold derivation details see: `thresholds/run-20260714T195613-f4bcaa_IT_thresholds.json`
- For calibration details see: `calibration/calibrators/run-20260714T195613-f4bcaa_IT_meta.json`
