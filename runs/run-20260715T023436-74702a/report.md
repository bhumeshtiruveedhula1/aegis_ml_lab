# AEGIS ML Lab — Evaluation Report

**Run ID:** `run-20260715T023436-74702a`  
**Entity type:** IT  
**Generated:** 2026-07-19 14:37 UTC  
**Evaluation seed:** 1337 (distinct from calibration seed 42)

---

## 1. Calibration / Evaluation Non-Overlap Verification

> **VERIFIED:** Evaluation windows do not overlap calibration windows — confirmed against `split_manifest.json` at 2026-07-19T14:37:50.889600+00:00
>
> Calibration seed: **42**  |  Evaluation seed: **1337**  
> Each scenario was independently generated with distinct seeds. No evaluation record shares an attack instance with calibration.

---

## 2. Raw `decision_function` Distributions

_(Lower = more anomalous in sklearn IF convention)_

| Scenario | N atk | N nml | Atk mean | Atk std | Nml mean | Nml std | Raw sep |
|----------|-------|-------|----------|---------|---------|---------|---------|
| brute_force_auth | 21 | 200 | 0.0584 | 0.0000 | 0.0419 | 0.0131 | +0.0164 |
| command_execution_powershell | 4 | 200 | 0.0000 | 0.0215 | 0.0419 | 0.0131 | -0.0419 |
| lateral_movement_smb | 9 | 200 | 0.0372 | 0.0000 | 0.0419 | 0.0131 | -0.0047 |
| credential_stuffing | 31 | 200 | 0.0372 | 0.0000 | 0.0419 | 0.0131 | -0.0047 |
| privilege_escalation_token | 3 | 200 | 0.0372 | 0.0000 | 0.0419 | 0.0131 | -0.0047 |
| persistence_scheduled_task | 2 | 200 | -0.0124 | 0.0000 | 0.0419 | 0.0131 | -0.0543 |
| network_discovery_scan | 50 | 200 | 0.0372 | 0.0000 | 0.0419 | 0.0131 | -0.0047 |
| data_exfiltration_http | 15 | 200 | 0.0372 | 0.0000 | 0.0419 | 0.0131 | -0.0047 |
| full_kill_chain_it | 26 | 200 | 0.0334 | 0.0132 | 0.0419 | 0.0131 | -0.0085 |
| brute_force_auth_cold_start | 21 | 200 | nan | nan | 0.0419 | 0.0131 | +nan |
| command_execution_cold_start | 4 | 200 | nan | nan | 0.0419 | 0.0131 | +nan |

---

## 3. Calibrated Score Distributions

_(IsotonicRegression output: 0=normal, 1=attack probability)_

| Scenario | Atk cal mean | Atk cal std | Nml cal mean | Nml cal std | Cal sep |
|----------|-------------|-------------|-------------|-------------|---------|
| brute_force_auth | 0.5122 | 0.0000 | 0.6370 | 0.1188 | -0.1248 |
| command_execution_powershell | 0.7500 | 0.0000 | 0.6370 | 0.1188 | +0.1130 |
| lateral_movement_smb | 0.7500 | 0.0000 | 0.6370 | 0.1188 | +0.1130 |
| credential_stuffing | 0.7500 | 0.0000 | 0.6370 | 0.1188 | +0.1130 |
| privilege_escalation_token | 0.6707 | 0.1121 | 0.6370 | 0.1188 | +0.0337 |
| persistence_scheduled_task | 0.6311 | 0.1189 | 0.6370 | 0.1188 | -0.0059 |
| network_discovery_scan | 0.7500 | 0.0000 | 0.6370 | 0.1188 | +0.1130 |
| data_exfiltration_http | 0.7500 | 0.0000 | 0.6370 | 0.1188 | +0.1130 |
| full_kill_chain_it | 0.7500 | 0.0000 | 0.6370 | 0.1188 | +0.1130 |
| brute_force_auth_cold_start | 0.1525 | 0.0000 | 0.6370 | 0.1188 | -0.4845 |
| command_execution_cold_start | 0.6006 | 0.2587 | 0.6370 | 0.1188 | -0.0364 |

---

## 4. Detection Rate and FPR at Computed Threshold

Threshold source: per-entity ECDF at 95th percentile (IT) / cold-start type-level fallback for unseen attackers.

| Scenario | Threshold | TP | FP | n_atk | n_nml | Det Rate | FPR | AUROC |
|----------|-----------|----|----|-------|-------|----------|-----|-------|
| brute_force_auth | 0.5122 | 21 | 200 | 21 | 200 | 100.0% | 100.0% | 0.237 |
| command_execution_powershell | 0.5122 | 4 | 200 | 4 | 200 | 100.0% | 100.0% | 0.738 |
| lateral_movement_smb | 0.5122 | 9 | 200 | 9 | 200 | 100.0% | 100.0% | 0.738 |
| credential_stuffing | 0.5122 | 31 | 200 | 31 | 200 | 100.0% | 100.0% | 0.738 |
| privilege_escalation_token | 0.5122 | 3 | 200 | 3 | 200 | 100.0% | 100.0% | 0.571 |
| persistence_scheduled_task | 0.5122 | 2 | 200 | 2 | 200 | 100.0% | 100.0% | 0.487 |
| network_discovery_scan | 0.5122 | 50 | 200 | 50 | 200 | 100.0% | 100.0% | 0.738 |
| data_exfiltration_http | 0.5122 | 15 | 200 | 15 | 200 | 100.0% | 100.0% | 0.738 |
| full_kill_chain_it | 0.5122 | 26 | 200 | 26 | 200 | 100.0% | 100.0% | 0.738 |
| brute_force_auth_cold_start | 0.5122 | 21 | 200 | 21 | 200 | 100.0% | 100.0% | 0.000 |
| command_execution_cold_start | 0.5122 | 4 | 200 | 4 | 200 | 100.0% | 100.0% | 0.553 |

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
  brute_force_auth_cold_start         [####################] 100.0%
  command_execution_cold_start        [####################] 100.0%

**FPR (bar chart):**

  brute_force_auth                    [####################] 100.0%
  command_execution_powershell        [####################] 100.0%
  lateral_movement_smb                [####################] 100.0%
  credential_stuffing                 [####################] 100.0%
  privilege_escalation_token          [####################] 100.0%
  persistence_scheduled_task          [####################] 100.0%
  network_discovery_scan              [####################] 100.0%
  data_exfiltration_http              [####################] 100.0%
  full_kill_chain_it                  [####################] 100.0%
  brute_force_auth_cold_start         [####################] 100.0%
  command_execution_cold_start        [####################] 100.0%

---

## 5. Comparison to Prior Run

_No prior run found. This is the first evaluation run._

---

## 6. MTTD Instrumentation

**Target:** MTTD < 120s (2 minutes)  
**Verdict:** ✅ PASS

### Primary MTTD (event\_timestamp → triggered\_at)

_Full pipeline story: from original security event occurring to alert firing._

| Metric | Value |
|--------|-------|
| Alerts instrumented | 159 |
| Mean MTTD | 0.046s |
| Median MTTD | 0.043s |
| P95 MTTD | 0.084s |
| Min MTTD | 0.015s |
| Max MTTD | 0.093s |
| Alerts within target | 100.0% |

### Secondary MTTD (extracted\_at → triggered\_at)

_Pipeline diagnostic: feature extraction → alert emission (pure processing latency)._

| Metric | Value |
|--------|-------|
| Mean | 0.0415s |
| Median | 0.0390s |
| P95 | 0.0717s |
| Min | 0.0149s |
| Max | 0.0786s |

### Per-Scenario MTTD Breakdown

| Scenario | N alerts | Mean MTTD (s) | Min (s) | Max (s) |
|----------|----------|--------------|---------|----------|
| brute_force_auth | 21 | 0.036 | 0.024 | 0.048 |
| command_execution_powershell | 4 | 0.019 | 0.017 | 0.021 |
| credential_stuffing | 31 | 0.045 | 0.027 | 0.062 |
| data_exfiltration_http | 15 | 0.029 | 0.021 | 0.037 |
| full_kill_chain_it | 26 | 0.048 | 0.029 | 0.070 |
| lateral_movement_smb | 9 | 0.023 | 0.018 | 0.028 |
| network_discovery_scan | 50 | 0.063 | 0.034 | 0.093 |
| persistence_scheduled_task | 1 | 0.015 | 0.015 | 0.015 |
| privilege_escalation_token | 2 | 0.017 | 0.016 | 0.017 |

_Results persisted to: `runs/run-20260715T023436-74702a/mttd_results.json`_

---

## 7. ATT&CK Chain Detection Accuracy

**Target:** Chain Detection Accuracy > 70%  
**Verdict:** PASS

| Metric | Value |
|--------|-------|
| Scenarios evaluated | 9 |
| Scenarios with chain detected | 9 |
| Total chains found | 9 |
| Attack chain detection accuracy | 100.0% |
| Mean technique recall | 100.0% |

### Per-Scenario Chain Results

| Scenario | Ground Truth | Detected | TP | FN | Recall | Chains |
|----------|-------------|----------|----|----|--------|--------|
| brute_force_auth | T1110 | T1110 | 1 | 0 | 100% | 1 |
| credential_stuffing | T1110.004 | T1110 | 1 | 0 | 100% | 1 |
| lateral_movement_smb | T1021.002,T1078 | T1021.002,T1078 | 2 | 0 | 100% | 1 |
| privilege_escalation_token | T1134 | T1134 | 1 | 0 | 100% | 1 |
| persistence_scheduled_task | T1053.005 | T1053 | 1 | 0 | 100% | 1 |
| command_execution_powershell | T1059.001 | T1059.001 | 1 | 0 | 100% | 1 |
| network_discovery_scan | T1046 | T1046 | 1 | 0 | 100% | 1 |
| data_exfiltration_http | T1041 | T1041 | 1 | 0 | 100% | 1 |
| full_kill_chain_it | T1110,T1021.002,T1059.001,T1041 | T1021.002,T1041,T1059.001,T1110 | 4 | 0 | 100% | 1 |

_Note: Chain detector requires >= 2 technique steps (MIN_CHAIN_LENGTH=2). Single-technique scenarios cannot form a chain by design._

_Results persisted to: `runs/run-20260715T023436-74702a/chain_eval_results.json`_

---

## Notes

- Calibrator: IsotonicRegression fitted on calibration split (seed 42) ONLY.
- This report uses evaluation split (seed 1337) — never seen by calibration.
- OT evaluation: not run — documented known limitation (< 14-day baseline window).
- SHAP annotations: 159 alerts annotated.
- For threshold derivation details see: `thresholds/run-20260715T023436-74702a_IT_thresholds.json`
- For calibration details see: `calibration/calibrators/run-20260715T023436-74702a_IT_meta.json`
