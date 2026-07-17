# AEGIS ML Lab — Evaluation Report

**Run ID:** `run-20260715T023436-74702a`  
**Entity type:** IT  
**Generated:** 2026-07-17 16:52 UTC  
**Evaluation seed:** 1337 (distinct from calibration seed 42)

---

## 1. Calibration / Evaluation Non-Overlap Verification

> **VERIFIED:** Evaluation windows do not overlap calibration windows — confirmed against `split_manifest.json` at 2026-07-17T16:52:13.672330+00:00
>
> Calibration seed: **42**  |  Evaluation seed: **1337**  
> Each scenario was independently generated with distinct seeds. No evaluation record shares an attack instance with calibration.

---

## 2. Raw `decision_function` Distributions

_(Lower = more anomalous in sklearn IF convention)_

| Scenario | N atk | N nml | Atk mean | Atk std | Nml mean | Nml std | Raw sep |
|----------|-------|-------|----------|---------|---------|---------|---------|
| brute_force_auth | 21 | 200 | 0.0727 | 0.0000 | 0.1020 | 0.0232 | -0.0293 |
| command_execution_powershell | 4 | 200 | 0.0131 | 0.0213 | 0.1020 | 0.0232 | -0.0889 |
| lateral_movement_smb | 9 | 200 | 0.0500 | 0.0000 | 0.1020 | 0.0232 | -0.0520 |
| credential_stuffing | 31 | 200 | 0.0500 | 0.0000 | 0.1020 | 0.0232 | -0.0520 |
| privilege_escalation_token | 3 | 200 | 0.0553 | 0.0074 | 0.1020 | 0.0232 | -0.0467 |
| persistence_scheduled_task | 2 | 200 | 0.0333 | 0.0325 | 0.1020 | 0.0232 | -0.0687 |
| network_discovery_scan | 50 | 200 | 0.0500 | 0.0000 | 0.1020 | 0.0232 | -0.0520 |
| data_exfiltration_http | 15 | 200 | 0.0500 | 0.0000 | 0.1020 | 0.0232 | -0.0520 |
| full_kill_chain_it | 26 | 200 | 0.0462 | 0.0131 | 0.1020 | 0.0232 | -0.0557 |

---

## 3. Calibrated Score Distributions

_(IsotonicRegression output: 0=normal, 1=attack probability)_

| Scenario | Atk cal mean | Atk cal std | Nml cal mean | Nml cal std | Cal sep |
|----------|-------------|-------------|-------------|-------------|---------|
| brute_force_auth | 0.5122 | 0.0000 | 0.0901 | 0.1541 | +0.4221 |
| command_execution_powershell | 0.6905 | 0.1030 | 0.0901 | 0.1541 | +0.6005 |
| lateral_movement_smb | 0.5122 | 0.0000 | 0.0901 | 0.1541 | +0.4221 |
| credential_stuffing | 0.5122 | 0.0000 | 0.0901 | 0.1541 | +0.4221 |
| privilege_escalation_token | 0.5122 | 0.0000 | 0.0901 | 0.1541 | +0.4221 |
| persistence_scheduled_task | 0.6311 | 0.1189 | 0.0901 | 0.1541 | +0.5410 |
| network_discovery_scan | 0.5122 | 0.0000 | 0.0901 | 0.1541 | +0.4221 |
| data_exfiltration_http | 0.5122 | 0.0000 | 0.0901 | 0.1541 | +0.4221 |
| full_kill_chain_it | 0.5305 | 0.0634 | 0.0901 | 0.1541 | +0.4404 |

---

## 4. Detection Rate and FPR at Computed Threshold

Threshold source: per-entity ECDF at 95th percentile (IT) / cold-start type-level fallback for unseen attackers.

| Scenario | Threshold | TP | FP | n_atk | n_nml | Det Rate | FPR | AUROC |
|----------|-----------|----|----|-------|-------|----------|-----|-------|
| brute_force_auth | 0.5122 | 21 | 18 | 21 | 200 | 100.0% | 9.0% | 0.950 |
| command_execution_powershell | 0.5122 | 4 | 18 | 4 | 200 | 100.0% | 9.0% | 0.986 |
| lateral_movement_smb | 0.5122 | 9 | 18 | 9 | 200 | 100.0% | 9.0% | 0.950 |
| credential_stuffing | 0.5122 | 31 | 18 | 31 | 200 | 100.0% | 9.0% | 0.950 |
| privilege_escalation_token | 0.5122 | 3 | 18 | 3 | 200 | 100.0% | 9.0% | 0.950 |
| persistence_scheduled_task | 0.5122 | 2 | 18 | 2 | 200 | 100.0% | 9.0% | 0.974 |
| network_discovery_scan | 0.5122 | 50 | 18 | 50 | 200 | 100.0% | 9.0% | 0.950 |
| data_exfiltration_http | 0.5122 | 15 | 18 | 15 | 200 | 100.0% | 9.0% | 0.950 |
| full_kill_chain_it | 0.5122 | 26 | 18 | 26 | 200 | 100.0% | 9.0% | 0.954 |

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

  brute_force_auth                    [##------------------] 9.0%
  command_execution_powershell        [##------------------] 9.0%
  lateral_movement_smb                [##------------------] 9.0%
  credential_stuffing                 [##------------------] 9.0%
  privilege_escalation_token          [##------------------] 9.0%
  persistence_scheduled_task          [##------------------] 9.0%
  network_discovery_scan              [##------------------] 9.0%
  data_exfiltration_http              [##------------------] 9.0%
  full_kill_chain_it                  [##------------------] 9.0%

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
| Alerts instrumented | 161 |
| Mean MTTD | -0.595s |
| Median MTTD | -0.408s |
| P95 MTTD | 0.030s |
| Min MTTD | -7.905s |
| Max MTTD | 0.054s |
| Alerts within target | 100.0% |

### Secondary MTTD (extracted\_at → triggered\_at)

_Pipeline diagnostic: feature extraction → alert emission (pure processing latency)._

| Metric | Value |
|--------|-------|
| Mean | 0.0503s |
| Median | 0.0498s |
| P95 | 0.0972s |
| Min | 0.0060s |
| Max | 0.1033s |

### Per-Scenario MTTD Breakdown

| Scenario | N alerts | Mean MTTD (s) | Min (s) | Max (s) |
|----------|----------|--------------|---------|----------|
| brute_force_auth | 21 | -0.384 | -0.863 | 0.049 |
| command_execution_powershell | 4 | -0.240 | -0.654 | 0.009 |
| credential_stuffing | 31 | -0.409 | -0.878 | 0.030 |
| data_exfiltration_http | 15 | -0.937 | -3.958 | 0.018 |
| full_kill_chain_it | 26 | -1.218 | -7.905 | 0.054 |
| lateral_movement_smb | 9 | -0.869 | -2.374 | 0.017 |
| network_discovery_scan | 50 | -0.402 | -0.848 | 0.042 |
| persistence_scheduled_task | 2 | 0.007 | 0.006 | 0.008 |
| privilege_escalation_token | 3 | -0.158 | -0.489 | 0.009 |

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
- SHAP annotations: 161 alerts annotated.
- For threshold derivation details see: `thresholds/run-20260715T023436-74702a_IT_thresholds.json`
- For calibration details see: `calibration/calibrators/run-20260715T023436-74702a_IT_meta.json`
