# AEGIS ML Lab — Judge Summary

**Run ID:** `run-20260711T121626-e7e047`  
**Entity type:** IT  
**Generated:** 2026-07-12T15:59:37 UTC  
**Calibration/Evaluation non-overlap:** ✅ VERIFIED

---

## Detection Results (eval_seed=1337)

| Scenario | N atk | Det Rate | FPR | AUROC | Threshold |
|----------|-------|----------|-----|-------|-----------|
| brute_force_auth | 21 | [OK] 100.0% | [WARN] 14.0% | 0.930 | 0.3750 |
| command_execution_powershell | 4 | [OK] 100.0% | [WARN] 14.0% | 1.000 | 0.3750 |
| lateral_movement_smb | 9 | [OK] 100.0% | [WARN] 14.0% | 1.000 | 0.3750 |

---

## Seed Sweep Stability (Phase 6.1)

**Verdict:** [FAIL] `UNSTABLE` (5 seeds)  
**DR range:** 100.0pp  
**FPR range:** 2.5pp

> [WARN] UNSTABLE: Detection rate range=100.0pp across 5 seeds (threshold: 10.0pp). Model performance depends strongly on IF random seed.

---

## Adversarial Drift (Phase 6.2)

**Overall:** [OK] `DETECTED — Model correctly detected brute_force_auth at all ...`  
**Native drift API:** No (simulation used)  
**Fractions tested:** []  
**Per-fraction verdicts:** []

---

## SHAP Feature Audit (Phase 4)

**Total alerts annotated:** 157  

| Rank | Feature | Alert Count | Dominance % |
|------|---------|-------------|-------------|

---

## OT Evaluation

> [WARN] **Known limitation:** OT evaluation not run — known limitation. Reason: OT baseline window is < 14 days (production data requirement). OT model training was incomplete due to insufficient historical depth. Resolution: accumulate ≥14 days of real OT telemetry, then re-run train → calibrate → evaluate for OT entity type.

---

## Mandatory Deferred Items

| Item | Status | Reason |
|------|--------|--------|
| CRC — Concept Drift Detection (ADWIN/DDM) | `DEFERRED` | Requires a live production event stream to detect real temporal drift.... |
| ADWIN Statistical Drift Window | `DEFERRED` | Depends on CRC above. ADWIN requires a sliding-window stream of produc... |
| SHAP-NL — Natural Language SHAP Explanations | `DEFERRED` | Requires an LLM integration layer to convert SHAP feature importance v... |