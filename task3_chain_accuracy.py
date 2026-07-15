"""
task3_chain_accuracy.py — Chain-Link Accuracy vs Ground Truth (v4, real SHAP path)
====================================================================================
All data synthetic (SyntheticAttackService, seed=1337). Ground truth from
AttackTemplate.mitre_techniques + stage.mitre_technique_hint.

SCORING PATH (exactly matches seed_sweep):
  - load_calibrator(run_id, "IT").predict_proba()
  - _score_records, _get_feature_records from run_e2e_suite
  - threshold = thresholds.type_level_fallback

TECHNIQUE PREDICTION (fixed vs v3):
  For each alerting FeatureRecord:
    1. Build a DetectionAlert from the record + calibrated score.
    2. Run SHAPAnnotator.explain() → SHAPAnnotation (top-3 features by |SHAP|).
    3. Convert SHAPAnnotation → ExplanationResult (minimal fields the mapper uses).
    4. Call MitreMapper.map_alert(alert, explanation) — the real production path.
  Union technique IDs across all alerting records per scenario.

  v3 used a direct KB-lookup bypass (no SHAP, no map_alert) which measured
  the mapper's no-SHAP fallback, not the fixed SHAP-top-3 path. This version
  exercises the actual code path that was fixed.

METRIC (set-level, unchanged from v3):
  precision = |GT ∩ Pred| / |Pred|
  recall    = |GT ∩ Pred| / |GT|
  F1        = 2PR/(P+R)
  full_chain_acc = 1.0 iff GT == Pred (exact set match)

Run: python aegis_ml_lab/task3_chain_accuracy.py
Output: runs/task3_chain_accuracy_<ts>.json
"""
from __future__ import annotations
import json
import pickle
import sys
from datetime import UTC, datetime
from pathlib import Path

_LAB_ROOT = Path(__file__).parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import warnings
warnings.filterwarnings("ignore")
import logging
logging.disable(logging.WARNING)
import numpy as np
import structlog

logger = structlog.get_logger(__name__)

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"
_RUNS_DIR     = _LAB_ROOT / "runs"
_BASELINE_DIR = _LAB_ROOT / "models" / "baselines"

from evaluate.run_e2e_suite import _IT_SCENARIOS, _get_feature_records, _score_records, _ENTITY_DIM

EVAL_SEED = 1337
RUN = "run-20260712T160707-a72627"


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def _get_ground_truth_techniques(scenario_name: str) -> list[str]:
    """GT: template.mitre_techniques + stage.mitre_technique_hint (deduplicated)."""
    from backend.synthetic_attack.templates import get_template
    gt: list[str] = []
    try:
        tpl = get_template(scenario_name)
        for t in tpl.mitre_techniques:
            if t and t not in gt:
                gt.append(t)
        for stage in tpl.stages:
            if stage.mitre_technique_hint and stage.mitre_technique_hint not in gt:
                gt.append(stage.mitre_technique_hint)
    except Exception as exc:
        logger.warning("gt_failed", scenario=scenario_name, error=str(exc))
    return gt


# ---------------------------------------------------------------------------
# Bridge: FeatureRecord + SHAPAnnotation → DetectionAlert + ExplanationResult
# ---------------------------------------------------------------------------

def _build_detection_alert(
    record,
    cal_score: float,
    threshold: float,
    raw_if_score: float,
    model_id: str,
) -> "DetectionAlert":
    """
    Build a minimal DetectionAlert from a FeatureRecord and its calibrated score.
    Uses only fields available on FeatureRecord — no production scorer involved.
    All data is synthetic.
    """
    from backend.detection.models import DetectionAlert
    from backend.features.models import FEATURE_DIMENSION

    return DetectionAlert(
        alert_id=f"alert-{record.event_id}",
        model_id=model_id,
        entity_key=record.entity_key,
        event_id=record.event_id,
        event_type=record.event_type,
        event_source=record.event_source,
        event_timestamp=record.event_timestamp,
        event_host=record.event_host,
        event_user=record.event_user,
        anomaly_score=float(cal_score),
        raw_if_score=float(raw_if_score),
        threshold_used=float(threshold),
        feature_dimension=FEATURE_DIMENSION,
        raw_feature_values={k: float(v) for k, v in record.feature_vector.values.items()},
        novelty_count=sum(1 for v in record.feature_vector.values.values() if v != 0.0),
        baseline_available=record.baseline_available,
    )


def _shap_annotation_to_explanation(
    annotation,   # SHAPAnnotation
    alert_id: str,
    model_id: str,
    cal_score: float,
    record,
) -> "ExplanationResult":
    """
    Convert a SHAPAnnotation (lab structure) to ExplanationResult (production structure).
    Only populates the fields MitreMapper.map_alert() actually reads:
      - top_features: list[str]  (the top-3 feature names by |SHAP|)
      - feature_contributions    (FeatureContribution objects, one per top-3 entry)
    Everything else is filled with safe defaults.
    """
    from backend.explainability.models import ExplanationResult, FeatureContribution

    top_features = [e.feature_id for e in annotation.top3]
    total_abs = sum(e.abs_shap for e in annotation.top3)

    contributions = []
    for rank, entry in enumerate(annotation.top3, start=1):
        contributions.append(FeatureContribution(
            feature_name=entry.feature_id,
            raw_value=float(entry.feature_value),
            shap_value=float(entry.shap_value),
            abs_shap_value=float(entry.abs_shap),
            contribution_rank=rank,
            contribution_pct=round(entry.abs_shap / total_abs * 100, 4) if total_abs > 0 else 0.0,
            direction="anomaly" if entry.shap_value > 0 else "normal",
        ))

    return ExplanationResult(
        explanation_id=f"expl-{alert_id}",
        alert_id=alert_id,
        model_id=model_id,
        entity_type=record.entity_key.entity_type,
        entity_id=record.entity_key.entity_id,
        event_id=record.event_id,
        anomaly_score=float(cal_score),
        expected_value=0.0,        # not used by mapper
        total_abs_shap=float(total_abs),
        feature_contributions=contributions,
        top_features=top_features,
    )


# ---------------------------------------------------------------------------
# Metric
# ---------------------------------------------------------------------------

def score_chain(gt: list[str], pred: list[str]) -> dict:
    gs, ps = set(gt), set(pred)
    tp = len(gs & ps)
    prec = tp / len(ps) if ps else 0.0
    rec  = tp / len(gs) if gs else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return {
        "gt_techniques":   sorted(gt),
        "pred_techniques": sorted(pred),
        "tp": tp, "fp": len(ps - gs), "fn": len(gs - ps),
        "precision":      round(prec, 4),
        "recall":         round(rec,  4),
        "f1":             round(f1,   4),
        "full_chain_acc": 1.0 if gs == ps else 0.0,
    }


# ---------------------------------------------------------------------------
# Per-scenario runner — real SHAP + map_alert path
# ---------------------------------------------------------------------------

def run_scenario(
    scenario_name: str,
    kwargs: dict,
    det_pipeline,
    calibrator,
    threshold: float,
    reader,
    entity_dim: str,
    annotator,      # SHAPAnnotator — constructed once outside, reused here
    mapper,         # MitreMapper — constructed once outside
    model_id: str,
) -> dict:
    """
    Generate attack events, score them, and for each alerting record:
      1. Build DetectionAlert
      2. Run SHAPAnnotator.explain() → SHAPAnnotation
      3. Convert to ExplanationResult
      4. Call MitreMapper.map_alert(alert, explanation)
    Union technique IDs across all alerting records for this scenario.
    All data is synthetic (SyntheticAttackService, seed=EVAL_SEED).
    """
    from backend.synthetic_attack.service import SyntheticAttackService

    gt = _get_ground_truth_techniques(scenario_name)

    svc    = SyntheticAttackService(persist=False, seed=EVAL_SEED)
    report = svc.generate(scenario_name, **kwargs)
    events = svc.get_canonical_events(report)

    all_records = _get_feature_records(events, reader, entity_dim)
    if not all_records:
        return {
            "scenario": scenario_name,
            "n_events": len(events), "n_records": 0, "n_alerts": 0,
            "gt_len": len(gt), "pred_len": 0,
            **score_chain(gt, []),
            "note": "no_records",
        }

    raw = _score_records(det_pipeline, all_records)
    cal = calibrator.predict_proba(raw)

    # Process alerting records through the real SHAP + map_alert path
    pred_techniques: set[str] = set()
    n_alerts = 0

    for cal_score, raw_if_score, rec in zip(cal, raw, all_records):
        if cal_score < threshold:
            continue
        n_alerts += 1

        # Step 1: Build DetectionAlert
        alert = _build_detection_alert(
            record=rec,
            cal_score=cal_score,
            threshold=threshold,
            raw_if_score=float(raw_if_score),
            model_id=model_id,
        )

        # Step 2: SHAP explanation via proven SHAPAnnotator
        try:
            annotation = annotator.explain(
                rec,
                alert_id=alert.alert_id,
                raw_if_score=float(raw_if_score),
            )
        except Exception as exc:
            logger.warning("shap_explain_failed", event_id=rec.event_id, error=str(exc))
            continue

        # Step 3: Convert to ExplanationResult
        explanation = _shap_annotation_to_explanation(
            annotation=annotation,
            alert_id=alert.alert_id,
            model_id=model_id,
            cal_score=cal_score,
            record=rec,
        )

        # Step 4: map_alert — the real fixed production path
        try:
            mapped = mapper.map_alert(alert, explanation)
            for tm in mapped.techniques:
                pred_techniques.add(tm.technique.technique_id)
        except Exception as exc:
            logger.warning("map_alert_failed", event_id=rec.event_id, error=str(exc))

    pred = sorted(pred_techniques)
    accuracy = score_chain(gt, pred)

    return {
        "scenario":    scenario_name,
        "n_events":    len(events),
        "n_records":   len(all_records),
        "n_alerts":    n_alerts,
        "gt_len":      len(gt),
        "pred_len":    len(pred),
        **accuracy,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from calibration.fit_isotonic import load_calibrator
    from thresholds.compute_ecdf import load_thresholds
    from backend.baseline.reader_api import BaselineReader
    from explain.shap_report import SHAPAnnotator
    from backend.mitre.mapper import MitreMapper

    pkl = _REGISTRY_DIR / RUN / "IT" / "isolation_forest.pkl"
    with pkl.open("rb") as f:
        det_pipeline = pickle.load(f)

    calibrator = load_calibrator(RUN, "IT")
    thresholds = load_thresholds(RUN, "IT")
    threshold  = thresholds.type_level_fallback
    reader     = BaselineReader(baseline_dir=_BASELINE_DIR / "IT")
    entity_dim = _ENTITY_DIM["IT"]
    model_id   = det_pipeline.metadata.model_id if hasattr(det_pipeline, "metadata") else RUN

    # Build SHAPAnnotator once (TreeExplainer construction is expensive)
    print("Building SHAPAnnotator (TreeExplainer)...")
    annotator = SHAPAnnotator(
        run_id=RUN,
        entity_type="IT",
        det_pipeline=det_pipeline,
        feature_names=list(det_pipeline.preprocessor.feature_names),
    )
    mapper = MitreMapper()

    print(f"model={RUN}  threshold={threshold:.4f}  eval_seed={EVAL_SEED}")
    print(f"method=MitreMapper.map_alert() with real SHAPAnnotator top-3 explanations\n")

    results = []
    for sc_name, kwargs in _IT_SCENARIOS.items():
        print(f"  {sc_name}...", end="", flush=True)
        try:
            r = run_scenario(
                sc_name, kwargs, det_pipeline, calibrator,
                threshold, reader, entity_dim,
                annotator=annotator,
                mapper=mapper,
                model_id=model_id,
            )
            results.append(r)
            print(f" alerts={r['n_alerts']}/{r['n_records']} GT={r['gt_len']} Pred={r['pred_len']} "
                  f"P={r['precision']:.3f} R={r['recall']:.3f} F1={r['f1']:.3f} FullChain={r['full_chain_acc']:.1f}")
        except Exception as exc:
            import traceback; traceback.print_exc()
            results.append({"scenario": sc_name, "error": str(exc)})
            print(f" FAILED: {exc}")

    valid = [r for r in results if "error" not in r]
    print(f"\n=== CHAIN-LINK ACCURACY (vs ATT&CK GROUND TRUTH) ===")
    print(f"{'Scenario':<42} {'Alerts':>8} {'GT':>4} {'Pred':>5} {'P':>7} {'R':>7} {'F1':>7} {'FullChain':>10}")
    for r in valid:
        print(f"{r['scenario']:<42} {str(r['n_alerts'])+'/'+str(r['n_records']):>8} "
              f"{r['gt_len']:>4} {r['pred_len']:>5} "
              f"{r['precision']:>7.3f} {r['recall']:>7.3f} {r['f1']:>7.3f} {r['full_chain_acc']:>10.1f}")

    if valid:
        prec_vals = [r['precision'] for r in valid]
        rec_vals  = [r['recall']    for r in valid]
        f1_vals   = [r['f1']        for r in valid]
        fc_vals   = [r['full_chain_acc'] for r in valid]
        print(f"\nAGGREGATE (n={len(valid)}):")
        print(f"  precision={np.mean(prec_vals):.3f}  recall={np.mean(rec_vals):.3f}  "
              f"F1={np.mean(f1_vals):.3f}  full_chain_acc={np.mean(fc_vals):.3f}")
        print(f"  total_alerts={sum(r['n_alerts'] for r in valid)}  "
              f"scenarios_with_alerts={sum(1 for r in valid if r['n_alerts']>0)}/9")

        print(f"\nBASELINE (v3 KB-direct, pre-fix): P=0.042 R=0.778 F1=0.078")
        print(f"THIS RUN  (v4 map_alert+SHAP):      "
              f"P={np.mean(prec_vals):.3f} R={np.mean(rec_vals):.3f} F1={np.mean(f1_vals):.3f}")

    ts  = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    out = _RUNS_DIR / f"task3_chain_accuracy_{ts}.json"
    out.write_text(json.dumps({
        "run_id":     RUN,
        "threshold":  threshold,
        "eval_seed":  EVAL_SEED,
        "method":     "MitreMapper.map_alert() with SHAPAnnotator top-3 ExplanationResult (v4 real SHAP path)",
        "baseline_v3": {"precision": 0.042, "recall": 0.778, "f1": 0.078,
                        "note": "KB-direct lookup, no SHAP, pre-mapper-fix"},
        "results": results,
        "aggregate": {
            "precision_mean":      round(float(np.mean([r['precision'] for r in valid])), 4) if valid else None,
            "recall_mean":         round(float(np.mean([r['recall']    for r in valid])), 4) if valid else None,
            "f1_mean":             round(float(np.mean([r['f1']        for r in valid])), 4) if valid else None,
            "full_chain_acc_mean": round(float(np.mean([r['full_chain_acc'] for r in valid])), 4) if valid else None,
            "total_alerts":        sum(r['n_alerts'] for r in valid) if valid else 0,
        },
    }, indent=2, default=str))
    print(f"\n[Task 3] Written to {out}")
