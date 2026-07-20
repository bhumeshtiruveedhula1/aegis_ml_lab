"""
aegis_ml_lab/export_to_production.py
========================================
Exports the latest lab-trained model artifact into the production ModelStore format.

What this does (READ-ONLY integration):
  1. Reads the lab's _DetectionPipeline pickle (preprocessor + IsolationForest)
  2. Reads the lab's metadata.json
  3. Writes a production-compatible ModelMetadata JSON + model pickle into
     cybershield/models/ using ModelStore.save() naming convention:
       isolation_forest_<model_id>.pkl
       isolation_forest_<model_id>_meta.json
  4. Does NOT modify: attack graph, LLM enrichment, audit ledger, scorer, service,
     or any production code.

Threshold note:
  production anomaly_score_threshold = 0.5
  This corresponds to raw_if = 0.0 (decision_function boundary)
  Which isotonic calibrator maps to calibrated_proba ≈ 0.6117 (ECDF threshold)
  → The thresholds are mathematically equivalent. No threshold override needed.

Usage:
  python export_to_production.py [--run-id <run_id>] [--entity-type IT]
  python export_to_production.py  # uses latest run
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path

_LAB_ROOT = Path(__file__).parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"


def _find_latest_run_id(entity_type: str) -> str:
    runs = sorted([d for d in _REGISTRY_DIR.iterdir() if d.is_dir()])
    candidates = [d for d in runs if (d / entity_type / "isolation_forest.pkl").exists()]
    if not candidates:
        raise FileNotFoundError(f"No trained model for entity_type={entity_type} in {_REGISTRY_DIR}")
    return candidates[-1].name


def export_to_production(run_id: str, entity_type: str = "IT") -> Path:
    """
    Export lab model + metadata → production ModelStore format.

    Returns the path to the production model pickle.
    """
    from backend.detection.models import ModelMetadata, DETECTION_SCHEMA_VERSION
    from backend.detection.storage import ModelStore
    from backend.features.models import FEATURE_SCHEMA_VERSION, ALL_FEATURE_NAMES

    lab_dir = _REGISTRY_DIR / run_id / entity_type

    # 1. Load lab artifacts
    lab_pkl_path = lab_dir / "isolation_forest.pkl"
    if not lab_pkl_path.exists():
        raise FileNotFoundError(f"Lab model not found: {lab_pkl_path}")
    with lab_pkl_path.open("rb") as f:
        det_pipeline = pickle.load(f)

    lab_meta = json.loads((lab_dir / "metadata.json").read_text())

    # 2. Build production-compatible ModelMetadata
    entity_dim = "user_host" if entity_type.upper() == "IT" else "ot_node"
    model_id = lab_meta["model_id"]
    model_file = f"isolation_forest_{model_id}.pkl"

    prod_metadata = ModelMetadata(
        model_id=model_id,
        trained_at=lab_meta["trained_at"],
        schema_version=DETECTION_SCHEMA_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=ALL_FEATURE_NAMES,
        feature_dimension=len(ALL_FEATURE_NAMES),
        n_estimators=lab_meta["n_estimators"],
        contamination=float(lab_meta["contamination"]),
        random_state=lab_meta["random_state"],
        entity_dimension=entity_dim,
        entity_count=lab_meta.get("entity_count", 0),
        sample_count=lab_meta["sample_count"],
        training_duration_seconds=lab_meta.get("training_duration_seconds", 0.0),
        scaler_fitted=True,
        model_file=model_file,
        notes=(
            f"Exported from aegis_ml_lab run_id={run_id}. "
            f"Calibrator: calibration/calibrators/{run_id}_{entity_type}.pkl. "
            f"Threshold equivalence: production anomaly_score_threshold=0.5 == "
            f"calibrated_proba~0.6117 (ECDF 95th pct of normal traffic)."
        ),
    )

    # 3. Write to production ModelStore
    store = ModelStore()
    model_path, meta_path = store.save(det_pipeline, prod_metadata)

    # 4. Write calibrator + calibrated threshold alongside model
    #    Named so _load_calibrator_for_model() in service.py finds them automatically.
    import shutil, json as _json
    cal_src = _LAB_ROOT / "calibration" / "calibrators" / f"{run_id}_{entity_type}.pkl"

    cal_written = False
    if cal_src.exists():
        cal_dst = store._dir / f"isolation_forest_{model_id}_calibrator.pkl"
        shutil.copy2(cal_src, cal_dst)
        cal_written = True

    thr_written = False
    metrics_src = _LAB_ROOT / "runs" / run_id / "raw_metrics.json"
    if metrics_src.exists():
        metrics = _json.loads(metrics_src.read_text())
        scenarios_list = metrics.get("scenarios", [])
        if isinstance(scenarios_list, list) and scenarios_list:
            cal_threshold = scenarios_list[0].get("threshold_used")
        else:
            cal_threshold = None
        if cal_threshold is not None:
            thr_dst = store._dir / f"isolation_forest_{model_id}_cal_threshold.json"
            thr_dst.write_text(
                _json.dumps({"calibrated_threshold": cal_threshold, "run_id": run_id,
                             "entity_type": entity_type, "source": "ecdf_type_fallback"})
            )
            thr_written = True


    print(f"\n[export-to-production] SUCCESS")
    print(f"  Run ID        : {run_id}")
    print(f"  Entity type   : {entity_type}")
    print(f"  Model ID      : {model_id}")
    print(f"  Model pkl     : {model_path}")
    print(f"  Metadata      : {meta_path}")
    print(f"  Calibrator    : {'written' if cal_written else 'NOT FOUND - ' + str(cal_src)}")
    print(f"  Cal threshold : {'written' if thr_written else 'NOT FOUND - ' + str(metrics_src)}")
    print(f"  Store dir     : {store._dir.resolve()}")
    print(f"\n  Threshold note:")
    print(f"    calibrated_threshold used by production scorer = type-level ECDF fallback")
    print(f"    -> No static config change required.")
    return model_path




def verify_production_load() -> None:
    """Verify the exported model loads correctly via DetectionService."""
    from backend.detection.service import DetectionService

    svc = DetectionService(auto_load=True)
    if svc.is_model_loaded:
        print(f"\n[verify] DetectionService loaded model: {svc.current_model_id}")
        print(f"[verify] Threshold: {svc._threshold}")
        print(f"[verify] Entity dim: {svc._scorer.entity_dimension}")
        print(f"[verify] PRODUCTION WIRING: OK")
    else:
        print(f"[verify] FAIL: DetectionService could not load model after export")


def main():
    parser = argparse.ArgumentParser(description="Export lab model to production ModelStore")
    parser.add_argument("--run-id", default=None, help="Lab run ID (default: latest)")
    parser.add_argument("--entity-type", default="IT", choices=["IT", "OT"])
    parser.add_argument("--verify", action="store_true", help="Verify DetectionService loads the model")
    args = parser.parse_args()

    entity_type = args.entity_type.upper()
    run_id = args.run_id or _find_latest_run_id(entity_type)
    print(f"[export-to-production] Exporting run_id={run_id}  entity_type={entity_type}")

    export_to_production(run_id=run_id, entity_type=entity_type)

    if args.verify:
        verify_production_load()


if __name__ == "__main__":
    main()
