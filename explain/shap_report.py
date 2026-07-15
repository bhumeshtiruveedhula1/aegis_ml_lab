"""
aegis_ml_lab/explain/shap_report.py
=====================================
Phase 4.1 — SHAP Audit Loop

Attaches SHAP TreeExplainer to the lab's IT Isolation Forest. Computes
SHAP values for any FeatureRecord that crossed the calibrated threshold,
annotates the record with the top-3 contributing features, and accumulates
a tally for the shap-audit report.

Design contracts (AEGIS_ML_Lab_ULTIMATE.md §4):
- Uses shap.TreeExplainer ONLY. No other SHAP variant.
- Never auto-removes a feature from the registry.
- top-3 annotation is an in-lab structure — does NOT touch production
  DetectionAlert or any downstream schema.
- Tally file (shap_tally.json) is append-updated, never overwritten.
- TreeExplainer is constructed once per run_id / entity_type and cached
  — do not reconstruct per alert (expensive).

Usage
-----
    from explain.shap_report import SHAPAnnotator

    annotator = SHAPAnnotator.for_run(run_id="run-...", entity_type="IT")
    annotation = annotator.explain(feature_record)  # returns SHAPAnnotation
    annotator.flush_tally()                          # write tally to disk

SHAP value sign convention for IsolationForest
------------------------------------------------
IsolationForest uses average_path_length internally. SHAP values for IF
represent each feature's contribution to the anomaly score:
  positive shap_value → feature pushed the score toward anomaly
  negative shap_value → feature pushed the score toward normal
We sort by |shap_value| for top-3 (absolute contribution regardless of sign).
"""

from __future__ import annotations

import json
import pickle
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
import structlog

_LAB_ROOT = Path(__file__).parent.parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

if TYPE_CHECKING:
    from backend.features.models import FeatureRecord

logger = structlog.get_logger(__name__)

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"
_RUNS_DIR = _LAB_ROOT / "runs"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SHAPEntry:
    """One feature's SHAP contribution to a single alert."""
    feature_id: str
    shap_value: float      # raw SHAP value (positive = toward anomaly)
    abs_shap: float        # |shap_value| — used for ranking
    feature_value: float   # the actual feature value at this event


@dataclass
class SHAPAnnotation:
    """SHAP top-3 annotation for one alert."""
    alert_id: str          # matches an alert_id or event_id for traceability
    entity_key: str
    entity_type: str
    run_id: str
    top3: list[SHAPEntry]  # sorted descending by abs_shap, length ≤ 3
    n_features: int
    raw_if_score: float    # decision_function value that triggered the alert

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "entity_key": self.entity_key,
            "entity_type": self.entity_type,
            "run_id": self.run_id,
            "raw_if_score": self.raw_if_score,
            "n_features": self.n_features,
            "shap_top3": [
                {
                    "feature_id": e.feature_id,
                    "shap_value": round(e.shap_value, 6),
                    "abs_shap": round(e.abs_shap, 6),
                    "feature_value": round(e.feature_value, 6),
                }
                for e in self.top3
            ],
        }


# ---------------------------------------------------------------------------
# Tally — persistent accumulator across multiple alerts
# ---------------------------------------------------------------------------

class SHAPTally:
    """
    Accumulates top-3 feature appearance counts across alerts for one run.

    Persisted to runs/<run_id>/shap_tally.json.
    Thread-safety: single-process only (lab context, not production).
    """

    def __init__(self, run_id: str, entity_type: str) -> None:
        self.run_id = run_id
        self.entity_type = entity_type
        self._tally_path = _RUNS_DIR / run_id / "shap_tally.json"
        self._counts: dict[str, int] = {}
        self._total_alerts: int = 0
        self._load_existing()

    def _load_existing(self) -> None:
        """Load any existing tally from disk (allows incremental accumulation)."""
        if self._tally_path.exists():
            data = json.loads(self._tally_path.read_text())
            self._counts = data.get("feature_counts", {})
            self._total_alerts = data.get("total_alerts", 0)
            logger.debug(
                "shap_tally_loaded",
                run_id=self.run_id,
                total_alerts=self._total_alerts,
                features_tracked=len(self._counts),
            )

    def record(self, annotation: SHAPAnnotation) -> None:
        """Increment counts for each of the top-3 features in this annotation."""
        self._total_alerts += 1
        for entry in annotation.top3:
            self._counts[entry.feature_id] = self._counts.get(entry.feature_id, 0) + 1

    def flush(self) -> Path:
        """Write tally to disk. Creates runs/<run_id>/ if needed."""
        out_dir = _RUNS_DIR / self.run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": self.run_id,
            "entity_type": self.entity_type,
            "total_alerts": self._total_alerts,
            "feature_counts": self._counts,
        }
        self._tally_path.write_text(json.dumps(payload, indent=2))
        logger.info(
            "shap_tally_flushed",
            run_id=self.run_id,
            total_alerts=self._total_alerts,
            path=str(self._tally_path),
        )
        return self._tally_path

    def appearance_rates(self, all_feature_names: list[str]) -> dict[str, float]:
        """
        Returns {feature_id: rate} for every feature in all_feature_names.
        rate = appearances / total_alerts. 0.0 if never appeared or no alerts.
        """
        if self._total_alerts == 0:
            return {f: 0.0 for f in all_feature_names}
        return {
            f: self._counts.get(f, 0) / self._total_alerts
            for f in all_feature_names
        }


# ---------------------------------------------------------------------------
# Main annotator
# ---------------------------------------------------------------------------

class SHAPAnnotator:
    """
    Constructs a shap.TreeExplainer for the lab IF model and produces
    SHAPAnnotation objects for individual alerts.

    Instantiate once per (run_id, entity_type) — TreeExplainer construction
    is expensive; do not build per alert.
    """

    def __init__(
        self,
        run_id: str,
        entity_type: str,
        det_pipeline,             # _DetectionPipeline (IF + preprocessor)
        feature_names: list[str],
    ) -> None:
        import shap

        self.run_id = run_id
        self.entity_type = entity_type
        self._det = det_pipeline
        self._feature_names = feature_names
        self._tally = SHAPTally(run_id=run_id, entity_type=entity_type)

        # Build TreeExplainer once. check_additivity=False avoids sklearn IF
        # internal caching issues that cause spurious additivity assertion failures.
        logger.info(
            "shap_explainer_building",
            entity_type=entity_type,
            run_id=run_id,
            n_features=len(feature_names),
        )
        self._explainer = shap.TreeExplainer(
            det_pipeline.isolation_forest,
            feature_perturbation="tree_path_dependent",
        )
        logger.info("shap_explainer_ready", entity_type=entity_type)

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def for_run(
        cls,
        run_id: str,
        entity_type: str,
    ) -> "SHAPAnnotator":
        """
        Load the latest trained model for (run_id, entity_type) and construct
        a SHAPAnnotator.  Raises FileNotFoundError if no model exists.
        """
        etype = entity_type.upper()
        pkl_path = _REGISTRY_DIR / run_id / etype / "isolation_forest.pkl"
        if not pkl_path.exists():
            # Fall back: most recent run with a model for this entity type
            candidates = sorted(_REGISTRY_DIR.iterdir()) if _REGISTRY_DIR.exists() else []
            hits = [d for d in candidates if (d / etype / "isolation_forest.pkl").exists()]
            if not hits:
                raise FileNotFoundError(
                    f"No trained IF model found for entity_type={etype!r}. "
                    "Run `python cli.py train --entity-type <type>` first."
                )
            pkl_path = hits[-1] / etype / "isolation_forest.pkl"
            run_id = hits[-1].name

        with pkl_path.open("rb") as f:
            det_pipeline = pickle.load(f)

        feature_names = list(det_pipeline.preprocessor.feature_names)
        return cls(
            run_id=run_id,
            entity_type=etype,
            det_pipeline=det_pipeline,
            feature_names=feature_names,
        )

    # ── Core explain ──────────────────────────────────────────────────────────

    def explain(
        self,
        record: "FeatureRecord",
        alert_id: str | None = None,
        raw_if_score: float = 0.0,
    ) -> SHAPAnnotation:
        """
        Compute SHAP values for one FeatureRecord and return a SHAPAnnotation.

        Parameters
        ----------
        record       : The FeatureRecord to explain.
        alert_id     : Optional alert ID for traceability (uses event_id if None).
        raw_if_score : The raw IF decision_function value for this record.

        Returns
        -------
        SHAPAnnotation with top-3 features by |shap_value|.
        """
        fv = record.feature_vector

        # Build scaled feature matrix (1 × n_features)
        X_scaled = self._det.preprocessor.transform([record])  # shape (1, n_features)

        # Compute SHAP values — shape depends on shap version:
        # For IsolationForest: shap_values is ndarray of shape (1, n_features)
        raw_shap = self._explainer.shap_values(X_scaled)

        # Normalize to 2-D (1, n_features) regardless of shap version quirks
        if isinstance(raw_shap, list):
            shap_vals = np.array(raw_shap[0])  # IF returns list with one element
        else:
            shap_vals = np.array(raw_shap)
        if shap_vals.ndim == 1:
            shap_vals = shap_vals.reshape(1, -1)
        shap_row = shap_vals[0]  # (n_features,)

        # Rank by absolute value
        abs_vals = np.abs(shap_row)
        top3_idx = np.argsort(abs_vals)[::-1][:3]

        top3 = []
        for idx in top3_idx:
            fname = self._feature_names[idx]
            top3.append(SHAPEntry(
                feature_id=fname,
                shap_value=float(shap_row[idx]),
                abs_shap=float(abs_vals[idx]),
                feature_value=float(fv.values.get(fname, 0.0)),
            ))

        annotation = SHAPAnnotation(
            alert_id=alert_id or getattr(record, "event_id", "unknown"),
            entity_key=str(record.entity_key),
            entity_type=self.entity_type,
            run_id=self.run_id,
            top3=top3,
            n_features=len(self._feature_names),
            raw_if_score=raw_if_score,
        )

        self._tally.record(annotation)
        return annotation

    def explain_batch(
        self,
        records: list["FeatureRecord"],
        alert_ids: list[str] | None = None,
        raw_if_scores: list[float] | None = None,
    ) -> list[SHAPAnnotation]:
        """
        Explain a batch of FeatureRecords. More efficient than calling
        explain() in a loop for large batches.
        """
        if not records:
            return []

        X_scaled = self._det.preprocessor.transform(records)  # (n, n_features)
        raw_shap = self._explainer.shap_values(X_scaled)

        if isinstance(raw_shap, list):
            shap_matrix = np.array(raw_shap[0])
        else:
            shap_matrix = np.array(raw_shap)
        if shap_matrix.ndim == 1:
            shap_matrix = shap_matrix.reshape(1, -1)

        annotations = []
        for i, record in enumerate(records):
            shap_row = shap_matrix[i]
            abs_vals = np.abs(shap_row)
            top3_idx = np.argsort(abs_vals)[::-1][:3]
            fv = record.feature_vector

            top3 = [
                SHAPEntry(
                    feature_id=self._feature_names[idx],
                    shap_value=float(shap_row[idx]),
                    abs_shap=float(abs_vals[idx]),
                    feature_value=float(fv.values.get(self._feature_names[idx], 0.0)),
                )
                for idx in top3_idx
            ]
            ann = SHAPAnnotation(
                alert_id=(alert_ids[i] if alert_ids else None) or getattr(record, "event_id", f"rec-{i}"),
                entity_key=str(record.entity_key),
                entity_type=self.entity_type,
                run_id=self.run_id,
                top3=top3,
                n_features=len(self._feature_names),
                raw_if_score=(raw_if_scores[i] if raw_if_scores else 0.0),
            )
            self._tally.record(ann)
            annotations.append(ann)

        return annotations

    def flush_tally(self) -> Path:
        """Persist the tally file to disk. Call after processing all alerts."""
        return self._tally.flush()

    @property
    def tally(self) -> SHAPTally:
        return self._tally

    @property
    def feature_names(self) -> list[str]:
        return list(self._feature_names)


# ---------------------------------------------------------------------------
# Audit report generator (called by shap-audit CLI command)
# ---------------------------------------------------------------------------

def generate_audit_report(
    run_id: str,
    entity_type: str,
    high_rate_threshold: float = 0.5,
) -> str:
    """
    Load shap_tally.json for run_id and produce a markdown audit report.

    Parameters
    ----------
    run_id              : The run to audit.
    entity_type         : "IT" or "OT"
    high_rate_threshold : Features with appearance_rate >= this are flagged as
                          consistently dominant (for human review).

    Returns
    -------
    Markdown string for the audit report.
    """
    import pickle

    etype = entity_type.upper()
    tally_path = _RUNS_DIR / run_id / "shap_tally.json"
    if not tally_path.exists():
        raise FileNotFoundError(
            f"No shap_tally.json found for run_id={run_id!r}. "
            "Run `python cli.py evaluate --all-scenarios` first to generate SHAP tallies."
        )

    tally_data = json.loads(tally_path.read_text())
    total_alerts = tally_data.get("total_alerts", 0)
    feature_counts = tally_data.get("feature_counts", {})

    if total_alerts == 0:
        return (
            f"# SHAP Audit Report — {etype} ({run_id})\n\n"
            f"**No alerts processed.** Run the evaluate harness first.\n"
        )

    # Load feature names from model
    pkl_path = _REGISTRY_DIR / run_id / etype / "isolation_forest.pkl"
    if not pkl_path.exists():
        candidates = sorted(_REGISTRY_DIR.iterdir()) if _REGISTRY_DIR.exists() else []
        hits = [d for d in candidates if (d / etype / "isolation_forest.pkl").exists()]
        pkl_path = hits[-1] / etype / "isolation_forest.pkl" if hits else None

    all_feature_names: list[str] = []
    if pkl_path and pkl_path.exists():
        with pkl_path.open("rb") as f:
            det = pickle.load(f)
        all_feature_names = list(det.preprocessor.feature_names)

    # Compute rates
    rates: dict[str, float] = {}
    for fname in (all_feature_names or list(feature_counts.keys())):
        rates[fname] = feature_counts.get(fname, 0) / total_alerts

    # Sort by rate descending
    ranked = sorted(rates.items(), key=lambda x: x[1], reverse=True)

    never_top3 = [f for f, r in rates.items() if r == 0.0]
    always_dominant = [f for f, r in rates.items() if r >= high_rate_threshold]
    moderate = [f for f, r in rates.items() if 0.0 < r < high_rate_threshold]

    lines = [
        f"# SHAP Audit Report — {etype} ({run_id})",
        f"",
        f"**Total alerts processed:** {total_alerts}",
        f"**Features tracked:** {len(all_feature_names) or len(feature_counts)}",
        f"**High-rate threshold:** {high_rate_threshold:.0%} (feature in top-3 >= this fraction of alerts)",
        f"",
        f"---",
        f"",
        f"## Feature Appearance Rates (top-3 frequency)",
        f"",
        f"| Rank | Feature | Count | Rate | Status |",
        f"|------|---------|-------|------|--------|",
    ]

    for i, (fname, rate) in enumerate(ranked, 1):
        count = feature_counts.get(fname, 0)
        if rate >= high_rate_threshold:
            status = "DOMINANT — review if signal or artifact"
        elif rate == 0.0:
            status = "NEVER in top-3 — consider review"
        else:
            status = "active"
        lines.append(f"| {i} | `{fname}` | {count} | {rate:.1%} | {status} |")

    lines += [
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        f"### Consistently dominant (rate >= {high_rate_threshold:.0%}) — {len(always_dominant)} features",
        f"These features appear in the top-3 of >= {high_rate_threshold:.0%} of alerts.",
        f"Verify they represent genuine signal, not a data artefact.",
        f"",
    ]
    for f in always_dominant:
        lines.append(f"- `{f}` (rate: {rates[f]:.1%})")

    lines += [
        f"",
        f"### Never in top-3 — {len(never_top3)} features",
        f"These features contributed zero top-3 appearances across all {total_alerts} alerts.",
        f"Flag for human review. Do NOT auto-remove — may contribute in ensemble or edge cases.",
        f"",
    ]
    for f in never_top3:
        lines.append(f"- `{f}`")

    lines += [
        f"",
        f"> **Note:** No features are automatically removed or deprecated based on SHAP tally.",
        f"> This report is for human review only. Registry changes require explicit human decision.",
        f"",
    ]

    return "\n".join(lines)


def run_shap_audit(run_id: str, entity_type: str) -> Path:
    """
    Generate SHAP audit report and save to runs/<run_id>/shap_audit_report.md.
    Returns the path.
    """
    report_md = generate_audit_report(run_id=run_id, entity_type=entity_type)
    out_dir = _RUNS_DIR / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "shap_audit_report.md"
    out_path.write_text(report_md, encoding="utf-8")
    logger.info("shap_audit_report_saved", path=str(out_path))
    print(report_md)
    return out_path
