"""
aegis_ml_lab/features/build_feature_vector.py
===============================================
Assembles feature vectors by DELEGATING to the production extractor pipeline.

Design contract:
  - The lab does NOT re-implement feature extraction logic.
  - It calls the same production BaseExtractor subclasses that
    cybershield/backend uses, then selects the subset marked
    status=="active" in feature_registry.yaml.
  - This is the correct "wraps the pipeline without touching it" pattern.

Feature ordering:
  - Active features are sorted alphabetically by id.
  - This ordering is stable and must be preserved in model artifacts.
  - A feature_names.json is written per run to record the vector layout.

Usage
-----
    from features.build_feature_vector import ProductionFeatureVectorBuilder

    builder = ProductionFeatureVectorBuilder()
    vector, names = builder.build(event, baseline, entity_type="IT")
    dim = builder.get_feature_dimension("IT")
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
import structlog
import yaml

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline
    from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)

_LAB_ROOT = Path(__file__).parent.parent          # aegis_ml_lab/
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"  # cybershield/


def _ensure_paths() -> None:
    """Ensure both lab and cybershield roots are importable."""
    for root in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
        if root not in sys.path:
            sys.path.insert(0, root)


# ---------------------------------------------------------------------------
# Production extractor access — thin delegation layer
# ---------------------------------------------------------------------------

def _load_production_extractors() -> dict:
    """
    Import and instantiate the production BaseExtractor subclasses.

    Returns dict: group_name → extractor_instance
    Fails loud if production extractors cannot be imported.
    """
    _ensure_paths()
    try:
        from backend.features.extractors import _build_registry
        return _build_registry()
    except ImportError as exc:
        raise RuntimeError(
            f"Cannot import production extractors from cybershield/backend. "
            f"Ensure you are running from the project root (cyber-et/). Error: {exc}"
        ) from exc


def _get_group_for_feature(feature_id: str) -> str:
    """
    Derive the production extractor group from the registry extractor_fn path.

    Registry format: "prod.auth.logon_type_is_novel"
    Group field returned: "auth"

    For candidate features (lab.*), returns "candidate".
    """
    return "candidate"  # overridden below in ProductionFeatureVectorBuilder._build_mapping


# ---------------------------------------------------------------------------
# Feature Vector Builder
# ---------------------------------------------------------------------------

class ProductionFeatureVectorBuilder:
    """
    Builds feature vectors from production extractors, filtered to active
    features in feature_registry.yaml.

    The vector is assembled by running all applicable production extractors
    once per event, then selecting only the active feature keys in sorted order.

    Parameters
    ----------
    registry_path : Path to feature_registry.yaml. Default: config/feature_registry.yaml.
    """

    def __init__(self, registry_path: Path | str | None = None) -> None:
        _ensure_paths()
        path = Path(registry_path) if registry_path else (_LAB_ROOT / "config" / "feature_registry.yaml")
        self._registry: list[dict] = self._load_registry(path)
        self._extractors: dict = _load_production_extractors()
        # group_name → set of feature_ids needed from that group
        self._group_to_active = self._build_group_mapping()
        self._lab_feature_fns = self._build_lab_feature_fns()
        logger.info(
            "prod_feature_vector_builder_init",
            active_it=self.get_feature_dimension("IT"),
            active_ot=self.get_feature_dimension("OT"),
            groups_used=list(self._group_to_active.keys()),
            lab_features=list(self._lab_feature_fns.keys()),
        )

    # ── Public API ─────────────────────────────────────────────────────────

    def build(
        self,
        event: "CanonicalEvent",
        baseline: "EntityBaseline | None",
        entity_type: str,
    ) -> tuple[np.ndarray, list[str]]:
        """
        Build a feature vector for one event using production extractors.

        Parameters
        ----------
        event       : CanonicalEvent
        baseline    : EntityBaseline or None (cold-start)
        entity_type : "IT" or "OT"

        Returns
        -------
        (vector np.ndarray, feature_names list[str])
        Both have the same length and same ordering.

        Raises
        ------
        RuntimeError: If no active features found for entity_type.
        ValueError:   If entity_type is not IT or OT.
        """
        etype = entity_type.upper()
        if etype not in ("IT", "OT"):
            raise ValueError(f"entity_type must be 'IT' or 'OT', got: {entity_type!r}")

        active = self._get_active(etype)
        if not active:
            raise RuntimeError(
                f"No active features found for entity_type={etype}. "
                f"Check config/feature_registry.yaml."
            )

        # Run all relevant production extractor groups once
        all_extracted: dict[str, float] = {}
        for group_name, extractor in self._extractors.items():
            # Only run groups that have at least one active feature for this entity_type
            needed = self._group_to_active.get(group_name, set())
            if not needed:
                continue
            features, warnings = extractor.safe_extract(event, baseline)
            all_extracted.update(features)
            if warnings:
                logger.warning(
                    "extractor_warnings",
                    group=group_name,
                    warnings=warnings,
                    event_id=getattr(event, "event_id", "unknown"),
                )

        # Assemble ordered vector from active features only
        values: list[float] = []
        names: list[str] = []
        for entry in active:
            fid = entry["id"]
            fn_path = entry.get("extractor_fn", "")
            if fid not in all_extracted:
                # Check if it's a lab-implemented feature (extractor_fn: lab.*)
                if fn_path.startswith("lab.") and fid in self._lab_feature_fns:
                    try:
                        val = self._lab_feature_fns[fid](event, baseline)
                        all_extracted[fid] = float(val)
                    except Exception as exc:
                        logger.warning(
                            "lab_feature_extraction_error",
                            feature_id=fid,
                            error=str(exc),
                        )
                        all_extracted[fid] = 0.0
                else:
                    # Feature exists in registry but its group extractor didn't return it.
                    # This is a config/code mismatch — fail loud.
                    raise RuntimeError(
                        f"Feature '{fid}' is active in registry but was NOT returned by "
                        f"any production extractor. This is a registry/code mismatch. "
                        f"Check the extractor_fn path: {fn_path}."
                    )
            values.append(all_extracted[fid])
            names.append(fid)

        return np.array(values, dtype=np.float64), names

    def get_active_feature_names(self, entity_type: str) -> list[str]:
        """Return sorted list of active feature ids for entity_type."""
        return [e["id"] for e in self._get_active(entity_type.upper())]

    def get_feature_dimension(self, entity_type: str) -> int:
        """Return number of active features for entity_type."""
        return len(self._get_active(entity_type.upper()))

    # ── Private ────────────────────────────────────────────────────────────

    def _get_active(self, entity_type: str) -> list[dict]:
        """
        Active features for entity_type.
        Includes features with entity_type == 'both'.
        Sorted alphabetically by id for deterministic vector ordering.
        """
        result = [
            f for f in self._registry
            if f["status"] == "active"
            and f["entity_type"].upper() in (entity_type, "BOTH")
        ]
        return sorted(result, key=lambda x: x["id"])

    def _build_group_mapping(self) -> dict[str, set[str]]:
        """
        Build group_name → {feature_id, ...} mapping from active prod.* features.

        Registry extractor_fn format: "prod.{group}.{feature_name}"
        e.g., "prod.network.dst_ip_is_novel" → group "network"
        Lab features (lab.*) are handled separately via _lab_feature_fns.
        """
        mapping: dict[str, set[str]] = {}
        for entry in self._registry:
            if entry["status"] != "active":
                continue
            fn_path: str = entry.get("extractor_fn", "")
            parts = fn_path.split(".")
            if len(parts) >= 2 and parts[0] == "prod":
                group = parts[1]
                mapping.setdefault(group, set()).add(entry["id"])
        return mapping

    def _build_lab_feature_fns(self) -> dict[str, object]:
        """
        Build feature_id → callable mapping for active lab.* features.

        Registry extractor_fn format: "lab.{module}.{fn_name}"
        e.g., "lab.auth_burst.auth_failure_burst_score"
        Function is looked up in features/extractors.py by fn_name.
        """
        import importlib
        fns: dict[str, object] = {}
        for entry in self._registry:
            if entry["status"] != "active":
                continue
            fn_path: str = entry.get("extractor_fn", "")
            if not fn_path.startswith("lab."):
                continue
            parts = fn_path.split(".")
            fn_name = parts[-1]  # last part is the function name
            # Try features.extractors first (the lab extractor module)
            try:
                _ensure_paths()
                mod = importlib.import_module("features.extractors")
                fn = getattr(mod, fn_name, None)
                if fn is None:
                    raise AttributeError(f"{fn_name} not found in features.extractors")
                fns[entry["id"]] = fn
                logger.info(
                    "lab_feature_fn_registered",
                    feature_id=entry["id"],
                    fn_path=fn_path,
                )
            except Exception as exc:
                logger.warning(
                    "lab_feature_fn_import_failed",
                    feature_id=entry["id"],
                    fn_path=fn_path,
                    error=str(exc),
                )
        return fns

    @staticmethod
    def _load_registry(path: Path) -> list[dict]:
        if not path.exists():
            raise FileNotFoundError(
                f"Feature registry not found at: {path}. "
                "Run from aegis_ml_lab/ root or pass registry_path explicitly."
            )
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        features = data.get("features", [])
        if not features:
            raise ValueError(f"feature_registry.yaml at {path} contains no feature entries.")
        return features
