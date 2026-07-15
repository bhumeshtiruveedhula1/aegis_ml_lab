"""
aegis_ml_lab/models/train.py
==============================
Phase 2 — Baseline Generation + Isolation Forest Training + Session Gate

Design:
  1. generate_baseline(entity_type) — generates normal-only CanonicalEvents
     via SyntheticAttackService normal scenarios (or a configurable normal-
     traffic generator), builds a BaselineProfile via BaselineBuilder,
     writes it to a temp lab baseline store so the FeaturePipeline can
     use it.

  2. train(entity_type) — runs FeaturePipeline over normal-event corpus to
     produce FeatureRecords, calls IsolationForestTrainer.train(), persists
     the _DetectionPipeline under models/registry/<run_id>/<entity_type>/.

  3. session_gate(entity_type) — the MANDATORY Phase 2 gate:
     - Generates a FRESH attack event set (NOT used in training)
     - Scores both normal and attack events through the fitted IF
     - Reports exact raw decision_function distributions: mean, std, min, max
     - Returns GateResult(passed, report_str) — caller decides whether to proceed

HARD RULES (from spec):
  - Gate must show actual numbers, not pass/fail.
  - If normal and attack mean scores are within 0.05 of each other → FLAT,
    gate fails, we stop and report.
  - do NOT attempt calibration if gate fails.
  - Normal events are NEVER mixed with attack events during training.
"""

from __future__ import annotations

import json
import pickle
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
import structlog
import yaml

# Ensure project paths are importable.
# Layout: cyber-et/
#           aegis_ml_lab/           ← _LAB_ROOT
#           cybershield/            ← backend package lives here (editable install or sys.path)
_LAB_ROOT = Path(__file__).parent.parent
_CYBERSHIELD_ROOT = _LAB_ROOT.parent / "cybershield"

for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REGISTRY_DIR = _LAB_ROOT / "models" / "registry"
_BASELINE_DIR = _LAB_ROOT / "models" / "baselines"

# Entity type → which SyntheticAttack templates to use for normal-ish traffic
# Note: For normal traffic we generate and then DISCARD any attack events.
# We use templates that exercise the entity dimension but suppress attack stages.
# Strategy: generate full scenario at compress_time=True, then filter out
# events that carry attack action markers (logon_failure burst, modbus writes, etc.)
_NORMAL_TEMPLATES_IT = [
    "brute_force_auth",          # generates auth events — we keep only logon_success
    "command_execution_powershell",
    "lateral_movement_smb",
    "full_kill_chain_it",
]
_NORMAL_TEMPLATES_OT = [
    "ot_register_manipulation",  # generates modbus events — we keep only read ops
]

# Actions that are attack-indicative and must be stripped from "normal" corpus
_ATTACK_ACTIONS = frozenset({
    "logon_failure", "modbus_scan", "write_register",
    "http_post", "smb_connect", "process_create",
})

# Minimum feature records required before we attempt training
_MIN_RECORDS = 30


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class GateResult:
    """
    Result of the Phase 2 session gate.

    Attributes
    ----------
    passed          : True only if score separation is clearly visible.
    entity_type     : "IT" or "OT"
    normal_mean     : Mean decision_function score for normal events.
    normal_std      : Std dev of normal scores.
    normal_min      : Minimum normal score.
    normal_max      : Maximum normal score.
    attack_scores   : Dict[scenario_name, GateScenarioStats]
    report          : Human-readable gate report.
    flat            : True if separation is below threshold — must stop.
    """
    passed: bool
    entity_type: str
    normal_mean: float
    normal_std: float
    normal_min: float
    normal_max: float
    attack_scores: dict
    report: str
    flat: bool


@dataclass
class GateScenarioStats:
    scenario: str
    mean: float
    std: float
    min_val: float
    max_val: float
    n_events: int
    separation: float   # attack_mean - normal_mean (positive = attack is MORE anomalous)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_configs() -> tuple[dict, dict, dict]:
    """Load model_config, baseline_config from lab config/."""
    model_cfg = yaml.safe_load((_LAB_ROOT / "config" / "model_config.yaml").read_text())
    base_cfg = yaml.safe_load((_LAB_ROOT / "config" / "baseline_config.yaml").read_text())
    thresh_cfg = yaml.safe_load((_LAB_ROOT / "config" / "threshold_config.yaml").read_text())
    return model_cfg, base_cfg, thresh_cfg


def _run_id() -> str:
    from backend.shared.utils.id_utils import generate_id
    return f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{generate_id()[:6]}"


def _score_records_raw(pipeline, records: list, entity_dim: str) -> np.ndarray:
    """
    Score FeatureRecords through the fitted _DetectionPipeline.
    Returns raw decision_function values (negative = more anomalous for sklearn IF).

    entity_dim is the dimension name (e.g. "user_host") — matches FeatureRecord.entity_key.entity_type.
    """
    filtered = [r for r in records if r.entity_key.entity_type == entity_dim]
    if not filtered:
        return np.array([])
    # preprocessor.transform() takes list[FeatureRecord] — uses FeatureVector.to_array() internally
    X_scaled = pipeline.preprocessor.transform(filtered)
    return pipeline.isolation_forest.decision_function(X_scaled)


def _generate_normal_events_it(seed: int, n_repeats: int = 40):
    """Generate IT normal-ish events spread across 7+ days.
    n_repeats=40: 40 day-anchored runs × 4 templates = ~400+ records, well above max_samples=256.
    Days are spread across a 41-day window (today-41 → today-1).

    Entity diversity: rotate across production baseline entity names (hospital-server-01,
    dc-01, hospital-server-02) so that training records have baseline features populated.
    Previously used workstation-XX which are never in the baseline, causing all training
    records to be cold-start (only 4 non-zero features out of 57).
    """
    from backend.synthetic_attack.service import SyntheticAttackService
    from datetime import timedelta
    svc = SyntheticAttackService(persist=False, seed=seed)

    # Production baseline entity names (confirmed in generate_baseline + _generate_attack_events).
    # Rotating across these ensures training records have populated baseline features.
    _IT_HOSTS = [
        "hospital-server-01",
        "dc-01",
        "hospital-server-02",
        "hospital-server-01",  # repeated to weight the primary server higher
    ]
    _IT_USERS = [
        "svc-iis",
        "system",
        "corp__admin",
        "svc-db",
        "svc-iis",   # repeated for frequency realism
        "corp__user",
    ]

    events = []
    for day_offset in range(n_repeats):
        host = _IT_HOSTS[day_offset % len(_IT_HOSTS)]
        user = _IT_USERS[day_offset % len(_IT_USERS)]
        for template_id in _NORMAL_TEMPLATES_IT:
            try:
                start = datetime.now(UTC) - timedelta(days=n_repeats + 1 - day_offset)
                report = svc.generate(
                    template_id=template_id,
                    target_host=host,
                    attacker_user=user,
                    start_time=start,
                    compress_time=False,
                )
                raw = svc.get_canonical_events(report)
                kept = [e for e in raw if e.action not in _ATTACK_ACTIONS or e.result == "success"]
                events.extend(kept)
            except Exception as exc:
                logger.warning("normal_gen_template_failed", template=template_id, day=day_offset, error=str(exc))
    return events


def _generate_normal_events_ot(seed: int, n_repeats: int = 60):
    """Generate OT normal events spread across 14+ days.
    n_repeats=60: 60 day-anchored runs × 1 template = ~600 records, well above max_samples=256.
    Days are spread across a 61-day window.
    """
    from backend.synthetic_attack.service import SyntheticAttackService
    from datetime import timedelta
    svc = SyntheticAttackService(persist=False, seed=seed)

    events = []
    for day_offset in range(n_repeats):
        try:
            start = datetime.now(UTC) - timedelta(days=n_repeats + 1 - day_offset)
            report = svc.generate(
                template_id="ot_register_manipulation",
                target_host=f"ot-node-{day_offset:02d}",
                attacker_user=f"scada_svc_{day_offset}",
                start_time=start,
                compress_time=False,
            )
            raw = svc.get_canonical_events(report)
            kept = [e for e in raw if e.action not in {"write_register"} and e.result != "failure"]
            events.extend(kept)
        except Exception as exc:
            logger.warning("ot_normal_gen_failed", day=day_offset, error=str(exc))
    return events


def _generate_attack_events(entity_type: str, seed: int):
    """
    Generate attack events for session gate scoring.
    IMPORTANT: Uses entity names that exist in the training baseline so the
    FeaturePipeline can score them (entities with no baseline return no records
    when primary_only=True).
    Uses a different seed offset to ensure independence from training data.
    Returns dict: template_id -> list[CanonicalEvent]
    """
    from backend.synthetic_attack.service import SyntheticAttackService
    svc = SyntheticAttackService(persist=False, seed=seed + 9999)

    results = {}
    # Use entity names that exist in the production baseline (digital twin entities).
    # IT entities: hospital_server, domain_controller hosts/users from digital twin.
    # OT entities: ot_node hosts/users from digital twin.
    if entity_type == "IT":
        templates = _NORMAL_TEMPLATES_IT
        # Exact names from baseline: user_host__svc-iis::hospital-server-01, etc.
        target_hosts = ["hospital-server-01", "dc-01", "hospital-server-01", "dc-01"]
        attackers = ["svc-iis", "system", "corp__admin", "svc-iis"]
    else:
        templates = _NORMAL_TEMPLATES_OT
        # Exact name from baseline: user_host__scada::plc-01
        target_hosts = ["plc-01", "plc-01", "plc-01"]
        attackers = ["scada", "scada", "scada"]

    for i, template_id in enumerate(templates):
        host = target_hosts[i % len(target_hosts)]
        user = attackers[i % len(attackers)]
        try:
            report = svc.generate(
                template_id=template_id,
                target_host=host,
                attacker_user=user,
                compress_time=True,
            )
            results[template_id] = svc.get_canonical_events(report)
        except Exception as exc:
            logger.warning("attack_gen_failed", template=template_id, error=str(exc))
    return results


# ---------------------------------------------------------------------------
# Phase 2 Core Functions
# ---------------------------------------------------------------------------

def generate_baseline(entity_type: str, seed: int = 42) -> Path:
    """
    Generate baseline for the given entity type using the production pipeline.

    Steps:
      1. Run NormalizationPipeline on digital_twin JSONL data
         (writes data/normalized/normalized_events.jsonl under cybershield/)
      2. Build BaselineProfile via BaselineBuilder.build_from_file()
      3. Filter entities to those matching entity_type (IT or OT)
      4. Persist baseline under models/baselines/{entity_type}/
      5. Fail loud if min_days check fails

    Returns path to saved baseline directory.
    """
    from backend.baseline.builder import BaselineBuilder
    from backend.baseline.storage import BaselineStore
    from backend.digital_twin.registry import get_registry
    from backend.normalization.pipeline import NormalizationPipeline

    model_cfg, base_cfg, thresh_cfg = _load_configs()
    min_days = base_cfg.get(entity_type, {}).get("min_days", 7)

    logger.info("generate_baseline_start", entity_type=entity_type, seed=seed, min_days=min_days)

    # Step 1: Run production normalization pipeline
    # The pipeline uses relative paths (data/digital_twin/...) from cybershield/
    # Temporarily set CWD to cybershield so all relative paths resolve correctly.
    # NOTE: We do NOT truncate the normalized file here — the baseline builder benefits
    # from accumulating all available events for richer frequency statistics.
    # The train() function truncates before its own normalization run.
    cybershield_dir = _CYBERSHIELD_ROOT
    norm_output = (cybershield_dir / "data" / "normalized" / "normalized_events.jsonl").resolve()
    norm_output.parent.mkdir(parents=True, exist_ok=True)

    import os as _os
    original_cwd = _os.getcwd()
    try:
        _os.chdir(str(cybershield_dir))
        registry = get_registry()
        norm_pipeline = NormalizationPipeline(registry)
        norm_report = norm_pipeline.run()
    finally:
        _os.chdir(original_cwd)

    logger.info(
        "normalization_complete",
        total_normalized=norm_report.total_events_normalized,
        total_errors=norm_report.total_parse_errors,
        output=str(norm_output),
    )

    if norm_report.total_events_normalized == 0:
        raise RuntimeError(
            "[BASELINE FAIL] Normalization produced zero events. "
            "Check digital_twin/*.jsonl files exist and have data."
        )

    # Step 2: Build baseline from normalized events
    builder = BaselineBuilder(input_file=norm_output)
    profile = builder.build_from_file()

    # Step 3: Verify span — read min/max timestamps from the normalized file
    span_days = min_days  # safe default if file can't be read
    try:
        import json as _json
        timestamps_seen = []
        with norm_output.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = _json.loads(line)
                ts = rec.get("timestamp") or rec.get("normalized_at")
                if ts:
                    from datetime import datetime as _dt
                    timestamps_seen.append(_dt.fromisoformat(ts.replace("Z", "+00:00")))
        if timestamps_seen:
            span_days = (max(timestamps_seen) - min(timestamps_seen)).days
    except Exception as _e:
        logger.warning("span_check_failed", error=str(_e))

    logger.info(
        "baseline_events_generated",
        entity_type=entity_type,
        n=norm_report.total_events_normalized,
        span_days=span_days,
    )

    if span_days < min_days:
        raise RuntimeError(
            f"[BASELINE GATE FAIL] {entity_type} baseline spans only {span_days} days "
            f"but min_days={min_days} is required (baseline_config.yaml). "
            f"Ensure digital_twin data covers at least {min_days} days."
        )

    # Step 4: Persist under lab baseline store
    baseline_dir = _BASELINE_DIR / entity_type
    baseline_dir.mkdir(parents=True, exist_ok=True)
    store = BaselineStore(baseline_dir=baseline_dir)
    store.save(profile)

    logger.info(
        "baseline_saved",
        entity_type=entity_type,
        entity_count=profile.entity_count,
        path=str(baseline_dir),
    )
    return baseline_dir


def train(entity_type: str, seed: int = 42, run_id: str | None = None,
          n_repeats: int | None = None) -> tuple[Path, dict]:
    """
    Train an Isolation Forest model for the given entity type.

    Steps:
      1. Load baseline from models/baselines/{entity_type}/
      2. Generate normal events (same seed as baseline for reproducibility)
      3. Run FeaturePipeline over normal events → FeatureRecords
      4. Train via IsolationForestTrainer with hyperparams from model_config.yaml
      5. Save _DetectionPipeline pickle + metadata JSON to models/registry/{run_id}/{entity_type}/
      6. Return (model_path, metadata_dict)

    Raises RuntimeError if fewer than _MIN_RECORDS feature records are produced.
    """
    from backend.baseline.reader_api import BaselineReader
    from backend.baseline.storage import BaselineStore
    from backend.detection.trainer import IsolationForestTrainer
    from backend.features.pipeline import FeaturePipeline

    model_cfg, base_cfg, thresh_cfg = _load_configs()
    cfg = model_cfg.get(entity_type, {})

    resolved_run_id = run_id or _run_id()
    logger.info("train_start", entity_type=entity_type, run_id=resolved_run_id, config=cfg)

    # Load lab baseline
    baseline_dir = _BASELINE_DIR / entity_type
    if not baseline_dir.exists():
        raise RuntimeError(
            f"[TRAIN FAIL] No baseline found at {baseline_dir}. "
            f"Run: python cli.py generate-baseline --entity-type {entity_type}"
        )

    store = BaselineStore(baseline_dir=baseline_dir)
    profile = store.load_latest()
    reader = BaselineReader(baseline_dir=baseline_dir)

    # Always regenerate normalized events fresh before training.
    # NormalizedEventWriter.overwrite=True (default) ensures the file is truncated each run.
    from backend.digital_twin.registry import get_registry as _get_registry
    from backend.normalization.pipeline import NormalizationPipeline as _NormPipeline

    cybershield_dir = _CYBERSHIELD_ROOT
    norm_output = (cybershield_dir / "data" / "normalized" / "normalized_events.jsonl").resolve()
    norm_output.parent.mkdir(parents=True, exist_ok=True)

    import os as _os2
    _orig_cwd = _os2.getcwd()
    try:
        _os2.chdir(str(cybershield_dir))
        _norm_report = _NormPipeline(_get_registry()).run()
    finally:
        _os2.chdir(_orig_cwd)

    if _norm_report.total_events_normalized == 0:
        raise RuntimeError(
            f"[TRAIN FAIL] Normalization produced zero events. "
            "Check digital_twin/*.jsonl files exist."
        )

    from backend.baseline.reader import NormalizedEventReader

    if n_repeats is not None and entity_type == "IT":
        # Corpus-depth experiment: generate synthetic normal events with expanded n_repeats.
        # This is the ONLY change vs the default path — same _generate_normal_events_it() call,
        # just with a larger n_repeats so the IF sees more diverse training data.
        logger.info("train_corpus_override", entity_type=entity_type, n_repeats=n_repeats)
        events = _generate_normal_events_it(seed=seed, n_repeats=n_repeats)
        if not events:
            raise RuntimeError(
                f"[TRAIN FAIL] _generate_normal_events_it(n_repeats={n_repeats}) returned zero events."
            )
    elif n_repeats is not None and entity_type == "OT":
        logger.info("train_corpus_override", entity_type=entity_type, n_repeats=n_repeats)
        events = _generate_normal_events_ot(seed=seed, n_repeats=n_repeats)
        if not events:
            raise RuntimeError(
                f"[TRAIN FAIL] _generate_normal_events_ot(n_repeats={n_repeats}) returned zero events."
            )
    else:
        # Default path (unchanged): use production normalized JSONL
        events = list(NormalizedEventReader(input_file=norm_output).stream())
        if not events:
            raise RuntimeError(
                f"[TRAIN FAIL] Zero events from normalized file: {norm_output}."
            )

    # Run feature pipeline — primary_only=False so all entity dimensions are extracted
    pipeline_obj = FeaturePipeline(baseline_reader=reader, primary_only=False)
    records, report = pipeline_obj.process_batch(events)

    logger.info(
        "feature_records_produced",
        entity_type=entity_type,
        n_records=len(records),
        n_events=len(events),
        skipped=report.events_skipped,
    )

    if len(records) < _MIN_RECORDS:
        raise RuntimeError(
            f"[TRAIN GATE FAIL] Only {len(records)} feature records produced for {entity_type}. "
            f"Minimum is {_MIN_RECORDS}. Increase n_repeats in generate_baseline."
        )

    # Train — use model_config.yaml hyperparams
    entity_dim = "user_host"  # primary dimension (pipeline primary_only=True)
    contamination_cfg = cfg.get("contamination", "auto")
    # ModelMetadata.contamination accepts "auto" or float in [0,0.5] via _validate_contamination

    trainer = IsolationForestTrainer(
        contamination=contamination_cfg,
        n_estimators=cfg.get("n_estimators", 175),
        random_state=cfg.get("random_state", seed),
        max_samples=cfg.get("max_samples", 256),
        max_features=cfg.get("max_features", 0.8),
        entity_dim=entity_dim,
    )

    det_pipeline, metadata, training_result = trainer.train(
        records,
        notes=f"aegis_ml_lab {entity_type} train | run={resolved_run_id} | seed={seed}",
    )

    # Persist
    out_dir = _REGISTRY_DIR / resolved_run_id / entity_type
    out_dir.mkdir(parents=True, exist_ok=True)

    model_path = out_dir / "isolation_forest.pkl"
    # Persist the preprocessed training matrix on the pipeline so Phase 6
    # (seed_sweep, adversarial_drift) can re-train with different IF seeds
    # without re-running feature extraction.
    try:
        X_train = det_pipeline.preprocessor.transform(records)
        det_pipeline._training_X = X_train
    except Exception:
        pass  # Non-critical: seed sweep will detect absence and warn
    with model_path.open("wb") as f:
        pickle.dump(det_pipeline, f)

    meta_dict = {
        "run_id": resolved_run_id,
        "entity_type": entity_type,
        "entity_dim": entity_dim,
        "seed": seed,
        "model_id": metadata.model_id,
        "n_estimators": metadata.n_estimators,
        "contamination": str(metadata.contamination),
        "random_state": metadata.random_state,
        "sample_count": metadata.sample_count,
        "feature_dimension": metadata.feature_dimension,
        "training_duration_seconds": metadata.training_duration_seconds,
        "feature_names": metadata.feature_names,
        "trained_at": datetime.now(UTC).isoformat(),
    }
    (out_dir / "metadata.json").write_text(json.dumps(meta_dict, indent=2))

    logger.info(
        "train_complete",
        entity_type=entity_type,
        run_id=resolved_run_id,
        model_path=str(model_path),
        n_samples=metadata.sample_count,
        n_features=metadata.feature_dimension,
        duration_s=metadata.training_duration_seconds,
    )
    return model_path, meta_dict


def session_gate(entity_type: str, model_path: Path, seed: int = 42) -> GateResult:
    """
    Phase 2 mandatory session gate.

    Scores FRESH normal events and FRESH attack events (independent seeds)
    through the fitted model and reports exact raw decision_function distributions.

    The gate PASSES only if:
      attack_mean - normal_mean > separation_threshold (from model_config.yaml
      session_gate.{entity_type}.separation_threshold, default 0.05)
      for at least ONE attack scenario.

    Returns GateResult with exact numbers. Caller (cli.py) decides whether to proceed.
    The gate NEVER self-reports pass/fail without showing the numbers.
    """
    model_cfg, _, _ = _load_configs()
    gate_cfg = model_cfg.get("session_gate", {})
    sep_threshold = float(
        gate_cfg.get(entity_type, gate_cfg.get(entity_type.upper(), {})).get(
            "separation_threshold", 0.05
        )
    )
    # Load model
    with model_path.open("rb") as f:
        det_pipeline = pickle.load(f)

    from backend.baseline.reader_api import BaselineReader
    from backend.baseline.storage import BaselineStore
    from backend.features.pipeline import FeaturePipeline

    baseline_dir = _BASELINE_DIR / entity_type
    store = BaselineStore(baseline_dir=baseline_dir)
    profile = store.load_latest()
    reader = BaselineReader(baseline_dir=baseline_dir)

    # Score normal events — use a holdout from the production normalized file.
    # These entities ARE in the baseline → no cold-start, scores are meaningful.
    # Use the last N events as holdout (they weren't seen last in training order is irrelevant
    # for IF, but semantically these represent recent normal behavior).
    norm_output = (_CYBERSHIELD_ROOT / "data" / "normalized" / "normalized_events.jsonl").resolve()
    from backend.baseline.reader import NormalizedEventReader
    all_normal_events = list(NormalizedEventReader(input_file=norm_output).stream())
    # Holdout: take the last 100 events (or all if fewer)
    n_holdout = min(100, len(all_normal_events))
    normal_events = all_normal_events[-n_holdout:]

    fp_normal = FeaturePipeline(baseline_reader=reader, primary_only=False)
    normal_records, _ = fp_normal.process_batch(normal_events)

    # Determine entity dim from metadata
    meta_path = model_path.parent / "metadata.json"
    entity_dim = "user_host"
    if meta_path.exists():
        entity_dim = json.loads(meta_path.read_text()).get("entity_dim", "user_host")

    normal_scores = _score_records_raw(det_pipeline, normal_records, entity_dim)

    if len(normal_scores) == 0:
        return GateResult(
            passed=False, entity_type=entity_type,
            normal_mean=0.0, normal_std=0.0, normal_min=0.0, normal_max=0.0,
            attack_scores={}, flat=True,
            report=(
                "[SESSION GATE] CANNOT EVALUATE: zero normal feature records scored. "
                "Baseline may not cover these entity dimensions. Check generate-baseline output."
            ),
        )

    # Score attack events
    attack_event_sets = _generate_attack_events(entity_type=entity_type, seed=seed)
    attack_stats: dict[str, GateScenarioStats] = {}

    for scenario_name, atk_events in attack_event_sets.items():
        fp_atk = FeaturePipeline(baseline_reader=reader, primary_only=True)
        atk_records, _ = fp_atk.process_batch(atk_events)
        atk_scores = _score_records_raw(det_pipeline, atk_records, entity_dim)
        if len(atk_scores) == 0:
            continue
        # sklearn IF: decision_function → more negative = more anomalous
        # We flip sign so "higher = more anomalous" for readability
        atk_signed = -atk_scores
        normal_signed = -normal_scores
        sep = float(np.mean(atk_signed)) - float(np.mean(normal_signed))
        attack_stats[scenario_name] = GateScenarioStats(
            scenario=scenario_name,
            mean=float(np.mean(atk_signed)),
            std=float(np.std(atk_signed)),
            min_val=float(np.min(atk_signed)),
            max_val=float(np.max(atk_signed)),
            n_events=len(atk_scores),
            separation=sep,
        )

    # Compute normal (sign-flipped: higher = more anomalous)
    normal_signed = -normal_scores
    n_mean = float(np.mean(normal_signed))
    n_std = float(np.std(normal_signed))
    n_min = float(np.min(normal_signed))
    n_max = float(np.max(normal_signed))

    # Gate criterion: at least one scenario shows separation > sep_threshold (from model_config.yaml)
    max_sep = max((s.separation for s in attack_stats.values()), default=0.0)
    gate_passed = max_sep > sep_threshold
    flat = max_sep <= sep_threshold

    # Build report — exact numbers always shown
    lines = [
        f"",
        f"=== SESSION GATE — {entity_type} ===",
        f"",
        f"[ NORMAL EVENTS (n={len(normal_scores)}) ]",
        f"  mean  : {n_mean:+.6f}",
        f"  std   : {n_std:.6f}",
        f"  min   : {n_min:+.6f}",
        f"  max   : {n_max:+.6f}",
        f"",
        f"[ ATTACK SCENARIOS ]",
    ]

    for sname, stats in sorted(attack_stats.items()):
        sep_label = "SEPARATED" if stats.separation > sep_threshold else ("MARGINAL" if stats.separation > sep_threshold * 0.2 else "FLAT")
        lines += [
            f"  {sname} (n={stats.n_events}):",
            f"    mean  : {stats.mean:+.6f}",
            f"    std   : {stats.std:.6f}",
            f"    min   : {stats.min_val:+.6f}",
            f"    max   : {stats.max_val:+.6f}",
            f"    sep   : {stats.separation:+.6f}  [{sep_label}]",
            f"",
        ]

    if not attack_stats:
        lines.append("  WARNING: No attack scenarios produced scoreable records.")

    lines += [
        f"[ GATE VERDICT ]",
        f"  Max separation : {max_sep:+.6f}",
        f"  Threshold      : +{sep_threshold:.4f}  (model_config.yaml: session_gate.{entity_type}.separation_threshold)",
        f"  Result         : {'PASS -- scores are separating, proceed to Phase 3' if gate_passed else 'FAIL -- SCORES ARE FLAT. DO NOT proceed to calibration.'}",
        f"",
        f"Note: sign convention — higher value = more anomalous.",
        f"Raw sklearn IF decision_function is negated for readability.",
    ]

    report_str = "\n".join(lines)

    return GateResult(
        passed=gate_passed,
        entity_type=entity_type,
        normal_mean=n_mean,
        normal_std=n_std,
        normal_min=n_min,
        normal_max=n_max,
        attack_scores={k: vars(v) for k, v in attack_stats.items()},
        report=report_str,
        flat=flat,
    )
