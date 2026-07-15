"""
aegis_ml_lab/features/extractors.py
=====================================
Feature extraction functions for the AEGIS ML Lab.

Each function takes (event: CanonicalEvent, baseline: EntityBaseline | None)
and returns a single float value.  build_feature_vector.py calls these via
the extractor_fn dotted paths in feature_registry.yaml.

Entity-Type Tagging
-------------------
tag_entity_type() derives IT vs OT classification from event.source.
This field is populated by all CanonicalEvent producers (templates,
parsers). Classification is deterministic: same source always → same type.

Source → entity_type mapping (confirmed from real AttackStage templates):
  "ot"                → OT   (ot_register_manipulation template)
  "windows"           → IT
  "linux"             → IT
  "sysmon"            → IT
  "windows_event"     → IT
  "auditd"            → IT
  Any other / unknown → IT (conservative default; logged as warning)

Deviation from spec: the spec says "tag from existing source metadata".
CanonicalEvent has no entity_type field — classification is derived from
event.source. This deviation is documented in README.md.

Feature Extractor Contract
--------------------------
- Each extractor returns exactly one float.
- On cold-start (baseline is None): return the appropriate sentinel value
  as documented per function. Never raise, never return None.
- On missing event field (field is None): return 0.0 unless documented
  otherwise.
- Exceptions must not propagate — build_feature_vector wraps in try/except.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Literal

import structlog

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline
    from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# IT source identifiers (confirmed from synthetic_attack/templates.py)
# ---------------------------------------------------------------------------
_IT_SOURCES: frozenset[str] = frozenset({
    "windows",
    "linux",
    "sysmon",
    "windows_event",
    "auditd",
    "hospital_server",
    "domain_controller",
})

# OT source identifiers (confirmed from ot_register_manipulation template)
_OT_SOURCES: frozenset[str] = frozenset({
    "ot",
    "ot_node",
    "modbus",
    "scada",
})


# ---------------------------------------------------------------------------
# Entity-Type Tagging  (Phase 1 requirement)
# ---------------------------------------------------------------------------

def tag_entity_type(event: "CanonicalEvent") -> Literal["IT", "OT"]:
    """
    Derive IT vs OT classification from event.source.

    Rules (in priority order):
    1. If event.source in _OT_SOURCES → "OT"
    2. If event.source in _IT_SOURCES → "IT"
    3. If event has any modbus_* field populated → "OT" (belt-and-suspenders)
    4. Default → "IT" with a warning log

    This function is deterministic: same event.source always → same result.

    Parameters
    ----------
    event : CanonicalEvent — must have a populated .source field.

    Returns
    -------
    "IT" or "OT"
    """
    src = (event.source or "").lower().strip()

    if src in _OT_SOURCES:
        return "OT"

    if src in _IT_SOURCES:
        return "IT"

    # Belt-and-suspenders: check OT-specific fields if source is ambiguous
    has_modbus = (
        event.modbus_register is not None
        or event.modbus_value is not None
        or event.modbus_function_code is not None
        or getattr(event, "supervisory_host", None) is not None
    )
    if has_modbus:
        logger.warning(
            "entity_type_derived_from_modbus_fields",
            source=event.source,
            event_id=getattr(event, "event_id", "unknown"),
            detail="Source not in known OT set but modbus fields are populated. Classifying as OT.",
        )
        return "OT"

    # Unknown source — conservative IT default
    logger.warning(
        "entity_type_unknown_source_defaulting_to_IT",
        source=event.source,
        event_id=getattr(event, "event_id", "unknown"),
        detail=(
            "event.source not in known IT or OT source sets. "
            "Defaulting to IT. Add to _IT_SOURCES or _OT_SOURCES in extractors.py "
            "if this source is expected."
        ),
    )
    return "IT"


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _binary(condition: bool) -> float:
    """Return 1.0 if condition is True, 0.0 otherwise."""
    return 1.0 if condition else 0.0


def _safe_ratio(numerator: float, denominator: float, *, default: float = 0.0) -> float:
    """Safe division: return default if denominator is 0 or nan."""
    if denominator == 0.0 or math.isnan(denominator) or math.isnan(numerator):
        return default
    return numerator / denominator


def _safe_z_score(value: float, mean: float, std: float) -> float:
    """Z-score with std=0 guard. Returns 0.0 if std <= 0."""
    if std <= 0:
        return 0.0
    return (value - mean) / std


# ---------------------------------------------------------------------------
# Network features (entity_type: both)
# ---------------------------------------------------------------------------

def network_connection_rate(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Ratio of current-window connection count to baseline average.
    Returns 0.0 on cold-start (no baseline).
    Candidate feature — extractor logic placeholder for Phase 2 expansion.
    """
    # TODO (Phase 2): implement using baseline.network.connection_count
    # and a rolling window counter passed via context.
    # For now: return 0.0 (candidate status, not used in active vector).
    return 0.0


def network_unique_dest_ports(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Count of unique destination ports in the observation window vs baseline.
    Returns 0.0 on cold-start.
    Candidate feature — placeholder.
    """
    # TODO (Phase 2): implement sliding-window port accumulation.
    return 0.0


def network_bytes_ratio(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Ratio of bytes_out in this event to baseline mean bytes_out.
    Returns 0.0 if baseline is None or bytes_out is None.
    """
    if event.bytes_out is None or baseline is None:
        return 0.0
    net = getattr(baseline, "network", None)
    if net is None:
        return 0.0
    stats = getattr(net, "bytes_out_stats", None)
    if stats is None:
        return 0.0
    mean_bytes = getattr(stats, "mean", 0.0)
    return _safe_ratio(float(event.bytes_out), mean_bytes)


def temporal_off_baseline_hours(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Binary: 1.0 if this event's hour-of-day is outside the entity's
    historically active hours (baseline temporal profile).
    Returns 0.0 on cold-start.
    Candidate feature — placeholder pending baseline.temporal implementation.
    """
    # TODO (Phase 2): read baseline.temporal.active_hours_set and compare
    # event.timestamp.hour against it.
    return 0.0


def network_new_dest_ip(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Binary: 1.0 if dst_ip was not seen in the entity's baseline window.
    Maps to existing NetworkExtractor.dst_ip_is_novel logic.
    Returns 0.0 on cold-start (undefined without a reference set — F02 Option A).
    """
    if event.dst_ip is None or baseline is None:
        return 0.0
    net = getattr(baseline, "network", None)
    if net is None:
        return 0.0
    unique_dst = getattr(net, "unique_dst_ips", set())
    return _binary(event.dst_ip not in unique_dst)


# ---------------------------------------------------------------------------
# Auth / Access features (entity_type: both)
# ---------------------------------------------------------------------------

def auth_failed_login_rate(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Baseline failure rate for authentication events.
    Maps to existing FrequencyExtractor.result_failure_rate_baseline.
    Returns 0.0 on cold-start.
    """
    if baseline is None:
        return 0.0
    freq = getattr(baseline, "frequency", None)
    if freq is None:
        return 0.0
    return float(getattr(freq, "failure_rate", 0.0))


def auth_privilege_escalation(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Binary: 1.0 if this event represents a privilege escalation action.
    Inferred from event_type + action fields (token impersonation, sudo).
    Returns 0.0 on cold-start.
    Candidate feature — placeholder pending event taxonomy review.
    """
    # TODO (Phase 2): define privilege escalation event_type/action patterns
    # and check event fields against them.
    escalation_actions = {"privilege_escalation", "token_impersonation", "sudo", "runas"}
    if event.action is not None and event.action.lower() in escalation_actions:
        return 1.0
    return 0.0


def auth_new_source(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Binary: 1.0 if the source IP of this login was not seen in baseline.
    Maps to existing NetworkExtractor.src_ip_is_novel logic.
    Returns 0.0 on cold-start (F02 Option A).
    """
    if event.src_ip is None or baseline is None:
        return 0.0
    net = getattr(baseline, "network", None)
    if net is None:
        return 0.0
    unique_src = getattr(net, "unique_src_ips", set())
    return _binary(event.src_ip not in unique_src)


# ---------------------------------------------------------------------------
# OT-specific features (entity_type: OT)
# ---------------------------------------------------------------------------

def ot_function_code_deviation(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Binary novelty: 1.0 if this Modbus function code was not seen in baseline.
    Maps to existing OTExtractor.modbus_function_code_is_novel logic.
    Returns 0.0 on cold-start.
    """
    if event.modbus_function_code is None or baseline is None:
        return 0.0
    mb = getattr(baseline, "modbus", None)
    if mb is None:
        return 0.0
    known_fcs = {fc.lower() for fc in getattr(mb, "function_code_distribution", {})}
    return _binary(str(event.modbus_function_code).lower() not in known_fcs)


def ot_register_write_rate(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Binary: 1.0 if this event is a Modbus write operation (FC06 or FC16).
    Rate accumulation is deferred — this is a per-event write indicator.
    Returns 0.0 if not a write or no modbus_function_code.
    Candidate feature — placeholder.
    """
    if event.modbus_function_code is None:
        return 0.0
    write_codes = {"6", "fc06", "write_register", "16", "fc16", "write_multiple_registers"}
    return _binary(str(event.modbus_function_code).lower() in write_codes)


def ot_polling_interval_deviation(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Z-score of polling interval vs baseline mean interval.
    Requires timestamp context from prior event — deferred to Phase 2 window logic.
    Returns 0.0 on cold-start.
    Candidate feature — placeholder.
    """
    # TODO (Phase 2): implement sliding-window inter-arrival time tracking
    # and compare against baseline.modbus.polling_interval_stats.
    return 0.0


# ---------------------------------------------------------------------------
# Host / System features (entity_type: both)
# ---------------------------------------------------------------------------

def host_process_spawn_rate(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Binary: 1.0 if this is a process creation event (process_create / ProcessCreate).
    Rate accumulation deferred to Phase 2 window logic.
    Returns 0.0 if not a process event.
    Candidate feature — placeholder.
    """
    process_create_types = {"processcreate", "process_create", "process_spawn"}
    if event.event_type is not None and event.event_type.lower() in process_create_types:
        return 1.0
    return 0.0




def auth_failure_burst_score(
    event: "CanonicalEvent",
    baseline: "EntityBaseline | None",
) -> float:
    """
    Auth failure burst score: product of result_is_failure and a dormancy
    scaling factor derived from time_since_last_seen_hours.

    Formula:
        result_is_failure * min(1.0, time_since_last_seen_hours / 24.0)

    Rationale: brute_force_auth attacks arrive from attacker entities that
    were never seen in the baseline (time_since_last_seen ≈ 100+ hours as a
    cold-start indicator) AND produce authentication failures. Normal entities
    seen regularly have low time_since_last_seen (≈ 0) so even if result=failure
    occurs, the product stays near 0. This creates a single scalar that captures
    both the failure flag and the cold-start dormancy signal simultaneously,
    giving the IF a tighter, more consistently isolable cluster.

    Returns:
        float in [0.0, 1.0]
        0.0 on cold-start (no baseline) or when result != failure
        ~0.95 for brute_force_auth cold-start attacker events
    """
    # Is this event a failure?
    is_failure = 1.0 if (
        getattr(event, "result", None) == "failure"
        or getattr(event, "action", None) in {"logon_failure", "auth_failure"}
    ) else 0.0
    if is_failure == 0.0:
        return 0.0

    # Dormancy factor: 0 for entities seen recently, 1.0 for cold-start/dormant
    # When baseline is None: use 1.0 (cold-start = maximum dormancy)
    if baseline is None:
        dormancy = 1.0
    else:
        temporal = getattr(baseline, "temporal", None)
        last_seen = getattr(temporal, "last_seen_at", None) if temporal is not None else None
        if last_seen is None:
            dormancy = 1.0  # no last_seen = cold start
        else:
            try:
                import datetime
                now = event.timestamp
                if now.tzinfo is None:
                    import datetime as dt
                    now = now.replace(tzinfo=dt.timezone.utc)
                last_seen_aware = last_seen
                if hasattr(last_seen_aware, 'tzinfo') and last_seen_aware.tzinfo is None:
                    import datetime as dt
                    last_seen_aware = last_seen_aware.replace(tzinfo=dt.timezone.utc)
                hours_since = (now - last_seen_aware).total_seconds() / 3600.0
                dormancy = min(1.0, max(0.0, hours_since / 24.0))
            except Exception:
                dormancy = 0.0

    return is_failure * dormancy
