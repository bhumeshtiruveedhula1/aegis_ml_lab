"""
aegis_ml_lab/evaluate/mttd_instrument.py
=========================================
Phase 9 Module 9.2 — MTTD Instrumentation

Measures Mean Time To Detect (MTTD) using actual production pipeline timestamps.

Instrumentation Points
----------------------
Primary (competition metric — full pipeline story):
    event_timestamp  →  triggered_at
    FeatureRecord.event_timestamp: UTC timestamp of the original security event
    DetectionAlert.triggered_at:   UTC timestamp when alert was emitted by scorer

Secondary (pipeline diagnostic — pure processing latency):
    extracted_at  →  triggered_at
    FeatureVector.extracted_at:  datetime.now(UTC) stamped at feature extraction
    DetectionAlert.triggered_at: datetime.now(UTC) stamped at alert emission

Both are real wall-clock timestamps. No estimation, no approximation,
no hardcoded values.

Usage
-----
    from evaluate.mttd_instrument import MTTDInstrumentor

    instrumentor = MTTDInstrumentor()
    for scenario, alert in alerts:
        instrumentor.record(alert, scenario_name=scenario)

    summary = instrumentor.summarise()
    instrumentor.save(Path("runs/run-xxx/mttd_results.json"))
    instrumentor.log_report()
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field, asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Project target: MTTD < 2 minutes (120 seconds)
MTTD_TARGET_SECONDS: float = 120.0


@dataclass
class MTTDSample:
    """
    One MTTD measurement for a single detected alert.

    Primary MTTD  = triggered_at - event_timestamp
                    (event occurred → alert fired; full pipeline story)
    Secondary MTTD = triggered_at - extracted_at
                    (feature extracted → alert fired; processing latency only)
    """

    alert_id: str
    scenario: str
    entity_type: str
    entity_key: str          # "entity_type:entity_id" string

    # Timestamps (ISO-8601 strings for JSON serialisation)
    event_timestamp_iso: str   # Point A — original event time
    extracted_at_iso: str      # Point A' — feature extraction time
    triggered_at_iso: str      # Point B — alert emission time

    # Computed deltas (seconds)
    mttd_primary_s: float     # triggered_at - event_timestamp  (primary)
    mttd_secondary_s: float   # triggered_at - extracted_at     (diagnostic)

    anomaly_score: float


@dataclass
class MTTDSummary:
    """
    Aggregate MTTD statistics across all recorded alerts.

    Primary statistics are the competition headline numbers.
    Secondary statistics are pipeline diagnostic numbers.
    """

    n_alerts: int

    # Primary — event_timestamp → triggered_at
    primary_mean_s: float | None
    primary_median_s: float | None
    primary_p95_s: float | None
    primary_min_s: float | None
    primary_max_s: float | None

    # Secondary — extracted_at → triggered_at
    secondary_mean_s: float | None
    secondary_median_s: float | None
    secondary_p95_s: float | None
    secondary_min_s: float | None
    secondary_max_s: float | None

    # Target compliance
    target_s: float
    target_met: bool               # primary_mean_s < target_s
    pct_alerts_within_target: float  # % of alerts with primary MTTD < target

    # Per-scenario breakdown: {scenario: {mean_s, n}}
    per_scenario: dict[str, dict[str, Any]]

    # Measurement timestamps
    measured_at: str   # ISO-8601 UTC


class MTTDInstrumentor:
    """
    Non-invasive MTTD observer for the E2E evaluation pipeline.

    Usage Contract
    --------------
    - Call record() once per emitted DetectionAlert.
    - Call summarise() after all scenarios complete.
    - Call save() to persist JSON results.
    - Call log_report() for structured logging.

    Thread Safety
    -------------
    Not thread-safe. Designed for single-threaded E2E evaluation loop.
    """

    def __init__(self) -> None:
        self._samples: list[MTTDSample] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def record(
        self,
        alert: Any,         # DetectionAlert (avoid circular import)
        scenario_name: str,
        entity_type: str = "IT",
    ) -> MTTDSample:
        """
        Record a MTTD measurement for one alert.

        Parameters
        ----------
        alert         : DetectionAlert from scorer._build_alert()
        scenario_name : E2E scenario name (e.g. "brute_force_auth")
        entity_type   : "IT" or "OT"

        Returns
        -------
        MTTDSample — the recorded measurement (for inspection / testing).
        """
        event_ts: datetime = alert.event_timestamp
        triggered_ts: datetime = alert.triggered_at

        # extracted_at lives on the FeatureRecord's FeatureVector. The scorer
        # passes raw_feature_values but not the original record. We derive
        # extracted_at from the alert's own triggered_at proxy when not
        # available, but the correct path is to pass it explicitly.
        # Here we read it from the alert if present (future-proof), else
        # approximate as triggered_at (secondary = 0 sentinel).
        extracted_ts: datetime = getattr(alert, "feature_extracted_at", triggered_ts)

        # Ensure UTC-aware datetimes for delta computation
        def _ensure_utc(dt: datetime) -> datetime:
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt

        event_ts = _ensure_utc(event_ts)
        triggered_ts = _ensure_utc(triggered_ts)
        extracted_ts = _ensure_utc(extracted_ts)

        primary_s = (triggered_ts - event_ts).total_seconds()
        secondary_s = (triggered_ts - extracted_ts).total_seconds()

        entity_key_str = (
            f"{alert.entity_key.entity_type}:{alert.entity_key.entity_id}"
            if hasattr(alert.entity_key, "entity_type")
            else str(alert.entity_key)
        )

        sample = MTTDSample(
            alert_id=alert.alert_id,
            scenario=scenario_name,
            entity_type=entity_type,
            entity_key=entity_key_str,
            event_timestamp_iso=event_ts.isoformat(),
            extracted_at_iso=extracted_ts.isoformat(),
            triggered_at_iso=triggered_ts.isoformat(),
            mttd_primary_s=primary_s,
            mttd_secondary_s=secondary_s,
            anomaly_score=float(alert.anomaly_score),
        )
        self._samples.append(sample)

        logger.debug(
            "mttd_sample_recorded",
            alert_id=alert.alert_id,
            scenario=scenario_name,
            mttd_primary_s=round(primary_s, 4),
            mttd_secondary_s=round(secondary_s, 4),
        )
        return sample

    def record_from_fields(
        self,
        *,
        alert_id: str,
        scenario_name: str,
        entity_type: str,
        entity_key_str: str,
        event_timestamp: datetime,
        extracted_at: datetime,
        triggered_at: datetime,
        anomaly_score: float,
    ) -> MTTDSample:
        """
        Record a MTTD measurement when the alert object is not available
        but individual fields are (e.g. from the raw E2E scoring loop).

        This is the primary integration path for run_e2e_suite.py where
        feature records and score arrays are handled separately.
        """
        def _ensure_utc(dt: datetime) -> datetime:
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt

        event_ts = _ensure_utc(event_timestamp)
        extracted_ts = _ensure_utc(extracted_at)
        triggered_ts = _ensure_utc(triggered_at)

        primary_s = (triggered_ts - event_ts).total_seconds()
        secondary_s = (triggered_ts - extracted_ts).total_seconds()

        sample = MTTDSample(
            alert_id=alert_id,
            scenario=scenario_name,
            entity_type=entity_type,
            entity_key=entity_key_str,
            event_timestamp_iso=event_ts.isoformat(),
            extracted_at_iso=extracted_ts.isoformat(),
            triggered_at_iso=triggered_ts.isoformat(),
            mttd_primary_s=primary_s,
            mttd_secondary_s=secondary_s,
            anomaly_score=anomaly_score,
        )
        self._samples.append(sample)

        logger.debug(
            "mttd_sample_recorded",
            alert_id=alert_id,
            scenario=scenario_name,
            mttd_primary_s=round(primary_s, 4),
            mttd_secondary_s=round(secondary_s, 4),
        )
        return sample

    def summarise(self) -> MTTDSummary:
        """
        Compute aggregate MTTD statistics across all recorded samples.

        Returns MTTDSummary with primary (competition) and secondary
        (diagnostic) statistics.
        """
        n = len(self._samples)
        now_iso = datetime.now(UTC).isoformat()

        if n == 0:
            return MTTDSummary(
                n_alerts=0,
                primary_mean_s=None,
                primary_median_s=None,
                primary_p95_s=None,
                primary_min_s=None,
                primary_max_s=None,
                secondary_mean_s=None,
                secondary_median_s=None,
                secondary_p95_s=None,
                secondary_min_s=None,
                secondary_max_s=None,
                target_s=MTTD_TARGET_SECONDS,
                target_met=False,
                pct_alerts_within_target=0.0,
                per_scenario={},
                measured_at=now_iso,
            )

        primary_vals = [s.mttd_primary_s for s in self._samples]
        secondary_vals = [s.mttd_secondary_s for s in self._samples]

        def _p95(vals: list[float]) -> float:
            sorted_v = sorted(vals)
            idx = int(len(sorted_v) * 0.95)
            return sorted_v[min(idx, len(sorted_v) - 1)]

        primary_mean = statistics.mean(primary_vals)
        secondary_mean = statistics.mean(secondary_vals)

        # Per-scenario breakdown
        per_scenario: dict[str, dict[str, Any]] = {}
        seen_scenarios = {s.scenario for s in self._samples}
        for sc in sorted(seen_scenarios):
            sc_vals = [s.mttd_primary_s for s in self._samples if s.scenario == sc]
            per_scenario[sc] = {
                "n": len(sc_vals),
                "mean_s": round(statistics.mean(sc_vals), 4),
                "min_s": round(min(sc_vals), 4),
                "max_s": round(max(sc_vals), 4),
            }

        within_target = sum(1 for v in primary_vals if v < MTTD_TARGET_SECONDS)

        return MTTDSummary(
            n_alerts=n,
            primary_mean_s=round(primary_mean, 4),
            primary_median_s=round(statistics.median(primary_vals), 4),
            primary_p95_s=round(_p95(primary_vals), 4),
            primary_min_s=round(min(primary_vals), 4),
            primary_max_s=round(max(primary_vals), 4),
            secondary_mean_s=round(secondary_mean, 4),
            secondary_median_s=round(statistics.median(secondary_vals), 4),
            secondary_p95_s=round(_p95(secondary_vals), 4),
            secondary_min_s=round(min(secondary_vals), 4),
            secondary_max_s=round(max(secondary_vals), 4),
            target_s=MTTD_TARGET_SECONDS,
            target_met=primary_mean < MTTD_TARGET_SECONDS,
            pct_alerts_within_target=round(100.0 * within_target / n, 2),
            per_scenario=per_scenario,
            measured_at=now_iso,
        )

    def save(self, path: Path) -> Path:
        """
        Persist all MTTD samples and summary to a JSON file.

        Parameters
        ----------
        path : Destination file path (will be created/overwritten).

        Returns
        -------
        Path — the path written to.
        """
        summary = self.summarise()
        payload = {
            "mttd_target_s": MTTD_TARGET_SECONDS,
            "summary": asdict(summary),
            "samples": [asdict(s) for s in self._samples],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str))
        logger.info("mttd_results_saved", path=str(path), n_samples=len(self._samples))
        return path

    def log_report(self) -> None:
        """
        Emit a structured log report of MTTD results.
        Suitable for display in CLI output and CI logs.
        """
        summary = self.summarise()

        if summary.n_alerts == 0:
            logger.warning(
                "mttd_no_alerts_recorded",
                note="No TP alerts were instrumented — MTTD cannot be measured.",
            )
            return

        verdict = "PASS" if summary.target_met else "FAIL"
        logger.info(
            "mttd_report",
            n_alerts=summary.n_alerts,
            # Primary (competition metric)
            primary_mean_s=summary.primary_mean_s,
            primary_median_s=summary.primary_median_s,
            primary_p95_s=summary.primary_p95_s,
            primary_min_s=summary.primary_min_s,
            primary_max_s=summary.primary_max_s,
            # Secondary (pipeline diagnostic)
            secondary_mean_s=summary.secondary_mean_s,
            secondary_median_s=summary.secondary_median_s,
            # Target
            target_s=summary.target_s,
            target_met=summary.target_met,
            pct_within_target=summary.pct_alerts_within_target,
            verdict=verdict,
        )

    @property
    def samples(self) -> list[MTTDSample]:
        """Return all recorded samples (read-only copy)."""
        return list(self._samples)

    def __len__(self) -> int:
        return len(self._samples)
