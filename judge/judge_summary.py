"""
aegis_ml_lab/judge/judge_summary.py
=====================================
Phase 8 — Judge Summary aggregator.

Reads all existing run artifacts without re-scoring:
  - raw_metrics.json         → detection rate, FPR, AUROC per scenario
  - seed_sweep_results.json  → seed stability verdict
  - adversarial_drift_result.json → drift detection verdict
  - shap_tally.json          → top SHAP features

Produces a single-page markdown judge report with:
  - Detection results table
  - Seed sweep stability
  - Adversarial drift verdict
  - SHAP feature audit summary
  - OT limitation note
  - Mandatory deferred items (CRC, ADWIN, SHAP-NL)

Output saved as judge_summary.json + judge_summary.md to runs/<run_id>/.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_LAB_ROOT = Path(__file__).parent.parent
_RUNS_DIR = _LAB_ROOT / "runs"

# Mandatory deferred items — spec rule 15. Never omit, never change.
_MANDATORY_DEFERRED = [
    {
        "item": "CRC \u2014 Concept Drift Detection (ADWIN/DDM)",
        "status": "DEFERRED",
        "reason": (
            "Requires a live production event stream to detect real temporal drift. "
            "The lab operates on a fixed synthetic baseline \u2014 ADWIN cannot be meaningfully "
            "applied without sequential real-world data across time windows."
        ),
    },
    {
        "item": "ADWIN Statistical Drift Window",
        "status": "DEFERRED",
        "reason": (
            "Depends on CRC above. ADWIN requires a sliding-window stream of production "
            "decision scores with timestamps. Not available in the lab's static evaluation setup."
        ),
    },
    {
        "item": "SHAP-NL \u2014 Natural Language SHAP Explanations",
        "status": "DEFERRED",
        "reason": (
            "Requires an LLM integration layer to convert SHAP feature importance vectors "
            "into human-readable narrative explanations. Out of scope for the ML lab layer; "
            "belongs in the alert rendering / SOC UI layer."
        ),
    },
]

_OT_LIMITATION = (
    "OT evaluation not run \u2014 known limitation. "
    "Reason: OT baseline window is < 14 days (production data requirement). "
    "OT model training was incomplete due to insufficient historical depth. "
    "Resolution: accumulate \u226514 days of real OT telemetry, then re-run "
    "train \u2192 calibrate \u2192 evaluate for OT entity type."
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    scenario: str
    detection_rate: float
    fpr: float
    auroc: float
    n_attack: int
    threshold: float


@dataclass
class SeedSweepSummary:
    stability_verdict: str
    dr_range_pp: float
    fpr_range_pp: float
    n_seeds: int
    notes: list[str] = field(default_factory=list)


@dataclass
class DriftSummary:
    overall_verdict: str
    native_api_available: bool
    simulation_method: str
    fractions_tested: list[float]
    verdicts: list[str]


@dataclass
class ShapSummary:
    total_alerts: int
    top_features: list[dict]


@dataclass
class JudgeSummary:
    run_id: str
    entity_type: str
    generated_at: str
    overlap_verified: bool
    scenarios: list[ScenarioResult]
    seed_sweep: SeedSweepSummary | None
    drift: DriftSummary | None
    shap: ShapSummary | None
    ot_limitation: str
    deferred: list[dict]

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "entity_type": self.entity_type,
            "generated_at": self.generated_at,
            "overlap_verified": self.overlap_verified,
            "ot_limitation": self.ot_limitation,
            "scenarios": [
                {
                    "scenario": s.scenario,
                    "detection_rate": s.detection_rate,
                    "fpr": s.fpr,
                    "auroc": s.auroc,
                    "n_attack": s.n_attack,
                    "threshold": s.threshold,
                }
                for s in self.scenarios
            ],
            "seed_sweep": (
                {
                    "stability_verdict": self.seed_sweep.stability_verdict,
                    "dr_range_pp": self.seed_sweep.dr_range_pp,
                    "fpr_range_pp": self.seed_sweep.fpr_range_pp,
                    "n_seeds": self.seed_sweep.n_seeds,
                    "notes": self.seed_sweep.notes,
                }
                if self.seed_sweep else None
            ),
            "drift": (
                {
                    "overall_verdict": self.drift.overall_verdict,
                    "native_api_available": self.drift.native_api_available,
                    "simulation_method": self.drift.simulation_method,
                    "fractions_tested": self.drift.fractions_tested,
                    "verdicts": self.drift.verdicts,
                }
                if self.drift else None
            ),
            "shap": (
                {
                    "total_alerts": self.shap.total_alerts,
                    "top_features": self.shap.top_features,
                }
                if self.shap else None
            ),
            "deferred": self.deferred,
        }


# ---------------------------------------------------------------------------
# Artifact loaders
# ---------------------------------------------------------------------------

def _find_latest_run_dir() -> Path:
    runs = [d for d in _RUNS_DIR.iterdir() if d.is_dir() and d.name.startswith("run-")]
    if not runs:
        raise RuntimeError(f"No run directories found in {_RUNS_DIR}")
    return max(runs, key=lambda d: d.stat().st_mtime)


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _load_scenarios(run_dir: Path) -> tuple[list[ScenarioResult], bool]:
    """Load per-scenario results from raw_metrics.json."""
    data = _load_json(run_dir / "raw_metrics.json")
    if data is None:
        return [], False
    scenarios_raw = data.get("scenarios", [])
    scenarios = []
    for s in scenarios_raw:
        scenarios.append(ScenarioResult(
            scenario=s.get("scenario", "unknown"),
            detection_rate=float(s.get("detection_rate", 0.0)),
            fpr=float(s.get("fpr", 1.0)),
            auroc=float(s.get("auroc", 0.0)),
            n_attack=int(s.get("n_attack", 0)),
            threshold=float(s.get("threshold_used", s.get("threshold", 0.0))),
        ))
    overlap_verified = data.get("overlap_verified", False)
    return scenarios, bool(overlap_verified)



def _load_seed_sweep(run_dir: Path) -> SeedSweepSummary | None:
    data = _load_json(run_dir / "seed_sweep_results.json")
    if data is None:
        return None
    # seed_sweep_results.json stores stability metrics at the top level
    # (not nested by seed — those are in per_seed_results flat list)
    verdict = data.get("stability_verdict", "UNKNOWN")
    dr_range_pp = float(data.get("dr_range_pp", 0.0))
    fpr_range_pp = float(data.get("fpr_range_pp", 0.0))
    n_seeds = int(data.get("n_seeds", 0))
    notes = data.get("stability_notes", [])

    return SeedSweepSummary(
        stability_verdict=verdict,
        dr_range_pp=round(dr_range_pp, 1),
        fpr_range_pp=round(fpr_range_pp, 1),
        n_seeds=n_seeds,
        notes=notes,
    )



def _load_drift(run_dir: Path) -> DriftSummary | None:
    data = _load_json(run_dir / "adversarial_drift_result.json")
    if data is None:
        return None
    fractions = data.get("fractions_tested", [])
    # fractions may be stored as floats or as "10%"-style strings
    fractions_float = []
    for f in fractions:
        if isinstance(f, str):
            fractions_float.append(float(f.strip("%")) / 100.0)
        else:
            fractions_float.append(float(f))
    verdicts = data.get("verdicts", [])
    return DriftSummary(
        overall_verdict=data.get("overall_verdict", "UNKNOWN"),
        native_api_available=bool(data.get("native_api_available", False)),
        simulation_method=data.get("simulation_method", "unknown"),
        fractions_tested=fractions_float,
        verdicts=verdicts,
    )


def _load_shap(run_dir: Path) -> ShapSummary | None:
    data = _load_json(run_dir / "shap_tally.json")
    if data is None:
        return None
    total = int(data.get("total_alerts", 0))
    top = data.get("top_features", [])
    return ShapSummary(total_alerts=total, top_features=top)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_judge_summary(
    run_id: str | None = None,
    entity_type: str = "IT",
) -> JudgeSummary:
    """
    Build a JudgeSummary by reading existing run artifacts.
    Does not re-score any events.

    Parameters
    ----------
    run_id : str | None
        Run ID. If None, uses the most recently modified run directory.
    entity_type : str
        Entity type (IT or OT). Default: IT.
    """
    if run_id is None:
        run_dir = _find_latest_run_dir()
        run_id = run_dir.name
    else:
        run_dir = _RUNS_DIR / run_id
    if not run_dir.exists():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")

    scenarios, overlap_verified = _load_scenarios(run_dir)
    seed_sweep = _load_seed_sweep(run_dir)
    drift = _load_drift(run_dir)
    shap = _load_shap(run_dir)

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S UTC")

    logger.info(
        "judge_summary_built",
        run_id=run_id,
        entity_type=entity_type,
        n_scenarios=len(scenarios),
        has_sweep=seed_sweep is not None,
        has_drift=drift is not None,
        has_shap=shap is not None,
    )

    return JudgeSummary(
        run_id=run_id,
        entity_type=entity_type.upper(),
        generated_at=generated_at,
        overlap_verified=overlap_verified,
        scenarios=scenarios,
        seed_sweep=seed_sweep,
        drift=drift,
        shap=shap,
        ot_limitation=_OT_LIMITATION,
        deferred=_MANDATORY_DEFERRED,
    )


def save_judge_summary(summary: JudgeSummary, run_id: str) -> Path:
    """Save JudgeSummary JSON to runs/<run_id>/judge_summary.json."""
    out = _RUNS_DIR / run_id / "judge_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
    logger.info("judge_summary_saved", path=str(out))
    return out


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def print_judge_report(summary: JudgeSummary) -> str:
    """
    Render the JudgeSummary as a markdown string, print to stdout (UTF-8),
    and return the string.
    """
    lines: list[str] = []

    # Header
    overlap_flag = "\u2705 VERIFIED" if summary.overlap_verified else "[WARN] NOT VERIFIED"
    lines += [
        "# AEGIS ML Lab \u2014 Judge Summary",
        "",
        f"**Run ID:** `{summary.run_id}`  ",
        f"**Entity type:** {summary.entity_type}  ",
        f"**Generated:** {summary.generated_at}  ",
        f"**Calibration/Evaluation non-overlap:** {overlap_flag}",
        "",
        "---",
        "",
        "## Detection Results (eval_seed=1337)",
        "",
        "| Scenario | N atk | Det Rate | FPR | AUROC | Threshold |",
        "|----------|-------|----------|-----|-------|-----------|",
    ]

    for s in summary.scenarios:
        dr_flag  = "[OK]"   if s.detection_rate >= 0.9 else "[WARN]" if s.detection_rate >= 0.5 else "[FAIL]"
        fpr_flag = "[OK]"   if s.fpr <= 0.05 else "[WARN]" if s.fpr <= 0.20 else "[FAIL]"
        lines.append(
            f"| {s.scenario} | {s.n_attack} | {dr_flag} {s.detection_rate:.1%} "
            f"| {fpr_flag} {s.fpr:.1%} | {s.auroc:.3f} | {s.threshold:.4f} |"
        )

    lines += ["", "---", "", "## Seed Sweep Stability (Phase 6.1)"]
    if summary.seed_sweep:
        sw = summary.seed_sweep
        verdict_flag = "[OK]" if sw.stability_verdict == "STABLE" else "[FAIL]"
        lines += [
            "",
            f"**Verdict:** {verdict_flag} `{sw.stability_verdict}` ({sw.n_seeds} seeds)  ",
            f"**DR range:** {sw.dr_range_pp}pp  ",
            f"**FPR range:** {sw.fpr_range_pp}pp",
        ]
        for note in sw.notes:
            lines.append("")
            lines.append(f"> [WARN] {note}")
    else:
        lines.append("_Seed sweep results not available._")

    lines += ["", "---", "", "## Adversarial Drift (Phase 6.2)"]
    if summary.drift:
        dr = summary.drift
        all_detected = all(v == "DETECTED" for v in dr.verdicts)
        drift_flag = "[OK]" if all_detected else "[FAIL]"
        verdict_short = dr.overall_verdict[:60] + ("..." if len(dr.overall_verdict) > 60 else "")
        frac_strs = [f"{int(round(f * 100))}%" for f in dr.fractions_tested]
        lines += [
            "",
            f"**Overall:** {drift_flag} `{verdict_short}`  ",
            f"**Native drift API:** {'Yes' if dr.native_api_available else 'No (simulation used)'}  ",
            f"**Fractions tested:** {frac_strs}  ",
            f"**Per-fraction verdicts:** {dr.verdicts}",
        ]
    else:
        lines.append("_Adversarial drift results not available._")

    lines += ["", "---", "", "## SHAP Feature Audit (Phase 4)"]
    if summary.shap:
        sh = summary.shap
        lines += [
            "",
            f"**Total alerts annotated:** {sh.total_alerts}  ",
            "",
            "| Rank | Feature | Alert Count | Dominance % |",
            "|------|---------|-------------|-------------|",
        ]
        for rank, feat in enumerate(sh.top_features, start=1):
            name = feat.get("feature", "?")
            count = feat.get("count", 0)
            pct = feat.get("dominance_pct", 0.0)
            lines.append(f"| {rank} | `{name}` | {count} | {pct:.1f}% |")
    else:
        lines.append("_SHAP tally not available._")

    # OT
    lines += [
        "", "---", "",
        "## OT Evaluation",
        "",
        f"> [WARN] **Known limitation:** {summary.ot_limitation}",
    ]

    # Deferred
    lines += [
        "", "---", "",
        "## Mandatory Deferred Items",
        "",
        "| Item | Status | Reason |",
        "|------|--------|--------|",
    ]
    for d in summary.deferred:
        reason_short = d["reason"][:70] + "..." if len(d["reason"]) > 70 else d["reason"]
        lines.append(f"| {d['item']} | `{d['status']}` | {reason_short} |")

    report = "\n".join(lines)
    sys.stdout.buffer.write((report + "\n").encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()
    return report
