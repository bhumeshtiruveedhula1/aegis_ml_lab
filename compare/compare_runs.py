"""
aegis_ml_lab/compare/compare_runs.py
======================================
Phase 7 — Bootstrap Confidence Interval Comparison Engine.

Compares two runs (or two seeds of the same run) using bootstrap resampling.
CI overlap/non-overlap IS the verdict — naive metric diffs are stored for
reference only and never used as the decision basis.

Usage
-----
    from compare.compare_runs import compare_runs, load_metrics_for_run
    result = compare_runs("run-abc", "run-xyz", n_bootstrap=10_000)

CLI
---
    python cli.py compare seed:0 seed:1
    python cli.py compare run-<id_a> run-<id_b>
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
import structlog

logger = structlog.get_logger(__name__)

_LAB_ROOT = Path(__file__).parent.parent
_RUNS_DIR = _LAB_ROOT / "runs"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MetricCI:
    metric: str
    run_a_mean: float
    run_b_mean: float
    run_a_ci_lo: float
    run_a_ci_hi: float
    run_b_ci_lo: float
    run_b_ci_hi: float
    overlap: bool
    verdict: str          # NOT_SIGNIFICANTLY_DIFFERENT | A_BETTER | B_BETTER
    naive_diff: float     # stored for reference, never the decision basis


@dataclass
class CompareResult:
    run_a_label: str
    run_b_label: str
    n_bootstrap: int
    ci_level: float
    metrics: list[MetricCI] = field(default_factory=list)
    overall_verdict: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "run_a_label": self.run_a_label,
            "run_b_label": self.run_b_label,
            "n_bootstrap": self.n_bootstrap,
            "ci_level": self.ci_level,
            "overall_verdict": self.overall_verdict,
            "note": self.note,
            "metrics": [
                {
                    "metric": m.metric,
                    "run_a_mean": round(m.run_a_mean, 4),
                    "run_b_mean": round(m.run_b_mean, 4),
                    "run_a_ci_lo": round(m.run_a_ci_lo, 4),
                    "run_a_ci_hi": round(m.run_a_ci_hi, 4),
                    "run_b_ci_lo": round(m.run_b_ci_lo, 4),
                    "run_b_ci_hi": round(m.run_b_ci_hi, 4),
                    "overlap": m.overlap,
                    "verdict": m.verdict,
                    "naive_diff": round(m.naive_diff, 4),
                }
                for m in self.metrics
            ],
        }

    def to_markdown(self) -> str:
        lines = [
            "# Bootstrap CI Comparison",
            "",
            f"**Run A:** `{self.run_a_label}`  ",
            f"**Run B:** `{self.run_b_label}`  ",
            f"**Bootstrap resamples:** {self.n_bootstrap:,}  ",
            f"**CI level:** {self.ci_level:.0%}",
            "",
            "> NOTE: The CI overlap/non-overlap IS the verdict.",
            "> Naive metric diffs are stored for reference but are NOT the basis for conclusions.",
            "",
            "| Metric | A mean | A 95% CI | B mean | B 95% CI | Overlap? | Verdict |",
            "|--------|--------|----------|--------|----------|----------|---------| ",
        ]
        for m in self.metrics:
            lines.append(
                f"| {m.metric} | {m.run_a_mean:.4f} | [{m.run_a_ci_lo:.4f}, {m.run_a_ci_hi:.4f}]"
                f" | {m.run_b_mean:.4f} | [{m.run_b_ci_lo:.4f}, {m.run_b_ci_hi:.4f}]"
                f" | {'YES' if m.overlap else 'NO'} | {m.verdict} |"
            )
        lines += [
            "",
            f"**Overall verdict:** `{self.overall_verdict}`",
            "",
        ]
        if self.note:
            lines.append(f"> {self.note}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Bootstrap CI computation
# ---------------------------------------------------------------------------

def _bootstrap_ci(
    samples: list[float],
    n_bootstrap: int = 10_000,
    ci_level: float = 0.95,
    rng: "np.random.Generator | None" = None,
) -> tuple[float, float, float]:
    """
    Compute bootstrap percentile CI for a list of samples.

    Returns (mean, ci_lo, ci_hi).
    If only one unique value, CI is [val, val] (zero-width — correct behaviour).
    """
    if rng is None:
        rng = np.random.default_rng(42)

    arr = np.array(samples, dtype=float)
    mean = float(arr.mean())

    if len(arr) == 0:
        return mean, mean, mean

    # Generate bootstrap resamples
    boot_means = np.array([
        rng.choice(arr, size=len(arr), replace=True).mean()
        for _ in range(n_bootstrap)
    ])

    alpha = 1.0 - ci_level
    lo = float(np.percentile(boot_means, 100 * alpha / 2))
    hi = float(np.percentile(boot_means, 100 * (1.0 - alpha / 2)))
    return mean, lo, hi


def _cis_overlap(a_lo: float, a_hi: float, b_lo: float, b_hi: float) -> bool:
    """True if two CIs share any interval."""
    return not (a_hi < b_lo or b_hi < a_lo)


def _per_metric_verdict(
    overlap: bool,
    a_mean: float,
    b_mean: float,
    metric: str,
) -> str:
    """
    Derive per-metric verdict from CI overlap.
    For FPR: lower is better. For detection_rate and auroc: higher is better.
    """
    if overlap:
        return "NOT_SIGNIFICANTLY_DIFFERENT"
    lower_is_better = metric in ("fpr",)
    if lower_is_better:
        return "B_BETTER" if b_mean < a_mean else "A_BETTER"
    else:
        return "B_BETTER" if b_mean > a_mean else "A_BETTER"


def _overall_verdict(metrics: list[MetricCI]) -> str:
    verdicts = {m.verdict for m in metrics}
    if verdicts == {"NOT_SIGNIFICANTLY_DIFFERENT"}:
        return "NOT_SIGNIFICANTLY_DIFFERENT"
    if "A_BETTER" in verdicts and "B_BETTER" not in verdicts:
        return "A_BETTER_ON_ALL_METRICS"
    if "B_BETTER" in verdicts and "A_BETTER" not in verdicts:
        return "B_BETTER_ON_ALL_METRICS"
    return "MIXED"


# ---------------------------------------------------------------------------
# Run data loading
# ---------------------------------------------------------------------------

def _find_latest_run_dir() -> Path:
    """Return the most recently modified run directory."""
    runs = [d for d in _RUNS_DIR.iterdir() if d.is_dir() and d.name.startswith("run-")]
    if not runs:
        raise RuntimeError(f"No run directories found in {_RUNS_DIR}")
    return max(runs, key=lambda d: d.stat().st_mtime)


def _load_seed_sweep(run_dir: Path) -> dict:
    p = run_dir / "seed_sweep_results.json"
    if not p.exists():
        raise FileNotFoundError(f"seed_sweep_results.json not found in {run_dir}")
    return json.loads(p.read_text(encoding="utf-8"))


def load_metrics_for_seed(seed_ref: str, run_dir: Path | None = None) -> tuple[dict[str, list[float]], str]:
    """
    Load per-scenario metrics for a specific seed from seed_sweep_results.json.

    seed_ref: "seed:N" (e.g., "seed:0")

    seed_sweep_results.json structure:
      {
        "seeds": [0, 1, 2, ...],
        "per_seed_results": [
          {"seed": 0, "scenario": "...", "detection_rate": ..., "fpr": ..., "auroc": ...},
          ...
        ],
        ...
      }

    Returns ({metric: [per_scenario_values_for_this_seed]}, label)
    """
    seed_n = int(seed_ref.split(":")[1])
    if run_dir is None:
        run_dir = _find_latest_run_dir()
    sweep = _load_seed_sweep(run_dir)
    valid_seeds = sweep.get("seeds", [])
    if seed_n not in valid_seeds:
        raise ValueError(
            f"Seed {seed_n} not found in sweep. Available: {valid_seeds}."
        )
    per_seed = sweep.get("per_seed_results", [])
    # Filter to this seed's rows
    rows = [r for r in per_seed if r.get("seed") == seed_n]
    if not rows:
        raise ValueError(f"No per_seed_results rows found for seed={seed_n}.")

    metrics: dict[str, list[float]] = {
        "detection_rate": [],
        "fpr": [],
        "auroc": [],
    }
    for row in rows:
        metrics["detection_rate"].append(float(row.get("detection_rate", 0.0)))
        metrics["fpr"].append(float(row.get("fpr", 1.0)))
        metrics["auroc"].append(float(row.get("auroc", 0.0)))

    label = f"{run_dir.name} seed={seed_n}"
    return metrics, label


def load_metrics_for_run(run_id: str) -> tuple[dict[str, list[float]], str]:
    """
    Load per-scenario metrics from raw_metrics.json for a named run.

    Returns ({metric: [per_scenario_values]}, label)
    """
    run_dir = _RUNS_DIR / run_id
    if not run_dir.exists():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")
    metrics_path = run_dir / "raw_metrics.json"
    if not metrics_path.exists():
        raise FileNotFoundError(f"raw_metrics.json not found in {run_dir}")
    data = json.loads(metrics_path.read_text(encoding="utf-8"))
    scenarios = data.get("scenarios", [])
    metrics: dict[str, list[float]] = {
        "detection_rate": [],
        "fpr": [],
        "auroc": [],
    }
    for s in scenarios:
        metrics["detection_rate"].append(float(s.get("detection_rate", 0.0)))
        metrics["fpr"].append(float(s.get("fpr", 1.0)))
        metrics["auroc"].append(float(s.get("auroc", 0.0)))
    label = run_id
    return metrics, label


def _resolve_run(
    ref: str,
    run_dir: Path | None = None,
) -> tuple[dict[str, list[float]], str]:
    """
    Resolve a run reference to (metrics_dict, label).
    Supports:
      "seed:N"          → load from seed_sweep_results.json
      "run-<id>"        → load from runs/<id>/raw_metrics.json
      bare run ID       → same as above
    """
    if ref.startswith("seed:"):
        return load_metrics_for_seed(ref, run_dir=run_dir)
    else:
        return load_metrics_for_run(ref)


# ---------------------------------------------------------------------------
# Main comparison entry point
# ---------------------------------------------------------------------------

def compare_runs(
    run_a_ref: str,
    run_b_ref: str,
    n_bootstrap: int = 10_000,
    ci_level: float = 0.95,
    run_dir: Path | None = None,
) -> CompareResult:
    """
    Bootstrap CI comparison of two runs.

    Parameters
    ----------
    run_a_ref, run_b_ref : str
        Run references — either "seed:N" or a run ID string.
    n_bootstrap : int
        Number of bootstrap resamples (default 10,000).
    ci_level : float
        Confidence level (default 0.95 = 95%).
    run_dir : Path | None
        Base run directory (for seed: refs). Defaults to latest run.

    Returns
    -------
    CompareResult with per-metric CIs and overall verdict.
    """
    rng = np.random.default_rng(42)

    metrics_a, label_a = _resolve_run(run_a_ref, run_dir=run_dir)
    metrics_b, label_b = _resolve_run(run_b_ref, run_dir=run_dir)

    result = CompareResult(
        run_a_label=label_a,
        run_b_label=label_b,
        n_bootstrap=n_bootstrap,
        ci_level=ci_level,
    )

    for metric in ("detection_rate", "fpr", "auroc"):
        samples_a = metrics_a.get(metric, [])
        samples_b = metrics_b.get(metric, [])

        if not samples_a or not samples_b:
            logger.warning("bootstrap_ci_skip_empty_samples", metric=metric)
            continue

        a_mean, a_lo, a_hi = _bootstrap_ci(samples_a, n_bootstrap, ci_level, rng)
        b_mean, b_lo, b_hi = _bootstrap_ci(samples_b, n_bootstrap, ci_level, rng)

        overlap = _cis_overlap(a_lo, a_hi, b_lo, b_hi)
        verdict = _per_metric_verdict(overlap, a_mean, b_mean, metric)

        ci_row = MetricCI(
            metric=metric,
            run_a_mean=round(a_mean, 4),
            run_b_mean=round(b_mean, 4),
            run_a_ci_lo=round(a_lo, 4),
            run_a_ci_hi=round(a_hi, 4),
            run_b_ci_lo=round(b_lo, 4),
            run_b_ci_hi=round(b_hi, 4),
            overlap=overlap,
            verdict=verdict,
            naive_diff=round(b_mean - a_mean, 4),
        )
        result.metrics.append(ci_row)

        a_str = f"{a_mean:.4f} [{a_lo:.4f}, {a_hi:.4f}]"
        b_str = f"{b_mean:.4f} [{b_lo:.4f}, {b_hi:.4f}]"
        logger.info(
            "bootstrap_ci_result",
            metric=metric,
            run_a=a_str,
            run_b=b_str,
            overlap=overlap,
            verdict=verdict,
        )

    result.overall_verdict = _overall_verdict(result.metrics)

    # Note for same-config seed comparisons
    if run_a_ref.startswith("seed:") and run_b_ref.startswith("seed:"):
        result.note = (
            "Comparing two seeds of the SAME config. CI overlap is the correct, "
            "expected result \u2014 it confirms the bootstrap mechanism works, not that there's a bug."
        )

    return result


def save_compare_result(result: CompareResult, run_dir: Path) -> Path:
    """Save comparison result JSON to run_dir."""
    # Sanitise labels for filename
    a_safe = re.sub(r"[^A-Za-z0-9_-]", "_", result.run_a_label.split()[0])
    b_safe = re.sub(r"[^A-Za-z0-9_-]", "_", result.run_b_label.split()[0])
    # Use last token (seed=N or run-id) for the filename
    def _short(label: str) -> str:
        parts = label.split()
        return re.sub(r"[^A-Za-z0-9_]", "_", parts[-1]) if len(parts) > 1 else re.sub(r"[^A-Za-z0-9_]", "_", parts[0])

    filename = f"compare_{_short(result.run_a_label)}_{_short(result.run_b_label)}.json"
    out = run_dir / filename
    out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    logger.info("compare_result_saved", path=str(out))
    return out
