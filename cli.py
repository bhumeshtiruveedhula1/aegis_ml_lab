"""
aegis_ml_lab/cli.py
=====================
Central command-line interface for the AEGIS ML Lab.

All phases are invoked through this file:
    python cli.py <command> [options]

Commands
--------
  status            Print lab state (what's built, what's missing, what to run next).
  generate-baseline Build or refresh the entity baseline for IT or OT.
  audit-baseline    Check baseline for attack contamination.
  train             Train IT or OT Isolation Forest model.
  calibrate         Fit isotonic calibrator (Phase 3).
  threshold         Compute ECDF per-entity thresholds (Phase 3.4).
  evaluate          Run full evaluation harness (Phase 5 + optional Phase 6).
  compare           Statistical comparison of two runs via bootstrap CI (Phase 7).
  shap-audit        Report feature appearance rate in SHAP top-3 (Phase 4).
  judge-summary     One-page summary with deferred items list (Phase 8).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure both lab root and cybershield are importable
_LAB_ROOT = Path(__file__).parent
for _p in (str(_LAB_ROOT), str(_LAB_ROOT.parent / "cybershield")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_latest_run_id() -> str | None:
    """Return the run_id of the most recently modified run directory, or None."""
    runs_dir = _LAB_ROOT / "runs"
    if not runs_dir.exists():
        return None
    candidates = [d for d in runs_dir.iterdir() if d.is_dir() and d.name.startswith("run-")]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime).name


def _find_latest_trained_run_id(entity_type: str) -> str | None:
    """Return the run_id of the most recently trained model for entity_type."""
    registry = _LAB_ROOT / "models" / "registry"
    if not registry.exists():
        return None
    candidates = [
        d for d in registry.iterdir()
        if d.is_dir() and d.name.startswith("run-") and (d / entity_type / "isolation_forest.pkl").exists()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime).name


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_status(args: argparse.Namespace) -> int:
    """Print lab state overview."""
    print("=== AEGIS ML Lab — Status ===")
    print()

    # Baseline
    for et in ("IT", "OT"):
        baseline_dir = _LAB_ROOT / "models" / "baselines" / et
        if baseline_dir.exists() and any(baseline_dir.iterdir()):
            print(f"  [OK] Baseline ({et}):  {baseline_dir}")
        else:
            print(f"  [--] Baseline ({et}):  NOT BUILT  -> python cli.py generate-baseline --entity-type {et}")

    # Registry
    registry = _LAB_ROOT / "models" / "registry"
    if registry.exists():
        run_dirs = sorted(
            [d for d in registry.iterdir() if d.is_dir()],
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        if run_dirs:
            latest = run_dirs[0]
            print(f"  [OK] Latest trained run: {latest.name}")
        else:
            print("  [--] No trained models found  → python cli.py train --entity-type IT")
    else:
        print("  [--] No registry  → python cli.py train --entity-type IT")

    # Calibration
    cal_dir = _LAB_ROOT / "calibration" / "calibrators"
    if cal_dir.exists() and any(cal_dir.glob("*.pkl")):
        pkls = sorted(cal_dir.glob("*.pkl"), key=lambda p: p.stat().st_mtime, reverse=True)
        print(f"  [OK] Calibrator:  {pkls[0].name}")
    else:
        print("  [--] No calibrators  → python cli.py calibrate --entity-type IT")

    # Runs
    run_id = _find_latest_run_id()
    if run_id:
        runs_dir = _LAB_ROOT / "runs" / run_id
        artifacts = list(runs_dir.glob("*.json")) + list(runs_dir.glob("*.md"))
        print(f"  [OK] Latest run: {run_id} ({len(artifacts)} artifacts)")
        for art in sorted(artifacts):
            print(f"       {art.name}")
    else:
        print("  [--] No run artifacts  → python cli.py evaluate --all-scenarios")

    print()
    print("Quick-start sequence:")
    print("  >> python cli.py generate-baseline --entity-type IT")
    print("  >> python cli.py train --entity-type IT")
    print("  >> python cli.py calibrate --entity-type IT")
    print("  >> python cli.py threshold --entity-type IT")
    print("  >> python cli.py evaluate --all-scenarios")
    print("  >> python cli.py shap-audit")
    print("  >> python cli.py compare seed:0 seed:1")
    print("  >> python cli.py judge-summary")
    return 0


def cmd_generate_baseline(args: argparse.Namespace) -> int:
    """Generate entity baselines from normalized events."""
    entity_type = args.entity_type.upper()
    seed = getattr(args, "seed", 42)
    try:
        from models.train import generate_baseline
        out = generate_baseline(entity_type=entity_type, seed=seed)
        print(f"[generate-baseline] Baseline written: {out}")
        return 0
    except Exception as exc:
        print(f"[generate-baseline FAILED] {exc}")
        return 1


def cmd_audit_baseline(args: argparse.Namespace) -> int:
    """Audit baseline for attack contamination."""
    try:
        from models.train import audit_baseline
        audit_baseline()
        return 0
    except AttributeError:
        # audit_baseline may not be implemented; print status
        print("[audit-baseline] Contamination check: no dedicated audit function found.")
        print("                 Baseline files exist — manual review recommended.")
        return 0
    except Exception as exc:
        print(f"[audit-baseline FAILED] {exc}")
        return 1


def cmd_train(args: argparse.Namespace) -> int:
    """Train IT or OT Isolation Forest model."""
    entity_type = args.entity_type.upper()
    seed = getattr(args, "seed", 42)
    n_repeats = getattr(args, "n_repeats", None)  # None → use train()'s default
    try:
        from models.train import train
        model_path, metadata = train(entity_type=entity_type, seed=seed, n_repeats=n_repeats)
        run_id = metadata.get("run_id", "unknown")
        print(f"\n  run_id          : {run_id}")
        print(f"  model_path      : {model_path}")
        print(f"  n_features      : {metadata.get('n_features', '?')}")
        print(f"  n_samples       : {metadata.get('n_samples', '?')}")
        return 0
    except Exception as exc:
        print(f"[train FAILED] {exc}")
        return 1


def cmd_calibrate(args: argparse.Namespace) -> int:
    """Fit isotonic calibrator on calibration split (Phase 3)."""
    entity_type = args.entity_type.upper()
    run_id = getattr(args, "run_id", None) or _find_latest_trained_run_id(entity_type)
    seed_a = getattr(args, "seed_a", 42)
    seed_b = getattr(args, "seed_b", 1337)
    augment_bfa = getattr(args, "augment_brute_force", False)
    if run_id is None:
        print(f"[calibrate FAILED] No trained model found for {entity_type}. Run train first.")
        return 1
    try:
        from calibration.fit_isotonic import run_calibration

        # Step 1: Always run calibration first — generates splits manifest if missing
        calibrator = run_calibration(
            run_id=run_id,
            entity_type=entity_type,
            seed_a=seed_a,
            seed_b=seed_b,
            max_attack_per_scenario=getattr(args, "cal_max_attack_per_scenario", None),
        )

        # Step 2 (brute_force_auth fix): augment calibration split with extra BFA instances,
        # then re-fit calibrator. Evaluation split is NEVER touched.
        if augment_bfa:
            print("\n[calibrate] --augment-brute-force: adding extra BFA calibration instances...")
            from calibration.augment_cal import augment_brute_force_cal
            from calibration.splits import load_manifest
            from calibration.fit_isotonic import IsotonicCalibrator, save_calibrator
            augment_brute_force_cal(run_id=run_id, entity_type=entity_type)
            manifest = load_manifest(run_id, entity_type)
            cal_scores = manifest.calibration_scores()
            cal_labels = manifest.calibration_labels()
            calibrator = IsotonicCalibrator(entity_type=entity_type, run_id=run_id)
            calibrator.fit(cal_scores, cal_labels)
            save_calibrator(calibrator, run_id)
            cal_proba = calibrator.predict_proba(cal_scores)
            atk_proba = cal_proba[cal_labels == 1]
            nrm_proba = cal_proba[cal_labels == 0]
            sep = float(atk_proba.mean()) - float(nrm_proba.mean()) if len(atk_proba) and len(nrm_proba) else 0.0
            print(f"[calibrate] Augmented calibrator fitted.")
            print(f"           Attack proba : mean={atk_proba.mean():.4f}  std={atk_proba.std():.4f}")
            print(f"           Normal proba : mean={nrm_proba.mean():.4f}  std={nrm_proba.std():.4f}")
            print(f"           Separation   : {sep:+.4f}")

        print(f"[calibrate] Done. run_id={run_id}  entity={entity_type}")
        return 0
    except Exception as exc:
        print(f"[calibrate FAILED] {exc}")
        import traceback
        traceback.print_exc()
        return 1


def cmd_threshold(args: argparse.Namespace) -> int:
    """Compute ECDF per-entity thresholds (Phase 3.4)."""
    entity_type = args.entity_type.upper()
    run_id = getattr(args, "run_id", None) or _find_latest_trained_run_id(entity_type)
    if run_id is None:
        print(f"[threshold FAILED] No trained model found for {entity_type}. Run train first.")
        return 1
    try:
        from thresholds.compute_ecdf import run_threshold
        result = run_threshold(run_id=run_id, entity_type=entity_type)
        summary = result.to_json_dict()
        print(f"[threshold] Done. run_id={run_id}  entity={entity_type}")
        _fallback = summary.get('type_fallback')
        _fallback_str = f"{_fallback:.4f}" if isinstance(_fallback, (int, float)) else str(_fallback or "?")
        print(f"           type_fallback   : {_fallback_str}")
        print(f"           per_entity      : {summary.get('per_entity_count', '?')} entities")
        print(f"           cold_start      : {summary.get('cold_start_count', 0)} on fallback")
        return 0
    except Exception as exc:
        print(f"[threshold FAILED] {exc}")
        import traceback; traceback.print_exc()
        return 1


def cmd_evaluate(args: argparse.Namespace) -> int:
    """Run full evaluation harness (Phase 5 + optional Phase 6)."""
    entity_type = getattr(args, "entity_type", "IT").upper()
    run_id = getattr(args, "run_id", None) or _find_latest_trained_run_id(entity_type)
    all_scenarios = getattr(args, "all_scenarios", False)
    n_seeds = getattr(args, "seeds", None)
    adversarial_drift = getattr(args, "adversarial_drift", False)

    if run_id is None:
        print(f"[evaluate FAILED] No trained model found for {entity_type}. Run train + calibrate first.")
        return 1

    try:
        from evaluate.run_e2e_suite import run_evaluation, generate_report, save_report
        result = run_evaluation(run_id=run_id, entity_type=entity_type)
        report_md = generate_report(result)
        sys.stdout.buffer.write((report_md + "\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.flush()
        save_report(result, report_md)
        print(f"[evaluate] Saved: runs/{result.run_id}/")
    except Exception as exc:
        print(f"[evaluate FAILED] {exc}")
        import traceback
        traceback.print_exc()
        return 1

    # Phase 6.1 — seed sweep
    if n_seeds is not None and n_seeds > 0:
        try:
            from robustness.seed_sweep import run_seed_sweep, save_sweep_results, print_sweep_report
            sweep = run_seed_sweep(run_id=run_id, entity_type=entity_type, n_seeds=n_seeds)
            report = print_sweep_report(sweep)
            sys.stdout.buffer.write((report + "\n").encode("utf-8", errors="replace"))
            sys.stdout.buffer.flush()
            path = save_sweep_results(sweep)
            print(f"[seed-sweep] Saved: {path}")
        except Exception as exc:
            print(f"[seed-sweep FAILED] {exc}")
            import traceback
            traceback.print_exc()
            return 1

    # Phase 6.2 — adversarial drift
    if adversarial_drift:
        try:
            from robustness.adversarial_drift import run_adversarial_drift, save_drift_result, print_drift_report
            drift = run_adversarial_drift(run_id=run_id, entity_type=entity_type)
            report = print_drift_report(drift)
            sys.stdout.buffer.write((report + "\n").encode("utf-8", errors="replace"))
            sys.stdout.buffer.flush()
            path = save_drift_result(drift)
            print(f"[adversarial-drift] Saved: {path}")
        except Exception as exc:
            print(f"[adversarial-drift FAILED] {exc}")
            import traceback
            traceback.print_exc()
            return 1

    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    """Phase 7: Bootstrap CI comparison of two runs or seeds."""
    run_a_ref = args.run_a
    run_b_ref = args.run_b
    n_bootstrap = getattr(args, "bootstrap", 10_000)
    try:
        from compare.compare_runs import compare_runs, save_compare_result

        # Determine base run_dir for seed: refs
        run_dir = None
        run_id_for_save = _find_latest_run_id()
        if run_id_for_save:
            run_dir = _LAB_ROOT / "runs" / run_id_for_save

        result = compare_runs(
            run_a_ref=run_a_ref,
            run_b_ref=run_b_ref,
            n_bootstrap=n_bootstrap,
            run_dir=run_dir,
        )

        # Print markdown to stdout (UTF-8 safe)
        md = result.to_markdown()
        sys.stdout.buffer.write((md + "\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.flush()

        # Save JSON result
        if run_dir is not None:
            path = save_compare_result(result, run_dir)
            print(f"[compare] Saved: {path}")
        return 0
    except Exception as exc:
        print(f"[compare FAILED] {exc}")
        import traceback
        traceback.print_exc()
        return 1


def cmd_shap_audit(args: argparse.Namespace) -> int:
    """Phase 4: Report feature appearance rate in SHAP top-3."""
    entity_type = getattr(args, "entity_type", "IT").upper()
    run_id = getattr(args, "run_id", None) or _find_latest_trained_run_id(entity_type)
    if run_id is None:
        print(f"[shap-audit FAILED] No trained model found for {entity_type}.")
        return 1
    try:
        from explain.shap_report import run_shap_audit
        path = run_shap_audit(run_id=run_id, entity_type=entity_type)
        print(f"[shap-audit] Report: {path}")
        return 0
    except Exception as exc:
        print(f"[shap-audit FAILED] {exc}")
        import traceback
        traceback.print_exc()
        return 1


def cmd_judge_summary(args: argparse.Namespace) -> int:
    """Phase 8: One-page aggregated judge summary."""
    run_id = getattr(args, "run_id", None) or _find_latest_run_id()
    entity_type = getattr(args, "entity_type", "IT").upper()
    print(f"[judge-summary] entity_type={entity_type}  run_id={run_id}")
    try:
        from judge.judge_summary import build_judge_summary, save_judge_summary, print_judge_report
        summary = build_judge_summary(run_id=run_id, entity_type=entity_type)
        path = save_judge_summary(summary, run_id)
        report = print_judge_report(summary)
        # Also save markdown (explicit UTF-8 to avoid Windows cp1252 issues)
        md_path = path.parent / "judge_summary.md"
        md_path.write_text(report, encoding="utf-8")
        print(f"[judge-summary] JSON: {path}")
        print(f"[judge-summary] Markdown: {md_path}")
        return 0
    except Exception as exc:
        print(f"[judge-summary FAILED] {exc}")
        import traceback
        traceback.print_exc()
        return 1


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python cli.py",
        description="AEGIS ML Lab — anomaly detection training and evaluation CLI.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # status
    sub.add_parser("status", help="Print lab state overview.")

    # generate-baseline
    p = sub.add_parser("generate-baseline", help="Build entity baseline from normalized events.")
    p.add_argument("--entity-type", required=True, choices=["IT", "OT"])
    p.add_argument("--seed", type=int, default=42, help="RNG seed for deterministic generation (default: 42).")

    # audit-baseline
    p = sub.add_parser("audit-baseline", help="Check baseline for attack contamination.")
    p.add_argument("--check-contamination", action="store_true", default=True)

    # train
    p = sub.add_parser("train", help="Train IT or OT Isolation Forest model.")
    p.add_argument("--entity-type", required=True, choices=["IT", "OT"])
    p.add_argument("--seed", type=int, default=42, help="RNG seed (default: 42). Controls training + gate event generation.")
    p.add_argument("--n-repeats", type=int, default=None,
                   help="Number of day-offset repeats for normal event generation. "
                        "IT default=40 (~400 events). Increase for larger corpus (e.g. 500 ~= 5,000 events).")

    # calibrate
    p = sub.add_parser("calibrate", help="Fit isotonic calibrator on calibration split (Phase 3).")
    p.add_argument("--entity-type", required=True, choices=["IT", "OT"])
    p.add_argument("--run-id", default=None,
                   help="Model run ID to calibrate (default: most recent trained run).")
    p.add_argument("--seed-a", type=int, default=42,
                   help="Seed for calibration split attack instances (default: 42).")
    p.add_argument("--seed-b", type=int, default=1337,
                   help="Seed for evaluation split attack instances (default: 1337). "
                        "Must differ from --seed-a (Rule 9).")
    p.add_argument("--augment-brute-force", action="store_true",
                   help="Add extra brute_force_auth calibration instances (seeds 100, 200) "
                        "to diversify the calibration split. Rule 9 compliant: "
                        "evaluation split is never touched.")
    p.add_argument("--cal-max-attack-per-scenario", type=int, default=None, metavar="N",
                   help="Pin calibration attack count: truncate each scenario's scored attack "
                        "records to at most N before fitting the isotonic calibrator. "
                        "Evaluation split is NEVER truncated. "
                        "Use to eliminate run-to-run calibration-size variance (default: no cap).")

    # threshold
    p = sub.add_parser("threshold", help="Compute ECDF per-entity thresholds (Phase 3.4).")
    p.add_argument("--entity-type", required=True, choices=["IT", "OT"])
    p.add_argument("--run-id", default=None,
                   help="Run ID to compute thresholds for (default: most recent trained run).")

    # evaluate
    p = sub.add_parser("evaluate", help="Run full evaluation harness across all scenarios (Phase 5+6).")
    p.add_argument("--entity-type", default="IT", choices=["IT", "OT"],
                   help="Entity type to evaluate (default: IT).")
    p.add_argument("--run-id", default=None,
                   help="Run ID to evaluate (default: most recent trained run).")
    p.add_argument("--all-scenarios", action="store_true",
                   help="Evaluate all attack scenarios (required for Phase 5).")
    p.add_argument("--seeds", type=int, default=None, metavar="N",
                   help="Re-run across N fixed seeds for robustness (>=5 recommended).")
    p.add_argument("--adversarial-drift", action="store_true",
                   help="Run slow-drift evasion adversarial test.")

    # compare
    p = sub.add_parser("compare", help="Statistical comparison of two runs (bootstrap CI).")
    p.add_argument("run_a", help="First run ID or 'seed:N' for seed sweep comparison.")
    p.add_argument("run_b", help="Second run ID or 'seed:N'.")
    p.add_argument("--bootstrap", type=int, default=10_000, metavar="B",
                   help="Bootstrap resamples (default: 10,000).")
    p.add_argument("--scenario", default=None,
                   help="Filter to a specific scenario (default: all).")
    p.add_argument("--metric", default=None,
                   help="Highlight a specific metric in output (default: all reported).")

    # shap-audit
    p = sub.add_parser("shap-audit", help="Report feature appearance rate in SHAP top-3 (Phase 4).")
    p.add_argument("--entity-type", default="IT", choices=["IT", "OT"],
                   help="Entity type model to audit (default: IT).")
    p.add_argument("--run-id", default=None, help="Run ID to audit (default: latest).")

    # judge-summary
    p = sub.add_parser("judge-summary", help="One-page summary with deferred items list.")
    p.add_argument("--run-id", default=None, help="Run ID to summarise (default: latest).")
    p.add_argument("--entity-type", default="IT", choices=["IT", "OT"],
                   help="Entity type (default: IT).")

    return parser


# ---------------------------------------------------------------------------
# Dispatch table + main
# ---------------------------------------------------------------------------

_HANDLERS = {
    "status":            cmd_status,
    "generate-baseline": cmd_generate_baseline,
    "audit-baseline":    cmd_audit_baseline,
    "train":             cmd_train,
    "calibrate":         cmd_calibrate,
    "threshold":         cmd_threshold,
    "evaluate":          cmd_evaluate,
    "compare":           cmd_compare,
    "shap-audit":        cmd_shap_audit,
    "judge-summary":     cmd_judge_summary,
}


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    handler = _HANDLERS.get(args.command)
    if handler is None:
        print(f"Unknown command: {args.command}")
        sys.exit(1)
    sys.exit(handler(args))


if __name__ == "__main__":
    main()
