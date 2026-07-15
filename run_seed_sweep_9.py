"""Run 9-scenario seed sweep (5 seeds) and print stability table."""
import sys, os, warnings, json
warnings.filterwarnings('ignore')
sys.path.insert(0, '.')
sys.path.insert(0, '../cybershield')
import logging
logging.disable(logging.WARNING)

from pathlib import Path
from robustness.seed_sweep import run_seed_sweep, save_sweep_results, print_sweep_report

RUN = "run-20260712T160707-a72627"
N_SEEDS = 5

sweep = run_seed_sweep(run_id=RUN, entity_type='IT', n_seeds=N_SEEDS)
path = save_sweep_results(sweep)

# Build per-scenario stability table
scenarios = sweep.scenarios
from collections import defaultdict
per_scenario = defaultdict(list)
for r in sweep.per_seed_results:
    per_scenario[r['scenario']].append(r)

# Flag for SMALL SAMPLE scenarios
SMALL_SAMPLE_SCENARIOS = {'privilege_escalation_token', 'persistence_scheduled_task'}

print(f"\n=== SEED SWEEP: {N_SEEDS} seeds x {len(scenarios)} IT scenarios ===")
print(f"Run: {RUN}\n")

unstable = []
print(f"{'Scenario':<36} {'n':>3} | " + "  ".join(f"s{i}" for i in range(N_SEEDS)) + "  | DR_min  DR_max  Verdict")
print("-" * 110)

for scen in scenarios:
    rows = sorted(per_scenario[scen], key=lambda r: r['seed'])
    n = rows[0]['n_attack'] if rows else '?'
    drs = [r['detection_rate'] for r in rows]
    dr_min, dr_max = min(drs), max(drs)
    dr_range_pp = (dr_max - dr_min) * 100
    # UNSTABLE if any seed has DR=0 or DR range > 10pp
    is_unstable = any(d == 0.0 for d in drs) or dr_range_pp > 10.0
    verdict = "UNSTABLE" if is_unstable else "STABLE"
    if is_unstable:
        unstable.append(scen)
    flag = " [SMALL]" if scen in SMALL_SAMPLE_SCENARIOS else ""
    dr_strs = "  ".join(f"{d:.0%}" for d in drs)
    print(f"{scen:<36} {n:>3} | {dr_strs}  | {dr_min:.0%}  {dr_max:.0%}  {verdict}{flag}")

print(f"\nSaved to: {path}")
print(f"\nUNSTABLE scenarios: {unstable if unstable else 'None'}")
print(f"Overall stability: {'STABLE' if not unstable else 'UNSTABLE (' + str(len(unstable)) + ' scenarios)'}")
print(f"\n--- FPR per seed (same for all scenarios, depends on normal-seed) ---")
# FPR is per-seed (same normal-traffic baseline for all scenarios in a seed)
fpr_by_seed = defaultdict(list)
for r in sweep.per_seed_results:
    fpr_by_seed[r['seed']].append(r['fpr'])
for seed_id in sorted(fpr_by_seed):
    fprs = fpr_by_seed[seed_id]
    print(f"  seed={seed_id}: FPR={fprs[0]:.1%} (same across all {len(fprs)} scenarios)")
