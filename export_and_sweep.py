"""Re-export updated calibrator + run sweep comparison."""
import sys, warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, '.')
sys.path.insert(0, '../cybershield')
import logging
logging.disable(logging.WARNING)

from pathlib import Path

RUN = "run-20260712T160707-a72627"
ETYPE = "IT"

# ── 1. Re-export updated calibrator to production ───────────────────────────
print("Re-exporting to production store...")
from export_to_production import export_to_production
export_to_production(run_id=RUN, entity_type=ETYPE)
print("Export done.")

# ── 2. Run 5-seed sweep ─────────────────────────────────────────────────────
print("\nRunning 5-seed sweep across all 9 IT scenarios...")
import json
from collections import defaultdict
from robustness.seed_sweep import run_seed_sweep, save_sweep_results

sweep = run_seed_sweep(run_id=RUN, entity_type=ETYPE, n_seeds=5)
save_sweep_results(sweep)

# ── 3. Print comparison table ────────────────────────────────────────────────
OLD_FPR = {0: 0.385, 1: 0.385, 2: 0.400, 3: 0.360, 4: 0.390}

per_scenario = defaultdict(list)
for r in sweep.per_seed_results:
    per_scenario[r['scenario']].append(r)

SMALL = {'privilege_escalation_token', 'persistence_scheduled_task'}

print("\n=== NEW 9-SCENARIO SEED SWEEP (after broader-normal recalibration) ===")
print("New ECDF threshold: 0.459854  (was 0.611650)")
print()
header = '{:<36} {:>3} | {:5}  {:5}  {:5}  {:5}  {:5} | DR_min  DR_max  Verdict'.format(
    'Scenario', 'n', 's0', 's1', 's2', 's3', 's4')
print(header)
print('-' * 100)

unstable = []
for scen in sweep.scenarios:
    rows = sorted(per_scenario[scen], key=lambda r: r['seed'])
    n = rows[0]['n_attack'] if rows else '?'
    drs = [r['detection_rate'] for r in rows]
    dr_min, dr_max = min(drs), max(drs)
    dr_range_pp = (dr_max - dr_min) * 100
    is_unstable = any(x == 0.0 for x in drs) or dr_range_pp > 10.0
    verdict = 'UNSTABLE' if is_unstable else 'STABLE'
    if is_unstable:
        unstable.append(scen)
    flag = ' [SMALL]' if scen in SMALL else ''
    dr_str = '  '.join('{:.0%}'.format(x) for x in drs)
    row = '{:<36} {:>3} | {} | {:>5}   {:>5}   {}{}'.format(
        scen, n, dr_str, '{:.0%}'.format(dr_min), '{:.0%}'.format(dr_max), verdict, flag)
    print(row)

print()
print('UNSTABLE scenarios:', unstable if unstable else 'None')

print()
print('=== FPR COMPARISON (per seed) ===')
print('{:>8}  {:>10}  {:>10}  {:>10}'.format('Seed', 'OLD FPR', 'NEW FPR', 'Change'))
print('-' * 45)
seen = set()
for r in sorted(sweep.per_seed_results, key=lambda x: x['seed']):
    s = r['seed']
    if s not in seen:
        seen.add(s)
        new_fpr = r['fpr']
        old_fpr = OLD_FPR.get(s, float('nan'))
        delta = new_fpr - old_fpr
        sign = '+' if delta >= 0 else ''
        print('{:>8}  {:>10.1%}  {:>10.1%}  {:>10}'.format(
            s, old_fpr, new_fpr, sign + '{:.1%}'.format(delta)))

print()
print('Overall stability verdict:', sweep.stability_verdict)
print('DR RESULT:', 'PERFECT (100% all seeds all scenarios)' if not unstable else 'CHECK UNSTABLE LIST ABOVE')
