"""Print seed sweep stability table from saved JSON."""
import json, sys
from pathlib import Path
from collections import defaultdict

d = json.loads(Path('runs/run-20260712T160707-a72627/seed_sweep_results.json').read_text())
print('Scenarios in sweep:', d['scenarios'])
print('Seeds:', d['seeds'])
print('Overall verdict:', d['stability_verdict'])
print()

per_scenario = defaultdict(list)
for r in d['per_seed_results']:
    per_scenario[r['scenario']].append(r)

SMALL = {'privilege_escalation_token', 'persistence_scheduled_task'}
header = '{:<36} {:>3} | {:5}  {:5}  {:5}  {:5}  {:5} | {:>6}  {:>6}  {}'.format(
    'Scenario', 'n', 's0', 's1', 's2', 's3', 's4', 'DR_min', 'DR_max', 'Verdict')
print(header)
print('-' * 100)
unstable = []
for scen in d['scenarios']:
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
print('FPR per seed (consistent across all scenarios):')
seen_seeds = set()
for r in sorted(d['per_seed_results'], key=lambda x: x['seed']):
    if r['seed'] not in seen_seeds:
        seen_seeds.add(r['seed'])
        print('  seed={}: FPR={:.1%}'.format(r['seed'], r['fpr']))
