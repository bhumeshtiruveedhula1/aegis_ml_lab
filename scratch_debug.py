"""
Compare baseline vs fd360a to find the real cause of FPR difference.
Evidence gathered, not inference.
"""
import json, hashlib, sys
from pathlib import Path

LAB = Path('c:/Users/bhumeshjyothi/Desktop/cyber-et/aegis_ml_lab')
CS  = Path('c:/Users/bhumeshjyothi/Desktop/cyber-et/cybershield')

BASELINE = 'run-20260712T160707-a72627'
FD360A   = 'run-20260714T195242-fd360a'

# ── 1. Compare metadata.json ──────────────────────────────────────────────────
print("=== 1. metadata.json comparison ===")
fields = ['random_state','seed','n_estimators','contamination','max_samples',
          'max_features','feature_dimension','sample_count','entity_type','entity_dim']

rows = {}
for run_id in [BASELINE, FD360A]:
    p = LAB / 'models' / 'registry' / run_id / 'IT' / 'metadata.json'
    if p.exists():
        rows[run_id] = json.loads(p.read_text())
    else:
        rows[run_id] = {'ERROR': f'not found at {p}'}

for f in fields:
    b = rows[BASELINE].get(f, 'MISSING')
    d = rows[FD360A].get(f, 'MISSING')
    diff = " <-- DIFFERS" if b != d else ""
    print(f"  {f:<22}: baseline={b!r:30}  fd360a={d!r}{diff}")

# ── 2. normalized_events.jsonl — hash + line count ────────────────────────────
print("\n=== 2. normalized_events.jsonl — current state ===")
norm_path = CS / 'data' / 'normalized' / 'normalized_events.jsonl'
if norm_path.exists():
    content = norm_path.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()
    lines = content.count(b'\n')
    mtime = norm_path.stat().st_mtime
    import datetime
    mt_str = datetime.datetime.fromtimestamp(mtime).isoformat()
    print(f"  path   : {norm_path}")
    print(f"  sha256 : {sha256}")
    print(f"  lines  : {lines}")
    print(f"  mtime  : {mt_str}")
else:
    print("  NOT FOUND")

# ── 3. Check whether the baseline run recorded an event count ─────────────────
print("\n=== 3. Baseline training info ===")
b_meta = rows[BASELINE]
print(f"  trained_at     : {b_meta.get('trained_at','?')}")
print(f"  sample_count   : {b_meta.get('sample_count','?')}")
print(f"  feature_names  : {len(b_meta.get('feature_names',[]))} features")
print(f"  run_id         : {b_meta.get('run_id','?')}")

print("\n=== 4. fd360a training info ===")
d_meta = rows[FD360A]
print(f"  trained_at     : {d_meta.get('trained_at','?')}")
print(f"  sample_count   : {d_meta.get('sample_count','?')}")
print(f"  feature_names  : {len(d_meta.get('feature_names',[]))} features")
print(f"  run_id         : {d_meta.get('run_id','?')}")

# ── 4. Check calibrator meta for both runs ────────────────────────────────────
print("\n=== 5. Calibrator metadata comparison ===")
for run_id in [BASELINE, FD360A]:
    cal_meta = LAB / 'calibration' / 'calibrators' / f'{run_id}_IT_meta.json'
    if cal_meta.exists():
        cm = json.loads(cal_meta.read_text())
        print(f"  [{run_id[:20]}]")
        for k in ['n_cal_samples','n_attack','n_normal','entity_type','run_id']:
            print(f"    {k}: {cm.get(k,'?')}")
    else:
        print(f"  [{run_id[:20]}] calibrator meta NOT FOUND")

# ── 5. Compare thresholds ──────────────────────────────────────────────────────
print("\n=== 6. Threshold files ===")
for run_id in [BASELINE, FD360A]:
    tf = LAB / 'thresholds' / f'{run_id}_IT_thresholds.json'
    if tf.exists():
        td = json.loads(tf.read_text())
        fallback = td.get('type_level_fallback') or td.get('type_fallback')
        per_entity = len(td.get('entity_thresholds', td.get('per_entity',{})))
        print(f"  {run_id}: fallback={fallback}  per_entity_count={per_entity}")
    else:
        print(f"  {run_id}: NO THRESHOLD FILE")

# ── 6. Check seed sweep results for baseline ──────────────────────────────────
print("\n=== 7. Baseline seed sweep FPR per seed ===")
sweep = LAB / 'runs' / BASELINE / 'seed_sweep_results.json'
if sweep.exists():
    sd = json.loads(sweep.read_text())
    seen = {}
    for r in sd.get('per_seed_results', []):
        s = r.get('seed')
        if s not in seen:
            seen[s] = r.get('fpr', '?')
    for s in sorted(seen):
        print(f"  seed={s}: fpr={seen[s]:.3f}")
else:
    print(f"  File not found: {sweep}")
