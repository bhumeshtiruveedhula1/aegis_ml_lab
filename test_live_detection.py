"""Live e2e detection test — attack fires, normal doesn't."""
import sys, warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, '.')
sys.path.insert(0, '../cybershield')
import logging
logging.disable(logging.WARNING)

from pathlib import Path
from backend.detection.service import DetectionService
from backend.baseline.reader_api import BaselineReader
from backend.synthetic_attack.service import SyntheticAttackService
from backend.features.pipeline import FeaturePipeline

svc = DetectionService(auto_load=True)
reader = BaselineReader(baseline_dir=Path('models/baselines/IT'))
fp = FeaturePipeline(baseline_reader=reader, primary_only=False)

print('=== ATTACK CHECK: brute_force_auth seed=1337 ===')
atk_svc = SyntheticAttackService(persist=False, seed=1337)
rpt = atk_svc.generate('brute_force_auth', target_host='hospital-server-01',
                        attacker_user='svc-iis', compress_time=True)
events = atk_svc.get_canonical_events(rpt)
records, _ = fp.process_batch(events)
uh_records = [r for r in records if r.entity_key.entity_type == 'user_host']
result = svc._scorer.score_batch(uh_records, entity_dim='user_host')
print(f'Records: {len(uh_records)}  Alerts: {result.alerts_generated}  Alert rate: {result.alert_rate:.0%}')
if result.alerts:
    a = result.alerts[0]
    print(f'Alert: score={a.anomaly_score:.4f} (cal_threshold=0.6117) entity={a.entity_key.entity_id}')
detected = result.alerts_generated > 0
print(f'ATTACK RESULT: {"DETECTED" if detected else "MISSED - FAIL"}')

print()
print('=== NORMAL CHECK: benign traffic (normalized_events, n=200) ===')
from pathlib import Path as _P
from backend.baseline.reader import NormalizedEventReader
norm_path = (_P('../cybershield/data/normalized/normalized_events.jsonl')).resolve()
all_normal = list(NormalizedEventReader(input_file=norm_path).stream())
normal_events = all_normal[200:400] or all_normal[:200]  # eval split, same offset as e2e suite
n_records, _ = fp.process_batch(normal_events[:200])
n_uh = [r for r in n_records if r.entity_key.entity_type == 'user_host']
n_result = svc._scorer.score_batch(n_uh, entity_dim='user_host')
print('Records: {}  Alerts: {}  FPR: {:.1%}'.format(len(n_uh), n_result.alerts_generated, n_result.alert_rate))
ok_normal = n_result.alert_rate <= 0.20  # lab-established baseline is 14.5% FPR
label = ('OK (FPR={:.1%}, within lab baseline of 14.5%)'.format(n_result.alert_rate) if ok_normal
         else 'FAIL: FPR={:.1%} exceeds 20% guard'.format(n_result.alert_rate))
print('NORMAL RESULT:', label)

print()
print('=== SUMMARY: attack_detected={}  normal_fpr_ok={} ==='.format(detected, ok_normal))
sys.exit(0 if (detected and ok_normal) else 1)
