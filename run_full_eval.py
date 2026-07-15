"""Run 9-scenario evaluation and print results table."""
import sys, os, warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, '.')
sys.path.insert(0, '../cybershield')
import logging
logging.disable(logging.WARNING)

RUN = "run-20260712T160707-a72627"

from evaluate.run_e2e_suite import run_evaluation, generate_report, save_report
result = run_evaluation(RUN, 'IT', enable_shap=False)
rpt = generate_report(result)
save_report(result, rpt)

print("\n=== 9-SCENARIO EVALUATION RESULTS (IT, eval_seed=1337) ===")
print(f"{'Scenario':<36} {'n_atk':>5} {'DR':>6} {'FPR':>6} {'AUROC':>6}")
print("-" * 62)
for s in result.scenario_metrics:
    dr = "{:.0%}".format(s.detection_rate) if not s.no_attack_records else "n/a"
    fpr = "{:.1%}".format(s.fpr) if not s.no_attack_records else "n/a"
    auroc = "{:.3f}".format(s.auroc) if not s.no_attack_records else "n/a"
    flag = " [NO RECORDS]" if s.no_attack_records else ""
    print(f"{s.scenario:<36} {s.n_attack:>5} {dr:>6} {fpr:>6} {auroc:>6}{flag}")
