"""
tests/test_chain_accuracy_aggregate.py
======================================
Regression test: the aggregate precision/recall/F1 in any task3_chain_accuracy
JSON must exactly match an independent recomputation from the per-scenario
tp/fp/fn fields in the same file.

This catches the exact class of error that went unnoticed in this build:
a harness bug producing n_alerts=21 when the calibrated-probability path
produces n_alerts=0, surfacing as a fabricated "161 alerts, P=0.042, R=0.778"
baseline that differed from what the corrected script actually measured.

Test strategy: load the two canonical result files (v3 and v4) by fixture,
recompute aggregate P/R/F1 independently from their per-scenario tp/fp/fn,
and assert equality to 4 decimal places. No network, no model loading.
"""
from __future__ import annotations
import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers — independent recomputation (no shared code with the harness)
# ---------------------------------------------------------------------------

def _recompute_aggregate(results: list[dict]) -> dict:
    """
    Given a list of per-scenario result dicts (each with precision/recall/f1),
    compute the simple mean across scenarios that have no 'error' key.
    This matches task3_chain_accuracy.py's reporting: mean over valid scenarios.
    """
    valid = [r for r in results if "error" not in r]
    assert valid, "No valid (non-error) scenarios in results"

    prec_vals = [r["precision"] for r in valid]
    rec_vals  = [r["recall"]    for r in valid]
    f1_vals   = [r["f1"]        for r in valid]

    def _mean4(vals: list[float]) -> float:
        return round(sum(vals) / len(vals), 4)

    return {
        "precision_mean": _mean4(prec_vals),
        "recall_mean":    _mean4(rec_vals),
        "f1_mean":        _mean4(f1_vals),
        "n_valid":        len(valid),
    }


def _recompute_scenario_prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """
    Independently recompute precision, recall, F1 from raw tp/fp/fn.
    Matches score_chain() logic in task3_chain_accuracy.py.
    """
    pred_size = tp + fp
    gt_size   = tp + fn
    prec = tp / pred_size if pred_size > 0 else 0.0
    rec  = tp / gt_size   if gt_size   > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return round(prec, 4), round(rec, 4), round(f1, 4)


# ---------------------------------------------------------------------------
# Fixtures — load real JSON output files
# ---------------------------------------------------------------------------

_RUNS_DIR = Path(__file__).parent.parent / "runs"

def _load_task3_json(filename: str) -> dict:
    path = _RUNS_DIR / filename
    if not path.exists():
        pytest.skip(f"Result file not present: {path}")
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def v3_data():
    return _load_task3_json("task3_chain_accuracy_20260715T033355.json")


@pytest.fixture(scope="module")
def v4_data():
    return _load_task3_json("task3_chain_accuracy_20260715T071136.json")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAggregateMatchesPerScenario:
    """
    The JSON 'aggregate' block must match an independent mean of the
    per-scenario precision/recall/f1 fields, to 4 decimal places.
    """

    def test_v3_aggregate_precision(self, v3_data):
        recomputed = _recompute_aggregate(v3_data["results"])
        assert v3_data["aggregate"]["precision_mean"] == recomputed["precision_mean"], (
            f"v3 aggregate precision_mean {v3_data['aggregate']['precision_mean']} "
            f"!= recomputed {recomputed['precision_mean']}"
        )

    def test_v3_aggregate_recall(self, v3_data):
        recomputed = _recompute_aggregate(v3_data["results"])
        assert v3_data["aggregate"]["recall_mean"] == recomputed["recall_mean"], (
            f"v3 aggregate recall_mean {v3_data['aggregate']['recall_mean']} "
            f"!= recomputed {recomputed['recall_mean']}"
        )

    def test_v3_aggregate_f1(self, v3_data):
        recomputed = _recompute_aggregate(v3_data["results"])
        assert v3_data["aggregate"]["f1_mean"] == recomputed["f1_mean"], (
            f"v3 aggregate f1_mean {v3_data['aggregate']['f1_mean']} "
            f"!= recomputed {recomputed['f1_mean']}"
        )

    def test_v4_aggregate_precision(self, v4_data):
        recomputed = _recompute_aggregate(v4_data["results"])
        assert v4_data["aggregate"]["precision_mean"] == recomputed["precision_mean"], (
            f"v4 aggregate precision_mean {v4_data['aggregate']['precision_mean']} "
            f"!= recomputed {recomputed['precision_mean']}"
        )

    def test_v4_aggregate_recall(self, v4_data):
        recomputed = _recompute_aggregate(v4_data["results"])
        assert v4_data["aggregate"]["recall_mean"] == recomputed["recall_mean"], (
            f"v4 aggregate recall_mean {v4_data['aggregate']['recall_mean']} "
            f"!= recomputed {recomputed['recall_mean']}"
        )

    def test_v4_aggregate_f1(self, v4_data):
        recomputed = _recompute_aggregate(v4_data["results"])
        assert v4_data["aggregate"]["f1_mean"] == recomputed["f1_mean"], (
            f"v4 aggregate f1_mean {v4_data['aggregate']['f1_mean']} "
            f"!= recomputed {recomputed['f1_mean']}"
        )


class TestPerScenarioPRFConsistentWithTPFPFN:
    """
    Each per-scenario precision/recall/f1 must be derivable from the same
    record's tp/fp/fn fields. Catches scoring-function bugs where the
    stored metric doesn't match the stored raw counts.
    """

    @pytest.mark.parametrize("fixture_name", ["v3_data", "v4_data"])
    def test_per_scenario_prf_consistent(self, fixture_name, request):
        data = request.getfixturevalue(fixture_name)
        valid = [r for r in data["results"] if "error" not in r]
        mismatches = []
        for r in valid:
            exp_p, exp_r, exp_f1 = _recompute_scenario_prf(r["tp"], r["fp"], r["fn"])
            if r["precision"] != exp_p or r["recall"] != exp_r or r["f1"] != exp_f1:
                mismatches.append(
                    f"{r['scenario']}: stored P={r['precision']}/R={r['recall']}/F1={r['f1']} "
                    f"vs recomputed P={exp_p}/R={exp_r}/F1={exp_f1} "
                    f"(tp={r['tp']}, fp={r['fp']}, fn={r['fn']})"
                )
        assert not mismatches, "Per-scenario P/R/F1 inconsistent with tp/fp/fn:\n" + "\n".join(mismatches)


class TestTotalAlertsConsistent:
    """
    aggregate.total_alerts must equal the sum of n_alerts across valid scenarios.
    """

    def test_v3_total_alerts(self, v3_data):
        valid = [r for r in v3_data["results"] if "error" not in r]
        computed_total = sum(r["n_alerts"] for r in valid)
        assert v3_data["aggregate"]["total_alerts"] == computed_total, (
            f"v3 total_alerts {v3_data['aggregate']['total_alerts']} != sum {computed_total}"
        )

    def test_v4_total_alerts(self, v4_data):
        valid = [r for r in v4_data["results"] if "error" not in r]
        computed_total = sum(r["n_alerts"] for r in valid)
        assert v4_data["aggregate"]["total_alerts"] == computed_total, (
            f"v4 total_alerts {v4_data['aggregate']['total_alerts']} != sum {computed_total}"
        )
