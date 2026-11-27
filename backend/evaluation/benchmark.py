"""
Evaluation Module: Benchmark Test Harness
Executes 100+ labelled simulation cases against RiskEngine.
Calculates Flagged-Attack Recall, False Positive Rate, Latency, and Scenario Breakdowns.
Directly satisfies Instructor Requirement 3.
"""
import time
from typing import Dict, Any, List
from backend.app.domain.transaction import DecisionState
from backend.app.engine.risk_engine import RiskEngine
from backend.app.engine.policy import DecisionPolicy
from backend.app.engine.checks.amount_check import AmountAnomalyCheck
from backend.app.engine.checks.device_check import DeviceRiskCheck
from backend.app.engine.checks.recipient_check import RecipientRiskCheck
from backend.app.engine.checks.login_anomaly_check import FailedLoginsCheck
from backend.app.engine.checks.unusual_hours_check import UnusualHoursCheck
from backend.app.engine.checks.velocity_check import VelocityCheck
from backend.app.engine.checks.splitting_check import SplittingCheck
from backend.app.engine.checks.ml_anomaly_check import IsolationForestCheck
from backend.evaluation.simulator import ScenarioSimulator, SimulationTestCase


def build_production_engine() -> RiskEngine:
    engine = RiskEngine(policy=DecisionPolicy())
    engine.register_check(AmountAnomalyCheck(weight=18.0))
    engine.register_check(DeviceRiskCheck(weight=14.0))
    engine.register_check(RecipientRiskCheck(weight=15.0))
    engine.register_check(FailedLoginsCheck(weight=15.0))
    engine.register_check(UnusualHoursCheck(weight=10.0))
    engine.register_check(VelocityCheck(weight=14.0))
    engine.register_check(SplittingCheck(weight=14.0))
    engine.register_check(IsolationForestCheck(weight=10.0))
    return engine


def run_benchmark_evaluation(seed: int = 42) -> Dict[str, Any]:
    simulator = ScenarioSimulator(seed=seed)
    test_cases: List[SimulationTestCase] = simulator.generate_evaluation_suite(count_normal=60)
    engine = build_production_engine()

    tp = 0  # Attack flagged as CHALLENGE, HOLD, or BLOCK
    fn = 0  # Attack approved (missed fraud)
    fp = 0  # Normal payment held or blocked (false alarm friction)
    tn = 0  # Normal payment approved or challenged softly

    latencies_ms: List[float] = []
    scenario_stats: Dict[str, Dict[str, int]] = {}

    for case in test_cases:
        s_name = case.scenario_name
        if s_name not in scenario_stats:
            scenario_stats[s_name] = {"total": 0, "flagged": 0, "approved": 0}
        scenario_stats[s_name]["total"] += 1

        t0 = time.perf_counter()
        report = engine.assess_transaction(case.transaction, case.profile)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(elapsed_ms)

        is_flagged = report.decision in (DecisionState.HOLD, DecisionState.BLOCK, DecisionState.CHALLENGE)
        is_severe_flagged = report.decision in (DecisionState.HOLD, DecisionState.BLOCK)

        if is_flagged:
            scenario_stats[s_name]["flagged"] += 1
        else:
            scenario_stats[s_name]["approved"] += 1

        if case.is_ground_truth_fraud:
            if is_flagged:
                tp += 1
            else:
                fn += 1
        else:
            # For legitimate normal transactions, placing them in HOLD or BLOCK is a severe False Positive
            if is_severe_flagged:
                fp += 1
            else:
                tn += 1

    total_attacks = tp + fn
    total_normal = fp + tn
    recall = (tp / total_attacks) * 100.0 if total_attacks > 0 else 0.0
    fp_rate = (fp / total_normal) * 100.0 if total_normal > 0 else 0.0
    precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    avg_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

    return {
        "total_cases_evaluated": len(test_cases),
        "total_attacks": total_attacks,
        "total_normal": total_normal,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "flagged_attack_recall_percent": round(recall, 2),
        "false_positive_rate_percent": round(fp_rate, 2),
        "precision_percent": round(precision, 2),
        "f1_score_percent": round(f1, 2),
        "average_decision_time_ms": round(avg_latency, 3),
        "scenario_breakdown": scenario_stats
    }


if __name__ == "__main__":
    import pprint
    results = run_benchmark_evaluation()
    print("=== DHOKA DETECTOR BENCHMARK EVALUATION RESULTS ===")
    pprint.pprint(results)
