"""
Check 7: SplittingCheck (Smurfing / Structuring Detection)
Evaluates if customer or adversary is intentionally splitting larger sums
into sub-threshold chunks to evade detection or reporting thresholds.
"""
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class SplittingCheck(RiskCheck):
    # Common structuring thresholds in Pakistani FinTech (e.g. just below 50,000 or 100,000 PKR)
    def __init__(self, weight: float = 14.0, window_seconds: int = 1800):
        super().__init__(
            name="SplittingCheck",
            weight=weight,
            signal_origin="BEHAVIORAL_BASELINE"
        )
        self.window_seconds: int = window_seconds  # Default: 30 minutes

    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        current_amount = transaction.amount
        recent_txs = profile.get_recent_transactions_within_seconds(
            current_time=transaction.timestamp,
            seconds=self.window_seconds
        )

        if not recent_txs:
            return CheckResult(
                check_name=self.name,
                weight=self.weight,
                raw_score=0.0,
                score_contribution=0.0,
                triggered=False,
                signal_origin=self.signal_origin,
                reason="No split transaction patterns detected.",
                evidence={"split_detected": False}
            )

        # 1. Pattern: Identical repeat amount within 30 minutes
        identical_repeats = [t for t in recent_txs if abs(t.amount - current_amount) < 1.0]
        
        # 2. Pattern: Structuring just below 50k (e.g. 45k - 49.9k) or below 100k
        is_sub_threshold = (45000 <= current_amount < 50000) or (90000 <= current_amount < 100000)
        recent_sub_thresholds = [
            t for t in recent_txs
            if (45000 <= t.amount < 50000) or (90000 <= t.amount < 100000)
        ]

        if len(identical_repeats) >= 2:
            return CheckResult(
                check_name=self.name,
                weight=self.weight,
                raw_score=1.0,
                score_contribution=round(1.0 * self.weight, 2),
                triggered=True,
                signal_origin=self.signal_origin,
                reason=f"High structuring risk: {len(identical_repeats) + 1} identical transactions of PKR {current_amount:,.0f} within {self.window_seconds // 60} mins.",
                evidence={"identical_repeats_count": len(identical_repeats), "pattern": "REPEATED_IDENTICAL_AMOUNT"}
            )

        if is_sub_threshold and len(recent_sub_thresholds) >= 1:
            return CheckResult(
                check_name=self.name,
                weight=self.weight,
                raw_score=0.85,
                score_contribution=round(0.85 * self.weight, 2),
                triggered=True,
                signal_origin=self.signal_origin,
                reason=f"Suspected smurfing/structuring: Repeated transfers right below regulatory reporting limit (PKR 50k/100k).",
                evidence={"sub_threshold_count": len(recent_sub_thresholds) + 1, "pattern": "SUB_THRESHOLD_SMURFING"}
            )

        return CheckResult(
            check_name=self.name,
            weight=self.weight,
            raw_score=0.0,
            score_contribution=0.0,
            triggered=False,
            signal_origin=self.signal_origin,
            reason="No splitting or structuring patterns identified.",
            evidence={"split_detected": False}
        )
