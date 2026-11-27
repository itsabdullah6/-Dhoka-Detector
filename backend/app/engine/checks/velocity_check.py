"""
Check 6: VelocityCheck
Evaluates transfer frequency in short time windows.
Detects automated bots, drain scripts, and rapid panic transfers.
"""
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class VelocityCheck(RiskCheck):
    def __init__(self, weight: float = 14.0, window_seconds: int = 600):
        super().__init__(
            name="VelocityCheck",
            weight=weight,
            signal_origin="BEHAVIORAL_BASELINE"
        )
        self.window_seconds: int = window_seconds  # Default: 10 minutes

    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        recent_txs = profile.get_recent_transactions_within_seconds(
            current_time=transaction.timestamp,
            seconds=self.window_seconds
        )
        count = len(recent_txs)

        if count >= 4:
            raw_score = 1.0
            triggered = True
            reason = f"Extreme velocity: {count} previous transfers executed within last {self.window_seconds // 60} minutes."
        elif count >= 2:
            raw_score = 0.65
            triggered = True
            reason = f"Elevated velocity: {count} transactions within last {self.window_seconds // 60} minutes."
        elif count == 1:
            raw_score = 0.20
            triggered = False
            reason = f"Normal velocity: 1 prior transaction in {self.window_seconds // 60}-minute window."
        else:
            raw_score = 0.0
            triggered = False
            reason = "No immediate prior transactions in velocity window."

        return CheckResult(
            check_name=self.name,
            weight=self.weight,
            raw_score=raw_score,
            score_contribution=round(raw_score * self.weight, 2),
            triggered=triggered,
            signal_origin=self.signal_origin,
            reason=reason,
            evidence={
                "tx_count_in_window": count,
                "window_seconds": self.window_seconds,
                "recent_amounts": [t.amount for t in recent_txs]
            }
        )
