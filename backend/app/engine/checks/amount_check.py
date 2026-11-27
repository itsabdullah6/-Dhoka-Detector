"""
Check 1: AmountAnomalyCheck
Evaluates whether transaction amount deviates drastically from customer's historical baseline.
"""
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class AmountAnomalyCheck(RiskCheck):
    def __init__(self, weight: float = 18.0):
        super().__init__(
            name="AmountAnomalyCheck",
            weight=weight,
            signal_origin="BEHAVIORAL_BASELINE"
        )

    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        amount = transaction.amount
        avg = profile.avg_amount
        max_hist = profile.max_historical_amount

        # Calculate ratio of current transaction to average baseline
        ratio_to_avg = amount / max(1.0, avg)
        ratio_to_max = amount / max(1.0, max_hist)

        raw_score = 0.0
        reason = "Transaction amount conforms to normal profile."
        triggered = False

        if ratio_to_max > 3.0 or ratio_to_avg > 8.0:
            # Extreme anomaly: > 3x max historical or > 8x average
            raw_score = 1.0
            triggered = True
            reason = f"Extreme spike: PKR {amount:,.0f} is {ratio_to_avg:.1f}x average (PKR {avg:,.0f}) and {ratio_to_max:.1f}x max past payment."
        elif ratio_to_max > 1.5 or ratio_to_avg > 4.0:
            # Moderate anomaly
            raw_score = 0.65
            triggered = True
            reason = f"Elevated amount: PKR {amount:,.0f} significantly exceeds typical payments ({ratio_to_avg:.1f}x average)."
        elif ratio_to_avg > 2.5:
            # Mild elevation
            raw_score = 0.35
            triggered = True
            reason = f"Noticeable increase: PKR {amount:,.0f} is {ratio_to_avg:.1f}x average."

        return CheckResult(
            check_name=self.name,
            weight=self.weight,
            raw_score=raw_score,
            score_contribution=round(raw_score * self.weight, 2),
            triggered=triggered,
            signal_origin=self.signal_origin,
            reason=reason,
            evidence={
                "amount": amount,
                "avg_baseline": avg,
                "max_historical": max_hist,
                "ratio_to_avg": round(ratio_to_avg, 2),
                "ratio_to_max": round(ratio_to_max, 2)
            }
        )
