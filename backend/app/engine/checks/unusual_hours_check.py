"""
Check 5: UnusualHoursCheck
Evaluates whether transaction timing coincides with customer's typical active hours.
Highlights midnight high-value runs (e.g. 1 AM to 5 AM).
"""
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class UnusualHoursCheck(RiskCheck):
    def __init__(self, weight: float = 10.0):
        super().__init__(
            name="UnusualHoursCheck",
            weight=weight,
            signal_origin="BEHAVIORAL_BASELINE"
        )

    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        hour = transaction.timestamp.hour
        is_typical = profile.is_within_typical_hours(hour)

        if is_typical:
            return CheckResult(
                check_name=self.name,
                weight=self.weight,
                raw_score=0.0,
                score_contribution=0.0,
                triggered=False,
                signal_origin=self.signal_origin,
                reason=f"Payment at {hour:02d}:00 falls within habitual activity window ({profile.typical_active_hours[0]:02d}:00 - {profile.typical_active_hours[1]:02d}:00).",
                evidence={"tx_hour": hour, "typical_range": profile.typical_active_hours}
            )

        # Deep night high risk penalty (01:00 to 05:00)
        is_deep_night = 1 <= hour <= 5
        raw_score = 1.0 if is_deep_night else 0.60
        severity_label = "Deep night hours (01:00-05:00)" if is_deep_night else "Off-hours"

        return CheckResult(
            check_name=self.name,
            weight=self.weight,
            raw_score=raw_score,
            score_contribution=round(raw_score * self.weight, 2),
            triggered=True,
            signal_origin=self.signal_origin,
            reason=f"Atypical timing: Payment initiated at {hour:02d}:00 during {severity_label}.",
            evidence={
                "tx_hour": hour,
                "typical_range": profile.typical_active_hours,
                "is_deep_night": is_deep_night
            }
        )
