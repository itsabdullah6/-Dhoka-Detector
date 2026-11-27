"""
Check 4: FailedLoginsCheck
Evaluates authentication integrity prior to transaction initiation.
Detects account takeover and credential guessing attempts.
"""
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class FailedLoginsCheck(RiskCheck):
    def __init__(self, weight: float = 15.0):
        super().__init__(
            name="FailedLoginsCheck",
            weight=weight,
            signal_origin="SIMULATED_TELEMETRY"
        )

    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        failed_count = transaction.failed_logins_prior

        if failed_count >= 5:
            raw_score = 1.0
            triggered = True
            reason = f"Severe authentication anomaly: {failed_count} consecutive failed login attempts before transaction."
        elif failed_count >= 3:
            raw_score = 0.70
            triggered = True
            reason = f"Suspicious login behavior: {failed_count} failed logins preceding immediate fund transfer request."
        elif failed_count == 2:
            raw_score = 0.35
            triggered = True
            reason = f"Minor login friction: {failed_count} failed logins noted."
        else:
            raw_score = 0.0
            triggered = False
            reason = "Clean authentication session: 0 or 1 failed login attempts."

        return CheckResult(
            check_name=self.name,
            weight=self.weight,
            raw_score=raw_score,
            score_contribution=round(raw_score * self.weight, 2),
            triggered=triggered,
            signal_origin=self.signal_origin,
            reason=reason,
            evidence={"failed_login_count": failed_count}
        )
