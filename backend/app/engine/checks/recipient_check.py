"""
Check 3: RecipientRiskCheck
Evaluates beneficiary risk: checks against central flagged accounts and customer familiarity.
"""
from typing import Set, Optional
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class RecipientRiskCheck(RiskCheck):
    # Default simulated flagged mule accounts list for Pakistani FinTech demo
    DEFAULT_FLAGGED_RECIPIENTS: Set[str] = {
        "PK99MULE77881122",
        "PK44FRAUD990011",
        "03009999999_reported",
        "mule_wallet_404"
    }

    def __init__(self, weight: float = 15.0, flagged_recipients: Optional[Set[str]] = None):
        super().__init__(
            name="RecipientRiskCheck",
            weight=weight,
            signal_origin="CENTRAL_THREAT_INTEL"
        )
        self.flagged_recipients: Set[str] = flagged_recipients or set(self.DEFAULT_FLAGGED_RECIPIENTS)

    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        recipient = transaction.recipient_id

        # 1. Critical Match: Blacklisted / Reported Mule Account
        if recipient in self.flagged_recipients:
            return CheckResult(
                check_name=self.name,
                weight=self.weight,
                raw_score=1.0,
                score_contribution=round(1.0 * self.weight, 2),
                triggered=True,
                signal_origin=self.signal_origin,
                reason=f"CRITICAL: Recipient '{recipient}' is listed in the National Fraud / Mule Registry.",
                evidence={"recipient_id": recipient, "is_blacklisted": True, "critical_risk": True}
            )

        # 2. Check familiarity
        if profile.is_recipient_frequent(recipient):
            return CheckResult(
                check_name=self.name,
                weight=self.weight,
                raw_score=0.0,
                score_contribution=0.0,
                triggered=False,
                signal_origin="BEHAVIORAL_BASELINE",
                reason=f"Recipient '{recipient}' is a frequent and verified contact.",
                evidence={"recipient_id": recipient, "is_frequent": True}
            )

        # 3. First-time unfamiliar recipient
        return CheckResult(
            check_name=self.name,
            weight=self.weight,
            raw_score=0.45,
            score_contribution=round(0.45 * self.weight, 2),
            triggered=True,
            signal_origin="BEHAVIORAL_BASELINE",
            reason=f"First-time transfer to unfamiliar beneficiary '{recipient}'.",
            evidence={"recipient_id": recipient, "is_frequent": False, "is_blacklisted": False}
        )
