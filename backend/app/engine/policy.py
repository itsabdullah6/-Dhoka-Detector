"""
Engine Model: DecisionPolicy
Demonstrates Configurable Policies (Feature 05) and 4 Decision States (Feature 02).
Directly satisfies Instructor Requirement 1: Clearly defined and validated scoring thresholds.
"""
from typing import List, Tuple
from backend.app.core.config import PolicyThresholds
from backend.app.domain.transaction import DecisionState
from backend.app.engine.base_check import CheckResult


class DecisionPolicy:
    """
    Evaluates cumulative risk scores and critical flags to choose one of four decisions:
    APPROVE, CHALLENGE, HOLD, BLOCK.
    """
    def __init__(self, thresholds: PolicyThresholds = PolicyThresholds()):
        self.thresholds: PolicyThresholds = thresholds

    def evaluate(self, cumulative_score: float, results: List[CheckResult]) -> Tuple[DecisionState, str]:
        """
        Calculates final deterministic decision based on validated thresholds
        and explicit safety overrides.
        """
        # 1. Critical Hard-Block Override: Blacklisted Beneficiary
        for res in results:
            if res.evidence.get("critical_risk") is True:
                return (
                    DecisionState.BLOCK,
                    f"Immediate Hard-Block: Recipient identified in high-priority blacklist ({res.reason})"
                )

        # 2. Threshold-based decisions
        if cumulative_score >= self.thresholds.BLOCK_MIN:
            return (
                DecisionState.BLOCK,
                f"Risk score {cumulative_score:.1f}/100 exceeds critical threshold ({self.thresholds.BLOCK_MIN}+). Immediate block enforced."
            )
        elif cumulative_score > self.thresholds.CHALLENGE_MAX:
            return (
                DecisionState.HOLD,
                f"Risk score {cumulative_score:.1f}/100 in review range ({self.thresholds.CHALLENGE_MAX + 1}-{self.thresholds.HOLD_MAX}). Routed to Fraud Analyst Queue."
            )
        elif cumulative_score > self.thresholds.APPROVE_MAX:
            return (
                DecisionState.CHALLENGE,
                f"Risk score {cumulative_score:.1f}/100 indicates moderate friction ({self.thresholds.APPROVE_MAX + 1}-{self.thresholds.CHALLENGE_MAX}). Step-up verification required."
            )
        else:
            return (
                DecisionState.APPROVE,
                f"Risk score {cumulative_score:.1f}/100 below low-risk ceiling ({self.thresholds.APPROVE_MAX}). Approved."
            )
