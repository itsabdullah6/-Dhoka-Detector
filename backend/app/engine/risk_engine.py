"""
Engine Orchestrator: RiskEngine
Demonstrates Polymorphism & Composition:
RiskEngine composes a collection of RiskChecks and executes them uniformly via their interface.
Integrates DecisionPolicy and TamperEvidentAuditTrail.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any
from backend.app.domain.transaction import Transaction, DecisionState
from backend.app.domain.customer import CustomerProfile
from backend.app.domain.audit import TamperEvidentAuditTrail, AuditBlock
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.engine.policy import DecisionPolicy


@dataclass
class AssessmentReport:
    tx_id: str
    risk_score: float
    decision: DecisionState
    decision_reason: str
    breakdown: List[CheckResult]
    audit_block_index: int
    audit_block_hash: str
    flagged_signals_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "risk_score": self.risk_score,
            "decision": self.decision.value,
            "decision_reason": self.decision_reason,
            "flagged_signals_count": self.flagged_signals_count,
            "audit_block_index": self.audit_block_index,
            "audit_block_hash": self.audit_block_hash,
            "breakdown": [
                {
                    "check_name": r.check_name,
                    "weight": r.weight,
                    "score_contribution": r.score_contribution,
                    "triggered": r.triggered,
                    "signal_origin": r.signal_origin,
                    "reason": r.reason,
                    "evidence": r.evidence
                }
                for r in self.breakdown
            ]
        }


class RiskEngine:
    """
    Composite Risk Engine running pluggable RiskChecks polymorphically.
    """
    def __init__(
        self,
        checks: List[RiskCheck] = None,
        policy: DecisionPolicy = None,
        audit_trail: TamperEvidentAuditTrail = None
    ):
        self._checks: List[RiskCheck] = checks or []
        self._policy: DecisionPolicy = policy or DecisionPolicy()
        self._audit_trail: TamperEvidentAuditTrail = audit_trail or TamperEvidentAuditTrail()

    @property
    def checks(self) -> List[RiskCheck]:
        return list(self._checks)

    @property
    def audit_trail(self) -> TamperEvidentAuditTrail:
        return self._audit_trail

    def register_check(self, check: RiskCheck) -> None:
        """Dynamically attach new checks (Pluggable checks architecture)."""
        self._checks.append(check)

    def assess_transaction(self, tx: Transaction, profile: CustomerProfile) -> AssessmentReport:
        """
        Runs all registered checks polymorphically, tallies scores,
        determines policy action, updates transaction state,
        and logs to the tamper-evident audit ledger.
        """
        results: List[CheckResult] = []
        raw_accumulated_score = 0.0
        total_possible_weight = 0.0

        # Polymorphic execution loop
        for check in self._checks:
            res = check.evaluate(tx, profile)
            results.append(res)
            raw_accumulated_score += res.score_contribution
            total_possible_weight += check.weight

        # Normalize score to 0 - 100 scale
        if total_possible_weight > 0:
            normalized_score = min(100.0, max(0.0, (raw_accumulated_score / total_possible_weight) * 100.0))
        else:
            normalized_score = 0.0
        
        normalized_score = round(normalized_score, 1)

        # Apply Decision Policy
        decision, reason = self._policy.evaluate(normalized_score, results)

        # Mutate Transaction State (Encapsulation)
        if decision == DecisionState.APPROVE:
            tx.approve(reason)
        elif decision == DecisionState.CHALLENGE:
            tx.challenge(reason)
        elif decision == DecisionState.HOLD:
            tx.hold(reason)
        elif decision == DecisionState.BLOCK:
            tx.block(reason)

        flagged_count = sum(1 for r in results if r.triggered)

        # Append to Tamper-Evident Audit Trail (Feature 07)
        audit_payload = {
            "tx_id": tx.tx_id,
            "sender_id": tx.sender_id,
            "recipient_id": tx.recipient_id,
            "amount": tx.amount,
            "risk_score": normalized_score,
            "decision": decision.value,
            "reason": reason,
            "flagged_checks": [r.check_name for r in results if r.triggered]
        }
        audit_block = self._audit_trail.append_event(
            event_type="TRANSACTION_ASSESSMENT",
            payload=audit_payload
        )

        return AssessmentReport(
            tx_id=tx.tx_id,
            risk_score=normalized_score,
            decision=decision,
            decision_reason=reason,
            breakdown=results,
            audit_block_index=audit_block.index,
            audit_block_hash=audit_block.current_hash,
            flagged_signals_count=flagged_count
        )
