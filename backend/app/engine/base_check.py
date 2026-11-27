"""
Engine Model: Abstract RiskCheck Base Class
Demonstrates Abstraction: Defines common contract for all fraud detection checks.
Addresses Instructor Requirement 2: Clearly labels signal origins (Rule-Based, Simulated Telemetry, ML).
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


@dataclass
class CheckResult:
    """
    Standardized result emitted by each polymorphic RiskCheck.
    """
    check_name: str
    weight: float
    raw_score: float             # Score between 0.0 and 1.0 (severity multiplier)
    score_contribution: float    # raw_score * weight (0 to weight)
    triggered: bool
    signal_origin: str           # E.g., 'BEHAVIORAL_BASELINE', 'SIMULATED_TELEMETRY', 'ML_ISOLATION_FOREST'
    reason: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class RiskCheck(ABC):
    """
    Abstract Base Class for all pluggable risk assessment checks.
    Subclasses must implement the `evaluate` method.
    """
    def __init__(self, name: str, weight: float, signal_origin: str = "BEHAVIORAL_BASELINE"):
        self._name: str = name
        self._weight: float = float(weight)
        self._signal_origin: str = signal_origin

    @property
    def name(self) -> str:
        return self._name

    @property
    def weight(self) -> float:
        return self._weight

    @property
    def signal_origin(self) -> str:
        return self._signal_origin

    @abstractmethod
    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        """
        Polymorphic method to evaluate risk on a transaction against customer baseline.
        Must return a structured CheckResult.
        """
        pass
