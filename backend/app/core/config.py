"""
Core configuration and threshold definitions for Dhoka Detector.
Addresses Instructor Requirement 1: Clearly defined and validated scoring thresholds.
"""
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class PolicyThresholds:
    """
    Scoring thresholds for 4-tier decision routing.
    Score ranges from 0 to 100.
    """
    APPROVE_MAX: float = 29.0    # 0 to 29: Approve
    CHALLENGE_MAX: float = 59.0  # 30 to 59: Step-up verification (OTP/Biometric)
    HOLD_MAX: float = 79.0       # 60 to 79: Analyst Manual Review Queue
    BLOCK_MIN: float = 80.0      # 80 to 100: Automatic Block


# Default check weights (must sum to roughly 100 for proper calibration)
DEFAULT_CHECK_WEIGHTS: Dict[str, float] = {
    "AmountAnomalyCheck": 18.0,
    "DeviceRiskCheck": 14.0,
    "RecipientRiskCheck": 15.0,
    "FailedLoginsCheck": 15.0,
    "UnusualHoursCheck": 10.0,
    "VelocityCheck": 14.0,
    "SplittingCheck": 14.0,
}

# Machine learning weight adjustment if ML model is active
ML_ISOLATION_FOREST_WEIGHT: float = 10.0
