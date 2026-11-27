"""
Security Module: Step-Up Verification Manager (Feature 08)
Provides mock 2FA / OTP challenge handling with expiry and single-use validation.
"""
import random
import time
from typing import Dict, Tuple


class OTPChallengeManager:
    """
    Manages mock OTP challenges for transactions routed to CHALLENGE state.
    Enforces expiration and single-use consumption.
    """
    def __init__(self, validity_seconds: int = 120):
        self.validity_seconds = validity_seconds
        # tx_id -> (otp_code, expires_at, used)
        self._challenges: Dict[str, Tuple[str, float, bool]] = {}

    def create_challenge(self, tx_id: str, fixed_code: str = None) -> str:
        """Issues a new 6-digit OTP challenge for a held transaction."""
        code = fixed_code or f"{random.randint(100000, 999999)}"
        expires_at = time.time() + self.validity_seconds
        self._challenges[tx_id] = (code, expires_at, False)
        return code

    def verify_challenge(self, tx_id: str, user_code: str) -> Tuple[bool, str]:
        """
        Validates OTP code.
        Returns (success: bool, status_message: str)
        """
        record = self._challenges.get(tx_id)
        if not record:
            return (False, "No active challenge found for this transaction.")

        code, expires_at, used = record

        if used:
            return (False, "OTP code has already been consumed.")

        if time.time() > expires_at:
            return (False, "OTP code has expired. Verification timed out.")

        if user_code.strip() != code:
            return (False, "Invalid OTP code entered.")

        # Mark consumed
        self._challenges[tx_id] = (code, expires_at, True)
        return (True, "Step-up verification successful.")
