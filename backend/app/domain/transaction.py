"""
Domain Model: Transaction
Demonstrates Encapsulation: Validates attributes and safeguards state transitions.
"""
from enum import Enum
from datetime import datetime, timezone
from typing import Optional


class DecisionState(str, Enum):
    APPROVE = "APPROVE"
    CHALLENGE = "CHALLENGE"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


class TransactionStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    CHALLENGED = "CHALLENGED"
    HELD = "HELD"
    BLOCKED = "BLOCKED"


class Transaction:
    """
    Encapsulated Transaction Entity.
    Guarantees integrity of financial amounts and transitions between states.
    """
    def __init__(
        self,
        tx_id: str,
        sender_id: str,
        recipient_id: str,
        amount: float,
        timestamp: Optional[datetime] = None,
        device_id: str = "device_default",
        ip_address: str = "127.0.0.1",
        channel: str = "MobileApp",
        currency: str = "PKR",
        failed_logins_prior: int = 0
    ):
        if amount <= 0:
            raise ValueError(f"Transaction amount must be strictly positive. Received: {amount}")
        
        self.__tx_id: str = tx_id
        self.__sender_id: str = sender_id
        self.__recipient_id: str = recipient_id
        self.__amount: float = float(amount)
        self.__currency: str = currency
        self.__timestamp: datetime = timestamp or datetime.now(timezone.utc)
        self.__device_id: str = device_id
        self.__ip_address: str = ip_address
        self.__channel: str = channel
        self.__failed_logins_prior: int = max(0, failed_logins_prior)
        self.__status: TransactionStatus = TransactionStatus.PENDING
        self.__decision_reason: str = ""

    # --- Encapsulated Getters ---
    @property
    def tx_id(self) -> str:
        return self.__tx_id

    @property
    def sender_id(self) -> str:
        return self.__sender_id

    @property
    def recipient_id(self) -> str:
        return self.__recipient_id

    @property
    def amount(self) -> float:
        return self.__amount

    @property
    def currency(self) -> str:
        return self.__currency

    @property
    def timestamp(self) -> datetime:
        return self.__timestamp

    @property
    def device_id(self) -> str:
        return self.__device_id

    @property
    def ip_address(self) -> str:
        return self.__ip_address

    @property
    def channel(self) -> str:
        return self.__channel

    @property
    def failed_logins_prior(self) -> int:
        return self.__failed_logins_prior

    @property
    def status(self) -> TransactionStatus:
        return self.__status

    @property
    def decision_reason(self) -> str:
        return self.__decision_reason

    # --- State Transitions (Encapsulated) ---
    def approve(self, reason: str = "Approved by Risk Engine") -> None:
        self.__status = TransactionStatus.APPROVED
        self.__decision_reason = reason

    def challenge(self, reason: str = "Step-up verification required") -> None:
        self.__status = TransactionStatus.CHALLENGED
        self.__decision_reason = reason

    def hold(self, reason: str = "Placed in manual review queue") -> None:
        self.__status = TransactionStatus.HELD
        self.__decision_reason = reason

    def block(self, reason: str = "Blocked due to high risk indicators") -> None:
        self.__status = TransactionStatus.BLOCKED
        self.__decision_reason = reason

    def to_dict(self) -> dict:
        return {
            "tx_id": self.__tx_id,
            "sender_id": self.__sender_id,
            "recipient_id": self.__recipient_id,
            "amount": self.__amount,
            "currency": self.__currency,
            "timestamp": self.__timestamp.isoformat(),
            "device_id": self.__device_id,
            "ip_address": self.__ip_address,
            "channel": self.__channel,
            "failed_logins_prior": self.__failed_logins_prior,
            "status": self.__status.value,
            "decision_reason": self.__decision_reason
        }
