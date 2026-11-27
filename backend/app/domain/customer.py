"""
Domain Model: CustomerProfile
Demonstrates Encapsulation: Manages customer baseline behaviors, trusted devices,
and transaction history.
"""
from typing import List, Set, Tuple
from datetime import datetime
from backend.app.domain.transaction import Transaction


class CustomerProfile:
    """
    Encapsulated Customer Behavior Profile.
    Holds behavioral baselines to assess anomalies against.
    """
    def __init__(
        self,
        customer_id: str,
        full_name: str,
        account_number: str,
        initial_balance: float = 100000.0,
        known_devices: Set[str] = None,
        frequent_recipients: Set[str] = None,
        typical_active_hours: Tuple[int, int] = (7, 23),
        avg_amount: float = 5000.0,
        max_historical_amount: float = 30000.0
    ):
        self.__customer_id: str = customer_id
        self.__full_name: str = full_name
        self.__account_number: str = account_number
        self.__balance: float = float(initial_balance)
        self.__known_devices: Set[str] = set(known_devices or ["device_primary"])
        self.__frequent_recipients: Set[str] = set(frequent_recipients or [])
        self.__typical_active_hours: Tuple[int, int] = typical_active_hours
        self.__avg_amount: float = float(avg_amount)
        self.__max_historical_amount: float = float(max_historical_amount)
        self.__recent_transactions: List[Transaction] = []

    # --- Getters ---
    @property
    def customer_id(self) -> str:
        return self.__customer_id

    @property
    def full_name(self) -> str:
        return self.__full_name

    @property
    def account_number(self) -> str:
        return self.__account_number

    @property
    def balance(self) -> float:
        return self.__balance

    @property
    def known_devices(self) -> Set[str]:
        return set(self.__known_devices)

    @property
    def frequent_recipients(self) -> Set[str]:
        return set(self.__frequent_recipients)

    @property
    def typical_active_hours(self) -> Tuple[int, int]:
        return self.__typical_active_hours

    @property
    def avg_amount(self) -> float:
        return self.__avg_amount

    @property
    def max_historical_amount(self) -> float:
        return self.__max_historical_amount

    @property
    def recent_transactions(self) -> List[Transaction]:
        return list(self.__recent_transactions)

    # --- Domain Methods ---
    def is_device_known(self, device_id: str) -> bool:
        return device_id in self.__known_devices

    def is_recipient_frequent(self, recipient_id: str) -> bool:
        return recipient_id in self.__frequent_recipients

    def is_within_typical_hours(self, hour: int) -> bool:
        start, end = self.__typical_active_hours
        if start <= end:
            return start <= hour <= end
        return hour >= start or hour <= end

    def register_device(self, device_id: str) -> None:
        self.__known_devices.add(device_id)

    def add_frequent_recipient(self, recipient_id: str) -> None:
        self.__frequent_recipients.add(recipient_id)

    def record_completed_transaction(self, tx: Transaction) -> None:
        """Updates behavioral baseline after successful transaction execution."""
        self.__recent_transactions.append(tx)
        if tx.amount > self.__max_historical_amount:
            self.__max_historical_amount = tx.amount
        
        # Incremental moving average calculation
        total_tx = len(self.__recent_transactions)
        self.__avg_amount = ((self.__avg_amount * (total_tx - 1)) + tx.amount) / total_tx
        self.__balance -= tx.amount

    def get_recent_transactions_within_seconds(self, current_time: datetime, seconds: int) -> List[Transaction]:
        """Returns transactions executed within the given time window."""
        window_txs = []
        for past_tx in reversed(self.__recent_transactions):
            diff = (current_time - past_tx.timestamp).total_seconds()
            if 0 <= diff <= seconds:
                window_txs.append(past_tx)
            elif diff > seconds:
                break
        return window_txs
