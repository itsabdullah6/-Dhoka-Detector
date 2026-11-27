"""
Database Layer: SQLite Repository
Persists Customers, Transactions, Tamper-Evident Audit Blocks, and Analyst Actions.
"""
import sqlite3
import json
from typing import Optional, List, Dict, Any
from backend.app.domain.transaction import Transaction, TransactionStatus
from backend.app.domain.customer import CustomerProfile
from backend.app.domain.audit import AuditBlock


class DatabaseRepository:
    def __init__(self, db_path: str = "dhoka_detector.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Customers Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS customers (
                    customer_id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    account_number TEXT NOT NULL,
                    balance REAL NOT NULL,
                    known_devices TEXT NOT NULL,
                    frequent_recipients TEXT NOT NULL,
                    typical_hours TEXT NOT NULL,
                    avg_amount REAL NOT NULL,
                    max_historical_amount REAL NOT NULL
                )
            """)

            # 2. Transactions Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    tx_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    amount REAL NOT NULL,
                    currency TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    failed_logins_prior INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    risk_score REAL DEFAULT 0.0,
                    decision_reason TEXT DEFAULT ''
                )
            """)

            # 3. Tamper-Evident Audit Ledger Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_blocks (
                    block_index INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                )
            """)

            # 4. Analyst Feedback & Review Table (Feature 09)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analyst_reviews (
                    review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tx_id TEXT NOT NULL,
                    analyst_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    is_false_positive INTEGER NOT NULL,
                    notes TEXT,
                    timestamp TEXT NOT NULL
                )
            """)

            conn.commit()

    # --- Customer Methods ---
    def save_customer(self, profile: CustomerProfile) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO customers 
                (customer_id, full_name, account_number, balance, known_devices, 
                 frequent_recipients, typical_hours, avg_amount, max_historical_amount)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.customer_id,
                profile.full_name,
                profile.account_number,
                profile.balance,
                json.dumps(list(profile.known_devices)),
                json.dumps(list(profile.frequent_recipients)),
                json.dumps(list(profile.typical_active_hours)),
                profile.avg_amount,
                profile.max_historical_amount
            ))
            conn.commit()

    def get_customer(self, customer_id: str) -> Optional[CustomerProfile]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM customers WHERE customer_id = ?", (customer_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return CustomerProfile(
                customer_id=row["customer_id"],
                full_name=row["full_name"],
                account_number=row["account_number"],
                initial_balance=row["balance"],
                known_devices=set(json.loads(row["known_devices"])),
                frequent_recipients=set(json.loads(row["frequent_recipients"])),
                typical_active_hours=tuple(json.loads(row["typical_hours"])),
                avg_amount=row["avg_amount"],
                max_historical_amount=row["max_historical_amount"]
            )

    # --- Transaction Methods ---
    def save_transaction(self, tx: Transaction, risk_score: float = 0.0) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO transactions 
                (tx_id, sender_id, recipient_id, amount, currency, timestamp,
                 device_id, ip_address, channel, failed_logins_prior, status, risk_score, decision_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tx.tx_id,
                tx.sender_id,
                tx.recipient_id,
                tx.amount,
                tx.currency,
                tx.timestamp.isoformat(),
                tx.device_id,
                tx.ip_address,
                tx.channel,
                tx.failed_logins_prior,
                tx.status.value,
                risk_score,
                tx.decision_reason
            ))
            conn.commit()

    def get_held_transactions(self) -> List[Dict[str, Any]]:
        """Returns queue of transactions in HELD state awaiting analyst review."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM transactions WHERE status = 'HELD' ORDER BY timestamp DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def update_transaction_status(self, tx_id: str, new_status: str, reason: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE transactions 
                SET status = ?, decision_reason = ? 
                WHERE tx_id = ?
            """, (new_status, reason, tx_id))
            conn.commit()

    # --- Audit Methods ---
    def save_audit_block(self, block: AuditBlock) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO audit_blocks 
                (block_index, timestamp, event_type, payload, previous_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                block.index,
                block.timestamp,
                block.event_type,
                json.dumps(block.payload),
                block.previous_hash,
                block.current_hash
            ))
            conn.commit()

    def get_all_audit_blocks(self) -> List[AuditBlock]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC")
            blocks = []
            for row in cursor.fetchall():
                blocks.append(AuditBlock(
                    index=row["block_index"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    payload=json.loads(row["payload"]),
                    previous_hash=row["previous_hash"],
                    current_hash=row["hash"]
                ))
            return blocks

    # --- Analyst Review Methods ---
    def record_analyst_review(
        self,
        tx_id: str,
        analyst_id: str,
        action: str,
        is_false_positive: bool,
        notes: str,
        timestamp: str
    ) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO analyst_reviews 
                (tx_id, analyst_id, action, is_false_positive, notes, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (tx_id, analyst_id, action, 1 if is_false_positive else 0, notes, timestamp))
            conn.commit()
