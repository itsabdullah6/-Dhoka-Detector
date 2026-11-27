"""
Evaluation Module: Scenario Simulator (Feature 11)
Addresses Instructor Requirements:
- Generates 100+ labelled test cases
- Covers 4 attack scenarios + normal transactions
- Strictly distinguishes ground truth fraud from simulated telemetry
"""
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class SimulationTestCase:
    def __init__(
        self,
        case_id: str,
        scenario_name: str,
        is_ground_truth_fraud: bool,
        transaction: Transaction,
        profile: CustomerProfile,
        expected_minimum_decision: str
    ):
        self.case_id = case_id
        self.scenario_name = scenario_name
        self.is_ground_truth_fraud = is_ground_truth_fraud
        self.transaction = transaction
        self.profile = profile
        self.expected_minimum_decision = expected_minimum_decision


class ScenarioSimulator:
    """
    Generates deterministic, repeatable test datasets representing Pakistani FinTech transactions.
    """
    def __init__(self, seed: int = 42):
        self.random = random.Random(seed)

    def generate_evaluation_suite(self, count_normal: int = 60) -> List[SimulationTestCase]:
        cases: List[SimulationTestCase] = []
        base_time = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)

        # -------------------------------------------------------------
        # 1. Normal Transactions (Baseline Non-Fraud: 60 cases)
        # -------------------------------------------------------------
        for i in range(count_normal):
            cust_id = f"CUST_NORM_{i:03d}"
            device_id = f"device_cust_{i}"
            profile = CustomerProfile(
                customer_id=cust_id,
                full_name=f"Customer {i}",
                account_number=f"PK20HABB000{i:04d}",
                known_devices={device_id},
                frequent_recipients={"PK_ELECTRIC_BILL", "SUPERMARKET_01", f"RECIP_{i}"},
                avg_amount=4000.0,
                max_historical_amount=15000.0
            )

            # Normal amount around avg +/- 30%
            normal_amt = round(self.random.uniform(1000.0, 7000.0), 2)
            normal_hour = self.random.choice([9, 11, 14, 16, 19, 21])
            tx_time = base_time.replace(hour=normal_hour, minute=self.random.randint(0, 59))

            tx = Transaction(
                tx_id=f"TX_NORM_{i:03d}",
                sender_id=cust_id,
                recipient_id=f"RECIP_{i}",
                amount=normal_amt,
                timestamp=tx_time,
                device_id=device_id,
                failed_logins_prior=0
            )

            cases.append(SimulationTestCase(
                case_id=tx.tx_id,
                scenario_name="NORMAL_PAYMENT",
                is_ground_truth_fraud=False,
                transaction=tx,
                profile=profile,
                expected_minimum_decision="APPROVE"
            ))

        # -------------------------------------------------------------
        # 2. Scenario A: Stolen login + new device (15 cases)
        # -------------------------------------------------------------
        for i in range(15):
            cust_id = f"CUST_ATK_A_{i:03d}"
            profile = CustomerProfile(
                customer_id=cust_id,
                full_name=f"Victim {i}",
                account_number=f"PK20MEZN000{i:04d}",
                known_devices={"device_registered_iphone"},
                frequent_recipients={"PK_GAS_BILL", "FAMILY_MEMBER_1"},
                avg_amount=3000.0,
                max_historical_amount=8000.0
            )
            tx = Transaction(
                tx_id=f"TX_ATK_A_{i:03d}",
                sender_id=cust_id,
                recipient_id=f"STRANGER_WALLET_{i}",
                amount=35000.0,
                timestamp=base_time,
                device_id="unregistered_kali_linux_browser",
                failed_logins_prior=self.random.randint(3, 6)
            )
            cases.append(SimulationTestCase(
                case_id=tx.tx_id,
                scenario_name="STOLEN_LOGIN_NEW_DEVICE",
                is_ground_truth_fraud=True,
                transaction=tx,
                profile=profile,
                expected_minimum_decision="HOLD"
            ))

        # -------------------------------------------------------------
        # 3. Scenario B: Rapid large transfers / Velocity drain (15 cases)
        # -------------------------------------------------------------
        for i in range(15):
            cust_id = f"CUST_ATK_B_{i:03d}"
            profile = CustomerProfile(
                customer_id=cust_id,
                full_name=f"Target User {i}",
                account_number=f"PK20BAHL000{i:04d}",
                known_devices={"device_phone"},
                avg_amount=2500.0,
                max_historical_amount=10000.0
            )
            # Inject 3 prior transactions in the last 5 minutes
            for past_idx in range(3):
                past_tx = Transaction(
                    tx_id=f"PAST_B_{i}_{past_idx}",
                    sender_id=cust_id,
                    recipient_id=f"DRAIN_RECIP_{past_idx}",
                    amount=45000.0,
                    timestamp=base_time - timedelta(minutes=(past_idx + 1) * 2),
                    device_id="device_phone"
                )
                profile.record_completed_transaction(past_tx)

            tx = Transaction(
                tx_id=f"TX_ATK_B_{i:03d}",
                sender_id=cust_id,
                recipient_id=f"DRAIN_RECIP_FINAL_{i}",
                amount=60000.0,
                timestamp=base_time,
                device_id="device_phone",
                failed_logins_prior=0
            )
            cases.append(SimulationTestCase(
                case_id=tx.tx_id,
                scenario_name="RAPID_LARGE_TRANSFERS",
                is_ground_truth_fraud=True,
                transaction=tx,
                profile=profile,
                expected_minimum_decision="HOLD"
            ))

        # -------------------------------------------------------------
        # 4. Scenario C: Simulated flagged recipient / Mule registry (15 cases)
        # -------------------------------------------------------------
        for i in range(15):
            cust_id = f"CUST_ATK_C_{i:03d}"
            profile = CustomerProfile(
                customer_id=cust_id,
                full_name=f"Customer C {i}",
                account_number=f"PK20UBL000{i:04d}",
                known_devices={"device_phone_c"},
                avg_amount=5000.0
            )
            tx = Transaction(
                tx_id=f"TX_ATK_C_{i:03d}",
                sender_id=cust_id,
                recipient_id="PK99MULE77881122",  # Blacklisted
                amount=25000.0,
                timestamp=base_time,
                device_id="device_phone_c",
                failed_logins_prior=0
            )
            cases.append(SimulationTestCase(
                case_id=tx.tx_id,
                scenario_name="FLAGGED_RECIPIENT_MULE",
                is_ground_truth_fraud=True,
                transaction=tx,
                profile=profile,
                expected_minimum_decision="BLOCK"
            ))

        # -------------------------------------------------------------
        # 5. Scenario D: Midnight high-value transfer (15 cases)
        # -------------------------------------------------------------
        for i in range(15):
            cust_id = f"CUST_ATK_D_{i:03d}"
            profile = CustomerProfile(
                customer_id=cust_id,
                full_name=f"Customer D {i}",
                account_number=f"PK20ALFH000{i:04d}",
                typical_active_hours=(8, 22),
                avg_amount=3500.0,
                max_historical_amount=12000.0
            )
            midnight_time = base_time.replace(hour=3, minute=self.random.randint(10, 50))
            tx = Transaction(
                tx_id=f"TX_ATK_D_{i:03d}",
                sender_id=cust_id,
                recipient_id=f"STRANGER_RECIP_{i}",
                amount=95000.0,  # 27x average
                timestamp=midnight_time,
                device_id="unseen_tablet_device",
                failed_logins_prior=2
            )
            cases.append(SimulationTestCase(
                case_id=tx.tx_id,
                scenario_name="MIDNIGHT_HIGH_VALUE_TRANSFER",
                is_ground_truth_fraud=True,
                transaction=tx,
                profile=profile,
                expected_minimum_decision="HOLD"
            ))

        return cases
