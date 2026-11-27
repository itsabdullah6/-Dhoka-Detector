"""
Unit Tests for Dhoka Detector
Validates individual OOP checks, polymorphic engine aggregation,
and the safety guardrail that AI explanations never override rule decisions.
"""
from datetime import datetime, timezone
import pytest

from backend.app.domain.transaction import Transaction, DecisionState, TransactionStatus
from backend.app.domain.customer import CustomerProfile
from backend.app.engine.base_check import CheckResult
from backend.app.engine.checks.amount_check import AmountAnomalyCheck
from backend.app.engine.checks.device_check import DeviceRiskCheck
from backend.app.engine.checks.recipient_check import RecipientRiskCheck
from backend.app.engine.checks.login_anomaly_check import FailedLoginsCheck
from backend.app.engine.checks.unusual_hours_check import UnusualHoursCheck
from backend.app.engine.checks.velocity_check import VelocityCheck
from backend.app.engine.checks.splitting_check import SplittingCheck
from backend.app.engine.policy import DecisionPolicy
from backend.app.engine.risk_engine import RiskEngine
from backend.app.ai.explainer import GroundedAIExplainer


@pytest.fixture
def baseline_customer():
    return CustomerProfile(
        customer_id="CUST_TEST_001",
        full_name="Fatima Zahra",
        account_number="PK99MEZN12345678",
        initial_balance=250000.0,
        known_devices={"device_trusted_primary"},
        frequent_recipients={"ELECTRICITY_BILL_PK", "SISTER_WALLET"},
        typical_active_hours=(8, 22),
        avg_amount=4000.0,
        max_historical_amount=20000.0
    )


def test_amount_anomaly_check(baseline_customer):
    check = AmountAnomalyCheck(weight=20.0)
    
    # 1. Normal amount
    tx_normal = Transaction("tx_1", "CUST_TEST_001", "SISTER_WALLET", 4500.0)
    res_normal = check.evaluate(tx_normal, baseline_customer)
    assert not res_normal.triggered
    assert res_normal.raw_score == 0.0

    # 2. Extreme anomaly (PKR 180,000 vs avg 4,000)
    tx_extreme = Transaction("tx_2", "CUST_TEST_001", "SISTER_WALLET", 180000.0)
    res_extreme = check.evaluate(tx_extreme, baseline_customer)
    assert res_extreme.triggered
    assert res_extreme.raw_score == 1.0
    assert res_extreme.score_contribution == 20.0


def test_device_risk_check(baseline_customer):
    check = DeviceRiskCheck(weight=15.0)

    # Known device
    tx_known = Transaction("tx_1", "CUST_TEST_001", "SISTER_WALLET", 2000.0, device_id="device_trusted_primary")
    res_known = check.evaluate(tx_known, baseline_customer)
    assert not res_known.triggered

    # Unknown device
    tx_unknown = Transaction("tx_2", "CUST_TEST_001", "SISTER_WALLET", 2000.0, device_id="unseen_hacker_os")
    res_unknown = check.evaluate(tx_unknown, baseline_customer)
    assert res_unknown.triggered
    assert res_unknown.raw_score == 1.0


def test_recipient_blacklist_hard_block(baseline_customer):
    check = RecipientRiskCheck(weight=15.0)

    # Transfer to blacklisted mule
    tx_mule = Transaction("tx_mule", "CUST_TEST_001", "PK99MULE77881122", 10000.0)
    res_mule = check.evaluate(tx_mule, baseline_customer)
    assert res_mule.triggered
    assert res_mule.evidence.get("critical_risk") is True

    # Ensure engine immediately BLOCKS
    engine = RiskEngine(checks=[check], policy=DecisionPolicy())
    report = engine.assess_transaction(tx_mule, baseline_customer)
    assert report.decision == DecisionState.BLOCK
    assert tx_mule.status == TransactionStatus.BLOCKED


def test_failed_logins_check(baseline_customer):
    check = FailedLoginsCheck(weight=15.0)

    tx_clean = Transaction("tx_1", "CUST_TEST_001", "SISTER_WALLET", 2000.0, failed_logins_prior=0)
    assert not check.evaluate(tx_clean, baseline_customer).triggered

    tx_attack = Transaction("tx_2", "CUST_TEST_001", "SISTER_WALLET", 2000.0, failed_logins_prior=4)
    res = check.evaluate(tx_attack, baseline_customer)
    assert res.triggered
    assert res.raw_score >= 0.70


def test_ai_explanation_never_overrides_decision(baseline_customer):
    """
    Directly satisfies Instructor Requirement 4:
    AI explanations must NEVER override the deterministic rule-based decision.
    """
    check = AmountAnomalyCheck(weight=20.0)
    engine = RiskEngine(checks=[check])
    explainer = GroundedAIExplainer()

    tx = Transaction("tx_test", "CUST_TEST_001", "SISTER_WALLET", 3000.0)
    report = engine.assess_transaction(tx, baseline_customer)
    
    # Store rule engine output
    original_decision = report.decision
    original_status = tx.status

    # Invoke explainer
    explanation = explainer.explain(tx, report)

    # Assert immutability
    assert explanation["decision_enforced"] == original_decision.value
    assert explanation["rule_decision_immutable"] is True
    assert explanation["ai_override_attempted"] is False
    assert report.decision == original_decision
    assert tx.status == original_status
