"""
Unit Tests for Tamper-Evident Audit Trail (Feature 07)
Proves that hash chaining cryptographic guarantees detect any tampering.
"""
from backend.app.domain.audit import TamperEvidentAuditTrail


def test_audit_trail_valid_chain():
    trail = TamperEvidentAuditTrail()
    trail.append_event("PAYMENT_ATTEMPT", {"tx_id": "TX_1", "amount": 10000})
    trail.append_event("ASSESSMENT", {"tx_id": "TX_1", "score": 25.0, "decision": "APPROVE"})
    trail.append_event("LEDGER_UPDATE", {"tx_id": "TX_1", "status": "COMPLETED"})

    valid, msg = trail.verify_integrity()
    assert valid is True
    assert "verified" in msg.lower()


def test_audit_trail_tamper_detection():
    trail = TamperEvidentAuditTrail()
    trail.append_event("PAYMENT_ATTEMPT", {"tx_id": "TX_A", "amount": 50000})
    b2 = trail.append_event("ASSESSMENT", {"tx_id": "TX_A", "score": 85.0, "decision": "BLOCK"})
    trail.append_event("LEDGER_UPDATE", {"tx_id": "TX_A", "status": "BLOCKED"})

    # Malicious actor tampers with Block 2 payload in memory/storage
    # Trying to alter decision from BLOCK to APPROVE
    trail.chain[2].payload["decision"] = "APPROVE"

    valid, msg = trail.verify_integrity()
    assert valid is False
    assert "Tampered Payload at Block 2" in msg
