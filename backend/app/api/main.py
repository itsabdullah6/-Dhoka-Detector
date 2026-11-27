"""
API Layer: FastAPI Application
Exposes REST endpoints for:
- /assess-transaction (Feature 10)
- /step-up/verify-otp (Feature 08)
- /analyst/hold-queue & /analyst/review (Feature 09)
- /audit/verify (Feature 07)
- /evaluation/benchmark (Feature 11 & Benchmark criteria)
"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.app.domain.transaction import Transaction, DecisionState
from backend.app.domain.customer import CustomerProfile
from backend.app.engine.risk_engine import RiskEngine
from backend.app.engine.policy import DecisionPolicy
from backend.app.engine.checks.amount_check import AmountAnomalyCheck
from backend.app.engine.checks.device_check import DeviceRiskCheck
from backend.app.engine.checks.recipient_check import RecipientRiskCheck
from backend.app.engine.checks.login_anomaly_check import FailedLoginsCheck
from backend.app.engine.checks.unusual_hours_check import UnusualHoursCheck
from backend.app.engine.checks.velocity_check import VelocityCheck
from backend.app.engine.checks.splitting_check import SplittingCheck
from backend.app.engine.checks.ml_anomaly_check import IsolationForestCheck
from backend.app.ai.explainer import GroundedAIExplainer
from backend.app.core.security import OTPChallengeManager
from backend.app.database.repository import DatabaseRepository
from backend.evaluation.benchmark import run_benchmark_evaluation
import urllib.request
import json


def dispatch_n8n_webhook(payload: dict) -> dict:
    """Dispatches webhook to n8n for HOLD/BLOCK transactions with graceful offline fallback."""
    url = "http://localhost:5678/webhook/dhoka-fraud-alert"
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            return {"connected": True, "status": f"HTTP {resp.getcode()} Sent to n8n"}
    except Exception:
        return {"connected": False, "status": "Simulated: n8n webhook staged (WhatsApp / SecOps pipeline)"}

app = FastAPI(
    title="Dhoka Detector API",
    description="An AI-assisted transaction risk and fraud defense system (FinTech prototype)",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize singletons
repo = DatabaseRepository("dhoka_detector.db")
otp_manager = OTPChallengeManager(validity_seconds=180)
explainer = GroundedAIExplainer()

# Assemble Engine (Polymorphism + Composition)
engine = RiskEngine(policy=DecisionPolicy())
engine.register_check(AmountAnomalyCheck(weight=18.0))
engine.register_check(DeviceRiskCheck(weight=14.0))
engine.register_check(RecipientRiskCheck(weight=15.0))
engine.register_check(FailedLoginsCheck(weight=15.0))
engine.register_check(UnusualHoursCheck(weight=10.0))
engine.register_check(VelocityCheck(weight=14.0))
engine.register_check(SplittingCheck(weight=14.0))
engine.register_check(IsolationForestCheck(weight=10.0))


# --- Request & Response Schemas ---
class AssessRequest(BaseModel):
    tx_id: str
    sender_id: str
    recipient_id: str
    amount: float = Field(gt=0, description="Amount in PKR must be positive")
    device_id: str = "device_default"
    ip_address: str = "127.0.0.1"
    channel: str = "MobileApp"
    failed_logins_prior: int = 0
    sender_avg_amount: Optional[float] = 5000.0
    sender_max_historical: Optional[float] = 30000.0


class OTPVerifyRequest(BaseModel):
    tx_id: str
    otp_code: str


class AnalystReviewRequest(BaseModel):
    tx_id: str
    analyst_id: str
    action: str  # "APPROVE" or "REJECT"
    is_false_positive: bool
    notes: str = ""


# --- Endpoints ---
@app.get("/health")
def health_check():
    return {"status": "ok", "app": "Dhoka Detector", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/assess-transaction")
def assess_transaction(req: AssessRequest) -> Dict[str, Any]:
    """
    Feature 10: POST /assess-transaction
    Evaluates transaction risk against profile, saves to DB & hash chain,
    and returns score, breakdown, decision, and grounded AI explanation.
    """
    # 1. Fetch or create Customer Profile
    profile = repo.get_customer(req.sender_id)
    if not profile:
        profile = CustomerProfile(
            customer_id=req.sender_id,
            full_name=f"Customer {req.sender_id}",
            account_number=f"PK99EASY{req.sender_id}",
            avg_amount=req.sender_avg_amount or 5000.0,
            max_historical_amount=req.sender_max_historical or 30000.0,
            known_devices={"device_registered_primary"}
        )
        repo.save_customer(profile)

    # 2. Instantiate Transaction Entity
    tx = Transaction(
        tx_id=req.tx_id,
        sender_id=req.sender_id,
        recipient_id=req.recipient_id,
        amount=req.amount,
        device_id=req.device_id,
        ip_address=req.ip_address,
        channel=req.channel,
        failed_logins_prior=req.failed_logins_prior
    )

    # 3. Polymorphic Assessment by RiskEngine
    report = engine.assess_transaction(tx, profile)

    # 4. Generate Grounded AI Explanation (Read-only; cannot alter decision)
    ai_explanation = explainer.explain(tx, report)

    # 5. Persist State & Audit Block
    repo.save_transaction(tx, risk_score=report.risk_score)
    repo.save_audit_block(engine.audit_trail.chain[-1])

    # If Challenge state, issue mock OTP for step-up verification
    mock_otp_code = None
    if report.decision == DecisionState.CHALLENGE:
        mock_otp_code = otp_manager.create_challenge(tx.tx_id)

    # If HOLD or BLOCK, trigger n8n enterprise automation webhook
    n8n_status = None
    if report.decision in (DecisionState.HOLD, DecisionState.BLOCK):
        n8n_status = dispatch_n8n_webhook({
            "tx_id": tx.tx_id,
            "sender_id": tx.sender_id,
            "recipient_id": tx.recipient_id,
            "amount": tx.amount,
            "risk_score": report.risk_score,
            "decision": report.decision.value,
            "reason": report.decision_reason,
            "audit_block_index": report.audit_block_index
        })

    return {
        "assessment": report.to_dict(),
        "ai_explanation": ai_explanation,
        "n8n_automation": n8n_status,
        "step_up_otp_issued": mock_otp_code,  # Provided for demo/testing convenience
        "transaction_status": tx.status.value
    }


@app.post("/step-up/verify-otp")
def verify_otp(req: OTPVerifyRequest):
    """
    Feature 08: Mock OTP Step-Up Verification
    """
    success, msg = otp_manager.verify_challenge(req.tx_id, req.otp_code)
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    # Update state & append to audit trail
    repo.update_transaction_status(req.tx_id, "APPROVED", "Approved via OTP Step-up verification")
    engine.audit_trail.append_event(
        event_type="STEP_UP_OTP_VERIFIED",
        payload={"tx_id": req.tx_id, "status": "APPROVED"}
    )
    repo.save_audit_block(engine.audit_trail.chain[-1])

    return {"status": "SUCCESS", "message": msg, "tx_id": req.tx_id}


@app.get("/analyst/hold-queue")
def get_analyst_hold_queue():
    """
    Feature 09: Returns held transactions for fraud analyst review.
    """
    return repo.get_held_transactions()


@app.post("/analyst/review")
def review_held_transaction(req: AnalystReviewRequest):
    """
    Feature 09: Analyst manual decision & feedback recording.
    """
    new_status = "APPROVED" if req.action.upper() == "APPROVE" else "BLOCKED"
    reason = f"Analyst ({req.analyst_id}) decision: {req.action}. Notes: {req.notes}"

    repo.update_transaction_status(req.tx_id, new_status, reason)
    repo.record_analyst_review(
        tx_id=req.tx_id,
        analyst_id=req.analyst_id,
        action=req.action,
        is_false_positive=req.is_false_positive,
        notes=req.notes,
        timestamp=datetime.now(timezone.utc).isoformat()
    )

    # Append to tamper-evident audit ledger
    engine.audit_trail.append_event(
        event_type="ANALYST_MANUAL_REVIEW",
        payload={
            "tx_id": req.tx_id,
            "analyst_id": req.analyst_id,
            "action": req.action,
            "is_false_positive": req.is_false_positive,
            "notes": req.notes
        }
    )
    repo.save_audit_block(engine.audit_trail.chain[-1])

    return {"status": "SUCCESS", "tx_id": req.tx_id, "final_status": new_status}


@app.get("/audit/verify")
def verify_audit_trail():
    """
    Feature 07: Validates full cryptographic SHA-256 chain integrity.
    """
    valid, message = engine.audit_trail.verify_integrity()
    return {
        "valid": valid,
        "message": message,
        "total_blocks": len(engine.audit_trail.chain),
        "blocks": [b.to_dict() for b in engine.audit_trail.chain]
    }


@app.get("/evaluation/benchmark")
def get_benchmark_report():
    """
    Feature 11 & Rubric: Runs the 100+ simulation test suite and returns performance metrics.
    """
    return run_benchmark_evaluation()
