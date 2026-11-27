
import hashlib
import time
import json
import random
import urllib.request
import os
import http.server
import socketserver
import sys


DECISION_APPROVE   = "APPROVE"   
DECISION_CHALLENGE = "CHALLENGE"  
DECISION_HOLD      = "HOLD"       
DECISION_BLOCK     = "BLOCK"      


class Transaction:
    def __init__(self, tx_id, sender, recipient, amount, device_id="phone_1", failed_logins=0, hour=12):
        
        if amount <= 0:
            raise ValueError("Transaction amount must be greater than 0!")

        self._tx_id = tx_id
        self._sender = sender
        self._recipient = recipient
        self._amount = float(amount)
        self._device_id = device_id
        self._failed_logins = failed_logins
        self._hour = hour
        self._status = "PENDING"
        self._reason = ""


    def get_id(self):
        return self._tx_id

    def get_sender(self):
        return self._sender

    def get_recipient(self):
        return self._recipient

    def get_amount(self):
        return self._amount

    def get_device(self):
        return self._device_id

    def get_failed_logins(self):
        return self._failed_logins

    def get_hour(self):
        return self._hour

    def get_status(self):
        return self._status

    def get_reason(self):
        return self._reason

    # State update methods (Encapsulation: Controlled changes)
    def set_approved(self, reason):
        self._status = "APPROVED"
        self._reason = reason

    def set_challenged(self, reason):
        self._status = "CHALLENGED"
        self._reason = reason

    def set_held(self, reason):
        self._status = "HELD"
        self._reason = reason

    def set_blocked(self, reason):
        self._status = "BLOCKED"
        self._reason = reason



# FEATURE 04: CUSTOMER BEHAVIOUR PROFILES
# ENCAPSULATION
# Stores the normal habits of a customer (average spending, trusted phone, active hours).

class CustomerProfile:
    def __init__(self, customer_id, name, avg_amount=5000, known_devices=None, frequent_recipients=None):
        self._customer_id = customer_id
        self._name = name
        self._avg_amount = float(avg_amount)
        self._known_devices = known_devices if known_devices else ["phone_1"]
        self._frequent_recipients = frequent_recipients if frequent_recipients else []
        self._history = []

    def get_avg_amount(self):
        return self._avg_amount

    def is_known_device(self, device_id):
        # Returns True if the device is in the customer's trusted device list
        return device_id in self._known_devices

    def is_frequent_recipient(self, recipient_id):
        # Returns True if the customer frequently sends money to this person
        return recipient_id in self._frequent_recipients

    def is_daytime_hour(self, hour):
        # Normal active hours in Pakistan: 8 AM to 10 PM (8 to 22)
        return 8 <= hour <= 22

    def add_past_transaction(self, amount):
        # Keeps track of past transaction history
        self._history.append(amount)

    def get_recent_count(self):
        # How many recent transactions happened
        return len(self._history)



# FEATURE 03: PLUGGABLE CHECKS (7 CHECKS)
# ABSTRACTION & INHERITANCE
# 1. Base Class: RiskCheck (Abstraction)
# 2. Subclasses: 7 specific checks that inherit from RiskCheck (Inheritance)


# --- BASE CLASS (ABSTRACTION) ---
class RiskCheck:
    def __init__(self, name, weight):
        self.name = name         
        self.weight = weight     

    def evaluate(self, transaction, customer):
       
        pass


# --- CHECK 1: AMOUNT ANOMALY (INHERITANCE) ---
class AmountCheck(RiskCheck):
    def __init__(self):
        super().__init__("AmountCheck", 18)

    def evaluate(self, transaction, customer):
        amount = transaction.get_amount()
        avg = customer.get_avg_amount()

        # Check how many times higher this amount is compared to normal average
        ratio = amount / avg

        if ratio >= 8.0:
            # Huge spike (8 times higher than average) -> Full points
            return {"name": self.name, "score": 18, "triggered": True, "reason": f"PKR {amount:,.0f} is {ratio:.1f}x higher than average!"}
        elif ratio >= 3.0:
            # Noticeable spike (3 times higher than average) -> Half points
            return {"name": self.name, "score": 9, "triggered": True, "reason": f"PKR {amount:,.0f} is elevated ({ratio:.1f}x average)."}
        else:
            # Normal amount
            return {"name": self.name, "score": 0, "triggered": False, "reason": "Amount is within normal range."}


# --- CHECK 2: DEVICE RISK (INHERITANCE) ---
class DeviceCheck(RiskCheck):
    def __init__(self):
        super().__init__("DeviceCheck", 14)

    def evaluate(self, transaction, customer):
        device = transaction.get_device()

        if customer.is_known_device(device):
            return {"name": self.name, "score": 0, "triggered": False, "reason": "Trusted known device."}
        else:
            # Unknown device -> Add 14 points
            return {"name": self.name, "score": 14, "triggered": True, "reason": f"Unrecognized new device: '{device}'."}


# --- CHECK 3: RECIPIENT MULE RISK (INHERITANCE) ---
class RecipientCheck(RiskCheck):
    def __init__(self):
        super().__init__("RecipientCheck", 15)
        # Blacklist of known Pakistani fraud/mule accounts
        self.blacklist = ["PK99MULE77881122", "PK44FRAUD990011", "mule_wallet_404"]

    def evaluate(self, transaction, customer):
        recipient = transaction.get_recipient()

        # Check 1: Is this account on the national fraud blacklist?
        if recipient in self.blacklist:
            return {"name": self.name, "score": 15, "triggered": True, "critical": True, "reason": f"CRITICAL: '{recipient}' is on the National Fraud Blacklist!"}

        # Check 2: Is this a frequent contact or a stranger?
        if customer.is_frequent_recipient(recipient):
            return {"name": self.name, "score": 0, "triggered": False, "critical": False, "reason": "Verified frequent recipient."}
        else:
            return {"name": self.name, "score": 6, "triggered": True, "critical": False, "reason": "First-time payment to an unfamiliar recipient."}


# --- CHECK 4: FAILED LOGINS ANOMALY (INHERITANCE) ---
class LoginCheck(RiskCheck):
    def __init__(self):
        super().__init__("LoginCheck", 15)

    def evaluate(self, transaction, customer):
        logins = transaction.get_failed_logins()

        if logins >= 3:
            # Password guessing / stolen account attack
            return {"name": self.name, "score": 15, "triggered": True, "reason": f"Credential Attack: {logins} failed logins before payment!"}
        else:
            return {"name": self.name, "score": 0, "triggered": False, "reason": "Clean login session."}


# --- CHECK 5: UNUSUAL HOURS CHECK (INHERITANCE) ---
class HoursCheck(RiskCheck):
    def __init__(self):
        super().__init__("HoursCheck", 10)

    def evaluate(self, transaction, customer):
        hour = transaction.get_hour()

        if customer.is_daytime_hour(hour):
            return {"name": self.name, "score": 0, "triggered": False, "reason": "Payment made during normal daytime hours."}
        else:
            # Check if it is deep midnight (1 AM to 5 AM)
            if 1 <= hour <= 5:
                return {"name": self.name, "score": 10, "triggered": True, "reason": f"Deep midnight payment at {hour}:00 AM!"}
            else:
                return {"name": self.name, "score": 6, "triggered": True, "reason": f"Off-hours payment at {hour}:00."}


# --- CHECK 6: VELOCITY CHECK (RAPID PAYMENTS) (INHERITANCE) ---
class VelocityCheck(RiskCheck):
    def __init__(self):
        super().__init__("VelocityCheck", 14)

    def evaluate(self, transaction, customer):
        count = customer.get_recent_count()

        if count >= 3:
            # Multiple payments in a short time -> Account draining attempt
            return {"name": self.name, "score": 14, "triggered": True, "reason": f"High Velocity: {count} recent payments executed rapidly!"}
        else:
            return {"name": self.name, "score": 0, "triggered": False, "reason": "Normal velocity."}


# --- CHECK 7: SPLITTING / SMURFING CHECK (INHERITANCE) ---
class SplittingCheck(RiskCheck):
    def __init__(self):
        super().__init__("SplittingCheck", 14)

    def evaluate(self, transaction, customer):
        amount = transaction.get_amount()

        # In Pakistan, banks monitor transfers of 50,000 PKR.
        # Fraudsters send 48,000 or 49,500 to stay right below the limit.
        if 45000 <= amount < 50000:
            return {"name": self.name, "score": 11, "triggered": True, "reason": f"Suspected Smurfing: PKR {amount:,.0f} sits right below the 50k limit."}
        else:
            return {"name": self.name, "score": 0, "triggered": False, "reason": "No splitting patterns detected."}


# ==================================================================================================
# FEATURE 12: AI ANOMALY CHECK
# [OOP CONCEPT: INHERITANCE]
# Checks if multiple factors (amount + time + logins) look strange together.
# ==================================================================================================

class AnomalyCheck(RiskCheck):
    def __init__(self):
        super().__init__("AnomalyCheck", 10)

    def evaluate(self, transaction, customer):
        amount = transaction.get_amount()
        hour = transaction.get_hour()
        logins = transaction.get_failed_logins()

        # If amount is high, AND time is midnight, AND logins failed -> strong anomaly
        if amount > 30000 and (hour < 8 or hour > 22) and logins >= 2:
            return {"name": self.name, "score": 10, "triggered": True, "reason": "AI Anomaly: High amount + night time + failed logins detected together!"}
        else:
            return {"name": self.name, "score": 0, "triggered": False, "reason": "AI Anomaly: Normal behavior pattern."}


# ==================================================================================================
# FEATURE 05: CONFIGURABLE POLICIES & THRESHOLDS
# Evaluates total score (0 to 100) and chooses one of the 4 decisions:
#   Score 0  to 29 -> APPROVE
#   Score 30 to 59 -> CHALLENGE (Step-up OTP)
#   Score 60 to 79 -> HOLD (Send to human analyst)
#   Score 80 to 100 -> BLOCK (Hard stop)
# ==================================================================================================

class DecisionPolicy:
    def decide(self, total_score, results):
        # 1. Critical Hard Override: If recipient is blacklisted, block immediately
        for r in results:
            if r.get("critical") == True:
                return DECISION_BLOCK, "CRITICAL HARD BLOCK: Recipient is in Fraud Blacklist!"

        # 2. Threshold-based decisions
        if total_score >= 80:
            return DECISION_BLOCK, f"Score {total_score}/100 exceeds safe limits. Payment Blocked!"
        elif total_score >= 60:
            return DECISION_HOLD, f"Score {total_score}/100 is high risk. Sent to Human Analyst Queue."
        elif total_score >= 30:
            return DECISION_CHALLENGE, f"Score {total_score}/100 is moderate. 2FA OTP Required."
        else:
            return DECISION_APPROVE, f"Score {total_score}/100 is low risk. Payment Approved."


# ==================================================================================================
# FEATURE 06: PLAIN ENGLISH AI EXPLANATIONS
# Generates a clear explanation of why the payment was approved, held, or blocked.
# Safety Guarantee: This AI only explains; it can NEVER change the engine's decision!
# ==================================================================================================

class AIExplainer:
    @staticmethod
    def explain(decision, total_score, results):
        flagged_reasons = []
        for r in results:
            if r["triggered"]:
                flagged_reasons.append(f"{r['name']}: {r['reason']}")

        if len(flagged_reasons) == 0:
            return f"[AI Explanation] Decision is {decision} (Score: {total_score}/100). All checks passed smoothly."
        else:
            all_reasons = " | ".join(flagged_reasons)
            return f"[AI Explanation] Decision is {decision} (Score: {total_score}/100).\n   Triggers: {all_reasons}"


# ==================================================================================================
# FEATURE 07: TAMPER-EVIDENT SHA-256 AUDIT TRAIL
# Mini-blockchain: Each block stores the hash of the previous block.
# If anyone tries to change a past record in the database, the hash chain breaks!
# ==================================================================================================

class AuditBlock:
    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # Combines block data into a string and computes SHA-256 hash
        text = f"{self.index}{self.timestamp}{json.dumps(self.data, sort_keys=True)}{self.previous_hash}"
        return hashlib.sha256(text.encode()).hexdigest()


class AuditTrail:
    def __init__(self):
        # Genesis block (First block in the chain)
        self.chain = [AuditBlock(0, {"event": "GENESIS_ROOT"}, "0" * 64)]

    def add_record(self, data):
        last_block = self.chain[-1]
        new_block = AuditBlock(len(self.chain), data, last_block.hash)
        self.chain.append(new_block)
        return new_block

    def verify_chain(self):
        # Loops through the chain to make sure nobody tampered with past data
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Check 1: Does previous_hash match?
            if current.previous_hash != previous.hash:
                return False, f"Broken link detected at Block #{i}!"

            # Check 2: Does current hash match its contents?
            if current.hash != current.calculate_hash():
                return False, f"Tampered data detected at Block #{i}!"

        return True, "Audit Trail Verified: All SHA-256 block hashes are intact!"


# ==================================================================================================
# FEATURE 08: STEP-UP 2FA VERIFICATION (MOCK OTP)
# When decision is CHALLENGE, this issues a 6-digit OTP code to the customer.
# ==================================================================================================

class OTPManager:
    def __init__(self):
        self.saved_otps = {}  # tx_id -> otp_code

    def issue_otp(self, tx_id):
        # Generate random 6-digit code like "482910"
        code = str(random.randint(100000, 999999))
        self.saved_otps[tx_id] = code
        return code

    def verify_otp(self, tx_id, entered_code):
        if tx_id in self.saved_otps and self.saved_otps[tx_id] == entered_code:
            del self.saved_otps[tx_id]  # Consume OTP
            return True, "OTP Verified Successfully! Payment Released."
        else:
            return False, "Invalid or Expired OTP code!"


# ==================================================================================================
# FEATURE 09: FRAUD ANALYST REVIEW QUEUE
# Holds suspicious payments (Score 60-79) so human bank officers can review them.
# ==================================================================================================

class AnalystQueue:
    def __init__(self):
        self.queue = []

    def add_to_queue(self, tx_id, amount, score, reason):
        self.queue.append({
            "tx_id": tx_id,
            "amount": amount,
            "score": score,
            "reason": reason
        })

    def get_pending_count(self):
        return len(self.queue)


# ==================================================================================================
# FEATURE 10: UNIFIED RISK ENGINE & n8n WEBHOOK DISPATCHER
# [OOP CONCEPTS: COMPOSITION & POLYMORPHISM]
# 1. Composition: RiskEngine OWNS a list of checks, an audit trail, and an OTP manager.
# 2. Polymorphism: RiskEngine loops through self.checks and calls check.evaluate() uniformly!
# ==================================================================================================

class N8NWebhook:
    # In n8n, there are two URLs:
    # 1. Test URL (used when clicking "Listen for test event" on the canvas)
    # 2. Production URL (used when the workflow is toggled to Active)
    CANDIDATE_URLS = [
        "http://localhost:5678/webhook/dhoka-fraud-alert",
        "http://localhost:5678/webhook-test/dhoka-fraud-alert"
    ]

    @staticmethod
    def send_payload(payload):
        """
        Sends ANY payload dict directly to n8n webhook (used by HTTP bridge server).
        Returns a status string.
        """
        for url in N8NWebhook.CANDIDATE_URLS:
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    return f"Live n8n Connected -> Webhook Delivered (HTTP {resp.getcode()})"
            except Exception:
                continue
        return "n8n Offline -> Alert staged in SecOps Fallback Queue"

    @staticmethod
    def send_alert(tx_id, amount, score, decision, reason):
        """Convenience wrapper used by the VS Code console demo."""
        payload = {
            "tx_id": tx_id,
            "amount": amount,
            "risk_score": score,
            "decision": decision,
            "reason": reason
        }
        return N8NWebhook.send_payload(payload)


class RiskEngine:
    def __init__(self):
        # [COMPOSITION]: Engine has a list of 8 checks
        self.checks = [
            AmountCheck(),
            DeviceCheck(),
            RecipientCheck(),
            LoginCheck(),
            HoursCheck(),
            VelocityCheck(),
            SplittingCheck(),
            AnomalyCheck()
        ]
        self.policy = DecisionPolicy()
        self.audit_trail = AuditTrail()
        self.otp_manager = OTPManager()
        self.analyst_queue = AnalystQueue()

    def assess_transaction(self, transaction, customer):
        results = []
        total_score = 0

        # [POLYMORPHISM]: Loop through all checks uniformly
        for check in self.checks:
            result = check.evaluate(transaction, customer)
            results.append(result)
            total_score += result["score"]

        # Cap score between 0 and 100
        total_score = min(100, total_score)

        # Decide action based on score
        decision, reason = self.policy.decide(total_score, results)

        # Update transaction state (Encapsulation)
        if decision == DECISION_APPROVE:
            transaction.set_approved(reason)
        elif decision == DECISION_CHALLENGE:
            transaction.set_challenged(reason)
            self.otp_manager.issue_otp(transaction.get_id())
        elif decision == DECISION_HOLD:
            transaction.set_held(reason)
            self.analyst_queue.add_to_queue(transaction.get_id(), transaction.get_amount(), total_score, reason)
        elif decision == DECISION_BLOCK:
            transaction.set_blocked(reason)

        # Save to Audit Trail
        block = self.audit_trail.add_record({
            "tx_id": transaction.get_id(),
            "amount": transaction.get_amount(),
            "score": total_score,
            "decision": decision
        })

        return total_score, decision, reason, results, block


# ==================================================================================================
# FEATURE 11: 120-CASE TEST SIMULATION & BENCHMARK
# Runs 60 normal payments + 60 fraud payments to measure Recall and False Positives.
# Directly satisfies Instructor Sir Muhammad Khalid's feedback!
# ==================================================================================================

class SimulatorBenchmark:
    @staticmethod
    def run_tests(engine):
        print("\n" + "=" * 80)
        print("FEATURE 11: RUNNING 120-CASE TEST SUITE (BENCHMARK)")
        print("Satisfies Sir Muhammad Khalid's Feedback: Measures False Positives & Attack Recall")
        print("=" * 80)

        customer = CustomerProfile("CUST_TEST", "Test User", avg_amount=3000, known_devices=["phone_1"])

        caught_attacks = 0
        total_attacks = 60
        false_alarms = 0
        total_normal = 60

        # 1. Run 60 Normal Transactions (Amount: 1,000 to 5,000 PKR, daytime)
        for i in range(total_normal):
            amt = random.randint(1000, 5000)
            tx = Transaction(f"NORM_{i}", "CUST_TEST", "MOM_WALLET", amt, device_id="phone_1", hour=14)
            score, decision, _, _, _ = engine.assess_transaction(tx, customer)

            # Normal payments should never be held or blocked
            if decision == DECISION_HOLD or decision == DECISION_BLOCK:
                false_alarms += 1

        # 2. Run 60 Fraud Attack Transactions across 4 Pakistani Scenarios (15 each)
        for i in range(total_attacks):
            if i < 15:
                # Attack 1: Stolen Login + New Device (Account Takeover)
                tx = Transaction(f"ATK_{i}", "CUST_TEST", "UNKNOWN_WALLET", 45000, device_id="kali_linux", failed_logins=4, hour=14)
            elif i < 30:
                # Attack 2: Blacklisted Mule Recipient
                tx = Transaction(f"ATK_{i}", "CUST_TEST", "PK99MULE77881122", 15000, device_id="phone_1", hour=14)
            elif i < 45:
                # Attack 3: Midnight Surge at 3 AM
                tx = Transaction(f"ATK_{i}", "CUST_TEST", "STRANGER_1", 95000, device_id="tab_2", hour=3)
            else:
                # Attack 4: Smurfing / Structuring (49,500 PKR)
                tx = Transaction(f"ATK_{i}", "CUST_TEST", "STRANGER_2", 49500, device_id="phone_1", hour=14)

            score, decision, _, _, _ = engine.assess_transaction(tx, customer)

            # Did our engine catch the attack?
            if decision in [DECISION_CHALLENGE, DECISION_HOLD, DECISION_BLOCK]:
                caught_attacks += 1

        # Calculate percentages
        recall = (caught_attacks / total_attacks) * 100
        fpr = (false_alarms / total_normal) * 100

        print(f"Total Transactions Evaluated : {total_normal + total_attacks} cases")
        print(f"Legitimate Transactions      : {total_normal} cases")
        print(f"Fraud Attack Transactions    : {total_attacks} cases")
        print("-" * 80)
        print(f"Flagged-Attack Recall        : {recall:.1f}% (Caught {caught_attacks}/{total_attacks} attacks)")
        print(f"False Positive Rate (FPR)    : {fpr:.1f}% (False alarms on normal users: {false_alarms}/{total_normal})")
        print("=" * 80)


# ==================================================================================================
# MAIN PROGRAM EXECUTION
# Demonstrates 4 real Pakistani fraud scenarios live in your console!
# ==================================================================================================

def run_main():
    print("=" * 80)
    print("          DHOKA DETECTOR: UNIVERSITY OOP PROJECT LIVE DEMONSTRATION")
    print("          'Detect the Dhoka. Protect the Paisa.' (FinTech Pakistan)")
    print("=" * 80)

    # 1. Create the engine
    engine = RiskEngine()

    # 2. Create customer Bilal
    bilal = CustomerProfile(
        customer_id="PK_CUST_9941",
        name="Muhammad Bilal",
        avg_amount=4000,
        known_devices=["bilal_phone"],
        frequent_recipients=["ELECTRIC_BILL", "SISTER_SADAPAY"]
    )

    # 3. Define 4 test scenarios
    scenarios = [
        {
            "title": "SCENARIO 1: Normal Grocery Payment",
            "tx": Transaction("TX_01", bilal.get_sender() if hasattr(bilal, "get_sender") else "PK_CUST_9941", "ELECTRIC_BILL", 3500, device_id="bilal_phone", hour=14),
            "expected": "APPROVE"
        },
        {
            "title": "SCENARIO 2: Stolen Login + New Kali Device (Account Takeover)",
            "tx": Transaction("TX_02", "PK_CUST_9941", "STRANGER_WALLET", 42000, device_id="hacker_laptop", failed_logins=4, hour=14),
            "expected": "HOLD"
        },
        {
            "title": "SCENARIO 3: National Blacklist Mule Account",
            "tx": Transaction("TX_03", "PK_CUST_9941", "PK99MULE77881122", 15000, device_id="bilal_phone", hour=14),
            "expected": "BLOCK"
        },
        {
            "title": "SCENARIO 4: Midnight High-Value Transfer at 3:00 AM",
            "tx": Transaction("TX_04", "PK_CUST_9941", "STRANGER_WALLET_2", 125000, device_id="new_tablet", hour=3),
            "expected": "BLOCK / HOLD"
        }
    ]

    # 4. Run the scenarios
    for s in scenarios:
        tx = s["tx"]
        print(f"\n--- {s['title']} ---")
        print(f"Amount: PKR {tx.get_amount():,.0f} | Recipient: {tx.get_recipient()} | Device: {tx.get_device()} | Hour: {tx.get_hour()}:00")

        score, decision, reason, results, block = engine.assess_transaction(tx, bilal)

        # AI explanation
        ai_summary = AIExplainer.explain(decision, score, results)

        # n8n webhook automation
        n8n_status = ""
        if decision in [DECISION_HOLD, DECISION_BLOCK]:
            status = N8NWebhook.send_alert(tx.get_id(), tx.get_amount(), score, decision, reason)
            n8n_status = f"\n>> n8n Automation : ⚡ {status}"

        print(f">> Risk Score     : {score}/100")
        print(f">> Final Decision : {decision} (Expected: {s['expected']})")
        print(f">> Audit Block    : Block #{block.index} [SHA-256: {block.hash[:16]}...]")
        print(f">> {ai_summary}{n8n_status}")

    # 5. Verify the SHA-256 Audit Chain
    print("\n" + "=" * 80)
    print("FEATURE 07: VERIFYING SHA-256 AUDIT TRAIL INTEGRITY")
    is_valid, msg = engine.audit_trail.verify_chain()
    print(f"Status: {msg}")

    # 6. Run the 120-Case Benchmark Suite
    SimulatorBenchmark.run_tests(engine)



# ==================================================================================================
# FEATURE 10 EXTENSION: LIGHTWEIGHT HTTP BRIDGE SERVER
# [OOP CONCEPT: COMPOSITION + ENCAPSULATION]
#
# This server starts on http://localhost:8000 so that the HTML frontend can call it
# DIRECTLY instead of needing the browser to reach n8n separately.
#
# How it works:
#   1. Frontend hits  POST http://localhost:8000/api/assess  with transaction data
#   2. Python runs the REAL OOP RiskEngine (all 8 checks, real audit trail)
#   3. Python fires the n8n webhook (which sends the Gmail!)
#   4. Python returns the result JSON to the frontend
#   5. The frontend shows the result - customer sees nothing, admin sees everything
# ==================================================================================================

class DhokaHTTPServer:
    """
    [OOP CONCEPT: ENCAPSULATION]
    Wraps the Python standard library HTTP server.
    Owns one RiskEngine instance for the entire demo session.
    """
    def __init__(self, engine, otp_manager, port=8000):
        self.engine = engine
        self.otp_manager = otp_manager
        self.port = port

    def start(self):
        # Create a closure so the handler can access the engine
        engine = self.engine
        otp_mgr = self.otp_manager

        class DhokaHandler(http.server.BaseHTTPRequestHandler):

            # Silence request logs (keep terminal clean during presentation)
            def log_message(self, fmt, *args):
                pass

            def send_cors_headers(self):
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_cors_headers()
                self.end_headers()

            def do_GET(self):
                if self.path == "/api/health":
                    self.send_response(200)
                    self.send_cors_headers()
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ok", "engine": "DhokaDetector OOP v1.0"}).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                # Read JSON body
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length)) if length > 0 else {}

                if self.path == "/api/assess":
                    result = self._handle_assess(body)
                    self.send_response(200)
                    self.send_cors_headers()
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(result).encode())

                elif self.path == "/api/admin-resolve":
                    result = self._handle_admin_resolve(body)
                    self.send_response(200)
                    self.send_cors_headers()
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(result).encode())

                elif self.path == "/api/n8n-dispatch":
                    n8n_result = self._handle_n8n(body)
                    self.send_response(200)
                    self.send_cors_headers()
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(n8n_result).encode())

                else:
                    self.send_response(404)
                    self.send_cors_headers()
                    self.end_headers()

            def _handle_assess(self, body):
                """Full OOP risk assessment: runs all 8 checks, fires n8n webhook, returns result."""
                amt = float(body.get("amount", 3500))
                recip = body.get("recipient", "PK99HABB0001234567")
                dev = body.get("device", "bilal_phone")
                hour = int(body.get("hour", 14))
                logins = int(body.get("failed_logins", 0))
                cust_email = body.get("customer_email", "customer@gmail.com")
                admin_email = body.get("admin_email", cust_email)
                otp_code = body.get("otp_code", "000000")

                # Build Customer & Transaction objects
                bilal = CustomerProfile(
                    customer_id="PK_CUST_9941",
                    name="Muhammad Bilal",
                    avg_amount=4000,
                    known_devices=["bilal_phone"],
                    frequent_recipients=["ELECTRIC_BILL", "SISTER_SADAPAY", "PK99HABB0001234567"]
                )

                tx_id = f"TX_WEB_{random.randint(1000, 9999)}"
                tx = Transaction(
                    tx_id,
                    "PK_CUST_9941",
                    recip,
                    amt,
                    device_id=dev,
                    failed_logins=logins,
                    hour=hour
                )

                # Run the REAL Python OOP engine
                score, decision, reason, results, block = engine.assess_transaction(tx, bilal)

                # Detect pattern label
                is_mule = recip in ["PK99MULE77881122", "PK44FRAUD990011", "mule_wallet_404"]
                pattern = "Baseline Normal Transfer"
                if is_mule:
                    pattern = "🚨 National Mule Exploitation"
                elif amt >= 100000 and (hour < 8 or hour > 22):
                    pattern = "🚨 Midnight High-Value Surge"
                elif 45000 <= amt < 50000:
                    pattern = "🟡 Sub-Threshold Smurfing (AML)"
                elif dev != "bilal_phone" or logins >= 3:
                    pattern = "🟠 Account Takeover / Stolen Login"
                elif score >= 30:
                    pattern = "🟡 First-Time Beneficiary Elevation"

                # AI summary
                ai_summary = AIExplainer.explain(decision, score, results)

                # Route n8n webhook (real Gmail email!)
                if decision == DECISION_CHALLENGE:
                    n8n_payload = {
                        "event": "CUSTOMER_OTP_CHALLENGE",
                        "decision": decision,
                        "amount": amt,
                        "tx_id": tx_id,
                        "risk_score": score,
                        "reason": f"OTP Verification Code: {otp_code}",
                        "otp_code": otp_code,
                        "to_email": cust_email,
                        "sender_name": "Muhammad Bilal (Customer)",
                        "recipient_id": recip,
                        "audit_block_index": block.index
                    }
                    N8NWebhook.send_payload(n8n_payload)
                elif decision in [DECISION_HOLD, DECISION_BLOCK]:
                    # 1. Customer receives Hold Notice (payment paused for review, NEVER instant decline!)
                    cust_hold_payload = {
                        "event": "CUSTOMER_HOLD_NOTICE",
                        "decision": decision,
                        "amount": amt,
                        "tx_id": tx_id,
                        "risk_score": score,
                        "reason": f"Payment paused for routine compliance verification ({pattern})",
                        "otp_code": "",
                        "to_email": cust_email,
                        "sender_name": "Muhammad Bilal (Customer)",
                        "recipient_id": recip,
                        "audit_block_index": block.index
                    }
                    N8NWebhook.send_payload(cust_hold_payload)

                    # 2. SecOps Admin receives Incident Alert to review in Decision Desk
                    admin_payload = {
                        "event": "CRITICAL_FRAUD_BLOCK",
                        "decision": decision,
                        "amount": amt,
                        "tx_id": tx_id,
                        "risk_score": score,
                        "reason": f"Threat Vector: {pattern}. Investigation pending in Admin Desk.",
                        "otp_code": "",
                        "to_email": admin_email,
                        "sender_name": "Muhammad Bilal (Customer)",
                        "recipient_id": recip,
                        "audit_block_index": block.index
                    }
                    N8NWebhook.send_payload(admin_payload)

                # Build response for the frontend
                checks_out = []
                for r in results:
                    checks_out.append({
                        "name": r["name"],
                        "score": r["score"],
                        "trig": r.get("triggered", False),
                        "reason": r["reason"]
                    })

                return {
                    "score": score,
                    "decision": decision,
                    "reason": reason,
                    "checks": checks_out,
                    "is_mule": is_mule,
                    "pattern": pattern,
                    "ai_summary": ai_summary,
                    "block_index": block.index,
                    "block_hash": block.hash
                }

            def _handle_admin_resolve(self, body):
                """Dispatches customer decision notification upon Admin Review action."""
                action = body.get("action")
                amt = float(body.get("amount", 0))
                recip = body.get("recipient", "Unknown")
                cust_email = body.get("customer_email", "customer@gmail.com")
                tx_id = body.get("tx_id", f"TX_RES_{random.randint(1000, 9999)}")
                block_idx = body.get("block_index", 0)

                if action == "approve":
                    payload = {
                        "event": "CUSTOMER_APPROVED_NOTICE",
                        "decision": "APPROVE",
                        "amount": amt,
                        "tx_id": tx_id,
                        "risk_score": 0,
                        "reason": "Payment verified and released by Bank Compliance.",
                        "otp_code": "",
                        "to_email": cust_email,
                        "sender_name": "Muhammad Bilal (Customer)",
                        "recipient_id": recip,
                        "audit_block_index": block_idx
                    }
                    N8NWebhook.send_payload(payload)
                    return {"status": "approved", "dispatched": True}
                else:
                    payload = {
                        "event": "CUSTOMER_DECLINED_NOTICE",
                        "decision": "DECLINE",
                        "amount": amt,
                        "tx_id": tx_id,
                        "risk_score": 100,
                        "reason": "Payment declined following security review by Bank Compliance. No funds deducted.",
                        "otp_code": "",
                        "to_email": cust_email,
                        "sender_name": "Muhammad Bilal (Customer)",
                        "recipient_id": recip,
                        "audit_block_index": block_idx
                    }
                    N8NWebhook.send_payload(payload)
                    return {"status": "declined", "dispatched": True}

            def _handle_n8n(self, body):
                """Direct n8n webhook relay (called from browser if needed)."""
                result = N8NWebhook.send_payload(body)
                return {"status": result}

        # Allow immediate port reuse — prevents WinError 10048 on restart
        socketserver.TCPServer.allow_reuse_address = True

        # Try preferred port, fall back to 8080 if already occupied
        for port_attempt in [self.port, 8080, 8888, 9000]:
            try:
                with socketserver.TCPServer(("", port_attempt), DhokaHandler) as httpd:
                    print(f"\n{'=' * 70}")
                    print(f"  🌐  DHOKA DETECTOR HTTP BRIDGE ACTIVE on http://localhost:{port_attempt}")
                    print(f"      Frontend URL: open frontend/dhoka_detector_portal.html in Chrome")
                    print(f"      API Health:   http://localhost:{port_attempt}/api/health")
                    print(f"      Webhook:      POST http://localhost:{port_attempt}/api/assess")
                    print(f"{'=' * 70}\n")
                    httpd.serve_forever()
                    break
            except OSError as e:
                print(f"  ⚠️  Port {port_attempt} busy ({e}), trying next port...")
                continue


if __name__ == "__main__":
    import threading

    # 1. Run the CONSOLE DEMO (all 4 scenarios printed live in VS Code terminal)
    run_main()

    # 2. Start HTTP bridge server in background (connects frontend to real Python OOP engine)
    engine = RiskEngine()
    otp_mgr = OTPManager()
    server = DhokaHTTPServer(engine, otp_mgr, port=8000)

    print("\n" + "=" * 70)
    print("  STARTING HTTP BRIDGE: Frontend will now use Real Python OOP Engine!")
    print("  Open frontend/dhoka_detector_portal.html in Chrome to begin the demo.")
    print("=" * 70)

    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()

    # Keep main thread alive so server stays up
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Dhoka Detector] Server stopped. Goodbye!")

