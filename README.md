# 🛡️ Dhoka Detector (DD)
### *Detect the Dhoka. Protect the Paisa.*
**An Object-Oriented Real-Time Fraud Defense & Cryptographic Audit Engine for Pakistani Digital Payment Rails**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Payment Rail](https://img.shields.io/badge/Payment_Rail-State_Bank_Raast-059669.svg)](https://www.sbp.org.pk/)
[![Security](https://img.shields.io/badge/Audit-SHA--256_Chained_Ledger-6366F1.svg)]()
[![Automation](https://img.shields.io/badge/Orchestration-n8n_Webhook-EA580C.svg?logo=n8n&logoColor=white)](https://n8n.io/)
[![Tests](https://img.shields.io/badge/Tests-100%25_Passing-success.svg)]()

---

## 📌 Project Overview
**Dhoka Detector** is an inline transaction risk evaluation and fraud prevention system engineered specifically for Pakistani instant payment rails (**State Bank Raast**, **SadaPay**, and **NayaPay**). 

In modern retail banking, transactions settle irreversibly within seconds. Traditional fraud systems either approve high-risk transfers blindly or abruptly decline legitimate transactions, creating customer friction. **Dhoka Detector** bridges this gap using strict **Object-Oriented Programming (OOP)** principles, a calibrated **Three-Tier Decision Matrix**, and a **Tamper-Evident SHA-256 Cryptographic Audit Ledger**.

---

## 👥 Academic Credits & Supervision
- **Institution**: FAST National University of Computer & Emerging Sciences (FAST-NUCES)
- **Course**: CS-2001 Object-Oriented Programming (OOP)
- **Project Supervisor**: Sir Muhammad Khalid
- **Project Team**:
  - **Muhammad Abdullah** (25k-5538)
  - **Muhammad Aneeq** (25k-5597)
  - **Shuja Ahmed** (25k-5747)
  - **Abdul Ahad** (25k-5578)

---

## 📸 System Interface & Live Verification

| Scenario 1: Baseline Approval | Scenario 2: 2FA OTP Challenge | Scenario 3: Critical Hold & SecOps Desk |
| :---: | :---: | :---: |
| ![Scenario 1](docs/screenshots/fig1_ui_approve.jpg) | ![Scenario 2](docs/screenshots/fig2_ui_challenge_otp.jpg) | ![Scenario 3](docs/screenshots/fig3_ui_hold_admin_desk.jpg) |
| **Score: 0/100 (Safe)**<br>Instant Raast settlement, balance deducted accurately. | **Score: 42/100 (Elevated)**<br>Automated OTP dispatched to customer Gmail. | **Score: 81/100 (Critical Fraud)**<br>Transaction paused; routed to SecOps Decision Desk. |

| Real Customer Gmail OTP | SecOps Sentinel Threat Alert | Customer Hold Status Notice |
| :---: | :---: | :---: |
| ![Gmail OTP](docs/screenshots/fig4_gmail_otp.jpg) | ![Gmail Alert](docs/screenshots/fig5_gmail_admin_alert.jpg) | ![Gmail Hold](docs/screenshots/fig6_gmail_customer_hold.jpg) |
| Live 6-digit OTP delivered in <1.2s via n8n webhook. | High-priority security dispatch with block details. | Transparent customer status update avoiding hard declines. |

---

## 🧱 Object-Oriented Architecture (OOP Implementation)

Dhoka Detector is architected around foundational Object-Oriented Design Patterns:

```
                      +-------------------+
                      |   <<abstract>>    |
                      |     RiskCheck     |
                      +-------------------+
                      | + assess() = 0    |
                      +---------+---------+
                                |
        +-----------------------+-----------------------+
        |                       |                       |
+-------v-------+       +-------v-------+       +-------v-------+
|  AmountCheck  |       | VelocityCheck |       |  DeviceCheck  |  ... (UnusualHours, Recipient, ML)
+---------------+       +---------------+       +---------------+
| + assess(...) |       | + assess(...) |       | + assess(...) |
+-------+-------+       +-------+-------+       +-------+-------+
        |                       |                       |
        +-----------------------+-----------------------+
                                |
                                v (Polymorphic Aggregation)
                      +-------------------+
                      |    RiskEngine     |
                      +-------------------+
                      | + evaluate()      |
                      +---------+---------+
                                |
                                v (Immutable Record)
                      +-------------------+
                      |    AuditBlock     | (SHA-256 Chained)
                      +-------------------+
```

### 1. Abstraction & Polymorphism
- **Abstract Base Class**: `RiskCheck` (`backend/app/engine/base_check.py`) enforces a pure virtual interface `assess(transaction, profile)`.
- **Concrete Subclasses**: Specialized heuristics inherit independently:
  - `AmountAnomalyCheck`: Exponential divergence from 90-day moving average.
  - `VelocityCheck`: High-frequency rapid transfer bursts.
  - `DeviceRiskCheck`: Unrecognized hardware, emulator environments, and device switches.
  - `UnusualHoursCheck`: High-value nocturnal surges (1:00 AM – 5:00 AM).
  - `SplittingCheck`: Smurfing and transaction structuring detection.
  - `IsolationForestCheck`: Machine learning multi-dimensional outlier scoring.
- **Uniform Execution**: `RiskEngine` composes a collection of `List[RiskCheck]` and evaluates them uniformly without concrete coupling (**Open-Closed Principle**).

### 2. Encapsulation & Data Protection
- **`CustomerProfile` & `CustomerAccount`**: Sensitive financial balances, daily velocity counters, and trusted device lists are strictly encapsulated with private internal attributes and controlled mutation methods.
- **`Transaction` State Machine**: Transitions (`PENDING` &rarr; `APPROVED`, `CHALLENGED`, or `HELD`) are strictly guarded against illegal state mutations.

### 3. Cryptographic Immutability
- **`TamperEvidentAuditTrail` & `AuditBlock`**: Every evaluated decision produces a cryptographically sealed block:
  $$H_n = \text{SHA-256}(n \parallel H_{n-1} \parallel \text{Timestamp} \parallel \text{Score} \parallel \text{Amount} \parallel \text{IBAN})$$
  Modifying any historical record in the database breaks the mathematical chain instantly, producing court-admissible audit proof.

---

## ⚡ The Three-Tier Decision Pipeline

| Risk Tier | Score Range | System Action & Enforcement | Real-World User Experience |
| :--- | :---: | :--- | :--- |
| **Tier 1: Approve** | `0 – 25` | Immediate balance deduction & instant settlement. | Seamless sub-2 second checkout for nominal daily transfers. |
| **Tier 2: Challenge** | `26 – 60` | Webhook triggers dynamic 6-digit OTP to customer Gmail. | Customer enters OTP on mobile to verify and release funds. |
| **Tier 3: Hold** | `61 – 100` | Provisional hold; SecOps alert; admin desk review. | Screen says *"Transaction on Hold"*; admin can **Override & Approve** or **Decline**. |

---

## 📂 Repository Directory Structure

```
dhoka-detector/
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   │   └── explainer.py          # Grounded AI Explainer (read-only observer)
│   │   ├── api/
│   │   │   └── main.py               # FastAPI REST endpoints
│   │   ├── core/
│   │   │   ├── config.py             # Risk thresholds, weights & system configs
│   │   │   └── security.py           # Verification & token security manager
│   │   ├── database/
│   │   │   └── repository.py         # Thread-safe database persistence
│   │   ├── domain/
│   │   │   ├── audit.py              # SHA-256 Hash-Chained AuditBlock & Ledger
│   │   │   ├── customer.py           # CustomerProfile entity
│   │   │   └── transaction.py        # Transaction entity & status state-machine
│   │   └── engine/
│   │       ├── checks/               # 8 Polymorphic Risk Checks
│   │       ├── base_check.py         # Abstract RiskCheck base class
│   │       ├── policy.py             # DecisionPolicy thresholds
│   │       └── risk_engine.py        # Composite RiskEngine orchestrator
│   └── evaluation/
│       ├── benchmark.py              # 120-case simulation benchmark harness
│       └── simulator.py              # Synthetic telemetry & attack scenario generator
├── docs/
│   ├── screenshots/                  # Verified system execution screenshots (Fig 1–6)
│   └── DHOKA_DETECTOR_IOOP_FINAL_REPORT.pdf  # Comprehensive academic project report
├── frontend/
│   ├── dhoka_detector_portal.html    # All-in-one unified simulation portal
│   ├── customer/index.html           # Customer mobile banking interface
│   └── analyst/index.html            # SecOps Decision Desk & investigation dashboard
├── n8n/
│   ├── dhoka_detector_n8n_workflow.json  # Complete n8n webhook automation flow
│   └── README.md                     # n8n webhook setup & Gmail dispatch guide
├── tests/
│   ├── test_audit_integrity.py       # Cryptographic tamper detection tests
│   └── test_checks.py                # Unit tests for OOP polymorphic checks
├── dhoka_detector_main.py            # Single-entrypoint runner for portal & backend
├── requirements.txt                  # Python dependencies
└── README.md                         # Repository documentation
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10 or higher
- Modern web browser (Chrome, Edge, Firefox)

### 2. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/<your-username>/dhoka-detector.git
cd dhoka-detector
pip install -r requirements.txt
```

### 3. Launch the Complete Interactive Portal
Run the unified application with a single command:
```bash
python dhoka_detector_main.py
```
- Open `frontend/dhoka_detector_portal.html` in your browser.
- Perform transfers, view real-time risk scores, test the OTP challenge modal, and inspect the SecOps Decision Desk.

### 4. Run Unit Tests & Cryptographic Audit Verification
```bash
# Run all unit tests
pytest tests/

# Run the 120-scenario performance benchmark
python -m backend.evaluation.benchmark
```

*Benchmark Results on Synthetic Telemetry:*
- **Attack Recall**: `100.0%`
- **False Positive Rate**: `0.0%`
- **Average Decision Latency**: `< 0.20 ms`
- **Audit Ledger Integrity**: `100% Cryptographically Verified (SHA-256)`

---

## 🛡️ License
This project was developed for academic evaluation in the CS-2001 Object-Oriented Programming course at **FAST-NUCES**. All rights reserved.
