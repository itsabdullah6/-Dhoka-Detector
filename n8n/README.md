# 🛡️ Dhoka Detector — n8n Automated Email Notification Engine

## What This Workflow Does

This n8n workflow listens for webhooks from the Python OOP engine (or standalone portal) and **automatically dispatches institutional banking Gmail emails**:

| Event Type | Recipient | Email Theme & Content |
|---|---|---|
| `CUSTOMER_OTP_CHALLENGE` | Customer Registered Email | Clean 6-digit OTP verification code with 3-minute validity timer |
| `CUSTOMER_HOLD_NOTICE` | Customer Registered Email | Professional banking notice: Transfer paused for routine compliance verification |
| `CUSTOMER_APPROVED_NOTICE` | Customer Registered Email | Official clearance notice: Transfer approved & funds released by Bank Compliance |
| `CUSTOMER_DECLINED_NOTICE` | Customer Registered Email | Safety notice: Transfer declined by compliance; zero funds deducted from balance |
| `CRITICAL_FRAUD_BLOCK` | SecOps Admin Email | High-visibility SecOps Incident Report with threat vector, risk score & audit block |

## Key Banking UX Policy

> **Anti-Tipping Off Banking Standard**:
> When a transaction is flagged for high risk or hard block (such as an unauthorized device, deep night velocity surge, or mule IBAN), **the customer is NEVER shown "Declined" immediately**.
> Instead, their banking app displays **"Transaction on Hold"** and they receive the `CUSTOMER_HOLD_NOTICE` email.
> The transaction enters the **Security Investigation & Decision Desk** on the admin portal. Only when the Compliance Officer confirms the decline does the customer receive `CUSTOMER_DECLINED_NOTICE`, or if overridden, `CUSTOMER_APPROVED_NOTICE`.

---

## Import & Setup Steps

1. Start n8n (e.g. via Docker: `docker start n8n` or `docker run -d --name n8n -p 5678:5678 -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n`).
2. Open **http://localhost:5678**.
3. In n8n, click **"Workflows"** → **"Import from File"**.
4. Select `n8n/dhoka_detector_n8n_workflow.json`.
5. Select your Gmail OAuth2 credential on the email send nodes.
6. Toggle the workflow switch in the top right to **ACTIVE**.
7. Ready! Webhook is live at `http://localhost:5678/webhook/dhoka-fraud-alert`.

---

## Webhook Routing Topology

```
Webhook POST /dhoka-fraud-alert
        ↓
   Is OTP Event?
     ├─ [Yes] ──► Customer OTP Email (Clean 6-digit code)
     └─ [No]  ──► Is Hold Event?
                    ├─ [Yes] ──► Customer Hold Notice Email (Paused for Review)
                    └─ [No]  ──► Is Approved Event?
                                   ├─ [Yes] ──► Customer Approved Email (Released)
                                   └─ [No]  ──► Is Declined Event?
                                                  ├─ [Yes] ──► Customer Declined Email (Safe decline)
                                                  └─ [No]  ──► SecOps Admin Alert (Incident Report)
```
