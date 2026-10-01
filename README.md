# PKI Control Plane

> Enterprise-style certificate lifecycle, secure code-signing, policy governance, RBAC and operational monitoring control plane.

![Status](https://img.shields.io/badge/status-active%20development-2563eb)
![Frontend](https://img.shields.io/badge/frontend-React-61DAFB)
![Backend](https://img.shields.io/badge/backend-Python%20%2F%20Flask-111827)
![Security](https://img.shields.io/badge/domain-PKI%20%26%20Secure%20Signing-10B981)

## Overview

PKI Control Plane is a security-engineering project exploring how **certificate lifecycle management, secure code signing, cryptographic policy, approval workflows, role-based access control, auditability and infrastructure health** can be brought together in one operational interface.

The project is intentionally designed as a **control-plane application**, not a static dashboard. Shared application state drives certificate inventory, requests, approvals, signing workflows, alerts, audit events and dashboard metrics so operational actions are reflected across the product.

> **Project status:** actively under development. This repository is a portfolio/reference implementation and is not intended to operate as a production Certificate Authority or real HSM service.

## Core capabilities

- Certificate request workflow with policy-validation and approval stages
- Certificate inventory with search, filtering, renewal and revocation flows
- Secure code-signing requests with approval/rejection lifecycle
- HSM / Key Vault operational visibility
- Crypto policies, compliance rules and trust configuration
- PKI trust hierarchy and certificate lifecycle analytics
- Security events, alerts and acknowledgement workflows
- System-health monitoring for API, database, HSM, signing and audit services
- Role-based access control and separation-of-duties modelling
- Searchable audit history and recent operational activity
- Persistent interactive state across routed application modules

## Application domains

| Domain | Modules |
|---|---|
| Certificate Management | New Request, My Requests, Certificates, Renewals, Revocation |
| Secure Signing | Signing Requests, My Signing Requests, HSM / Key Vault |
| Policy Management | Crypto Policies, Compliance Rules, Trust Configuration |
| Audit & Monitoring | Audit Logs, Events & Alerts, System Health |
| Identity & Access | Users, Roles & Permissions |
| Platform | Dashboard, global search, notifications, settings |

## Technology

**Frontend:** React, React Router, shared application state, responsive dark enterprise UI  
**Backend:** Python / Flask API foundation  
**Persistence:** SQL-backed service foundation plus persisted interactive demo state  
**Security concepts:** PKI, X.509 lifecycle, cryptographic policy, RBAC, separation of duties, audit logging, HSM / Key Vault abstractions

## Architecture

```text
Operators / Security Admins
          |
          v
   React Control Plane
          |
          v
 Shared Workflow State
          |
          v
      Python API
          |
          v
   SQL Persistence
```

The UI is **not** treated as a security boundary. A production implementation must enforce identity, authorization, policy and separation-of-duties controls server-side and keep private keys inside approved HSM/KMS boundaries.

## Local development

### Prerequisites

- Python 3.12+
- Node.js LTS / npm

### Backend

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

### Frontend

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local Vite URL shown in the terminal.

## Security scope

This project models enterprise PKI controls but deliberately does **not** claim production-grade cryptographic key custody. HSM and Key Vault behaviour is simulated for application-design and workflow demonstration.

No real private keys, production secrets or customer data belong in this repository.

See [SECURITY.md](SECURITY.md) for limitations and the intended security boundary.

## Engineering principles

- One source of truth for related operational data
- Explicit request/approval lifecycle states
- Requester/approver separation-of-duties concepts
- Auditable lifecycle operations
- No private-key exposure to the browser
- Observable health, latency and operational events
- Clear distinction between simulated infrastructure and production security controls

## Roadmap

Current development priorities include deeper server-side persistence, stronger policy enforcement, richer approval history, certificate operation APIs, improved HSM integration abstractions, automated testing and deployment hardening.

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Disclaimer

This is an independent educational/portfolio project. Product names such as Azure Key Vault are used only to describe integration concepts. The project is not affiliated with or endorsed by any employer or third-party vendor.

---

**Built to explore secure infrastructure engineering, PKI lifecycle automation and operational control-plane design.**
