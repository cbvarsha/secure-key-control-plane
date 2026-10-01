# Architecture

## System flow

`User → React UI → FastAPI REST API → Domain Services → SQLAlchemy/SQLite`

Main workflow:

`Developer → Signing Request → Policy Validation → Security Approval → Release Approval (Production) → Simulated HSM → Evidence + Audit`

## Backend boundaries

- `app/api`: HTTP routes and endpoint orchestration.
- `app/models`: persistence entities.
- `app/schemas`: API contracts.
- `app/security`: JWT and password verification.
- `app/services/policy_engine.py`: environment-aware policy evaluation.
- `app/services/workflow_service.py`: request and approval state transitions.
- `app/services/audit_service.py`: SHA-256 chained audit entries.
- `app/services/simulated_hsm.py`: explicit non-production HSM simulation.
- `app/services/evidence_service.py`: evidence creation and exports.

## Security principles

1. Authorization is server-side.
2. Requesters cannot approve their own requests.
3. Production requires distinct Security and Release approval stages.
4. Private-key material is never stored or exposed.
5. Secrets are environment-only.
6. Audit records are chained to provide tamper evidence.

## Deployment

Docker Compose runs FastAPI on port 8000 and the React/Nginx frontend on port 3000. SQLite is persisted in a named Docker volume for local demonstration.
