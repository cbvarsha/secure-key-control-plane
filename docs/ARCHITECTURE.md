# Architecture

## Context

The Secure Key & Code-Signing Control Plane models the governance layer around software signing.

## Workflow

Developer → Signing Request → Pre-flight Policy Evaluation → Security Approval → Release Approval for Production → Simulated HSM Operation → Evidence → Audit Chain

## Components

- Frontend: React + TypeScript + Vite.
- API: FastAPI authenticated REST API.
- Domain services: policy engine, workflow, audit, evidence and Simulated HSM.
- Persistence: SQLAlchemy models with SQLite for local demonstration.
- Runtime: Docker Compose.

The browser is an untrusted client. Security-sensitive authorization is enforced by the backend.

## Audit

Each audit entry contains a previous hash and entry hash. Verification recomputes the sequence to detect historical modification. This provides tamper evidence, not immutable/WORM storage.
