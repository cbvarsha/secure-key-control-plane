# Secure Key & Code-Signing Control Plane — Project Guide

## Executive overview

This repository demonstrates an enterprise-style control plane for governed software code-signing operations. The focus is the surrounding governance: identity, RBAC, policy validation, separation of duties, approvals, logical key lifecycle, evidence, audit integrity and operational monitoring.

## Core workflow

Developer → Signing Request → Policy Validation → Security Approval → Release Approval (Production) → Simulated HSM → Evidence + Audit

## Architecture

- Frontend: React + TypeScript + Vite + Tailwind.
- API: FastAPI with JWT authentication.
- Domain services: policy engine, workflow service, audit service, evidence service and Simulated HSM.
- Persistence: SQLAlchemy with SQLite for local demonstration.
- Runtime: Docker Compose.

## Security controls

### Policy validation

The backend checks requester role, artifact type, key state, key expiry, algorithm and key/environment compatibility.

### Separation of duties

The requester cannot approve their own signing request. Production uses separate Security and Release approval stages.

### Audit integrity

Each audit record includes a previous hash and entry hash. Chain verification recomputes the sequence and detects historical changes.

### HSM boundary

The HSM is simulated. No private-key material is stored or exposed. Generated signatures are simulation metadata only.

## Evidence

Evidence records capture artifact metadata, policy results, approvals, timestamps, logical key information, HSM operation references and an evidence hash. The backend supports JSON and PDF evidence export.

## UI

The control plane contains Dashboard, Signing Requests, Request Detail, Approvals, Keys & Certificates, HSM / Key Vault, Policies, Audit & Evidence, Monitoring, Users & Roles and Settings.

## Repository standards

The repository includes README and architecture documentation, an engineering runbook, security policy, contribution guidelines, code of conduct, CI workflow, pull-request template, automated backend control tests and explicit non-production boundaries.

## Local run

Run: docker compose up --build

Frontend: http://localhost:3000
API: http://localhost:8000
Swagger: http://localhost:8000/docs

## Non-production boundary

This is a portfolio demonstration. It does not provide production HSM integration, private-key custody, immutable/WORM audit storage or production cryptographic signing.
