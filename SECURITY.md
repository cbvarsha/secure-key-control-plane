# Security Policy

## Project classification

This repository is an educational/portfolio implementation of PKI control-plane concepts. It is **not a production Certificate Authority, signing service or HSM implementation**.

## Security principles demonstrated

- Role-based access control concepts
- Requester/approver separation of duties
- Certificate lifecycle state transitions
- Cryptographic policy modelling
- Audit-event generation
- HSM / Key Vault boundary modelling
- Operational alerting and service-health visibility

## Important limitations

The current implementation uses synthetic data and simulated infrastructure. Browser state and demo API endpoints must not be treated as security boundaries. Do not store real private keys, production certificates, credentials, customer data or secrets in this application.

A production implementation would require server-side authorization, authenticated identities, protected secrets, real HSM/KMS integrations, tamper-resistant audit logging, secure key ceremonies, rate limiting, hardened deployment, vulnerability management, backup/recovery and independent security review.

## Reporting

If you find a security issue in the project code, open a GitHub issue containing only non-sensitive reproduction details. Do not publish real credentials or secrets.
