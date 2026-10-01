# Security Policy

This repository is a portfolio demonstration of a secure signing control plane. It is not a production cryptographic signing service.

## Security boundary

- The HSM integration is explicitly simulated.
- No private-key material is stored or exposed.
- Authentication uses JWT access tokens.
- Authorization is enforced server-side through role checks.
- Production approvals use separation of duties.
- Audit records use a chained SHA-256 integrity mechanism.
- Secrets must be supplied through environment variables and never committed.

## Production hardening still required

A production deployment would require managed database infrastructure, real HSM/KMS integration, secret management, TLS, immutable audit storage, centralized logging, monitoring, rate limiting, SSO/MFA and formal threat modelling.
