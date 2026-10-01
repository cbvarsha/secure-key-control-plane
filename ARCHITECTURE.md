# Architecture

## Design goals

The PKI Control Plane is structured around four concerns: **lifecycle orchestration, policy governance, operational visibility and auditable access control**.

## Logical components

### Control-plane UI
Provides routed operational modules for certificates, signing, policy, trust, monitoring and access administration. Shared application state keeps mutations synchronized across related views.

### Python service layer
Provides the API boundary and SQL persistence foundation. PKI integrations can evolve behind stable service contracts.

### Security boundary
The UI is not a security boundary. Production authorization, policy enforcement and separation of duties must be enforced server-side. Private keys must never be exposed to the browser or ordinary application storage.

## Target production evolution

```text
Users / Operators
      |
Identity Provider + MFA
      |
React Control Plane
      |
API Gateway / AuthZ
      |
PKI Orchestration Services
  |       |        |
 CA     HSM/KMS   Audit Store
  |       |        |
Certificates   Signing Evidence
```

## Reliability principles

- Idempotent lifecycle operations
- Explicit approval states
- Tamper-resistant audit evidence
- No private-key export from the HSM/KMS boundary
- Observable service health and latency
- Separation between requester and approver roles
