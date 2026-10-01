# Secure Key & Code-Signing Control Plane — Workflow Architecture

## System flow

```mermaid
flowchart TD
 U["Users / Role Personas"] --> UI["React Control Plane"]
 UI --> API["Backend API"]
 API --> AUTH["Authentication & RBAC"]
 API --> WF["Signing Workflow Service"]
 WF --> SOD["Approval / SoD Controls"]
 WF --> POL["Cryptographic Policy Engine"]
 WF --> HSM["Simulated HSM / KMS Boundary"]
 WF --> EV["Evidence Service"]
 AUTH --> DB[("SQL Persistence")]
 SOD --> DB
 POL --> DB
 EV --> DB
 HSM --> DB
 API --> AUD["Audit Hash Chain"]
 API --> MON["Monitoring Aggregations"]
 AUD --> DB
 MON --> DB
```

## Secure signing workflow

```mermaid
sequenceDiagram
 participant R as Requester
 participant P as Policy Engine
 participant A as Approver
 participant H as HSM/KMS
 participant E as Evidence Store
 R->>P: Submit artifact + signing profile
 P->>P: Validate policy and environment
 P->>A: Create approval task
 A->>A: Enforce separation of duties
 A->>H: Authorize signing operation
 H-->>A: Signature metadata
 A->>E: Persist approval + signing evidence
 E-->>R: Evidence reference / status
```

## Security boundary

Private keys are modelled as non-exportable assets behind the HSM/KMS boundary. Production authorization, cryptographic policy and separation-of-duties controls must be enforced server-side; the browser is not a trusted security boundary.
