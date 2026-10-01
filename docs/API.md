# API Overview

Base path: /api/v1

Authentication: POST /auth/login, GET /auth/me

Signing workflow: GET /requests, POST /requests, GET /requests/{id}, POST /requests/{id}/security-approval, POST /requests/{id}/release-approval

Keys: GET /keys, GET /keys/{id}, POST /keys/{id}/lifecycle

HSM: GET /hsm

Policies: GET /policies, PUT /policies/{id}

Audit/evidence: GET /audit, POST /audit/verify, GET /evidence, GET /evidence/{id}/export/json, GET /evidence/{id}/export/pdf

Interactive OpenAPI documentation is available at /docs when the API is running.
