# Secure Key & Code-Signing Control Plane

Full-stack portfolio control plane for governed code-signing workflows.

## Stack
- FastAPI + SQLAlchemy + SQLite
- React + Vite + TypeScript
- Tailwind CSS + Recharts
- Docker Compose

## Security model
This portfolio uses a Simulated HSM. It does not store private keys or perform production cryptographic signing. Backend authorization and separation-of-duties controls are enforced server-side.

## Local run
```bash
docker compose up --build
```

Frontend: http://localhost:3000
Backend: http://localhost:8000
Swagger: http://localhost:8000/docs

## Tests
```bash
cd backend
pytest -q
```

The repository contains the Docker configuration and source archive used for the current project build.