# Runbook

## Start

```bash
docker compose up --build
```

Frontend: http://localhost:3000  
API: http://localhost:8000  
Swagger: http://localhost:8000/docs

## Backend checks

```bash
cd backend
python -m compileall -q app
pytest -q
```

## Frontend checks

```bash
cd frontend
npm install
npm run build
```

## Port conflict

```bash
docker ps
docker stop <conflicting-container>
docker compose up --build
```

## Stale frontend image

```bash
docker compose down
docker compose build --no-cache frontend
docker compose up -d
```
