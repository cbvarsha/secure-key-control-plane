# Engineering Runbook

## Start

```bash
docker compose up --build
```

## Stop

```bash
docker compose down
```

## Reset demo data

```bash
docker compose down -v
docker compose up --build
```

## URLs

- UI: `http://localhost:3000`
- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

## Backend tests

```bash
cd backend
pytest -q
```

## Frontend build

```bash
cd frontend
npm install
npm run build
```

## Demo users

All seeded users use the development-only password `Portfolio123!`. Do not reuse these credentials outside the local portfolio environment.

## Troubleshooting

If the dashboard shows no seeded data, remove the Docker volume with `docker compose down -v` and restart. If the frontend build fails, verify that the TypeScript target is ES2021 or newer and that `npm install` has completed.
