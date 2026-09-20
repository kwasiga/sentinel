# Sentinel

Sentinel is a FastAPI-based foundation for a security event monitoring and incident response service.

The intended pipeline is:

```text
telemetry -> normalization -> detection -> risk scoring -> incident response
```

The project is currently an early scaffold. The `/health` endpoint is implemented; the telemetry adapters, detection engine, risk and response engines, persistence layer, and event/incident APIs are extension points for future work.

## Current status

Implemented today:

- FastAPI application with `GET /health`
- Basic application configuration via environment variables
- Docker image for local development
- Docker Compose services for PostgreSQL and Redis
- Initial package boundaries for telemetry, detection, risk, response, API, schemas, and models
- Health-check test

Not implemented yet:

- Event ingestion and normalization
- Authentication and authorization
- Database models, migrations, and repositories
- Detection rule execution and state management
- Risk scoring
- Incident creation, enrichment, and response actions
- Production security hardening and observability

## Quick start

### Run locally

Create a virtual environment, install dependencies, and start the API:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The service runs at `http://localhost:8000`.

Check that it is healthy:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status":"ok"}
```

FastAPI's interactive documentation is available at `http://localhost:8000/docs`.

### Start local dependencies

PostgreSQL and Redis are provided for local development:

```bash
docker compose up -d
```

The Compose defaults are:

| Service | Address | Default credentials |
| --- | --- | --- |
| PostgreSQL | `localhost:5432` | database `sentinel`, user `sentinel`, password `sentinel` |
| Redis | `localhost:6379` | none |

The application does not yet connect these services. Do not use the default credentials in a shared or production environment.

To stop the dependencies:

```bash
docker compose down
```

Add `-v` only when you intentionally want to remove the local PostgreSQL and Redis volumes.

## Configuration

Configuration is read from environment variables through `app.config.Settings`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | empty | Future SQLAlchemy/PostgreSQL connection URL |
| `REDIS_URL` | empty | Future Redis connection URL |

Example:

```bash
export DATABASE_URL='postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel'
export REDIS_URL='redis://localhost:6379/0'
```

## Development

Run the test suite with:

```bash
pytest
```

The repository currently contains a health-check test. Add tests alongside each implemented boundary, especially for parser behavior, detection windows, risk decisions, authorization, and response idempotency.

## Repository layout

```text
app/                  FastAPI application, configuration, API, schemas, and models
telemetry/            Authentication and CloudTrail adapters plus normalization
detection/            Detection engine, state, and detection rules
risk/                 Risk scoring engine
response/             Incident response engine
tests/                Automated tests
docs/                 Architecture, detection, and threat-model notes
Dockerfile            Container image definition
docker-compose.yml    Local PostgreSQL and Redis dependencies
```

## Planned architecture

1. **Ingest** security events from authentication systems and AWS CloudTrail.
2. **Normalize** provider-specific payloads into a common event model.
3. **Detect** suspicious behavior using stateful rules such as brute-force attempts, password spraying, and suspicious IAM activity.
4. **Score risk** using event context, rule confidence, asset/user criticality, and historical state.
5. **Create and manage incidents** with evidence, status, ownership, and audit history.
6. **Respond** through controlled, authenticated, and auditable actions.

The design notes in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/DETECTIONS.md`](docs/DETECTIONS.md), and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) are placeholders and should evolve with each implementation milestone.

## Security considerations

Before using Sentinel with real security telemetry, the project needs at least:

- Strong authentication and role-based authorization for all non-health endpoints
- Secret management instead of committed or default credentials
- Input validation, payload-size limits, and replay/duplication handling
- Tenant and data-access isolation, if the service is multi-tenant
- Encryption in transit and at rest where appropriate
- Structured audit logs for detections, incident changes, and response actions
- Safe, approval-aware response actions with idempotency and rollback procedures
- Retention, redaction, and access controls for sensitive event data

## License

No license has been selected for this repository yet.
