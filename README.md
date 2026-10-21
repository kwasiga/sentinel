# Sentinel

Sentinel is a security event monitoring and incident response service for collecting telemetry, detecting suspicious activity, scoring risk, and coordinating response work from a single API.

Sentinel will provide an end-to-end security operations pipeline:

```text
telemetry -> normalization -> detection -> risk scoring -> incident response
```

The goal is to make security events easier to trust, investigate, and act on. Sentinel ingests events from authentication systems, cloud audit logs, and network signals, normalizes them into a common model, evaluates them against detection rules, scores the resulting risk, and creates incident records with the evidence needed for response.

## Capabilities

Sentinel is designed to support:

- Security event ingestion through API endpoints and telemetry adapters
- Normalization of provider-specific payloads into a consistent event schema
- Stateful detection rules for patterns such as brute force attempts, password spraying, port scanning, and suspicious IAM behavior
- Durable detection findings with supporting evidence and timestamps
- Risk scoring based on rule severity, event context, user or asset criticality, and historical behavior
- Incident creation, enrichment, assignment, status tracking, and audit history
- Controlled response actions that are authenticated, idempotent, and reviewable
- Local development with FastAPI, PostgreSQL, Redis, SQLAlchemy, and Docker Compose

## System Overview

Sentinel is organized around five main responsibilities:

1. **Ingest** security events from authentication systems, cloud providers, and network sources.
2. **Normalize** raw telemetry into a common event shape that detection rules can evaluate consistently.
3. **Detect** suspicious behavior using stateful rules and configurable thresholds.
4. **Score** the risk of findings so response work can be prioritized.
5. **Respond** by creating incidents and coordinating approved follow-up actions.

The FastAPI application exposes the service boundary. SQLAlchemy models persist users, security events, detection findings, and incidents. Redis can be used for event fan-out so downstream workers and integrations can subscribe to the security event stream.

## Quick Start

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

FastAPI's interactive API documentation is available at `http://localhost:8000/docs`.

## Local Dependencies

PostgreSQL and Redis are available through Docker Compose:

```bash
docker compose up -d
```

The local defaults are:

| Service | Address | Default credentials |
| --- | --- | --- |
| PostgreSQL | `localhost:5432` | database `sentinel`, user `sentinel`, password `sentinel` |
| Redis | `localhost:6379` | none |

Use the PostgreSQL database by setting `DATABASE_URL`. Enable Redis event publishing by setting `REDIS_URL`.

```bash
export DATABASE_URL='postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel'
export REDIS_URL='redis://localhost:6379/0'
```

Do not use the default credentials in shared or production environments.

To stop local dependencies:

```bash
docker compose down
```

Add `-v` only when you intentionally want to remove the local PostgreSQL and Redis volumes.

## Authentication Bootstrap

Sentinel can create an initial local user at startup when bootstrap credentials are provided:

```bash
export AUTH_SECRET='replace-with-a-long-random-secret'
export BOOTSTRAP_USERNAME='admin'
export BOOTSTRAP_PASSWORD='replace-with-a-strong-password'
```

After starting the API, request an access token:

```bash
curl -X POST http://localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"replace-with-a-strong-password"}'
```

Each login attempt is recorded as an `authentication.login` security event. Failed login bursts are evaluated by detection rules and can produce detection findings when configured thresholds are crossed.

## Event Ingestion

Security events can be submitted to the ingestion API:

```bash
curl -X POST http://localhost:8000/events \
  -H 'Content-Type: application/json' \
  -d '{
    "event_type": "network.connection",
    "actor": "scanner",
    "source": "firewall",
    "outcome": "failure",
    "payload": {
      "source_ip": "203.0.113.10",
      "destination_port": 22
    }
  }'
```

In the complete system, ingestion will support multiple telemetry sources while preserving enough raw context for investigations and audit trails.

## Configuration

Configuration is read from environment variables through `app.config.Settings`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | in-memory SQLite | SQLAlchemy database connection URL; use PostgreSQL for deployed environments |
| `REDIS_URL` | empty | Redis connection URL; when set, security events are published to Redis Streams |
| `AUTH_SECRET` | development value | HMAC secret used to sign login tokens |
| `AUTH_TOKEN_TTL_SECONDS` | `3600` | Login-token lifetime |
| `BOOTSTRAP_USERNAME` | empty | Optional initial user created at startup |
| `BOOTSTRAP_PASSWORD` | empty | Password for the optional initial user |
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed logins required to trigger brute-force detection |
| `BRUTE_FORCE_WINDOW_SECONDS` | `60` | Sliding window for brute-force detection |
| `PORT_SCAN_THRESHOLD` | `10` | Distinct destination ports required to trigger port-scan detection |
| `PORT_SCAN_WINDOW_SECONDS` | `60` | Sliding window for port-scan detection |

## Development

Run the test suite from the repository root:

```bash
python3 -m pytest
```

Using `python3 -m pytest` keeps the repository root on Python's import path.

## Repository Layout

```text
app/                  FastAPI application, configuration, API routes, schemas, and models
telemetry/            Authentication and CloudTrail adapters plus normalization utilities
detection/            Detection engine, state management, and detection rules
risk/                 Risk scoring engine
response/             Incident response engine
tests/                Automated tests
docs/                 Architecture, detection, and threat-model notes
Dockerfile            Container image definition
docker-compose.yml    Local PostgreSQL and Redis dependencies
```

## Documentation

Additional design notes live in:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/DETECTIONS.md`](docs/DETECTIONS.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

## Security Expectations

Before Sentinel is used with real security telemetry, deployments should provide:

- Strong authentication and role-based authorization for all non-health endpoints
- Production secret management instead of default or committed credentials
- Input validation, payload-size limits, deduplication, and replay protection
- Tenant and data-access isolation where applicable
- Encryption in transit and at rest
- Structured audit logs for detections, incident updates, and response actions
- Approval-aware response actions with idempotency and rollback procedures
- Retention, redaction, and access controls for sensitive event data

## License

No license has been selected for this repository yet.
