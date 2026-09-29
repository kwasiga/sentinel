from fastapi.testclient import TestClient

from app.main import app


def test_ingest_network_tcp_event() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/events",
            json={
                "event_type": "network.tcp.connection",
                "actor": "workstation-17",
                "source": "endpoint-agent",
                "outcome": "success",
                "payload": {
                    "source_ip": "10.0.1.25",
                    "source_port": 53144,
                    "destination_ip": "10.0.2.10",
                    "destination_port": 22,
                    "protocol": "tcp",
                    "direction": "outbound",
                    "socket_state": "connected",
                    "bytes_sent": 1280,
                    "bytes_received": 4096,
                },
            },
        )

    assert response.status_code == 201
    body = response.json()
    assert body["id"]
    assert body["event_type"] == "network.tcp.connection"
    assert body["actor"] == "workstation-17"
    assert body["source"] == "endpoint-agent"
    assert body["outcome"] == "success"
    assert body["payload"]["destination_port"] == 22
    assert body["created_at"]


def test_ingest_event_requires_core_fields() -> None:
    response = TestClient(app).post("/events", json={"payload": {}})

    assert response.status_code == 422
