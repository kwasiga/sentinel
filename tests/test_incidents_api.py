from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


def test_detection_creates_incident_and_incident_can_be_triaged(monkeypatch) -> None:
    monkeypatch.setattr(settings, "PORT_SCAN_THRESHOLD", 3)

    with TestClient(app) as client:
        for port in [22, 80, 443]:
            response = client.post(
                "/events",
                json={
                    "event_type": "network.tcp.connection",
                    "actor": "workstation-17",
                    "source": "endpoint-agent",
                    "outcome": "refused",
                    "payload": {
                        "source_ip": "10.0.1.25",
                        "destination_ip": "10.0.2.10",
                        "destination_port": port,
                        "protocol": "tcp",
                    },
                },
            )
            assert response.status_code == 201

        list_response = client.get("/incidents")
        assert list_response.status_code == 200
        incidents = list_response.json()
        assert len(incidents) == 1

        incident = incidents[0]
        assert incident["title"] == "Possible TCP port scan"
        assert incident["severity"] == "high"
        assert incident["status"] == "open"
        assert incident["finding_id"]
        assert incident["evidence"]["ports"] == [22, 80, 443]

        get_response = client.get(f"/incidents/{incident['id']}")
        assert get_response.status_code == 200
        assert get_response.json()["id"] == incident["id"]

        patch_response = client.patch(f"/incidents/{incident['id']}", json={"status": "acknowledged"})
        assert patch_response.status_code == 200
        assert patch_response.json()["status"] == "acknowledged"


def test_incident_update_rejects_unknown_status() -> None:
    with TestClient(app) as client:
        response = client.patch("/incidents/missing", json={"status": "closed"})

    assert response.status_code == 422
