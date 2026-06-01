"""Comprehensive tests for the MITRE coverage API endpoint."""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "MitreTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    r = module_client.post("/api/kb/seed/mitre")
    assert r.status_code == 200
    yield
    module_client.post("/api/auth/logout")


class TestMitreCoverage:
    def test_coverage_returns_structure(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/mitre/coverage")
        assert r.status_code == 200
        data = r.json()
        assert "techniques" in data
        assert "tactic_order" in data
        assert "stats" in data
        assert "kb_seeded" in data

    def test_coverage_has_tactics(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/mitre/coverage")
        data = r.json()
        assert len(data["tactic_order"]) > 0
        assert "Reconnaissance" in data["tactic_order"]

    def test_coverage_stats(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/mitre/coverage")
        data = r.json()
        stats = data["stats"]
        assert "total_techniques" in stats
        assert "covered" in stats
        assert "steps_total" in stats

    def test_coverage_techniques_structure(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/mitre/coverage")
        data = r.json()
        if data["techniques"]:
            tech = data["techniques"][0]
            assert "id" in tech
            assert "tactic" in tech
            assert "name" in tech
            assert "used" in tech

    def test_coverage_unmapped(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/mitre/coverage")
        data = r.json()
        assert "unmapped" in data
        assert isinstance(data["unmapped"], list)
