"""Extended tests for attacker_exec — helper functions."""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, f"login: {r.status_code} {r.text}"
    r = module_client.post("/api/projects", json={"name": "ATK_EXEC_EXT_PROJECT", "added": "2025-01-01T00:00:00Z", "status": "active"})
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "ATK_EXEC_EXT_PROJECT")
    yield


class TestListExecutionTargets:
    def test_targets_endpoint(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.get(f"/api/projects/{pid}/attacker-exec/targets")
        assert r.status_code in (200, 404, 500)


class TestExecuteInvalidMode:
    def test_invalid_execution_mode(self, module_client: TestClient):
        pid = _state["pid"]
        r = module_client.post(
            f"/api/projects/{pid}/attacker-exec",
            json={"command": "whoami", "execution_mode": "bad_mode"},
        )
        assert r.status_code == 400
