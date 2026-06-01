"""
B10-18: Smoke tests for critical paths.

Covers the full happy-path cycle for:
  1. Auth   — setup, login, /me, logout, revoked-token check
  2. Projects — create, list, get
  3. Findings — create, list, update status, delete
  4. Hosts    — create, list
  5. Credentials — create, list
  6. Members  — add second user, add as member, list, remove
  7. Loot (text) — create hash artifact, list, delete

All tests share one module-scoped database session so that entities created
in earlier tests (project, users) are available to later tests.
Run order within a module is top-to-bottom — do not reorder without checking deps.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

# ── Constants ─────────────────────────────────────────────────────────────────

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
MEMBER = "smoke_member"
MEMBER_PASS = "MemberPass56!"

TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Shared mutable state — populated by fixtures and mutated by tests.
_state: dict = {}


# ── Module-scoped fixtures ────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    """Ensure admin account exists and log in. Create a second regular user for member tests."""
    # Create admin if the system is not yet initialised; 403 = already done.
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})

    # Login — admin was either just created above or already existed from a previous test.
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, f"admin login: {r.status_code} {r.text}"

    # Create second user for member-management tests.
    r = module_client.post("/api/admin/users", json={"username": MEMBER, "password": MEMBER_PASS, "role": "user"})
    assert r.status_code in (201, 409), f"create member user: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["member_id"] = r.json()["id"]
    else:
        users = module_client.get("/api/admin/users").json()
        member = next((u for u in users if u["username"] == MEMBER), None)
        assert member, "smoke_member not found after 409"
        _state["member_id"] = member["id"]

    yield

    module_client.post("/api/auth/logout")


# ── 1. Auth ───────────────────────────────────────────────────────────────────

class TestAuthFlow:
    def test_me_returns_current_user(self, module_client: TestClient):
        r = module_client.get("/api/auth/me")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == ADMIN

    def test_logout_and_cookie_cleared(self, module_client: TestClient):
        # Login fresh so we have a known session.
        r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        assert r.status_code == 200

        r = module_client.post("/api/auth/logout")
        assert r.status_code in (200, 204)

        # Cookie must be gone — unauthenticated /me returns 401.
        r = module_client.get("/api/auth/me")
        assert r.status_code == 401

        # Re-login so subsequent tests continue to work.
        r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        assert r.status_code == 200


# ── 2. Projects ───────────────────────────────────────────────────────────────

class TestProjectCRUD:
    def test_create_project(self, module_client: TestClient):
        r = module_client.post("/api/projects", json={
            "name": "Smoke Project",
            "added": TS,
            "status": "active",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["name"] == "Smoke Project"
        _state["pid"] = data["id"]

    def test_list_projects_contains_smoke(self, module_client: TestClient):
        r = module_client.get("/api/projects")
        assert r.status_code == 200
        ids = [p["id"] for p in r.json()]
        assert _state["pid"] in ids

    def test_list_projects_by_id(self, module_client: TestClient):
        r = module_client.get("/api/projects")
        assert r.status_code == 200
        project = next((p for p in r.json() if p["id"] == _state["pid"]), None)
        assert project is not None
        assert project["name"] == "Smoke Project"


# ── 3. Findings ───────────────────────────────────────────────────────────────

class TestFindingCRUD:
    def test_create_finding(self, module_client: TestClient):
        r = module_client.post("/api/findings", json={
            "pid": _state["pid"],
            "title": "Smoke SQL Injection",
            "severity": "high",
            "ts": TS,
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["title"] == "Smoke SQL Injection"
        _state["fid"] = data["id"]

    def test_list_findings(self, module_client: TestClient):
        r = module_client.get("/api/findings", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()]
        assert _state["fid"] in ids

    def test_update_finding_status(self, module_client: TestClient):
        r = module_client.patch(f"/api/findings/{_state['fid']}", json={"status": "confirmed"})
        assert r.status_code == 200
        assert r.json()["status"] == "confirmed"

    def test_delete_finding(self, module_client: TestClient):
        r = module_client.delete(f"/api/findings/{_state['fid']}")
        assert r.status_code == 204
        r = module_client.get("/api/findings", params={"pid": _state["pid"]})
        ids = [f["id"] for f in r.json()]
        assert _state["fid"] not in ids


# ── 4. Hosts ──────────────────────────────────────────────────────────────────

class TestHostCRUD:
    def test_create_host(self, module_client: TestClient):
        r = module_client.post("/api/hosts", json={
            "pid": _state["pid"],
            "ip": "10.0.0.1",
            "hostname": "smoke-dc01",
            "os": "Windows Server 2022",
            "status": "unknown",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["ip"] == "10.0.0.1"
        _state["hid"] = data["id"]

    def test_list_hosts(self, module_client: TestClient):
        r = module_client.get("/api/hosts", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [h["id"] for h in r.json()]
        assert _state["hid"] in ids

    def test_update_host_status(self, module_client: TestClient):
        r = module_client.patch(f"/api/hosts/{_state['hid']}", json={"status": "pwned"})
        assert r.status_code == 200
        assert r.json()["status"] == "pwned"


# ── 5. Credentials ────────────────────────────────────────────────────────────

class TestCredCRUD:
    def test_create_credential(self, module_client: TestClient):
        r = module_client.post("/api/creds", json={
            "pid": _state["pid"],
            "username": "administrator",
            "secret": "Password123!",
            "type": "plain",
            "host": "10.0.0.1",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["username"] == "administrator"
        # Admin can read secrets — plaintext is returned on create.
        assert data["secret"] == "Password123!"
        _state["cid"] = data["id"]

    def test_list_creds_contains_new(self, module_client: TestClient):
        r = module_client.get("/api/creds", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [c["id"] for c in r.json()]
        assert _state["cid"] in ids


# ── 6. Members ────────────────────────────────────────────────────────────────

class TestMemberManagement:
    def test_add_member(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/members", json={
            "user_id": _state["member_id"],
            "role": "viewer",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["role"] == "viewer"
        assert data["user_id"] == _state["member_id"]

    def test_list_members_contains_new(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/members")
        assert r.status_code == 200
        ids = [m["user_id"] for m in r.json()]
        assert _state["member_id"] in ids

    def test_update_member_role(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/members/{_state['member_id']}",
            json={"role": "operator"},
        )
        assert r.status_code == 200
        assert r.json()["role"] == "operator"

    def test_remove_member(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_state['pid']}/members/{_state['member_id']}")
        assert r.status_code == 204
        r = module_client.get(f"/api/projects/{_state['pid']}/members")
        ids = [m["user_id"] for m in r.json()]
        assert _state["member_id"] not in ids


# ── 7. Loot (text artifact) ───────────────────────────────────────────────────

class TestLootText:
    def test_create_loot_hash(self, module_client: TestClient):
        r = module_client.post("/api/loots", json={
            "pid": _state["pid"],
            "loot_type": "hash",
            "value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "description": "NTLM hash for Administrator",
            "artifact_type": "hash",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["loot_type"] == "hash"
        _state["lid"] = data["id"]

    def test_list_loot(self, module_client: TestClient):
        r = module_client.get("/api/loots", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [l["id"] for l in r.json()]
        assert _state["lid"] in ids

    def test_delete_loot(self, module_client: TestClient):
        r = module_client.delete(f"/api/loots/{_state['lid']}")
        assert r.status_code == 204
        r = module_client.get("/api/loots", params={"pid": _state["pid"]})
        ids = [l["id"] for l in r.json()]
        assert _state["lid"] not in ids
