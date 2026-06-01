"""Members API integration tests — add, list, update role, remove, bulk, permissions."""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
MEMBER_USER = "members_test_user"
MEMBER_PASS = "MemberPass999!"
TS = "2025-01-01T00:00:00Z"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    r = module_client.post("/api/projects", json={"name": "Members Test", "added": TS, "status": "active"})
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    r = module_client.post("/api/admin/users", json={"username": MEMBER_USER, "password": MEMBER_PASS, "role": "user"})
    assert r.status_code in (201, 409), r.text
    if r.status_code == 201:
        _state["member_id"] = r.json()["id"]
    else:
        users = module_client.get("/api/admin/users").json()
        member = next((u for u in users if u["username"] == MEMBER_USER), None)
        assert member
        _state["member_id"] = member["id"]
    r2 = module_client.post("/api/admin/users", json={"username": "members_test_user2", "password": "Pass1234!xyz", "role": "user"})
    assert r2.status_code in (201, 409), f"create member2: {r2.status_code} {r2.text}"
    if r2.status_code == 201:
        _state["member2_id"] = r2.json()["id"]
    else:
        users = module_client.get("/api/admin/users").json()
        m2 = next((u for u in users if u["username"] == "members_test_user2"), None)
        assert m2, "members_test_user2 not found after 409"
        _state["member2_id"] = m2["id"]
    yield
    module_client.post("/api/auth/logout")


class TestListMembers:
    def test_list_members_empty(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/members")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_members_nonexistent_project_404(self, module_client: TestClient):
        r = module_client.get("/api/projects/prj_nonexistent/members")
        assert r.status_code == 404


class TestAddMember:
    def test_add_member_as_viewer(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/members", json={
            "user_id": _state["member_id"],
            "role": "viewer",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["role"] == "viewer"
        assert data["user_id"] == _state["member_id"]

    def test_list_members_contains_added(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/members")
        assert r.status_code == 200
        ids = [m["user_id"] for m in r.json()]
        assert _state["member_id"] in ids

    def test_add_nonexistent_user_404(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/members", json={
            "user_id": "usr_nonexistent",
            "role": "viewer",
        })
        assert r.status_code == 404

    def test_add_member_invalid_role_400(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/members", json={
            "user_id": _state["member_id"],
            "role": "super_invalid_role",
        })
        assert r.status_code == 400

    def test_readd_member_updates_role(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/members", json={
            "user_id": _state["member_id"],
            "role": "operator",
        })
        assert r.status_code == 201
        assert r.json()["role"] == "operator"


class TestUpdateMemberRole:
    def test_update_role_to_admin(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/members/{_state['member_id']}",
            json={"role": "admin"},
        )
        assert r.status_code == 200
        assert r.json()["role"] == "admin"

    def test_update_nonexistent_member_404(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/members/usr_nonexistent",
            json={"role": "viewer"},
        )
        assert r.status_code == 404

    def test_update_invalid_role_400(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/projects/{_state['pid']}/members/{_state['member_id']}",
            json={"role": "invalid_role"},
        )
        assert r.status_code == 400


class TestBulkAddMembers:
    def test_bulk_add_members(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/members/bulk", json={
            "user_ids": [_state["member_id"], _state["member2_id"]],
            "role": "viewer",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert len(data) >= 2

    def test_bulk_add_empty_list_400(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/members/bulk", json={
            "user_ids": [],
            "role": "viewer",
        })
        assert r.status_code == 400

    def test_bulk_add_invalid_role_400(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_state['pid']}/members/bulk", json={
            "user_ids": [_state["member_id"]],
            "role": "bad_role",
        })
        assert r.status_code == 400


class TestAvailableUsers:
    def test_list_available_users(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/available-users")
        assert r.status_code == 200
        users = r.json()
        member_ids = [u["id"] for u in users]
        assert _state["member_id"] not in member_ids


class TestRemoveMember:
    def test_remove_member(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_state['pid']}/members/{_state['member_id']}")
        assert r.status_code == 204

    def test_removed_member_not_in_list(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/members")
        assert r.status_code == 200
        ids = [m["user_id"] for m in r.json()]
        assert _state["member_id"] not in ids

    def test_remove_nonexistent_member_404(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_state['pid']}/members/usr_nonexistent")
        assert r.status_code == 404


class TestPermissions:
    def test_get_my_permissions(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/permissions/me")
        assert r.status_code == 200
        data = r.json()
        assert data["is_super_admin"] is True
        assert len(data["permissions"]) > 0

    def test_permissions_nonexistent_project_404(self, module_client: TestClient):
        r = module_client.get("/api/projects/prj_nonexistent/permissions/me")
        assert r.status_code == 404


class TestTransferOwnership:
    def test_transfer_ownership(self, module_client: TestClient):
        module_client.post(f"/api/projects/{_state['pid']}/members", json={
            "user_id": _state["member2_id"],
            "role": "admin",
        })
        r = module_client.post(f"/api/projects/{_state['pid']}/transfer-ownership", json={
            "user_id": _state["member2_id"],
        })
        assert r.status_code == 200
        module_client.post(f"/api/projects/{_state['pid']}/transfer-ownership", json={
            "user_id": _state["member2_id"],
        })
