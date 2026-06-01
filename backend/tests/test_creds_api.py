"""Comprehensive API tests for the credentials router."""

import pytest
from fastapi.testclient import TestClient

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    r = module_client.post(
        "/api/projects",
        json={"name": "Creds Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Creds Test Proj")
    yield


class TestCredCRUD:
    def test_create(self, module_client):
        r = module_client.post(
            "/api/creds",
            json={
                "pid": _state["pid"],
                "username": "svc_account",
                "secret": "SuperSecret123!",
                "type": "plain",
                "host": "10.0.0.5",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["username"] == "svc_account"
        assert data["secret"] == "SuperSecret123!"
        assert data["type"] == "plain"
        _state["cid"] = data["id"]

    def test_list(self, module_client):
        r = module_client.get("/api/creds", params={"pid": _state["pid"]})
        assert r.status_code == 200
        ids = [c["id"] for c in r.json()]
        assert _state["cid"] in ids

    def test_list_has_total_count(self, module_client):
        r = module_client.get("/api/creds", params={"pid": _state["pid"]})
        assert "x-total-count" in r.headers

    def test_update_username(self, module_client):
        r = module_client.patch(
            f"/api/creds/{_state['cid']}",
            json={"username": "updated_svc"},
        )
        assert r.status_code == 200
        assert r.json()["username"] == "updated_svc"

    def test_update_secret(self, module_client):
        r = module_client.patch(
            f"/api/creds/{_state['cid']}",
            json={"secret": "NewSecret456!"},
        )
        assert r.status_code == 200
        assert r.json()["secret"] == "NewSecret456!"

    def test_update_notes(self, module_client):
        r = module_client.patch(
            f"/api/creds/{_state['cid']}",
            json={"notes": "Found during post-exploitation"},
        )
        assert r.status_code == 200
        assert r.json()["notes"] == "Found during post-exploitation"

    def test_update_tags(self, module_client):
        r = module_client.patch(
            f"/api/creds/{_state['cid']}",
            json={"tags": ["admin", "domain"]},
        )
        assert r.status_code == 200
        assert r.json()["tags"] == ["admin", "domain"]

    def test_update_cracked_flag(self, module_client):
        r = module_client.patch(
            f"/api/creds/{_state['cid']}",
            json={"cracked": True},
        )
        assert r.status_code == 200
        assert r.json()["cracked"] is True

    def test_delete(self, module_client):
        r = module_client.delete(f"/api/creds/{_state['cid']}")
        assert r.status_code == 204
        r = module_client.get("/api/creds", params={"pid": _state["pid"]})
        ids = [c["id"] for c in r.json()]
        assert _state["cid"] not in ids


class TestCredTypes:
    def test_create_hash_cred(self, module_client):
        r = module_client.post(
            "/api/creds",
            json={
                "pid": _state["pid"],
                "username": "hashuser",
                "secret": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                "type": "ntlm",
            },
        )
        assert r.status_code == 201
        assert r.json()["type"] == "ntlm"

    def test_create_ticket_cred(self, module_client):
        r = module_client.post(
            "/api/creds",
            json={
                "pid": _state["pid"],
                "username": "ticketuser",
                "secret": "base64ticketdata==",
                "type": "ticket",
            },
        )
        assert r.status_code == 201
        assert r.json()["type"] == "ticket"

    def test_create_key_cred(self, module_client):
        r = module_client.post(
            "/api/creds",
            json={
                "pid": _state["pid"],
                "username": "keyuser",
                "secret": "ssh-rsa AAAA...",
                "type": "key",
            },
        )
        assert r.status_code == 201
        assert r.json()["type"] == "key"


class TestCredEdgeCases:
    def test_invalid_cred_type(self, module_client):
        r = module_client.post(
            "/api/creds",
            json={
                "pid": _state["pid"],
                "username": "badtype",
                "secret": "x",
                "type": "invalid_type",
            },
        )
        assert r.status_code in (422, 500)

    def test_update_nonexistent_returns_404(self, module_client):
        r = module_client.patch("/api/creds/nonexistent_c", json={"username": "x"})
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, module_client):
        r = module_client.delete("/api/creds/nonexistent_c")
        assert r.status_code == 404

    def test_create_without_secret(self, module_client):
        r = module_client.post(
            "/api/creds",
            json={
                "pid": _state["pid"],
                "username": "nosecret",
                "type": "plain",
            },
        )
        assert r.status_code == 201
        _state["cid2"] = r.json()["id"]

    def test_create_domain_cred_with_at_username(self, module_client):
        r = module_client.post(
            "/api/creds",
            json={
                "pid": _state["pid"],
                "username": "admin@corp.local",
                "secret": "domainpass",
                "type": "plain",
                "is_domain": True,
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["is_domain"] is True
