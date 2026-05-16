"""Integration tests for job API endpoints (filter, retry, rerun)."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.utils import new_id
from app.core.job_tracker import queue_job, finish_job


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _setup_and_login(client: TestClient) -> dict:
    """Return auth headers for an admin user, creating one if needed.

    Login (B1-1) sets an httpOnly cookie instead of returning a token in
    the body. The auth middleware accepts either the cookie OR an
    Authorization Bearer header, so we extract the token from the cookie
    and surface it as a header for tests that pass `headers=auth`.
    """
    client.post("/api/auth/setup", json={"username": "admin", "password": "testpass"})
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "testpass"})
    assert resp.status_code == 200, resp.text
    from app.core.config import COOKIE_NAME
    token = resp.cookies.get(COOKIE_NAME, "")
    assert token, f"No '{COOKIE_NAME}' cookie set on login response. Cookies: {dict(resp.cookies)}"
    # Drop the persistent cookie jar — tests pass auth explicitly via the
    # returned Authorization header so that requests without `headers=auth`
    # are genuinely unauthenticated (e.g. test_unauthenticated_returns_401).
    client.cookies.clear()
    return {"Authorization": f"Bearer {token}"}


def _create_project(client: TestClient, headers: dict) -> str:
    resp = client.post("/api/projects", json={"name": "Test Project", "ip": "", "added": "2024-01-01"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def auth(client: TestClient):
    return _setup_and_login(client)


@pytest.fixture()
def pid(client: TestClient, auth: dict) -> str:
    return _create_project(client, auth)


@pytest.fixture()
def queued_job(db: Session, pid: str) -> models.Job:
    return queue_job(db, pid, "nmap", "Nmap Scan",
                     connector_key="nmap", operation="scan",
                     request_json={"target": "10.0.0.1"})


@pytest.fixture()
def done_job(db: Session, pid: str) -> models.Job:
    job = queue_job(db, pid, "nmap", "Nmap Done",
                    connector_key="nmap", operation="scan",
                    request_json={"target": "10.0.0.2"})
    return finish_job(db, job, status="done", output="results", result={"hosts_found": 3})


@pytest.fixture()
def failed_job(db: Session, pid: str) -> models.Job:
    job = queue_job(db, pid, "nmap", "Nmap Failed",
                    connector_key="nmap", operation="scan",
                    request_json={"target": "10.0.0.3"})
    return finish_job(db, job, status="failed", error_output="timeout")


@pytest.fixture()
def cancelled_job(db: Session, pid: str) -> models.Job:
    job = queue_job(db, pid, "cme", "CME Scan",
                    connector_key="netexec", operation="scan",
                    request_json={"target": "10.0.0.4"})
    return finish_job(db, job, status="cancelled")


# ---------------------------------------------------------------------------
# List / filter tests
# ---------------------------------------------------------------------------

class TestListJobs:
    def test_list_returns_jobs(self, client: TestClient, auth: dict, pid: str, done_job: models.Job):
        resp = client.get(f"/api/projects/{pid}/jobs", headers=auth)
        assert resp.status_code == 200
        ids = [j["id"] for j in resp.json()]
        assert done_job.id in ids

    def test_filter_by_status_done(self, client: TestClient, auth: dict, pid: str, done_job: models.Job, failed_job: models.Job):
        resp = client.get(f"/api/projects/{pid}/jobs?status=done", headers=auth)
        assert resp.status_code == 200
        statuses = {j["status"] for j in resp.json()}
        assert statuses == {"done"}

    def test_filter_by_status_failed(self, client: TestClient, auth: dict, pid: str, done_job: models.Job, failed_job: models.Job):
        resp = client.get(f"/api/projects/{pid}/jobs?status=failed", headers=auth)
        assert resp.status_code == 200
        assert all(j["status"] == "failed" for j in resp.json())

    def test_filter_by_connector_key(self, client: TestClient, auth: dict, pid: str, done_job: models.Job, cancelled_job: models.Job):
        resp = client.get(f"/api/projects/{pid}/jobs?connector_key=nmap", headers=auth)
        assert resp.status_code == 200
        assert all(j["connector_key"] == "nmap" for j in resp.json())

    def test_filter_by_type(self, client: TestClient, auth: dict, pid: str, done_job: models.Job, cancelled_job: models.Job):
        resp = client.get(f"/api/projects/{pid}/jobs?type=nmap", headers=auth)
        assert resp.status_code == 200
        assert all(j["type"] == "nmap" for j in resp.json())

    def test_filter_by_playbook_run_id(self, client: TestClient, auth: dict, pid: str, db: Session):
        run_id = "pbr_testrun001"
        job = queue_job(db, pid, "nmap", "Playbook Job",
                        connector_key="nmap", operation="scan",
                        request_json={"target": "10.1.1.1", "playbook_run_id": run_id})
        other = queue_job(db, pid, "nmap", "Unrelated Job",
                          connector_key="nmap", operation="scan",
                          request_json={"target": "10.1.1.2"})
        resp = client.get(f"/api/projects/{pid}/jobs?playbook_run_id={run_id}", headers=auth)
        assert resp.status_code == 200
        ids = [j["id"] for j in resp.json()]
        assert job.id in ids
        assert other.id not in ids

    def test_limit_param(self, client: TestClient, auth: dict, pid: str, db: Session):
        for i in range(5):
            queue_job(db, pid, "nmap", f"Job {i}", connector_key="nmap", operation="scan",
                      request_json={"target": f"10.0.{i}.1"})
        resp = client.get(f"/api/projects/{pid}/jobs?limit=2", headers=auth)
        assert resp.status_code == 200
        assert len(resp.json()) <= 2

    def test_unknown_project_returns_empty_for_admin(self, client: TestClient, auth: dict):
        """Global admin bypasses project membership checks (access.py::_evaluate),
        so a nonexistent project just yields an empty job list rather than 404.
        For a non-admin user the membership check would 404 — covered in
        test_access.py::TestMembershipRequired."""
        resp = client.get("/api/projects/nonexistent/jobs", headers=auth)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_unauthenticated_returns_401(self, client: TestClient, pid: str):
        resp = client.get(f"/api/projects/{pid}/jobs")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------

class TestCancelJob:
    def test_cancel_queued_job(self, client: TestClient, auth: dict, pid: str, queued_job: models.Job):
        resp = client.patch(f"/api/projects/{pid}/jobs/{queued_job.id}/cancel", headers=auth)
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    def test_cancel_terminal_job_error(self, client: TestClient, auth: dict, pid: str, done_job: models.Job):
        resp = client.patch(f"/api/projects/{pid}/jobs/{done_job.id}/cancel", headers=auth)
        assert resp.status_code == 400

    def test_cancel_nonexistent(self, client: TestClient, auth: dict, pid: str):
        resp = client.patch(f"/api/projects/{pid}/jobs/job_missing/cancel", headers=auth)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------

class TestRetryJob:
    def test_retry_failed_job(self, client: TestClient, auth: dict, pid: str, failed_job: models.Job):
        resp = client.post(f"/api/projects/{pid}/jobs/{failed_job.id}/retry", headers=auth)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "queued"
        assert data["retry_of_job_id"] == failed_job.id

    def test_retry_cancelled_job(self, client: TestClient, auth: dict, pid: str, cancelled_job: models.Job):
        resp = client.post(f"/api/projects/{pid}/jobs/{cancelled_job.id}/retry", headers=auth)
        assert resp.status_code == 201
        assert resp.json()["retry_of_job_id"] == cancelled_job.id

    def test_retry_done_job_rejected(self, client: TestClient, auth: dict, pid: str, done_job: models.Job):
        resp = client.post(f"/api/projects/{pid}/jobs/{done_job.id}/retry", headers=auth)
        assert resp.status_code == 400

    def test_retry_queued_job_rejected(self, client: TestClient, auth: dict, pid: str, queued_job: models.Job):
        resp = client.post(f"/api/projects/{pid}/jobs/{queued_job.id}/retry", headers=auth)
        assert resp.status_code == 400

    def test_retry_nonexistent(self, client: TestClient, auth: dict, pid: str):
        resp = client.post(f"/api/projects/{pid}/jobs/job_missing/retry", headers=auth)
        assert resp.status_code == 404

    def test_retry_without_request_json_rejected(self, client: TestClient, auth: dict, pid: str, db: Session):
        job = queue_job(db, pid, "nmap", "No payload",
                        connector_key="nmap", operation="scan",
                        request_json={})
        finish_job(db, job, status="failed")
        resp = client.post(f"/api/projects/{pid}/jobs/{job.id}/retry", headers=auth)
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Rerun
# ---------------------------------------------------------------------------

class TestRerunJob:
    def test_rerun_done_job(self, client: TestClient, auth: dict, pid: str, done_job: models.Job):
        resp = client.post(f"/api/projects/{pid}/jobs/{done_job.id}/rerun", headers=auth)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "queued"
        assert data["id"] != done_job.id

    def test_rerun_active_job_rejected(self, client: TestClient, auth: dict, pid: str, queued_job: models.Job):
        resp = client.post(f"/api/projects/{pid}/jobs/{queued_job.id}/rerun", headers=auth)
        assert resp.status_code == 400

    def test_rerun_creates_independent_job(self, client: TestClient, auth: dict, pid: str, done_job: models.Job):
        resp = client.post(f"/api/projects/{pid}/jobs/{done_job.id}/rerun", headers=auth)
        assert resp.status_code == 201
        assert resp.json()["retry_of_job_id"] in ("", None)


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

class TestDeleteJob:
    def test_delete_job(self, client: TestClient, auth: dict, pid: str, done_job: models.Job):
        resp = client.delete(f"/api/projects/{pid}/jobs/{done_job.id}", headers=auth)
        assert resp.status_code == 204

    def test_deleted_job_not_found(self, client: TestClient, auth: dict, pid: str, done_job: models.Job):
        client.delete(f"/api/projects/{pid}/jobs/{done_job.id}", headers=auth)
        resp = client.get(f"/api/projects/{pid}/jobs/{done_job.id}", headers=auth)
        assert resp.status_code == 404

    def test_delete_nonexistent(self, client: TestClient, auth: dict, pid: str):
        resp = client.delete(f"/api/projects/{pid}/jobs/job_missing", headers=auth)
        assert resp.status_code == 404
