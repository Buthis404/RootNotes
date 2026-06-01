"""Comprehensive tests for the timeline API endpoints."""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.utils import new_id, ts_now

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db: Session):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "TimelineTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    r = module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.3.3.3", "hostname": "tl-host",
        "os": "Linux", "status": "alive",
    })
    assert r.status_code == 201
    _state["hid"] = r.json()["id"]

    r = module_client.post("/api/findings", json={
        "pid": _state["pid"], "title": "TL Finding", "severity": "high", "ts": TS,
    })
    assert r.status_code == 201
    _state["fid"] = r.json()["id"]

    module_db.add(models.TimelineEvent(
        id=new_id("evt"), pid=_state["pid"], username="admin",
        entity="host", action="create", label="Bootstrap host", meta={}, ts=ts_now(),
    ))
    module_db.add(models.TimelineEvent(
        id=new_id("evt"), pid=_state["pid"], username="admin",
        entity="finding", action="create", label="Bootstrap finding", meta={}, ts=ts_now(),
    ))
    module_db.commit()
    yield
    module_client.post("/api/auth/logout")


def _make_event(db: Session, pid: str, meta: dict) -> str:
    eid = new_id("evt")
    db.add(models.TimelineEvent(
        id=eid, pid=pid, username="admin",
        entity="test", action="undo_test", label="undo test event",
        meta=meta, ts=ts_now(),
    ))
    db.commit()
    return eid


class TestGetTimeline:
    def test_list_by_pid(self, module_client: TestClient):
        r = module_client.get("/api/timeline", params={"pid": _state["pid"]})
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 2
        assert "X-Total-Count" in r.headers

    def test_filter_by_entity(self, module_client: TestClient):
        r = module_client.get("/api/timeline", params={"pid": _state["pid"], "entity": "finding"})
        assert r.status_code == 200
        for e in r.json():
            assert e["entity"] == "finding"

    def test_limit_and_offset(self, module_client: TestClient):
        r = module_client.get("/api/timeline", params={"pid": _state["pid"], "limit": 1, "offset": 0})
        assert r.status_code == 200
        assert len(r.json()) <= 1


class TestUndoEvent:
    def test_undo_patch_host_status(self, module_client: TestClient, module_db: Session):
        host = module_db.query(models.Host).filter(models.Host.id == _state["hid"]).first()
        host.status = "pwned"
        module_db.commit()

        meta = {
            "reversible": True,
            "undo": {
                "type": "patch",
                "entity": "host",
                "id": _state["hid"],
                "patch": {"status": "alive"},
            },
        }
        eid = _make_event(module_db, _state["pid"], meta)
        _state["undo_evt_id"] = eid

        r = module_client.post(f"/api/timeline/{eid}/undo")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["undo_type"] == "patch"

        module_db.refresh(host)
        assert host.status == "alive"

    def test_undo_already_undone(self, module_client: TestClient):
        r = module_client.post(f"/api/timeline/{_state['undo_evt_id']}/undo")
        assert r.status_code == 400

    def test_undo_nonexistent_event(self, module_client: TestClient):
        r = module_client.post("/api/timeline/evtnonexistent/undo")
        assert r.status_code == 404

    def test_undo_non_reversible_event(self, module_client: TestClient, module_db: Session):
        eid = _make_event(module_db, _state["pid"], {})
        r = module_client.post(f"/api/timeline/{eid}/undo")
        assert r.status_code == 400

    def test_undo_delete_host_activity(self, module_client: TestClient, module_db: Session):
        act = models.HostActivity(
            id=new_id("ha"), pid=_state["pid"], host_id=_state["hid"],
            title="To undo-delete", activity_type="recon", ts=TS,
        )
        module_db.add(act)
        module_db.commit()
        act_id = act.id

        meta = {
            "reversible": True,
            "undo": {
                "type": "delete",
                "entity": "host_activity",
                "id": act_id,
            },
        }
        eid = _make_event(module_db, _state["pid"], meta)

        r = module_client.post(f"/api/timeline/{eid}/undo")
        assert r.status_code == 200
        assert r.json()["ok"] is True

        assert module_db.query(models.HostActivity).filter(models.HostActivity.id == act_id).first() is None

    def test_undo_batch(self, module_client: TestClient, module_db: Session):
        act = models.HostActivity(
            id=new_id("ha"), pid=_state["pid"], host_id=_state["hid"],
            title="Batch target", activity_type="recon", ts=TS,
        )
        module_db.add(act)
        module_db.commit()
        act_id = act.id

        meta = {
            "reversible": True,
            "undo": {
                "type": "batch",
                "operations": [
                    {"type": "delete", "entity": "host_activity", "id": act_id},
                    {"type": "patch", "entity": "host", "id": _state["hid"], "patch": {"hostname": "tl-host"}},
                ],
            },
        }
        eid = _make_event(module_db, _state["pid"], meta)

        r = module_client.post(f"/api/timeline/{eid}/undo")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["operations_applied"] == 2

    def test_undo_unsupported_type(self, module_client: TestClient, module_db: Session):
        meta = {
            "reversible": True,
            "undo": {"type": "explode", "entity": "host", "id": "x"},
        }
        eid = _make_event(module_db, _state["pid"], meta)
        r = module_client.post(f"/api/timeline/{eid}/undo")
        assert r.status_code == 400
