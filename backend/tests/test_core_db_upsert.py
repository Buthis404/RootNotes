"""Unit tests for app.core.db_upsert race-safe upserts."""
import pytest
from unittest.mock import patch
from sqlalchemy.exc import IntegrityError

from app import models
from app.core import db_upsert as du
from app.core.db_upsert import upsert_host_by_ip, try_insert_or_get
from app.core.utils import new_id
from tests.conftest import *


def _make_project(db, **overrides):
    pid = new_id("prj")
    project = models.Project(
        id=pid,
        name="Test Project",
        status="active",
        ip="",
        os="Linux",
        added="2026-01-01T00:00:00Z",
        **overrides,
    )
    db.add(project)
    db.flush()
    return pid


@patch.object(du, "_has_index", return_value=False)
class TestUpsertHostByIp:
    def test_create_new_host(self, mock_idx, db):
        pid = _make_project(db)
        host, created = upsert_host_by_ip(
            db,
            pid=pid,
            ip="10.0.0.1",
            defaults={"hostname": "test-host", "os": "Linux"},
        )
        db.flush()
        assert created is True
        assert host.ip == "10.0.0.1"
        assert host.pid == pid

    def test_update_existing_host(self, mock_idx, db):
        pid = _make_project(db)
        upsert_host_by_ip(db, pid=pid, ip="10.0.0.1", defaults={"hostname": "old"})
        db.flush()
        host, created = upsert_host_by_ip(
            db,
            pid=pid,
            ip="10.0.0.1",
            defaults={"hostname": "old"},
            update_on_conflict={"hostname": "new"},
        )
        db.flush()
        assert created is False
        assert host.hostname == "new"

    def test_empty_ip_raises(self, mock_idx, db):
        pid = _make_project(db)
        with pytest.raises(ValueError):
            upsert_host_by_ip(db, pid=pid, ip="", defaults={})

    def test_whitespace_ip_stripped(self, mock_idx, db):
        pid = _make_project(db)
        host, created = upsert_host_by_ip(
            db, pid=pid, ip="  10.0.0.1  ", defaults={"hostname": "test"}
        )
        db.flush()
        assert created is True
        assert host.ip == "10.0.0.1"

    def test_different_projects_same_ip(self, mock_idx, db):
        pid1 = _make_project(db)
        pid2 = _make_project(db)
        h1, c1 = upsert_host_by_ip(db, pid=pid1, ip="10.0.0.1", defaults={"hostname": "h1"})
        db.flush()
        h2, c2 = upsert_host_by_ip(db, pid=pid2, ip="10.0.0.1", defaults={"hostname": "h2"})
        db.flush()
        assert c1 is True
        assert c2 is True
        assert h1.id != h2.id

    def test_custom_id(self, mock_idx, db):
        pid = _make_project(db)
        custom_id = "hstcustom1"
        host, created = upsert_host_by_ip(
            db, pid=pid, ip="10.0.0.1", defaults={"id": custom_id, "hostname": "test"}
        )
        db.flush()
        assert created is True
        assert host.id == custom_id

    def test_no_update_on_conflict(self, mock_idx, db):
        pid = _make_project(db)
        upsert_host_by_ip(db, pid=pid, ip="10.0.0.1", defaults={"hostname": "original"})
        db.flush()
        host, created = upsert_host_by_ip(
            db, pid=pid, ip="10.0.0.1", defaults={"hostname": "new-default"}
        )
        db.flush()
        assert created is False
        assert host.hostname == "original"


class TestTryInsertOrGet:
    def test_insert_new(self, db):
        pid = _make_project(db)
        new_host = models.Host(
            id=new_id("hst"), pid=pid, ip="10.0.0.1", hostname="test"
        )
        host, created = try_insert_or_get(
            db,
            new_host,
            lambda: db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == "10.0.0.1").first(),
        )
        assert created is True
        assert host.ip == "10.0.0.1"

    def test_conflict_returns_existing(self, db):
        pid = _make_project(db)
        existing = models.Host(
            id=new_id("hst"), pid=pid, ip="10.0.0.1", hostname="existing"
        )
        db.add(existing)
        db.flush()

        duplicate = models.Host(
            id=new_id("hst"), pid=pid, ip="10.0.0.1", hostname="duplicate"
        )
        host, created = try_insert_or_get(
            db,
            duplicate,
            lambda: db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == "10.0.0.1").first(),
        )
        assert created is False
        assert host.hostname == "existing"
