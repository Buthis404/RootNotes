"""Tests for app.core.job_tracker — job lifecycle helpers."""

import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.orm import Session

from app import models
from app.core.job_tracker import _job_dict, start_job, queue_job, mark_job_running, finish_job
from app.core.utils import new_id


@pytest.fixture()
def pid(db: Session) -> str:
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="Test Project", added="2024-01-01"))
    db.commit()
    return p_id


class TestJobDict:
    def test_serializes_job(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test", connector_key="nmap", operation="scan")
        d = _job_dict(job)
        assert d["id"] == job.id
        assert d["pid"] == pid
        assert d["status"] == "queued"
        assert d["type"] == "nmap"
        assert d["request_json"] == {}
        assert d["result_json"] == {}


class TestStartJob:
    def test_creates_running_job(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test scan", target="10.0.0.1", command="nmap -sV 10.0.0.1")
        assert job.status == "running"
        assert job.target == "10.0.0.1"
        assert job.started_at != ""
        assert job.created_at != ""

    def test_with_related_entity(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test", related_entity=("host", "h1"))
        assert job.related_entity_type == "host"
        assert job.related_entity_id == "h1"

    def test_with_request_json(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test", request_json={"key": "value"})
        assert job.request_json == {"key": "value"}


class TestQueueJob:
    def test_creates_queued_job(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test", target="10.0.0.1")
        assert job.status == "queued"
        assert job.started_at == ""

    def test_with_scope(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test", scope=("global", "g1"))
        assert job.scope_type == "global"
        assert job.scope_id == "g1"

    def test_with_retry_opts(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test", retry_opts={"retry_of_job_id": "j1", "retry_count": 1, "max_retries": 3, "priority": 5})
        assert job.retry_of_job_id == "j1"
        assert job.retry_count == 1
        assert job.max_retries == 3


class TestMarkJobRunning:
    def test_updates_status(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test")
        updated = mark_job_running(db, job)
        assert updated.status == "running"
        assert updated.started_at != ""


class TestFinishJob:
    def test_marks_done(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        updated = finish_job(db, job, status="done", output="scan complete")
        assert updated.status == "done"
        assert updated.output == "scan complete"
        assert updated.finished_at != ""

    def test_marks_failed(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        updated = finish_job(db, job, status="failed", error_output="timeout")
        assert updated.status == "failed"
        assert updated.error_output == "timeout"

    def test_cancelled_not_overwritten(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        job.status = "cancelled"
        db.commit()
        updated = finish_job(db, job, status="done", output="late result")
        assert updated.status == "cancelled"

    def test_with_result_json(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        updated = finish_job(db, job, status="done", result={"hosts": 5})
        assert updated.result_json == {"hosts": 5}

    def test_default_result_json(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        updated = finish_job(db, job, status="done")
        assert updated.result_json == {}
