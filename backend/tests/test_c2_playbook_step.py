"""
Tests for the new c2:exec playbook step (P4 — C2 live actions in playbooks).

Covers:
  - supports_queued_execution registration
  - _job_spec_for_step validation and payload shape
  - dispatch wiring through _dispatch_job
"""
import pytest
from fastapi import HTTPException

from app import models
from app.core.job_runner import supports_queued_execution
from app.core.utils import new_id
from app.routers.playbooks import _job_spec_for_step, PlaybookRunBody


@pytest.fixture
def base_run_body():
    return PlaybookRunBody(target="", target_url="", flags="", severity="medium")


# ── Queue registration ───────────────────────────────────────────────

def test_c2_exec_is_queued():
    """The new connector/operation must be on the queued list so the
    worker pool dispatches it instead of finishing immediately."""
    assert supports_queued_execution("c2", "exec") is True


def test_unknown_operation_not_queued():
    assert supports_queued_execution("c2", "deploy") is False


# ── Step spec validation ─────────────────────────────────────────────

class TestJobSpecValidation:
    def _step(self, **params):
        return {
            "connector_key": "c2",
            "operation": "exec",
            "params": params,
            "title": "Whoami via Adaptix",
        }

    def test_minimal_valid_step(self, base_run_body):
        spec = _job_spec_for_step("p-test", self._step(
            integration_id="c2int", agent_id="ag-1",
            host_id="hst-1", commandline="whoami",
        ), base_run_body, "tester")
        assert spec["job_type"] == "c2_exec"
        assert spec["connector_key"] == "c2"
        assert spec["operation"] == "exec"
        assert spec["related_entity_id"] == "hst-1"
        rj = spec["request_json"]
        assert rj["integration_id"] == "c2int"
        assert rj["agent_id"] == "ag-1"
        assert rj["commandline"] == "whoami"
        assert rj["mode"] == "command"  # default
        assert rj["wait_for_output"] is True
        assert rj["timeout_seconds"] == 12

    def test_missing_integration_id_rejected(self, base_run_body):
        with pytest.raises(HTTPException) as exc:
            _job_spec_for_step("p-test", self._step(
                agent_id="ag-1", host_id="hst-1", commandline="whoami",
            ), base_run_body, "tester")
        assert exc.value.status_code == 400
        assert "integration_id" in exc.value.detail

    def test_missing_agent_id_rejected(self, base_run_body):
        with pytest.raises(HTTPException) as exc:
            _job_spec_for_step("p-test", self._step(
                integration_id="c2int", host_id="hst-1", commandline="whoami",
            ), base_run_body, "tester")
        assert exc.value.status_code == 400
        assert "agent_id" in exc.value.detail

    def test_missing_host_id_rejected(self, base_run_body):
        with pytest.raises(HTTPException) as exc:
            _job_spec_for_step("p-test", self._step(
                integration_id="c2int", agent_id="ag-1", commandline="whoami",
            ), base_run_body, "tester")
        assert exc.value.status_code == 400
        assert "host_id" in exc.value.detail

    def test_missing_commandline_rejected(self, base_run_body):
        with pytest.raises(HTTPException) as exc:
            _job_spec_for_step("p-test", self._step(
                integration_id="c2int", agent_id="ag-1", host_id="hst-1",
            ), base_run_body, "tester")
        assert exc.value.status_code == 400
        assert "commandline" in exc.value.detail

    def test_invalid_mode_rejected(self, base_run_body):
        with pytest.raises(HTTPException) as exc:
            _job_spec_for_step("p-test", self._step(
                integration_id="c2int", agent_id="ag-1",
                host_id="hst-1", commandline="x", mode="ransom",
            ), base_run_body, "tester")
        assert exc.value.status_code == 400
        assert "mode" in exc.value.detail

    def test_bof_mode_accepted(self, base_run_body):
        spec = _job_spec_for_step("p-test", self._step(
            integration_id="c2int", agent_id="ag-1",
            host_id="hst-1", commandline="bof_inline_assembly",
            mode="bof",
        ), base_run_body, "tester")
        assert spec["request_json"]["mode"] == "bof"

    def test_custom_timeout_passes_through(self, base_run_body):
        spec = _job_spec_for_step("p-test", self._step(
            integration_id="c2int", agent_id="ag-1",
            host_id="hst-1", commandline="x", timeout_seconds=60,
        ), base_run_body, "tester")
        assert spec["request_json"]["timeout_seconds"] == 60

    def test_credential_fields_propagated(self, base_run_body):
        spec = _job_spec_for_step("p-test", self._step(
            integration_id="c2int", agent_id="ag-1",
            host_id="hst-1", commandline="net use %username%",
            credential_id="crd-1", credential_source="rootnotes",
        ), base_run_body, "tester")
        rj = spec["request_json"]
        assert rj["credential_id"] == "crd-1"
        assert rj["credential_source"] == "rootnotes"


# ── %var% substitution ───────────────────────────────────────────────

class TestVarSubstitution:
    """Run-time variables in commandline should be substituted like other
    step types (attacker_ssh:exec uses _substitute_run_vars too)."""

    def test_target_substituted(self):
        body = PlaybookRunBody(target="10.0.0.5", target_url="", flags="",
                               severity="medium", username="alice")
        step = {
            "connector_key": "c2", "operation": "exec",
            "params": {
                "integration_id": "c2int", "agent_id": "ag-1",
                "host_id": "hst-1", "commandline": "ping {target}",
            },
        }
        spec = _job_spec_for_step("p-test", step, body, "tester")
        assert spec["request_json"]["commandline"] == "ping 10.0.0.5"

    def test_username_substituted(self):
        body = PlaybookRunBody(target="", target_url="", flags="",
                               severity="medium", username="alice")
        step = {
            "connector_key": "c2", "operation": "exec",
            "params": {
                "integration_id": "c2int", "agent_id": "ag-1",
                "host_id": "hst-1", "commandline": "whoami {username}",
            },
        }
        spec = _job_spec_for_step("p-test", step, body, "tester")
        assert "alice" in spec["request_json"]["commandline"]


# ── End-to-end dispatch error path ───────────────────────────────────

class TestDispatchErrorPath:
    """When the worker picks up a c2:exec job but the integration is
    missing in the project, it must finish_job(failed) rather than crash."""

    @pytest.mark.asyncio
    async def test_missing_host_finishes_failed(self, db):
        from app.core.job_tracker import queue_job
        from app.core.job_runner import _dispatch_job
        from app.core.transport import CancellationToken

        project = models.Project(id=new_id("p"), name="t", added="2026-01-01")
        db.add(project)
        db.commit()

        job = queue_job(
            db, project.id, "c2_exec", "test",
            connector_key="c2", operation="exec",
            request_json={
                "integration_id": "missing", "agent_id": "ag-1",
                "host_id": "hst-does-not-exist",
                "commandline": "whoami", "mode": "command",
            },
        )
        await _dispatch_job(db, job, CancellationToken())
        db.refresh(job)
        assert job.status == "failed"
        assert "host_id" in (job.error_output or "").lower() or "not in project" in (job.error_output or "").lower()
