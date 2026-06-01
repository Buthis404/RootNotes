"""
Tests for playbook engine pure helper functions.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from app.routers.playbooks._engine import (
    _now,
    _resolve_next_step_index,
    _playbook_run_dict,
    _aggregate_run_results,
    _status_icon,
    _job_result_terminal,
    _dag_terminal_status,
    _serialize_builtin,
    _serialize_custom,
    _substitute_run_vars,
    _spec_topology,
    _spec_nmap_scan,
    _spec_nuclei_scan,
    _spec_netexec_scan,
    _spec_attacker_ssh_exec,
    _spec_donpapi_scan,
    _spec_httpx_scan,
    _spec_c2_exec,
    _spec_ffuf_scan,
    _validate_c2_required_params,
    _job_spec_for_step,
    _seq_build_result,
    _parse_step_retry_config,
    _set_step_terminal,
    _SPEC_DISPATCH,
)
from app.routers.playbooks._models import PlaybookRunBody


def _body(**kwargs):
    defaults = {
        "target": "10.0.0.1",
        "target_url": "http://10.0.0.1",
        "target_id": None,
        "flags": "-sV",
        "severity": "critical,high",
        "keep_manual_positions": True,
        "create_missing_networks": True,
        "username": "admin",
        "password": "pass",
        "domain": "corp.local",
        "hash": "nthash",
    }
    defaults.update(kwargs)
    return PlaybookRunBody(**defaults)


class TestNow:
    def test_returns_string(self):
        result = _now()
        assert isinstance(result, str)
        assert len(result) > 0


class TestStatusIcon:
    def test_done(self):
        assert _status_icon("done") == "\u2705"

    def test_failed(self):
        assert _status_icon("failed") == "\u274c"

    def test_other(self):
        assert _status_icon("running") == "\u23f9"

    def test_queued(self):
        assert _status_icon("queued") == "\u23f9"


class TestJobResultTerminal:
    def test_done(self):
        assert _job_result_terminal({"status": "done"}) == "done"

    def test_cancelled(self):
        assert _job_result_terminal({"status": "cancelled"}) == "cancelled"

    def test_failed(self):
        assert _job_result_terminal({"status": "failed"}) == "failed"

    def test_other_status(self):
        assert _job_result_terminal({"status": "running"}) == "failed"

    def test_missing_status(self):
        assert _job_result_terminal({}) == "failed"


class TestDagTerminalStatus:
    def test_all_done(self):
        assert _dag_terminal_status(cancelled_any=False, any_failed=False) == "done"

    def test_cancelled_no_failures(self):
        assert _dag_terminal_status(cancelled_any=True, any_failed=False) == "cancelled"

    def test_failed(self):
        assert _dag_terminal_status(cancelled_any=False, any_failed=True) == "failed"

    def test_cancelled_and_failed(self):
        assert _dag_terminal_status(cancelled_any=True, any_failed=True) == "failed"


class TestPlaybookRunDict:
    def test_full_mapping(self):
        run = MagicMock()
        run.id = "pbr_123"
        run.pid = "prj_1"
        run.playbook_id = "pb_1"
        run.title = "Test Run"
        run.status = "done"
        run.created_by = "admin"
        run.created_at = "2025-01-01"
        run.started_at = "2025-01-01"
        run.finished_at = "2025-01-01"
        run.target = "10.0.0.1"
        run.error_output = ""
        run.jobs_json = [{"id": "j1"}]
        run.request_json = {"target": "10.0.0.1"}
        run.result_json = {"ok": True}
        d = _playbook_run_dict(run)
        assert d["id"] == "pbr_123"
        assert d["pid"] == "prj_1"
        assert d["status"] == "done"
        assert d["jobs_json"] == [{"id": "j1"}]

    def test_none_jobs_json(self):
        run = MagicMock()
        run.jobs_json = None
        run.request_json = None
        run.result_json = None
        d = _playbook_run_dict(run)
        assert d["jobs_json"] == []
        assert d["request_json"] == {}
        assert d["result_json"] == {}


class TestSerializeBuiltin:
    def test_full(self):
        pb = {
            "id": "builtin_1",
            "title": "Nmap Scan",
            "description": "Scan network",
            "steps": [{"step": 1}],
        }
        result = _serialize_builtin(pb)
        assert result["id"] == "builtin_1"
        assert result["title"] == "Nmap Scan"
        assert result["description"] == "Scan network"
        assert result["editable"] is False
        assert result["source"] == "builtin"
        assert result["steps"] == [{"step": 1}]

    def test_missing_description(self):
        pb = {"id": "b2", "title": "T", "steps": []}
        result = _serialize_builtin(pb)
        assert result["description"] == ""

    def test_missing_steps(self):
        pb = {"id": "b3", "title": "T"}
        result = _serialize_builtin(pb)
        assert result["steps"] == []


class TestSerializeCustom:
    def test_full(self):
        cp = MagicMock()
        cp.id = "cp_1"
        cp.title = "Custom"
        cp.description = "desc"
        cp.created_by = "admin"
        cp.created_at = "2025-01-01"
        cp.updated_at = "2025-01-02"
        cp.steps_json = [{"step": 1}]
        result = _serialize_custom(cp)
        assert result["id"] == "cp_1"
        assert result["editable"] is True
        assert result["source"] == "custom"
        assert result["created_by"] == "admin"

    def test_none_steps_json(self):
        cp = MagicMock()
        cp.steps_json = None
        result = _serialize_custom(cp)
        assert result["steps"] == []


class TestSubstituteRunVars:
    def test_target(self):
        body = _body(target="10.0.0.1")
        assert _substitute_run_vars("scan {target}", body) == "scan 10.0.0.1"

    def test_domain(self):
        body = _body(domain="corp.local")
        assert _substitute_run_vars("{domain}", body) == "corp.local"

    def test_username(self):
        body = _body(username="admin")
        assert _substitute_run_vars("{username}", body) == "admin"

    def test_password(self):
        body = _body(password="pass")
        assert _substitute_run_vars("{password}", body) == "pass"

    def test_hash(self):
        body = _body(hash="nthash")
        assert _substitute_run_vars("{hash}", body) == "nthash"

    def test_multiple_vars(self):
        body = _body(target="10.0.0.1", username="admin", password="pass")
        result = _substitute_run_vars("{username}:{password}@{target}", body)
        assert result == "admin:pass@10.0.0.1"

    def test_no_vars(self):
        body = _body()
        assert _substitute_run_vars("plain command", body) == "plain command"

    def test_empty_body_vars(self):
        body = PlaybookRunBody()
        assert _substitute_run_vars("{target}", body) == ""

    def test_missing_vars_stay(self):
        body = _body()
        assert _substitute_run_vars("{unknown_var}", body) == "{unknown_var}"


class TestSpecTopology:
    def test_auto_build(self):
        body = _body()
        result = _spec_topology("pid1", {}, body, "admin", "Build Topo", operation="auto_build")
        assert result["job_type"] == "topology"
        assert result["connector_key"] == "topology"
        assert result["operation"] == "auto_build"

    def test_rebuild_layout(self):
        body = _body()
        result = _spec_topology("pid1", {}, body, "admin", "Rebuild", operation="rebuild_layout")
        assert result["operation"] == "rebuild_layout"

    def test_unsupported_operation(self):
        body = _body()
        with pytest.raises(HTTPException) as exc_info:
            _spec_topology("pid1", {}, body, "admin", "Bad", operation="invalid_op")
        assert exc_info.value.status_code == 400

    def test_params_override(self):
        body = _body(keep_manual_positions=False)
        result = _spec_topology("pid1", {"keep_manual_positions": True}, body, "admin", "T", operation="auto_build")
        assert result["request_json"]["keep_manual_positions"] is True

    def test_params_fallback_to_body(self):
        body = _body(keep_manual_positions=True)
        result = _spec_topology("pid1", {}, body, "admin", "T", operation="auto_build")
        assert result["request_json"]["keep_manual_positions"] is True


class TestSpecNmapScan:
    def test_basic(self):
        body = _body(target="192.168.1.0/24")
        result = _spec_nmap_scan("pid1", {}, body, "admin", "Nmap Scan")
        assert result["job_type"] == "nmap"
        assert result["target"] == "192.168.1.0/24"
        assert "nmap" in result["command"]

    def test_no_target(self):
        body = _body(target="")
        with pytest.raises(HTTPException) as exc_info:
            _spec_nmap_scan("pid1", {}, body, "admin", "Scan")
        assert exc_info.value.status_code == 400

    def test_params_target_override(self):
        body = _body(target="10.0.0.1")
        result = _spec_nmap_scan("pid1", {"target": "172.16.0.0/16"}, body, "admin", "Scan")
        assert result["target"] == "172.16.0.0/16"

    def test_timeout_from_params(self):
        body = _body()
        result = _spec_nmap_scan("pid1", {"timeout_seconds": 300}, body, "admin", "Scan")
        assert result["request_json"]["timeout_seconds"] == 300

    def test_default_timeout(self):
        body = _body()
        result = _spec_nmap_scan("pid1", {}, body, "admin", "Scan")
        assert result["request_json"]["timeout_seconds"] == 180


class TestSpecNucleiScan:
    def test_basic(self):
        body = _body(target_url="http://10.0.0.1")
        result = _spec_nuclei_scan("pid1", {}, body, "admin", "Nuclei Scan")
        assert result["job_type"] == "nuclei"
        assert result["target"] == "http://10.0.0.1"
        assert "nuclei" in result["command"]

    def test_no_target_url(self):
        body = _body(target_url="")
        with pytest.raises(HTTPException) as exc_info:
            _spec_nuclei_scan("pid1", {}, body, "admin", "Scan")
        assert exc_info.value.status_code == 400

    def test_params_override(self):
        body = _body(target_url="http://old")
        result = _spec_nuclei_scan("pid1", {"target_url": "http://new", "severity": "critical"}, body, "admin", "Scan")
        assert result["target"] == "http://new"
        assert result["request_json"]["severity"] == "critical"

    def test_extra_flags(self):
        body = _body(target_url="http://10.0.0.1")
        result = _spec_nuclei_scan("pid1", {"extra_flags": "-t cves"}, body, "admin", "Scan")
        assert "-t cves" in result["command"]


class TestSpecNetexecScan:
    def test_basic(self):
        body = _body(target="10.0.0.1")
        result = _spec_netexec_scan("pid1", {}, body, "admin", "CME Scan")
        assert result["job_type"] == "cme"
        assert result["target"] == "10.0.0.1"
        assert "nxc" in result["command"]

    def test_no_target(self):
        body = _body(target="")
        with pytest.raises(HTTPException) as exc_info:
            _spec_netexec_scan("pid1", {}, body, "admin", "Scan")
        assert exc_info.value.status_code == 400

    def test_protocol_override(self):
        body = _body(target="10.0.0.1")
        result = _spec_netexec_scan("pid1", {"protocol": "smb"}, body, "admin", "Scan")
        assert "smb" in result["command"]

    def test_default_protocol(self):
        body = _body(target="10.0.0.1")
        result = _spec_netexec_scan("pid1", {}, body, "admin", "Scan")
        assert result["request_json"]["protocol"] == "smb"

    def test_credential_params(self):
        body = _body()
        result = _spec_netexec_scan("pid1", {"target": "10.0.0.1", "username": "u", "password": "p"}, body, "admin", "Scan")
        assert result["request_json"]["username"] == "u"
        assert result["request_json"]["password"] == "p"

    def test_hash_param(self):
        body = _body()
        result = _spec_netexec_scan("pid1", {"target": "10.0.0.1", "hash": "abc"}, body, "admin", "Scan")
        assert result["request_json"]["hash"] == "abc"


class TestSpecAttackerSshExec:
    def test_basic(self):
        body = _body()
        result = _spec_attacker_ssh_exec("pid1", {"command": "id"}, body, "admin", "Exec")
        assert result["job_type"] == "exec"
        assert result["command"] == "id"
        assert result["connector_key"] == "attacker_ssh"

    def test_no_command(self):
        body = _body()
        with pytest.raises(HTTPException) as exc_info:
            _spec_attacker_ssh_exec("pid1", {"command": ""}, body, "admin", "Exec")
        assert exc_info.value.status_code == 400

    def test_command_substitution(self):
        body = _body(target="10.0.0.1", username="admin")
        result = _spec_attacker_ssh_exec("pid1", {"command": "scan {target} as {username}"}, body, "admin", "Exec")
        assert "10.0.0.1" in result["command"]
        assert "admin" in result["command"]

    def test_empty_command_stripped(self):
        body = _body()
        with pytest.raises(HTTPException) as exc_info:
            _spec_attacker_ssh_exec("pid1", {"command": "   "}, body, "admin", "Exec")
        assert exc_info.value.status_code == 400


class TestSpecDonpapiScan:
    def test_with_cred_id(self):
        body = _body(target="10.0.0.1")
        result = _spec_donpapi_scan("pid1", {"target": "10.0.0.1", "cred_id": "crd_1"}, body, "admin", "DP")
        assert result["job_type"] == "donpapi"
        assert result["request_json"]["cred_id"] == "crd_1"

    def test_with_username_password(self):
        body = _body(target="10.0.0.1")
        result = _spec_donpapi_scan("pid1", {"target": "10.0.0.1", "username": "u", "password": "p"}, body, "admin", "DP")
        assert result["request_json"]["username"] == "u"

    def test_no_target(self):
        body = _body(target="")
        with pytest.raises(HTTPException) as exc_info:
            _spec_donpapi_scan("pid1", {}, body, "admin", "DP")
        assert exc_info.value.status_code == 400

    def test_no_cred_no_username(self):
        body = _body(target="10.0.0.1", username="", password="", hash="")
        with pytest.raises(HTTPException) as exc_info:
            _spec_donpapi_scan("pid1", {"target": "10.0.0.1"}, body, "admin", "DP")
        assert exc_info.value.status_code == 400

    def test_no_cred_no_password_or_hash(self):
        body = _body(target="10.0.0.1", password="", hash="")
        with pytest.raises(HTTPException) as exc_info:
            _spec_donpapi_scan("pid1", {"target": "10.0.0.1", "username": "u"}, body, "admin", "DP")
        assert exc_info.value.status_code == 400

    def test_with_nthash(self):
        body = _body(target="10.0.0.1")
        result = _spec_donpapi_scan("pid1", {"target": "10.0.0.1", "username": "u", "nthash": "abc123"}, body, "admin", "DP")
        assert result["request_json"]["nthash"] == "abc123"


class TestSpecHttpxScan:
    def test_basic(self):
        body = _body(target="10.0.0.1")
        result = _spec_httpx_scan("pid1", {}, body, "admin", "Httpx")
        assert result["job_type"] == "httpx"
        assert "httpx" in result["command"]

    def test_no_target(self):
        body = _body(target="")
        with pytest.raises(HTTPException) as exc_info:
            _spec_httpx_scan("pid1", {}, body, "admin", "Httpx")
        assert exc_info.value.status_code == 400

    def test_custom_flags(self):
        body = _body(target="10.0.0.1")
        result = _spec_httpx_scan("pid1", {"flags": "-status-code"}, body, "admin", "Httpx")
        assert "-status-code" in result["command"]


class TestValidateC2RequiredParams:
    def test_missing_integration_id(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_c2_required_params("", "agent", "host", "cmd")
        assert "integration_id" in str(exc_info.value.detail)

    def test_missing_agent_id(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_c2_required_params("integ", "", "host", "cmd")
        assert "agent_id" in str(exc_info.value.detail)

    def test_missing_host_id(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_c2_required_params("integ", "agent", "", "cmd")
        assert "host_id" in str(exc_info.value.detail)

    def test_missing_commandline(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_c2_required_params("integ", "agent", "host", "")
        assert "commandline" in str(exc_info.value.detail)

    def test_all_present(self):
        _validate_c2_required_params("integ", "agent", "host", "cmd")


class TestSpecC2Exec:
    def test_basic(self):
        body = _body()
        result = _spec_c2_exec("pid1", {
            "integration_id": "integ_1",
            "agent_id": "agent_1",
            "host_id": "host_1",
            "commandline": "whoami",
        }, body, "admin", "C2 Exec")
        assert result["job_type"] == "c2_exec"
        assert result["request_json"]["integration_id"] == "integ_1"

    def test_missing_params(self):
        body = _body()
        with pytest.raises(HTTPException) as exc_info:
            _spec_c2_exec("pid1", {}, body, "admin", "C2 Exec")
        assert exc_info.value.status_code == 400

    def test_invalid_mode(self):
        body = _body()
        with pytest.raises(HTTPException) as exc_info:
            _spec_c2_exec("pid1", {
                "integration_id": "i", "agent_id": "a", "host_id": "h",
                "commandline": "c", "mode": "invalid",
            }, body, "admin", "C2 Exec")
        assert exc_info.value.status_code == 400

    def test_bof_mode(self):
        body = _body()
        result = _spec_c2_exec("pid1", {
            "integration_id": "i", "agent_id": "a", "host_id": "h",
            "commandline": "c", "mode": "bof",
        }, body, "admin", "C2 Exec")
        assert result["request_json"]["mode"] == "bof"

    def test_command_substitution(self):
        body = _body(target="10.0.0.1")
        result = _spec_c2_exec("pid1", {
            "integration_id": "i", "agent_id": "a", "host_id": "h",
            "commandline": "scan {target}",
        }, body, "admin", "C2 Exec")
        assert "10.0.0.1" in result["command"]


class TestSpecFfufScan:
    def test_basic(self):
        body = _body(target_url="http://10.0.0.1")
        result = _spec_ffuf_scan("pid1", {}, body, "admin", "Ffuf")
        assert result["job_type"] == "ffuf"
        assert "ffuf" in result["command"]
        assert "FUZZ" in result["command"]

    def test_no_target_url(self):
        body = _body(target_url="")
        with pytest.raises(HTTPException) as exc_info:
            _spec_ffuf_scan("pid1", {}, body, "admin", "Ffuf")
        assert exc_info.value.status_code == 400

    def test_custom_wordlist(self):
        body = _body(target_url="http://10.0.0.1")
        result = _spec_ffuf_scan("pid1", {"wordlist": "/custom/wl.txt"}, body, "admin", "Ffuf")
        assert "/custom/wl.txt" in result["command"]

    def test_extensions(self):
        body = _body(target_url="http://10.0.0.1")
        result = _spec_ffuf_scan("pid1", {"extensions": "php,html"}, body, "admin", "Ffuf")
        assert "-e php,html" in result["command"]

    def test_empty_extensions(self):
        body = _body(target_url="http://10.0.0.1")
        result = _spec_ffuf_scan("pid1", {"extensions": ""}, body, "admin", "Ffuf")
        assert "-e" not in result["command"]


class TestJobSpecForStep:
    def test_nmap_scan(self):
        body = _body(target="10.0.0.1")
        step = {"connector_key": "nmap", "operation": "scan", "params": {"target": "10.0.0.1"}}
        result = _job_spec_for_step("pid1", step, body, "admin")
        assert result["job_type"] == "nmap"

    def test_topology_auto_build(self):
        body = _body()
        step = {"connector_key": "topology", "operation": "auto_build", "params": {}}
        result = _job_spec_for_step("pid1", step, body, "admin")
        assert result["job_type"] == "topology"

    def test_unsupported_step(self):
        body = _body()
        step = {"connector_key": "unknown", "operation": "unknown", "params": {}}
        with pytest.raises(HTTPException) as exc_info:
            _job_spec_for_step("pid1", step, body, "admin")
        assert exc_info.value.status_code == 400

    def test_step_title_override(self):
        body = _body(target="10.0.0.1")
        step = {"connector_key": "nmap", "operation": "scan", "title": "My Scan", "params": {"target": "10.0.0.1"}}
        result = _job_spec_for_step("pid1", step, body, "admin")
        assert "My Scan" in result["title"]

    def test_default_title(self):
        body = _body(target="10.0.0.1")
        step = {"connector_key": "nmap", "operation": "scan", "params": {"target": "10.0.0.1"}}
        result = _job_spec_for_step("pid1", step, body, "admin")
        assert "nmap" in result["title"]


class TestSpecDispatch:
    def test_all_handlers_registered(self):
        assert ("topology", "auto_build") in _SPEC_DISPATCH
        assert ("topology", "rebuild_layout") in _SPEC_DISPATCH
        assert ("nmap", "scan") in _SPEC_DISPATCH
        assert ("nuclei", "scan") in _SPEC_DISPATCH
        assert ("netexec", "scan") in _SPEC_DISPATCH
        assert ("attacker_ssh", "exec") in _SPEC_DISPATCH
        assert ("donpapi", "scan") in _SPEC_DISPATCH
        assert ("httpx", "scan") in _SPEC_DISPATCH
        assert ("c2", "exec") in _SPEC_DISPATCH
        assert ("ffuf", "scan") in _SPEC_DISPATCH


class TestSeqBuildResult:
    def test_basic(self):
        completed = [{"id": "j1"}, {"id": "j2"}]
        failed = [{"id": "j3"}]
        result = _seq_build_result(completed, failed)
        assert result["completed_jobs"] == ["j1", "j2"]
        assert result["failed_jobs"] == ["j3"]
        assert result["rollup"] == {}

    def test_with_rollup(self):
        result = _seq_build_result([], [], rollup={"hosts_found": 5})
        assert result["rollup"] == {"hosts_found": 5}

    def test_with_extra(self):
        result = _seq_build_result([], [], job_count=3)
        assert result["job_count"] == 3


class TestParseStepRetryConfig:
    def test_defaults(self):
        step = {}
        count, delay, on = _parse_step_retry_config(step)
        assert count == 0
        assert delay == 0
        assert on == {"failed"}

    def test_custom_values(self):
        step = {"retry_count": 3, "retry_delay_seconds": 30, "retry_on": ["failed", "cancelled"]}
        count, delay, on = _parse_step_retry_config(step)
        assert count == 3
        assert delay == 30
        assert on == {"failed", "cancelled"}

    def test_filters_invalid_retry_on(self):
        step = {"retry_count": 1, "retry_on": ["invalid", "failed"]}
        count, delay, on = _parse_step_retry_config(step)
        assert on == {"invalid", "failed"}

    def test_string_retry_count(self):
        step = {"retry_count": "2"}
        count, delay, on = _parse_step_retry_config(step)
        assert count == 2


class TestSetStepTerminal:
    def test_sets_both_statuses(self):
        state = {0: {"status": "running", "final_status": None}}
        _set_step_terminal(state, 0, "done")
        assert state[0]["status"] == "done"
        assert state[0]["final_status"] == "done"

    def test_sets_failed(self):
        state = {0: {"status": "running", "final_status": None}}
        _set_step_terminal(state, 0, "failed")
        assert state[0]["status"] == "failed"
        assert state[0]["final_status"] == "failed"


class TestAggregateRunResults:
    def test_empty_job_ids(self):
        db = MagicMock()
        assert _aggregate_run_results(db, []) == {}

    def test_no_jobs_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        assert _aggregate_run_results(db, ["j_missing"]) == {}

    def test_aggregates_keys(self):
        job1 = MagicMock()
        job1.result_json = {"hosts_found": 3, "creds_created": 1}
        job2 = MagicMock()
        job2.result_json = {"hosts_found": 2}
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [job1, job2]
        result = _aggregate_run_results(db, ["j1", "j2"])
        assert result["hosts_found"] == 5
        assert result["creds_created"] == 1

    def test_structured_counts(self):
        job = MagicMock()
        job.result_json = {"structured": {"counts": {"findings_found": 10}}}
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [job]
        result = _aggregate_run_results(db, ["j1"])
        assert result["findings_found"] == 10

    def test_ignores_zero_and_negative(self):
        job = MagicMock()
        job.result_json = {"hosts_found": 0, "creds_created": -1}
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [job]
        result = _aggregate_run_results(db, ["j1"])
        assert "hosts_found" not in result
        assert "creds_created" not in result

    def test_none_result_json(self):
        job = MagicMock()
        job.result_json = None
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [job]
        result = _aggregate_run_results(db, ["j1"])
        assert result == {}


class TestResolveNextStepIndexExtended:
    def test_no_on_success_defaults_to_next(self):
        step = {}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) == 1

    def test_no_on_failure_defaults_to_stop(self):
        step = {}
        assert _resolve_next_step_index(step, success=False, current_idx=0, total_steps=3) is None

    def test_continue_normalizes(self):
        step = {"on_success": "continue"}
        assert _resolve_next_step_index(step, success=True, current_idx=1, total_steps=3) == 2

    def test_jump_boundary_min(self):
        step = {"on_success": "jump", "on_success_step": 1}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) == 0

    def test_jump_boundary_max(self):
        step = {"on_success": "jump", "on_success_step": 3}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) == 2

    def test_failure_jump_boundary(self):
        step = {"on_failure": "jump", "on_failure_step": 1}
        assert _resolve_next_step_index(step, success=False, current_idx=2, total_steps=3) == 0

    def test_negative_step_target(self):
        step = {"on_success": "jump", "on_success_step": -1}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) is None

    def test_jump_non_int_target(self):
        step = {"on_success": "jump", "on_success_step": "abc"}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) is None
