"""Unit tests for app.core.result_normalizer job result normalization."""
from app.core.result_normalizer import normalize
from app.core.result_schema import StructuredResult


def _make_job(**overrides):
    defaults = {
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "status": "done",
        "output": "",
        "error_output": "",
        "request_json": {},
        "result_json": {},
    }
    defaults.update(overrides)

    class FakeJob:
        pass

    job = FakeJob()
    for k, v in defaults.items():
        setattr(job, k, v)
    return job


class TestNormalizeSSHExec:
    def test_exec_success(self):
        job = _make_job(result_json={"exit_code": 0})
        result = normalize(job)
        assert result.ok is True
        assert result.auth_success is True
        assert "exec ok" in result.summary

    def test_exec_unreachable(self):
        job = _make_job(result_json={"exit_code": 255})
        result = normalize(job)
        assert result.ok is False
        assert "unreachable" in result.summary

    def test_exec_auth_failure(self):
        job = _make_job(
            result_json={"exit_code": 1},
            output="Permission denied (publickey).",
        )
        result = normalize(job)
        assert result.auth_success is False
        assert "auth failed" in result.summary

    def test_exec_generic_failure(self):
        job = _make_job(result_json={"exit_code": 1}, output="something went wrong")
        result = normalize(job)
        assert result.ok is False
        assert "exec failed" in result.summary

    def test_exec_with_host_id(self):
        job = _make_job(
            result_json={"exit_code": 0, "host_id": "hst123"},
            request_json={"host_id": "hst123"},
        )
        result = normalize(job)
        assert "hst123" in result.hosts_affected

    def test_exec_with_cred_id(self):
        job = _make_job(
            result_json={"exit_code": 0},
            request_json={"cred_id": "cred123"},
        )
        result = normalize(job)
        assert "cred123" in result.creds_affected

    def test_pwned_sets_admin_role(self):
        job = _make_job(
            result_json={"exit_code": 0},
            output="(Pwn3d!)",
        )
        result = normalize(job)
        assert result.access_role == "local_admin"

    def test_root_sets_shell_role(self):
        job = _make_job(
            result_json={"exit_code": 0},
            output="uid=0(root)",
        )
        result = normalize(job)
        assert result.access_role == "shell"

    def test_adcs_enum(self):
        job = _make_job(
            operation="adcs_enum",
            result_json={"exit_code": 0},
            output="ESC1 ESC2 vulnerable Template Name : VulnTemplate",
        )
        result = normalize(job)
        assert any("adcs" in f["type"] for f in result.finding_candidates)

    def test_delegation_enum(self):
        job = _make_job(
            operation="delegation_enum",
            result_json={"exit_code": 0},
            output="unconstrained delegation found",
        )
        result = normalize(job)
        assert any("delegation" in f["type"] for f in result.finding_candidates)

    def test_spn_enum(self):
        job = _make_job(
            operation="spn_enum",
            result_json={"exit_code": 0},
            output="ServicePrincipalName: HTTP/dc01.corp.local",
        )
        result = normalize(job)
        assert any("kerberoastable" in f["type"] for f in result.finding_candidates)

    def test_bloodhound_collect(self):
        job = _make_job(
            operation="bloodhound_collect",
            result_json={"exit_code": 0},
            output="Enumeration completed",
        )
        result = normalize(job)
        assert "complete" in result.summary.lower() or "bloodhound" in result.summary.lower()

    def test_privileged_access_finding(self):
        job = _make_job(
            result_json={"exit_code": 0, "host_id": "hst1"},
            output="(Pwn3d!)",
        )
        result = normalize(job)
        assert any(f["type"] == "pwned_host" for f in result.finding_candidates) or \
               any("privileged" in f["type"] for f in result.finding_candidates)


class TestNormalizeNetexec:
    def test_pwned(self):
        job = _make_job(
            connector_key="netexec",
            operation="scan",
            status="done",
            request_json={"command": "netexec smb 10.0.0.1"},
            output="SMB    10.0.0.1    445    DC01    [+] 10.0.0.1 (Pwn3d!)",
        )
        result = normalize(job)
        assert result.access_role == "local_admin"
        assert any("pwned" in f["type"] for f in result.finding_candidates)

    def test_success(self):
        job = _make_job(
            connector_key="netexec",
            operation="scan",
            status="done",
            request_json={"command": "netexec smb 10.0.0.1"},
            output="[+] 10.0.0.1 CORP\\admin:Password123",
        )
        result = normalize(job)
        assert result.auth_success is True

    def test_failed(self):
        job = _make_job(
            connector_key="netexec",
            operation="scan",
            status="done",
            request_json={"command": "netexec smb 10.0.0.1"},
            output="[-] 10.0.0.1 AUTHENTICATION FAILED",
        )
        result = normalize(job)
        assert result.auth_success is False

    def test_winrm_proto(self):
        job = _make_job(
            connector_key="netexec",
            operation="scan",
            status="done",
            request_json={"command": "netexec winrm 10.0.0.1"},
            output="netexec winrm\n[+] 10.0.0.1 admin:Password123",
        )
        result = normalize(job)
        assert result.auth_success is True

    def test_proto_detection_smb(self):
        job = _make_job(
            connector_key="netexec",
            operation="scan",
            status="done",
            request_json={"command": "netexec smb 10.0.0.1"},
            output="[+] 10.0.0.1 admin:Password123",
        )
        result = normalize(job)
        assert "SMB" in result.summary


class TestNormalizeCredValidate:
    def test_valid(self):
        job = _make_job(
            operation="cred_validate",
            status="done",
            result_json={"hosts_valid": 3, "hosts_failed": 0, "hosts_total": 5},
        )
        result = normalize(job)
        assert result.auth_success is True
        assert result.counts["hosts_valid"] == 3

    def test_many_hosts_finding(self):
        job = _make_job(
            operation="cred_validate",
            status="done",
            result_json={"hosts_valid": 5, "hosts_failed": 0, "hosts_total": 10, "cred_id": "c1"},
        )
        result = normalize(job)
        assert any(f["type"] == "valid_on_many_hosts" for f in result.finding_candidates)

    def test_failed(self):
        job = _make_job(
            operation="cred_validate",
            status="done",
            result_json={"hosts_valid": 0, "hosts_failed": 3, "hosts_total": 3},
        )
        result = normalize(job)
        assert result.auth_success is False


class TestNormalizeScanConnectors:
    def test_nmap(self):
        job = _make_job(
            connector_key="nmap",
            operation="scan",
            status="done",
            result_json={"hosts_found": 5, "hosts_created": 3, "hosts_updated": 2},
        )
        result = normalize(job)
        assert "nmap" in result.summary
        assert result.counts["hosts_found"] == 5

    def test_nuclei(self):
        job = _make_job(
            connector_key="nuclei",
            operation="scan",
            status="done",
            result_json={"findings_found": 4, "findings_created": 2},
        )
        result = normalize(job)
        assert "nuclei" in result.summary
        assert result.counts["findings_created"] == 2

    def test_httpx(self):
        job = _make_job(
            connector_key="httpx",
            operation="scan",
            status="done",
            result_json={"urls_found": 10, "hosts_found": 3, "activities_created": 5},
        )
        result = normalize(job)
        assert "httpx" in result.summary
        assert result.counts["urls_found"] == 10

    def test_ffuf(self):
        job = _make_job(
            connector_key="ffuf",
            operation="scan",
            status="done",
            result_json={"paths_found": 50, "findings_created": 5},
        )
        result = normalize(job)
        assert "ffuf" in result.summary

    def test_c2_sync(self):
        job = _make_job(
            connector_key="c2_havoc",
            operation="sync",
            status="done",
            result_json={"hosts_created": 3, "creds_created": 1},
        )
        result = normalize(job)
        assert "c2 sync" in result.summary

    def test_topology(self):
        job = _make_job(
            connector_key="topology",
            operation="build",
            status="done",
            result_json={"nodes": 10, "edges": 20},
        )
        result = normalize(job)
        assert "topology" in result.summary


class TestNormalizeFailedJob:
    def test_failed_status_gets_summary(self):
        job = _make_job(
            connector_key="unknown",
            operation="unknown",
            status="failed",
        )
        result = normalize(job)
        assert result.summary == "job failed"
