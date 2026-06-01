"""
Extended tests for bulk_actions helper functions.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from app.routers.bulk_actions import (
    _build_validate_command,
    _parse_validation_result,
    _validate_access_role,
    _infer_bulk_access_role,
    _is_bulk_auth_success,
    _netexec_plus_success,
    _winrm_auth_success,
    _bulk_build_command,
    _bulk_track_undo_ops,
    _apply_host_enrichment,
    _merge_list_field,
    _maybe_promote_host_status,
    _edge_version,
    _auto_detect_service,
    _require_attacker_ssh,
    _SMB_INVALID_CREDS,
    _SMB_PWNED,
    _resolve_collection_to_host_ids,
    _resolve_bulk_credential,
    BulkExecBody,
    ValidateCredBody,
)


class TestBuildValidateCommand:
    def _cred(self, username="admin", secret="pass", ctype="plain"):
        c = MagicMock()
        c.username = username
        c.secret = secret
        c.type = ctype
        return c

    def test_ssh_plain(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("mypass"))
        cmd = _build_validate_command(c, "10.0.0.1", "ssh")
        assert "sshpass" in cmd
        assert "10.0.0.1" in cmd
        assert "admin" in cmd

    def test_ssh_key(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("KEYDATA"), ctype="key")
        cmd = _build_validate_command(c, "10.0.0.1", "ssh")
        assert "mktemp" in cmd
        assert "chmod 600" in cmd
        assert "-i" in cmd

    def test_smb(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("mypass"))
        cmd = _build_validate_command(c, "10.0.0.1", "smb")
        assert "netexec smb" in cmd
        assert "10.0.0.1" in cmd

    def test_winrm(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("mypass"))
        cmd = _build_validate_command(c, "10.0.0.1", "winrm")
        assert "netexec winrm" in cmd

    def test_mssql(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("mypass"))
        cmd = _build_validate_command(c, "10.0.0.1", "mssql")
        assert "netexec mssql" in cmd

    def test_ldap(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("mypass"))
        cmd = _build_validate_command(c, "10.0.0.1", "ldap")
        assert "netexec ldap" in cmd

    def test_rdp(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("mypass"))
        cmd = _build_validate_command(c, "10.0.0.1", "rdp")
        assert "netexec rdp" in cmd

    def test_default_fallback_smb(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("mypass"))
        cmd = _build_validate_command(c, "10.0.0.1", "unknown_svc")
        assert "netexec smb" in cmd

    def test_hash_type_uses_h_flag(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("AADM:HASH"), ctype="ntlm")
        cmd = _build_validate_command(c, "10.0.0.1", "smb")
        assert "-H" in cmd

    def test_plain_type_uses_p_flag(self):
        from app.core.crypto import encrypt_str
        c = self._cred(secret=encrypt_str("mypass"), ctype="plain")
        cmd = _build_validate_command(c, "10.0.0.1", "smb")
        assert "-p" in cmd


class TestParseValidationResult:
    def test_ssh_ok_exit0(self):
        assert _parse_validation_result(True, 0, "uid=0(root)", "ssh") is True

    def test_ssh_ok_nonzero_exit(self):
        assert _parse_validation_result(True, 1, "error", "ssh") is False

    def test_ssh_not_ok(self):
        assert _parse_validation_result(False, 0, "", "ssh") is False

    def test_smb_pwned(self):
        assert _parse_validation_result(True, 0, "[+] pwn3d!", "smb") is True

    def test_smb_logon_failure(self):
        assert _parse_validation_result(True, 0, "[+] status_logon_failure", "smb") is False

    def test_smb_access_denied(self):
        assert _parse_validation_result(True, 0, "[+] status_access_denied", "smb") is False

    def test_smb_invalid_creds(self):
        assert _parse_validation_result(True, 0, f"[+] {_SMB_INVALID_CREDS}", "smb") is False

    def test_smb_auth_failed(self):
        assert _parse_validation_result(True, 0, "[+] authentication failed", "smb") is False

    def test_smb_no_plus(self):
        assert _parse_validation_result(True, 0, "some output", "smb") is False

    def test_winrm_success(self):
        assert _parse_validation_result(True, 0, "[+] winrm success", "winrm") is True

    def test_ldap_success(self):
        assert _parse_validation_result(True, 0, "[+] ldap", "ldap") is True


class TestValidateAccessRole:
    def test_ssh_root(self):
        assert _validate_access_role("ssh", "uid=0(root)") == "local_admin"

    def test_ssh_uid0(self):
        assert _validate_access_role("ssh", "uid=0") == "local_admin"

    def test_ssh_normal(self):
        assert _validate_access_role("ssh", "uid=1000") == "ssh"

    def test_smb_pwned(self):
        assert _validate_access_role("smb", _SMB_PWNED) == "local_admin"

    def test_smb_not_pwned(self):
        assert _validate_access_role("smb", "access granted") == "smb"

    def test_winrm_pwned(self):
        assert _validate_access_role("winrm", _SMB_PWNED) == "local_admin"

    def test_winrm_not_pwned(self):
        assert _validate_access_role("winrm", "access ok") == "winrm"

    def test_ldap_domain_admins(self):
        assert _validate_access_role("ldap", "domain admins group") == "domain_admin"

    def test_ldap_domain_admin_singular(self):
        assert _validate_access_role("ldap", "domain admin member") == "domain_admin"

    def test_ldap_normal(self):
        assert _validate_access_role("ldap", "regular user") == "domain_user"

    def test_rdp(self):
        assert _validate_access_role("rdp", "") == "rdp"

    def test_mssql_sysadmin_da(self):
        assert _validate_access_role("mssql", "sysadmin domain admins") == "domain_admin"

    def test_mssql_sysadmin_no_da(self):
        assert _validate_access_role("mssql", "sysadmin only") == "database"

    def test_mssql_normal(self):
        assert _validate_access_role("mssql", "regular output") == "database"

    def test_unknown_service(self):
        assert _validate_access_role("custom_svc", "") == "custom_svc"


class TestInferBulkAccessRole:
    def test_evil_winrm(self):
        assert _infer_bulk_access_role("evil-winrm foo") == "winrm"

    def test_netexec_winrm(self):
        assert _infer_bulk_access_role("netexec winrm foo") == "winrm"

    def test_netexec_mssql(self):
        assert _infer_bulk_access_role("netexec mssql foo") == "database"

    def test_netexec_ldap(self):
        assert _infer_bulk_access_role("netexec ldap foo") == "domain_user"

    def test_netexec_rdp(self):
        assert _infer_bulk_access_role("netexec rdp foo") == "rdp"

    def test_ssh_command(self):
        assert _infer_bulk_access_role("ssh user@host") == "ssh"

    def test_sshpass(self):
        assert _infer_bulk_access_role("sshpass -p x ssh host") == "ssh"

    def test_wmiexec(self):
        assert _infer_bulk_access_role("wmiexec host") == "local_admin"

    def test_psexec(self):
        assert _infer_bulk_access_role("psexec host") == "local_admin"

    def test_none_on_unknown(self):
        assert _infer_bulk_access_role("echo hello") is None

    def test_empty_string(self):
        assert _infer_bulk_access_role("") is None

    def test_none_input(self):
        assert _infer_bulk_access_role(None) is None


class TestNetexecPlusSuccess:
    def test_plus_present(self):
        assert _netexec_plus_success("[+] success") is True

    def test_plus_with_logon_failure(self):
        assert _netexec_plus_success("[+] status_logon_failure") is False

    def test_plus_with_access_denied(self):
        assert _netexec_plus_success("[+] status_access_denied") is False

    def test_plus_with_invalid_creds(self):
        assert _netexec_plus_success(f"[+] {_SMB_INVALID_CREDS}") is False

    def test_plus_with_auth_failed(self):
        assert _netexec_plus_success("[+] authentication failed") is False

    def test_no_plus(self):
        assert _netexec_plus_success("regular output") is False

    def test_plus_with_logon_failure_typo(self):
        assert _netexec_plus_success("[+] logon_failure") is False


class TestWinrmAuthSuccess:
    def test_pwned(self):
        assert _winrm_auth_success("pwn3d! output", True, 0) is True

    def test_established(self):
        assert _winrm_auth_success("connection established", True, 0) is True

    def test_evil_winrm_shell(self):
        assert _winrm_auth_success("evil-winrm shell opened", True, 0) is True

    def test_netexec_plus(self):
        assert _winrm_auth_success("[+] success", False, 1) is True

    def test_ok_exit0(self):
        assert _winrm_auth_success("regular output", True, 0) is True

    def test_failure(self):
        assert _winrm_auth_success("error", False, 1) is False


class TestIsBulkAuthSuccess:
    def test_netexec_smb_pwned(self):
        assert _is_bulk_auth_success("netexec smb 10.0.0.1", True, 0, _SMB_PWNED) is True

    def test_netexec_smb_plus(self):
        assert _is_bulk_auth_success("netexec smb 10.0.0.1", True, 0, "[+] success") is True

    def test_netexec_smb_failure(self):
        assert _is_bulk_auth_success("netexec smb 10.0.0.1", True, 0, "[-] failed") is False

    def test_crackmapexec_smb(self):
        assert _is_bulk_auth_success("crackmapexec smb 10.0.0.1", True, 0, _SMB_PWNED) is True

    def test_netexec_winrm_pwned(self):
        assert _is_bulk_auth_success("netexec winrm 10.0.0.1", True, 0, _SMB_PWNED) is True

    def test_netexec_winrm_established(self):
        assert _is_bulk_auth_success("netexec winrm 10.0.0.1", True, 0, "established") is True

    def test_evil_winrm(self):
        assert _is_bulk_auth_success("evil-winrm -i 10.0.0.1", True, 0, "evil-winrm shell") is True

    def test_netexec_mssql_plus(self):
        assert _is_bulk_auth_success("netexec mssql 10.0.0.1", True, 0, "[+] success") is True

    def test_netexec_ldap_plus(self):
        assert _is_bulk_auth_success("netexec ldap 10.0.0.1", True, 0, "[+] success") is True

    def test_netexec_rdp_plus(self):
        assert _is_bulk_auth_success("netexec rdp 10.0.0.1", True, 0, "[+] success") is True

    def test_ldapsearch_success(self):
        output = "dn: cn=admin result: 0 success"
        assert _is_bulk_auth_success("ldapsearch -x", True, 0, output) is True

    def test_ldapsearch_invalid_creds(self):
        output = f"dn: cn=admin {_SMB_INVALID_CREDS}"
        assert _is_bulk_auth_success("ldapsearch -x", True, 0, output) is False

    def test_ldapsearch_no_dn(self):
        assert _is_bulk_auth_success("ldapsearch -x", True, 0, "no results") is False

    def test_generic_ok_exit0(self):
        assert _is_bulk_auth_success("custom command", True, 0, "") is True

    def test_generic_not_ok(self):
        assert _is_bulk_auth_success("custom command", False, 1, "") is False

    def test_generic_ok_nonzero_exit(self):
        assert _is_bulk_auth_success("custom command", True, 1, "") is False


class TestBulkBuildCommand:
    def _host(self, ip="10.0.0.1", hostname="testhost"):
        h = MagicMock()
        h.ip = ip
        h.hostname = hostname
        return h

    def test_basic_substitution(self):
        body = BulkExecBody(host_ids=[], command_template="nmap {target}")
        host = self._host()
        target_ip, command, safe_command, title, cred_secret, safe_body = _bulk_build_command(body, host, None)
        assert target_ip == "10.0.0.1"
        assert "10.0.0.1" in command
        assert cred_secret == ""

    def test_uppercase_target(self):
        body = BulkExecBody(host_ids=[], command_template="nmap {TARGET}")
        host = self._host()
        _, command, _, _, _, _ = _bulk_build_command(body, host, None)
        assert "10.0.0.1" in command

    def test_double_brace_target(self):
        body = BulkExecBody(host_ids=[], command_template="nmap {{target}}")
        host = self._host()
        _, command, _, _, _, _ = _bulk_build_command(body, host, None)
        assert "10.0.0.1" in command

    def test_double_brace_upper_target(self):
        body = BulkExecBody(host_ids=[], command_template="nmap {{TARGET}}")
        host = self._host()
        _, command, _, _, _, _ = _bulk_build_command(body, host, None)
        assert "10.0.0.1" in command

    def test_with_credential(self):
        from app.core.crypto import encrypt_str
        cred = MagicMock()
        cred.secret = encrypt_str("secretpass")
        cred.username = "admin"
        cred.domain = "corp.local"
        body = BulkExecBody(host_ids=[], command_template="cmd {{USER}} {{PASS}} {{DOMAIN}}")
        host = self._host()
        _, command, _, _, cred_secret, _ = _bulk_build_command(body, host, cred)
        assert "admin" in command
        assert "secretpass" in command
        assert "corp.local" in command
        assert cred_secret == "secretpass"

    def test_credential_hash_placeholder(self):
        from app.core.crypto import encrypt_str
        cred = MagicMock()
        cred.secret = encrypt_str("nthashvalue")
        cred.username = "admin"
        cred.domain = ""
        body = BulkExecBody(host_ids=[], command_template="cmd {{HASH}} {{SECRET}}")
        host = self._host()
        _, command, _, _, _, _ = _bulk_build_command(body, host, cred)
        assert "nthashvalue" in command

    def test_snippet_title_default(self):
        body = BulkExecBody(host_ids=[], command_template="id", scan_type="exec")
        host = self._host()
        _, _, _, title, _, _ = _bulk_build_command(body, host, None)
        assert title == "exec: 10.0.0.1"

    def test_snippet_title_custom(self):
        body = BulkExecBody(host_ids=[], command_template="id", snippet_title="My Scan")
        host = self._host()
        _, _, _, title, _, _ = _bulk_build_command(body, host, None)
        assert title == "My Scan"

    def test_safe_command_scrubbed(self):
        from app.core.crypto import encrypt_str
        cred = MagicMock()
        cred.secret = encrypt_str("supersecret")
        cred.username = "admin"
        cred.domain = ""
        body = BulkExecBody(host_ids=[], command_template="echo {{PASSWORD}}")
        host = self._host()
        _, _, safe_command, _, _, _ = _bulk_build_command(body, host, cred)
        assert "supersecret" not in safe_command

    def test_host_no_ip_uses_hostname(self):
        body = BulkExecBody(host_ids=[], command_template="scan {target}")
        host = MagicMock()
        host.ip = None
        host.hostname = "myhost"
        target_ip, _, _, _, _, _ = _bulk_build_command(body, host, None)
        assert target_ip == "myhost"

    def test_host_no_ip_no_hostname(self):
        body = BulkExecBody(host_ids=[], command_template="scan {target}")
        host = MagicMock()
        host.ip = None
        host.hostname = None
        target_ip, _, _, _, _, _ = _bulk_build_command(body, host, None)
        assert target_ip == "unknown"

    def test_realm_placeholder(self):
        from app.core.crypto import encrypt_str
        cred = MagicMock()
        cred.secret = encrypt_str("pass")
        cred.username = "admin"
        cred.domain = "CORP.LOCAL"
        body = BulkExecBody(host_ids=[], command_template="cmd {{REALM}}")
        host = self._host()
        _, command, _, _, _, _ = _bulk_build_command(body, host, cred)
        assert "CORP.LOCAL" in command

    def test_username_placeholder(self):
        from app.core.crypto import encrypt_str
        cred = MagicMock()
        cred.secret = encrypt_str("pass")
        cred.username = "john"
        cred.domain = ""
        body = BulkExecBody(host_ids=[], command_template="cmd {{USERNAME}}")
        host = self._host()
        _, command, _, _, _, _ = _bulk_build_command(body, host, cred)
        assert "john" in command

    def test_safe_body_scrubbed(self):
        from app.core.crypto import encrypt_str
        cred = MagicMock()
        cred.secret = encrypt_str("supersecret")
        cred.username = "admin"
        cred.domain = ""
        body = BulkExecBody(host_ids=[], command_template="echo {{PASSWORD}}")
        host = self._host()
        _, _, _, _, _, safe_body = _bulk_build_command(body, host, cred)
        assert "supersecret" not in safe_body["command_template"]


class TestBulkTrackUndoOps:
    def test_status_change_tracked(self):
        host = MagicMock()
        host.id = "h_1"
        host.status = "access"
        undo_ops = []
        _bulk_track_undo_ops(host, "alive", [], undo_ops)
        assert len(undo_ops) == 1
        assert undo_ops[0]["entity"] == "host"
        assert undo_ops[0]["type"] == "patch"
        assert undo_ops[0]["patch"]["status"] == "alive"

    def test_no_status_change(self):
        host = MagicMock()
        host.id = "h_1"
        host.status = "alive"
        undo_ops = []
        _bulk_track_undo_ops(host, "alive", [], undo_ops)
        assert len(undo_ops) == 0

    def test_cred_changes_tracked(self):
        host = MagicMock()
        host.id = "h_1"
        host.status = "alive"
        cred_changes = [{"id": "crd_1"}, {"id": "crd_2"}]
        undo_ops = []
        _bulk_track_undo_ops(host, "alive", cred_changes, undo_ops)
        assert len(undo_ops) == 2
        assert all(op["entity"] == "cred" and op["type"] == "delete" for op in undo_ops)

    def test_cred_changes_without_id_skipped(self):
        host = MagicMock()
        host.id = "h_1"
        host.status = "alive"
        cred_changes = [{"no_id": True}]
        undo_ops = []
        _bulk_track_undo_ops(host, "alive", cred_changes, undo_ops)
        assert len(undo_ops) == 0

    def test_cred_changes_non_dict(self):
        host = MagicMock()
        host.id = "h_1"
        host.status = "alive"
        cred_changes = ["not_a_dict"]
        undo_ops = []
        _bulk_track_undo_ops(host, "alive", cred_changes, undo_ops)
        assert len(undo_ops) == 0

    def test_combined_status_and_cred(self):
        host = MagicMock()
        host.id = "h_1"
        host.status = "access"
        cred_changes = [{"id": "crd_1"}]
        undo_ops = []
        _bulk_track_undo_ops(host, "alive", cred_changes, undo_ops)
        assert len(undo_ops) == 2


class TestApplyHostEnrichment:
    def _host(self, ip="10.0.0.1", hostname=None, os=None, domain=None, ports=None, services=None, status="unknown"):
        h = MagicMock()
        h.ip = ip
        h.hostname = hostname
        h.os = os
        h.domain = domain
        h.ports = ports
        h.services = services
        h.status = status
        return h

    def test_no_hosts_in_enrichment(self):
        host = self._host()
        changes = _apply_host_enrichment(None, None, host, {})
        assert changes == []

    def test_no_matching_ip(self):
        host = self._host(ip="10.0.0.1")
        enrichment = {"hosts": [{"ip": "10.0.0.2", "hostname": "other"}]}
        changes = _apply_host_enrichment(None, None, host, enrichment)
        assert changes == []

    def test_hostname_set_when_empty(self):
        host = self._host()
        enrichment = {"hosts": [{"ip": "10.0.0.1", "hostname": "newhost"}]}
        changes = _apply_host_enrichment(None, None, host, enrichment)
        assert len(changes) == 1
        assert changes[0]["field"] == "hostname"
        assert host.hostname == "newhost"

    def test_hostname_not_overwritten(self):
        host = self._host(hostname="existing")
        enrichment = {"hosts": [{"ip": "10.0.0.1", "hostname": "newhost"}]}
        changes = _apply_host_enrichment(None, None, host, enrichment)
        assert len(changes) == 0
        assert host.hostname == "existing"

    def test_os_set_when_empty(self):
        host = self._host()
        enrichment = {"hosts": [{"ip": "10.0.0.1", "os": "Linux"}]}
        changes = _apply_host_enrichment(None, None, host, enrichment)
        assert any(c["field"] == "os" for c in changes)
        assert host.os == "Linux"

    def test_os_not_overwritten(self):
        host = self._host(os="Windows")
        enrichment = {"hosts": [{"ip": "10.0.0.1", "os": "Linux"}]}
        changes = _apply_host_enrichment(None, None, host, enrichment)
        assert not any(c["field"] == "os" for c in changes)

    def test_domain_set_when_empty(self):
        host = self._host()
        enrichment = {"hosts": [{"ip": "10.0.0.1", "domain": "corp.local"}]}
        changes = _apply_host_enrichment(None, None, host, enrichment)
        assert any(c["field"] == "domain" for c in changes)
        assert host.domain == "corp.local"

    def test_ports_merged(self):
        host = self._host(ports=[80, 443])
        enrichment = {"hosts": [{"ip": "10.0.0.1", "ports": [22, 80]}]}
        changes = _apply_host_enrichment(None, None, host, enrichment)
        port_change = next((c for c in changes if c["field"] == "ports"), None)
        assert port_change is not None
        assert 22 in host.ports
        assert 80 in host.ports
        assert 443 in host.ports

    def test_services_merged(self):
        host = self._host(services=["http"])
        enrichment = {"hosts": [{"ip": "10.0.0.1", "services": ["ssh", "http"]}]}
        changes = _apply_host_enrichment(None, None, host, enrichment)
        assert "ssh" in host.services

    def test_status_promoted_to_alive(self):
        host = self._host(status="unknown")
        enrichment = {"hosts": [{"ip": "10.0.0.1", "hostname": "host1"}]}
        _apply_host_enrichment(None, None, host, enrichment)
        assert host.status == "alive"

    def test_status_not_promoted_when_set(self):
        host = self._host(status="access")
        enrichment = {"hosts": [{"ip": "10.0.0.1", "hostname": "host1"}]}
        _apply_host_enrichment(None, None, host, enrichment)
        assert host.status == "access"


class TestMergeListField:
    def test_merge_additions(self):
        result = _merge_list_field(["a"], ["b"])
        assert set(result) == {"a", "b"}

    def test_merge_no_additions(self):
        assert _merge_list_field(["a"], []) is None

    def test_merge_none_additions(self):
        assert _merge_list_field(["a"], None) is None

    def test_merge_existing_none(self):
        result = _merge_list_field(None, ["a"])
        assert "a" in result

    def test_merge_same_set_returns_none(self):
        assert _merge_list_field(["a", "b"], ["a", "b"]) is None

    def test_merge_dedupes(self):
        result = _merge_list_field(["a"], ["a", "b"])
        assert set(result) == {"a", "b"}


class TestMaybePromoteHostStatus:
    def test_promote_unknown(self):
        h = MagicMock(status="unknown")
        _maybe_promote_host_status(h, True)
        assert h.status == "access"

    def test_promote_empty(self):
        h = MagicMock(status="")
        _maybe_promote_host_status(h, True)
        assert h.status == "access"

    def test_promote_alive(self):
        h = MagicMock(status="alive")
        _maybe_promote_host_status(h, True)
        assert h.status == "access"

    def test_no_promote_on_failure(self):
        h = MagicMock(status="unknown")
        _maybe_promote_host_status(h, False)
        assert h.status == "unknown"

    def test_no_promote_already_access(self):
        h = MagicMock(status="access")
        _maybe_promote_host_status(h, True)
        assert h.status == "access"

    def test_no_promote_pwned(self):
        h = MagicMock(status="pwned")
        _maybe_promote_host_status(h, True)
        assert h.status == "pwned"


class TestEdgeVersion:
    def test_no_version(self):
        assert _edge_version({}) == 1

    def test_existing_version(self):
        assert _edge_version({"version": 3}) == 4

    def test_zero_version(self):
        assert _edge_version({"version": 0}) == 1

    def test_string_version(self):
        assert _edge_version({"version": "5"}) == 6


class TestAutoDetectService:
    def _cred(self, service="", ctype="plain", is_domain=False):
        c = MagicMock()
        c.service = service
        c.type = ctype
        c.is_domain = is_domain
        return c

    def _host(self, os="Linux"):
        h = MagicMock()
        h.os = os
        return h

    def test_explicit_service(self):
        assert _auto_detect_service("ssh", self._cred(), self._host()) == "ssh"

    def test_auto_ssh_key(self):
        assert _auto_detect_service("auto", self._cred(ctype="key"), self._host()) == "ssh"

    def test_auto_ssh_service(self):
        assert _auto_detect_service("auto", self._cred(service="ssh"), self._host()) == "ssh"

    def test_auto_winrm(self):
        assert _auto_detect_service("auto", self._cred(service="winrm"), self._host()) == "winrm"

    def test_auto_rdp(self):
        assert _auto_detect_service("auto", self._cred(service="rdp"), self._host()) == "rdp"

    def test_auto_mssql(self):
        assert _auto_detect_service("auto", self._cred(service="mssql"), self._host()) == "mssql"

    def test_auto_ldap(self):
        assert _auto_detect_service("auto", self._cred(service="ldap"), self._host()) == "ldap"

    def test_auto_smb(self):
        assert _auto_detect_service("auto", self._cred(service="smb"), self._host()) == "smb"

    def test_auto_windows_host(self):
        assert _auto_detect_service("auto", self._cred(), self._host(os="Windows")) == "smb"

    def test_auto_domain_cred(self):
        assert _auto_detect_service("auto", self._cred(is_domain=True), self._host()) == "smb"

    def test_auto_ntlm_type(self):
        assert _auto_detect_service("auto", self._cred(ctype="ntlm"), self._host()) == "smb"

    def test_auto_hash_type(self):
        assert _auto_detect_service("auto", self._cred(ctype="hash"), self._host()) == "smb"

    def test_auto_fallback_ssh(self):
        assert _auto_detect_service("auto", self._cred(), self._host()) == "ssh"


class TestRequireAttackerSsh:
    def test_raises_when_disabled(self):
        with patch("app.routers.bulk_actions.registry") as mock_reg:
            mock_mod = MagicMock()
            mock_mod.enabled = False
            mock_reg.get.return_value = mock_mod
            with pytest.raises(HTTPException) as exc_info:
                _require_attacker_ssh()
            assert exc_info.value.status_code == 404

    def test_raises_when_missing(self):
        with patch("app.routers.bulk_actions.registry") as mock_reg:
            mock_reg.get.return_value = None
            with pytest.raises(HTTPException) as exc_info:
                _require_attacker_ssh()
            assert exc_info.value.status_code == 404

    def test_passes_when_enabled(self):
        with patch("app.routers.bulk_actions.registry") as mock_reg:
            mock_mod = MagicMock()
            mock_mod.enabled = True
            mock_reg.get.return_value = mock_mod
            _require_attacker_ssh()


class TestResolveCollectionToHostIds:
    def test_no_collection_id(self):
        db = MagicMock()
        body = MagicMock()
        body.collection_id = None
        body.host_ids = ["h1"]
        _resolve_collection_to_host_ids(db, "pid", body)
        db.query.assert_not_called()

    def test_collection_id_with_existing_hosts(self):
        db = MagicMock()
        body = MagicMock()
        body.collection_id = None
        body.host_ids = ["h1"]
        _resolve_collection_to_host_ids(db, "pid", body)
        assert body.host_ids == ["h1"]

    def test_collection_id_without_host_ids_resolves(self):
        db = MagicMock()
        coll = MagicMock()
        coll.filters_json = {}
        host1 = MagicMock()
        host1.id = "h_1"
        db.query.return_value.filter.return_value.first.return_value = coll
        body = MagicMock()
        body.collection_id = "coll_1"
        body.host_ids = []
        with patch("app.routers.bulk_actions.resolve_collection_hosts", return_value=[host1]):
            _resolve_collection_to_host_ids(db, "pid", body)
        assert body.host_ids == ["h_1"]

    def test_collection_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        body = MagicMock()
        body.collection_id = "coll_missing"
        body.host_ids = []
        with pytest.raises(HTTPException) as exc_info:
            _resolve_collection_to_host_ids(db, "pid", body)
        assert exc_info.value.status_code == 404


class TestResolveBulkCredential:
    def test_no_credential_id(self):
        db = MagicMock()
        user = MagicMock()
        body = MagicMock()
        body.credential_id = None
        assert _resolve_bulk_credential(db, "pid", user, body, None) is None

    def test_non_admin_no_secret_perm(self):
        db = MagicMock()
        user = MagicMock()
        membership = MagicMock()
        membership.role = "viewer"
        body = MagicMock()
        body.credential_id = "crd_1"
        body.host_ids = ["h1"]
        with patch("app.routers.bulk_actions.is_admin", return_value=False), \
             patch("app.routers.bulk_actions.get_membership", return_value=membership), \
             patch("app.routers.bulk_actions.get_permissions_for_role", return_value=[]):
            with pytest.raises(HTTPException) as exc_info:
                _resolve_bulk_credential(db, "pid", user, body, None)
            assert exc_info.value.status_code == 403

    def test_credential_not_found(self):
        db = MagicMock()
        user = MagicMock()
        body = MagicMock()
        body.credential_id = "crd_missing"
        body.host_ids = []
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.routers.bulk_actions.is_admin", return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                _resolve_bulk_credential(db, "pid", user, body, None)
            assert exc_info.value.status_code == 404

    def test_credential_no_secret(self):
        cred = MagicMock()
        cred.secret = None
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = cred
        user = MagicMock()
        body = MagicMock()
        body.credential_id = "crd_1"
        body.host_ids = []
        with patch("app.routers.bulk_actions.is_admin", return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                _resolve_bulk_credential(db, "pid", user, body, None)
            assert exc_info.value.status_code == 400

    def test_admin_with_valid_credential(self):
        cred = MagicMock()
        cred.secret = "encrypted"
        cred.id = "crd_1"
        cred.username = "admin"
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = cred
        user = MagicMock()
        user.username = "testadmin"
        body = MagicMock()
        body.credential_id = "crd_1"
        body.host_ids = ["h1"]
        with patch("app.routers.bulk_actions.is_admin", return_value=True), \
             patch("app.routers.bulk_actions.log_event"):
            result = _resolve_bulk_credential(db, "pid", user, body, "testadmin")
        assert result is cred
