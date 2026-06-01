import pytest
from unittest.mock import MagicMock

from app.core.result_normalizer import (
    _extract_adcs_templates,
    _nxc_detect_proto,
    _nxc_classify_line,
    _nxc_scan_output_lines,
    _ssh_exec_infer_role,
    _ssh_exec_op_adcs,
    _ssh_exec_op_delegation,
    StructuredResult,
    finding_candidate,
)


class TestExtractAdcsTemplates:
    def test_basic(self):
        output = """
Template Name : VulnTemplate
Template Name : SafeTemplate
Other line
"""
        r = _extract_adcs_templates(output)
        assert "VulnTemplate" in r
        assert "SafeTemplate" in r

    def test_empty(self):
        assert _extract_adcs_templates("") == []

    def test_no_templates(self):
        assert _extract_adcs_templates("no templates here") == []


class TestNxcDetectProto:
    def test_winrm(self):
        assert _nxc_detect_proto("netexec winrm 10.0.0.1", "") == "winrm"

    def test_mssql(self):
        assert _nxc_detect_proto("", "netexec mssql connection") == "mssql"

    def test_ldap(self):
        assert _nxc_detect_proto("netexec ldap 10.0.0.1", "") == "ldap"

    def test_rdp(self):
        assert _nxc_detect_proto("", "netexec rdp 10.0.0.1") == "rdp"

    def test_smb_default(self):
        assert _nxc_detect_proto("netexec smb 10.0.0.1", "") == "smb"

    def test_empty(self):
        assert _nxc_detect_proto("", "") == "smb"


class TestNxcClassifyLine:
    def test_pwned(self):
        p, s, f, sys, da = [], [], [], [], []
        _nxc_classify_line("10.0.0.1  (Pwn3d!) admin", p, s, f, sys, da)
        assert len(p) == 1

    def test_success(self):
        p, s, f, sys, da = [], [], [], [], []
        _nxc_classify_line("[+] 10.0.0.1 admin:pass", p, s, f, sys, da)
        assert len(s) == 1

    def test_failed(self):
        p, s, f, sys, da = [], [], [], [], []
        _nxc_classify_line("[-] 10.0.0.1 failed", p, s, f, sys, da)
        assert len(f) == 1

    def test_sysadmin(self):
        p, s, f, sys, da = [], [], [], [], []
        _nxc_classify_line("[+] 10.0.0.1 admin:pass (SYSADMIN)", p, s, f, sys, da)
        assert len(sys) == 1

    def test_da(self):
        p, s, f, sys, da = [], [], [], [], []
        _nxc_classify_line("[+] 10.0.0.1 admin:pass (Domain Admins)", p, s, f, sys, da)
        assert len(da) == 1

    def test_no_ip(self):
        p, s, f, sys, da = [], [], [], [], []
        _nxc_classify_line("no ip here", p, s, f, sys, da)
        assert len(p) == 0


class TestNxcScanOutputLines:
    def test_mixed(self):
        output = """10.0.0.1  (Pwn3d!) admin
[+] 10.0.0.2 user:pass
[-] 10.0.0.3 failed
"""
        pwned, success, failed, sysadmin, da = _nxc_scan_output_lines(output)
        assert len(pwned) == 1
        assert len(success) == 1
        assert len(failed) == 1


class TestSshExecInferRole:
    def test_pwned(self):
        r = StructuredResult(ok=True)
        _ssh_exec_infer_role(r, {}, {}, "output (Pwn3d!) more text")
        assert r.access_role == "local_admin"

    def test_root(self):
        r = StructuredResult(ok=True)
        _ssh_exec_infer_role(r, {}, {}, "root@host#")
        assert r.access_role == "shell"

    def test_from_req(self):
        r = StructuredResult(ok=True)
        _ssh_exec_infer_role(r, {"access_role": "user"}, {}, "normal output")
        assert r.access_role == "user"

    def test_from_res(self):
        r = StructuredResult(ok=True)
        _ssh_exec_infer_role(r, {}, {"access_role": "admin"}, "normal output")
        assert r.access_role == "admin"


class TestSshExecOpAdcs:
    def test_vuln(self):
        r = StructuredResult(ok=True)
        _ssh_exec_op_adcs(r, "ESC1 ESC2 found\nTemplate Name : SubCA", None)
        assert len(r.finding_candidates) == 1
        assert r.counts["vulnerable_templates"] == 2

    def test_no_vuln(self):
        r = StructuredResult(ok=True)
        _ssh_exec_op_adcs(r, "no vulnerable templates", None)
        assert len(r.finding_candidates) == 0
        assert "no vulnerable templates" in r.summary


class TestSshExecOpDelegation:
    def test_unconstrained(self):
        r = StructuredResult(ok=True)
        _ssh_exec_op_delegation(r, "unconstrained delegation found", None)
        assert len(r.finding_candidates) == 1
        assert r.counts["unconstrained"] == 1

    def test_constrained(self):
        r = StructuredResult(ok=True)
        _ssh_exec_op_delegation(r, "constrained delegation msDS-AllowedToDelegateTo", None)
        assert r.counts["constrained"] >= 1

    def test_none(self):
        r = StructuredResult(ok=True)
        _ssh_exec_op_delegation(r, "no delegation", None)
        assert r.counts["unconstrained"] == 0
