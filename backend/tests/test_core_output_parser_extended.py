"""Extended tests for app.core.output_parser — additional edge cases."""

from app.core.output_parser import (
    detect_tool,
    parse_nmap,
    parse_netexec,
    parse_secretsdump,
    parse_hydra,
    parse_output,
    _nmap_text_parse_host_line,
    _nmap_text_try_os,
    _nmap_text_try_port,
    _nxc_update_host,
    _nxc_collect_cred,
)


class TestNmapTextParseHostLine:
    def test_ip_only(self):
        r = _nmap_text_parse_host_line("Nmap scan report for 10.0.0.1")
        assert r is not None
        assert r["ip"] == "10.0.0.1"
        assert r["hostname"] == ""

    def test_hostname_with_ip(self):
        r = _nmap_text_parse_host_line("Nmap scan report for dc01.corp.local (10.0.0.1)")
        assert r is not None
        assert r["ip"] == "10.0.0.1"
        assert r["hostname"] == "dc01.corp.local"

    def test_non_host_line(self):
        assert _nmap_text_parse_host_line("PORT    STATE SERVICE") is None

    def test_empty_line(self):
        assert _nmap_text_parse_host_line("") is None


class TestNmapTextTryOs:
    def test_os_details(self):
        current = {"os": ""}
        assert _nmap_text_try_os("OS details: Linux 5.4", current) is True
        assert current["os"] == "Linux 5.4"

    def test_aggressive_os_guess(self):
        current = {"os": ""}
        assert _nmap_text_try_os("Aggressive OS guesses: Windows 10 (95%)", current) is True
        assert current["os"] == "Windows 10"

    def test_already_set(self):
        current = {"os": "Linux"}
        assert _nmap_text_try_os("OS details: FreeBSD", current) is False
        assert current["os"] == "Linux"

    def test_non_os_line(self):
        current = {"os": ""}
        assert _nmap_text_try_os("22/tcp open ssh", current) is False


class TestNmapTextTryPort:
    def test_tcp_port(self):
        current = {"ports": [], "services": []}
        _nmap_text_try_port("22/tcp   open  ssh     OpenSSH 8.9", current)
        assert "22/tcp" in current["ports"]
        assert any("ssh" in s for s in current["services"])

    def test_udp_port(self):
        current = {"ports": [], "services": []}
        _nmap_text_try_port("53/udp   open  domain", current)
        assert "53/udp" in current["ports"]

    def test_duplicate_port_skipped(self):
        current = {"ports": ["22/tcp"], "services": []}
        _nmap_text_try_port("22/tcp   open  ssh", current)
        assert current["ports"].count("22/tcp") == 1

    def test_non_port_line(self):
        current = {"ports": [], "services": []}
        _nmap_text_try_port("some random text", current)
        assert current["ports"] == []


class TestNxcUpdateHost:
    def test_creates_new_host(self):
        import re
        hosts = {}
        m = re.match(r"SMB\s+([\d.]+)\s+(\d+)\s+(\S+)\s+\[", "SMB    10.0.0.1    445    DC01    [")
        _nxc_update_host("SMB    10.0.0.1    445    DC01    [", m, hosts)
        assert "10.0.0.1" in hosts
        assert hosts["10.0.0.1"]["hostname"] == "DC01"

    def test_updates_existing_host(self):
        import re
        hosts = {"10.0.0.1": {"ip": "10.0.0.1", "hostname": "DC01", "domain": "", "ports": ["445/tcp"], "services": [], "os": "", "smb_signing": None}}
        m = re.match(r"WINRM\s+([\d.]+)\s+(\d+)\s+(\S+)\s+\[", "WINRM    10.0.0.1    5985    DC01    [")
        _nxc_update_host("WINRM    10.0.0.1    5985    DC01    [", m, hosts)
        assert "5985/tcp" in hosts["10.0.0.1"]["ports"]


class TestNxcCollectCred:
    def test_plain_cred(self):
        creds = []
        _nxc_collect_cred("[+] CORP\\admin:Password123", creds)
        assert len(creds) == 1
        assert creds[0]["username"] == "admin"
        assert creds[0]["type"] == "plain"

    def test_hash_cred(self):
        creds = []
        _nxc_collect_cred("[+] admin:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", creds)
        assert len(creds) == 1
        assert creds[0]["type"] == "hash"

    def test_no_plus_sign(self):
        creds = []
        _nxc_collect_cred("[-] CORP\\admin:badpass", creds)
        assert len(creds) == 0

    def test_empty_secret_skipped(self):
        creds = []
        _nxc_collect_cred("[+] admin:", creds)
        assert len(creds) == 0


class TestParseNmapEdgeCases:
    def test_nmaprun_prefix_without_xml_header(self):
        xml = "<nmaprun><host><status state='up'/><address addrtype='ipv4' addr='10.0.0.1'/></host></nmaprun>"
        hosts = parse_nmap(xml)
        assert len(hosts) == 1

    def test_empty_addr_excluded(self):
        xml = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addrtype="ipv4" addr=""/></host></nmaprun>"""
        assert parse_nmap(xml) == []


class TestParseOutputEdgeCases:
    def test_none_output(self):
        result = parse_output("nmap 10.0.0.1", "")
        assert result["hosts"] == []
        assert result["creds"] == []

    def test_tool_detected_empty_output(self):
        result = parse_output("nmap 10.0.0.1", "")
        assert result["tool"] == "nmap"

    def test_unknown_tool_with_output(self):
        result = parse_output("somecmd args", "output")
        assert result["tool"] is None
        assert result["hosts"] == []


class TestParseSecretsdumpEdgeCases:
    def test_non_hash_line_ignored(self):
        output = "Some random text that is not a hash"
        result = parse_secretsdump(output)
        assert result["creds"] == []

    def test_mixed_lines(self):
        output = (
            "CORP\\admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "This is not a hash line\n"
            "CORP\\user:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
        result = parse_secretsdump(output)
        assert len(result["creds"]) == 2


class TestParseHydraEdgeCases:
    def test_no_matching_format(self):
        result = parse_hydra("just some random output\nno creds here")
        assert result["creds"] == []

    def test_hydra_service_extraction(self):
        output = "[22][ssh] host: 10.0.0.1   login: root   password: toor"
        result = parse_hydra(output)
        assert result["creds"][0]["username"] == "root"
        assert result["creds"][0]["secret"] == "toor"
