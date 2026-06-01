"""Consolidated tests for test_core_output_parser (merged variant files)."""

# ════════ from test_core_output_parser.py ════════
from app.core.output_parser import (
    detect_tool,
    parse_nmap,
    parse_netexec,
    parse_secretsdump,
    parse_hydra,
    parse_output,
)


class TestDetectTool:
    def test_nmap(self):
        assert detect_tool("nmap -sV 10.0.0.1") == "nmap"

    def test_netexec(self):
        assert detect_tool("netexec smb 10.0.0.1") == "netexec"

    def test_nxc_alias(self):
        assert detect_tool("nxc smb 10.0.0.1") == "netexec"

    def test_crackmapexec_alias(self):
        assert detect_tool("crackmapexec smb 10.0.0.1") == "netexec"

    def test_cme_alias(self):
        assert detect_tool("cme smb 10.0.0.1") == "netexec"

    def test_secretsdump(self):
        assert detect_tool("impacket-secretsdump domain/user:pass@10.0.0.1") == "secretsdump"

    def test_hydra(self):
        assert detect_tool("hydra -l admin -p pass 10.0.0.1 ssh") == "hydra"

    def test_medusa_alias(self):
        assert detect_tool("medusa -h 10.0.0.1") == "hydra"

    def test_crowbar_alias(self):
        assert detect_tool("crowbar -b rdp") == "hydra"

    def test_unknown_returns_none(self):
        assert detect_tool("curl http://example.com") is None

    def test_empty(self):
        assert detect_tool("") is None


class TestParseNmapText:
    def test_single_host(self):
        output = (
            "Nmap scan report for 10.0.0.1\n"
            "Host is up (0.001s latency).\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh     OpenSSH 8.9\n"
            "80/tcp   open  http    nginx 1.24\n"
        )
        hosts = parse_nmap(output)
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.0.1"
        assert "22/tcp" in hosts[0]["ports"]
        assert "80/tcp" in hosts[0]["ports"]

    def test_host_with_hostname(self):
        output = "Nmap scan report for dc01.corp.local (10.0.0.1)\n"
        hosts = parse_nmap(output)
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.0.1"
        assert hosts[0]["hostname"] == "dc01.corp.local"

    def test_os_detection(self):
        output = (
            "Nmap scan report for 10.0.0.1\n"
            "OS details: Windows Server 2019\n"
        )
        hosts = parse_nmap(output)
        assert hosts[0]["os"] == "Windows Server 2019"

    def test_aggressive_os_guess(self):
        output = (
            "Nmap scan report for 10.0.0.1\n"
            "Aggressive OS guesses: Linux 5.4 (96%)\n"
        )
        hosts = parse_nmap(output)
        assert hosts[0]["os"] == "Linux 5.4"

    def test_multiple_hosts(self):
        output = (
            "Nmap scan report for 10.0.0.1\n"
            "22/tcp open ssh\n"
            "Nmap scan report for 10.0.0.2\n"
            "80/tcp open http\n"
        )
        hosts = parse_nmap(output)
        assert len(hosts) == 2

    def test_empty_output(self):
        assert parse_nmap("") == []

    def test_services_extracted(self):
        output = (
            "Nmap scan report for 10.0.0.1\n"
            "22/tcp open  ssh     OpenSSH 8.9p1\n"
        )
        hosts = parse_nmap(output)
        assert any("ssh" in s for s in hosts[0]["services"])


class TestParseNmapXml:
    def test_basic_xml(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addrtype="ipv4" addr="10.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        hosts = parse_nmap(xml)
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.0.1"
        assert "22/tcp" in hosts[0]["ports"]
        assert any("ssh" in s for s in hosts[0]["services"])

    def test_down_host_excluded(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <address addrtype="ipv4" addr="10.0.0.1"/>
  </host>
</nmaprun>"""
        hosts = parse_nmap(xml)
        assert len(hosts) == 0

    def test_no_ipv4_excluded(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addrtype="mac" addr="AA:BB:CC:DD:EE:FF"/>
  </host>
</nmaprun>"""
        hosts = parse_nmap(xml)
        assert len(hosts) == 0

    def test_closed_port_excluded(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addrtype="ipv4" addr="10.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        hosts = parse_nmap(xml)
        assert hosts[0]["ports"] == []

    def test_invalid_xml(self):
        assert parse_nmap("<invalid xml") == []

    def test_xml_hostname(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addrtype="ipv4" addr="10.0.0.1"/>
    <hostnames>
      <hostname type="user" name="dc01.corp.local"/>
    </hostnames>
  </host>
</nmaprun>"""
        hosts = parse_nmap(xml)
        assert hosts[0]["hostname"] == "dc01.corp.local"

    def test_xml_os(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addrtype="ipv4" addr="10.0.0.1"/>
    <os><osmatch name="Windows Server 2019"/></os>
  </host>
</nmaprun>"""
        hosts = parse_nmap(xml)
        assert hosts[0]["os"] == "Windows Server 2019"


class TestParseNetexec:
    def test_host_detection(self):
        output = "SMB    10.0.0.1    445    DC01    [+] domain:CORP.LOCAL"
        result = parse_netexec(output)
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip"] == "10.0.0.1"
        assert result["hosts"][0]["hostname"] == "DC01"

    def test_credential_extraction(self):
        output = (
            "SMB    10.0.0.1    445    DC01    [*]\n"
            "[+] CORP\\admin:Password123\n"
        )
        result = parse_netexec(output)
        assert len(result["creds"]) == 1
        assert result["creds"][0]["username"] == "admin"
        assert result["creds"][0]["secret"] == "Password123"
        assert result["creds"][0]["type"] == "plain"

    def test_hash_credential(self):
        output = (
            "SMB    10.0.0.1    445    DC01    [*]\n"
            "[+] CORP\\admin:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
        )
        result = parse_netexec(output)
        assert len(result["creds"]) == 1
        assert result["creds"][0]["type"] == "hash"

    def test_pwned_detection(self):
        output = (
            "SMB    10.0.0.1    445    DC01    [*]\n"
            "[+] CORP\\admin:Password123 (Pwn3d!)\n"
        )
        result = parse_netexec(output)
        assert len(result["creds"]) == 1
        assert result["creds"][0]["pwned"] is True

    def test_empty_output(self):
        result = parse_netexec("")
        assert result["hosts"] == []
        assert result["creds"] == []

    def test_domain_extraction(self):
        output = "SMB    10.0.0.1    445    DC01    [*] (domain:CORP.LOCAL) signing:True"
        result = parse_netexec(output)
        assert result["hosts"][0]["domain"] == "CORP.LOCAL"

    def test_os_extraction(self):
        output = "SMB    10.0.0.1    445    DC01    [*] Windows Server 2019 (domain:CORP.LOCAL)"
        result = parse_netexec(output)
        assert "Windows Server" in result["hosts"][0]["os"]

    def test_signing_detection(self):
        output = "SMB    10.0.0.1    445    DC01    [*] (signing:True)"
        result = parse_netexec(output)
        assert result["hosts"][0]["smb_signing"] is True

    def test_empty_secret_skipped(self):
        output = (
            "SMB    10.0.0.1    445    DC01    [*]\n"
            "[+] CORP\\admin:<empty>\n"
        )
        result = parse_netexec(output)
        assert len(result["creds"]) == 0


class TestParseSecretsdump:
    def test_ntlm_hash(self):
        output = "CORP\\admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        result = parse_secretsdump(output)
        assert len(result["creds"]) == 1
        assert result["creds"][0]["username"] == "admin"
        assert result["creds"][0]["domain"] == "CORP"
        assert result["creds"][0]["type"] == "ntlm"

    def test_no_domain(self):
        output = "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        result = parse_secretsdump(output)
        assert result["creds"][0]["domain"] == ""

    def test_multiple_hashes(self):
        output = (
            "CORP\\admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "CORP\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
        result = parse_secretsdump(output)
        assert len(result["creds"]) == 2

    def test_empty_output(self):
        result = parse_secretsdump("")
        assert result["creds"] == []


class TestParseHydra:
    def test_hydra_format(self):
        output = (
            "[22][ssh] host: 10.0.0.1   login: admin   password: Secret123"
        )
        result = parse_hydra(output)
        assert len(result["creds"]) == 1
        assert result["creds"][0]["host"] == "10.0.0.1"
        assert result["creds"][0]["username"] == "admin"
        assert result["creds"][0]["secret"] == "Secret123"
        assert result["creds"][0]["type"] == "plain"

    def test_medusa_format(self):
        output = (
            "ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: admin Password: P@ss (SUCCESS)"
        )
        result = parse_hydra(output)
        assert len(result["creds"]) == 1
        assert result["creds"][0]["host"] == "10.0.0.1"
        assert result["creds"][0]["username"] == "admin"

    def test_empty_output(self):
        result = parse_hydra("")
        assert result["creds"] == []


class TestParseOutput:
    def test_nmap_dispatch(self):
        result = parse_output("nmap -sV 10.0.0.1", "Nmap scan report for 10.0.0.1\n")
        assert result["tool"] == "nmap"
        assert len(result["hosts"]) == 1

    def test_netexec_dispatch(self):
        result = parse_output("netexec smb 10.0.0.1", "SMB    10.0.0.1    445    DC01")
        assert result["tool"] == "netexec"

    def test_secretsdump_dispatch(self):
        result = parse_output("secretsdump domain/admin@10.0.0.1", "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::")
        assert result["tool"] == "secretsdump"
        assert len(result["creds"]) == 1

    def test_hydra_dispatch(self):
        result = parse_output("hydra -l admin 10.0.0.1 ssh", "[22][ssh] host: 10.0.0.1 login: admin password: x")
        assert result["tool"] == "hydra"

    def test_unknown_tool(self):
        result = parse_output("curl http://example.com", "some output")
        assert result["tool"] is None
        assert result["hosts"] == []
        assert result["creds"] == []

    def test_empty_output(self):
        result = parse_output("nmap 10.0.0.1", "")
        assert result["hosts"] == []


# ════════ from test_core_output_parser_extended.py ════════
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
