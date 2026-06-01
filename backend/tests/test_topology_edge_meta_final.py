import pytest
from datetime import datetime, timezone, timedelta

from app.routers.topology._edge_meta import (
    _is_key_host,
    _is_rfc1918,
    _role_from_tags,
    _role_from_hostname_patterns,
    _role_from_ports,
    _auto_assign_host_role,
    _edge_action_tags,
    _decay_confidence,
    _ip_in_network,
    _score_pivot_candidate,
    _find_pivot_host,
)
import ipaddress


class TestIsKeyHost:
    def test_attacker(self):
        assert _is_key_host({"is_attacker": True}) is True

    def test_dc_role(self):
        assert _is_key_host({"role": "domain_controller"}) is True

    def test_tag_match(self):
        assert _is_key_host({"tags": ["attacker"]}) is True

    def test_router_tag(self):
        assert _is_key_host({"tags": ["router"]}) is True

    def test_not_key(self):
        assert _is_key_host({"role": "workstation", "tags": []}) is False


class TestIsRfc1918:
    def test_10_net(self):
        assert _is_rfc1918("10.0.0.1") is True

    def test_172_net(self):
        assert _is_rfc1918("172.16.0.1") is True

    def test_192_net(self):
        assert _is_rfc1918("192.168.1.1") is True

    def test_public(self):
        assert _is_rfc1918("8.8.8.8") is False

    def test_invalid(self):
        assert _is_rfc1918("invalid") is True

    def test_loopback(self):
        assert _is_rfc1918("127.0.0.1") is True


class TestRoleFromTags:
    def test_dc(self):
        assert _role_from_tags({"dc"}) == "domain_controller"

    def test_domain_controller(self):
        assert _role_from_tags({"domain-controller"}) == "domain_controller"

    def test_router(self):
        assert _role_from_tags({"router"}) == "router"

    def test_database(self):
        assert _role_from_tags({"database"}) == "database"

    def test_mail(self):
        assert _role_from_tags({"mail"}) == "mail"

    def test_web(self):
        assert _role_from_tags({"web"}) == "web"

    def test_no_match(self):
        assert _role_from_tags({"unknown"}) is None


class TestRoleFromHostnamePatterns:
    def test_dc(self):
        assert _role_from_hostname_patterns("DC01") == "domain_controller"

    def test_web(self):
        assert _role_from_hostname_patterns("WEB01") == "web"

    def test_sql(self):
        assert _role_from_hostname_patterns("MSSQL01") == "database"

    def test_mail(self):
        assert _role_from_hostname_patterns("EXCHANGE01") == "mail"

    def test_vpn(self):
        assert _role_from_hostname_patterns("VPN01") == "router"

    def test_no_match(self):
        assert _role_from_hostname_patterns("WORKSTATION01") is None

    def test_dash_prefix(self):
        assert _role_from_hostname_patterns("DC-SERVER") == "domain_controller"

    def test_dot_prefix(self):
        assert _role_from_hostname_patterns("DC.SERVER") == "domain_controller"


class TestRoleFromPorts:
    def test_dc_ports(self):
        assert _role_from_ports({"88/tcp", "389/tcp"}, "", "") == "domain_controller"

    def test_db_ports(self):
        assert _role_from_ports({"1433/tcp"}, "", "") == "database"

    def test_mail_ports(self):
        assert _role_from_ports({"25/tcp"}, "", "") == "mail"

    def test_web_ports(self):
        assert _role_from_ports({"80/tcp"}, "", "") == "web"

    def test_smb_with_domain(self):
        assert _role_from_ports({"445/tcp"}, "corp.local", "") == "workstation"

    def test_ssh_only(self):
        assert _role_from_ports({"22/tcp"}, "", "") == "server"

    def test_domain_only(self):
        assert _role_from_ports(set(), "corp.local", "") == "workstation"

    def test_empty(self):
        assert _role_from_ports(set(), "", "") is None


class TestEdgeActionTags:
    def test_cred_validation(self):
        tags = _edge_action_tags("cred_validation")
        assert "T1078" in tags["mitre_techniques"]

    def test_bulk_exec(self):
        tags = _edge_action_tags("bulk_exec")
        assert tags["noise_level"] == "high"

    def test_host_activity_c2(self):
        tags = _edge_action_tags("host_activity", "c2")
        assert "T1071" in tags["mitre_techniques"]

    def test_host_activity_lateral(self):
        tags = _edge_action_tags("host_activity", "lateral")
        assert "T1021" in tags["mitre_techniques"]

    def test_host_activity_postex(self):
        tags = _edge_action_tags("host_activity", "postex")
        assert tags["noise_level"] == "high"

    def test_host_activity_default(self):
        tags = _edge_action_tags("host_activity", "other")
        assert tags["noise_level"] == "med"

    def test_pivot_observation(self):
        tags = _edge_action_tags("pivot_observation")
        assert "T1090" in tags["mitre_techniques"]

    def test_unknown(self):
        assert _edge_action_tags("unknown") == {}


class TestDecayConfidence:
    def test_zero_tau(self):
        c, expired = _decay_confidence(0.9, "2025-01-01T00:00:00Z", 0)
        assert c == 0.9
        assert expired is False

    def test_negative_tau(self):
        c, expired = _decay_confidence(0.9, "2025-01-01T00:00:00Z", -1)
        assert c == 0.9

    def test_empty_ts(self):
        c, expired = _decay_confidence(0.9, "", 30)
        assert c == 0.9

    def test_invalid_ts(self):
        c, expired = _decay_confidence(0.9, "not-a-date", 30)
        assert c == 0.9


class TestIpInNetwork:
    def test_in_network(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _ip_in_network("10.0.0.5", net) is True

    def test_not_in_network(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _ip_in_network("192.168.1.1", net) is False

    def test_invalid_ip(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _ip_in_network("invalid", net) is False


class TestScorePivotCandidate:
    def test_no_ip(self):
        assert _score_pivot_candidate({"ip": ""}, [], None, set()) is None

    def test_excluded_ip(self):
        assert _score_pivot_candidate({"ip": "10.0.0.1"}, [], None, {"10.0.0.1"}) is None

    def test_not_in_entry_nets(self):
        net = ipaddress.ip_network("192.168.0.0/24")
        assert _score_pivot_candidate({"ip": "10.0.0.1"}, [net], None, set()) is None

    def test_in_remote_net(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        assert _score_pivot_candidate({"ip": "10.0.0.1"}, [net], net, set()) is None

    def test_not_junction(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        result = _score_pivot_candidate({"ip": "10.0.0.1", "role": "workstation", "tags": [], "hostname": "ws1"}, [net], ipaddress.ip_network("192.168.0.0/24"), set())
        assert result is None

    def test_valid_pivot(self):
        entry = ipaddress.ip_network("10.0.0.0/24")
        remote = ipaddress.ip_network("192.168.0.0/24")
        score = _score_pivot_candidate({"ip": "10.0.0.1", "role": "router", "tags": [], "hostname": "gw1"}, [entry], remote, set())
        assert score is not None
        assert score > 0


class TestFindPivotHost:
    def test_empty(self):
        result = _find_pivot_host(ipaddress.ip_network("192.168.0.0/24"), [], [], set())
        assert result is None

    def test_finds_best(self):
        entry = ipaddress.ip_network("10.0.0.0/24")
        remote = ipaddress.ip_network("192.168.0.0/24")
        scope_defs = [{"net_obj": entry, "is_entry": True}]
        hosts = [{"ip": "10.0.0.1", "role": "router", "tags": [], "hostname": "gw"}]
        result = _find_pivot_host(remote, scope_defs, hosts, set())
        assert result is not None
        assert result["ip"] == "10.0.0.1"
