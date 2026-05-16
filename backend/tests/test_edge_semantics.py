"""
Tests for app.core.edge_semantics.classify_edge.

The function derives (transport, kind) from existing edge fields without
touching the database. Goal: every edge produced by Smart Build / manual
edits / BloodHound import lands in one of the documented categories.
"""
import pytest

from app.core.edge_semantics import classify_edge


# ── Direct protocol matches ──────────────────────────────────────────

@pytest.mark.parametrize("etype,expected_transport", [
    ("ssh", "ssh"),
    ("ssh_admin", "ssh"),
    ("ssh_user", "ssh"),
    ("winrm", "winrm"),
    ("winrm_admin", "winrm"),
    ("smb", "smb"),
    ("smb_admin", "smb"),
    ("rdp", "rdp"),
    ("rdp_user", "rdp"),
    ("c2_session", "c2"),
    ("ldap", "ldap"),
    ("mssql", "mssql"),
    ("mssql_admin", "mssql"),
    ("http_admin", "http"),
    ("web", "http"),
])
def test_direct_transport_match(etype, expected_transport):
    transport, _ = classify_edge({"type": etype})
    assert transport == expected_transport


# ── Case insensitivity ───────────────────────────────────────────────

def test_uppercase_type_normalized():
    transport, kind = classify_edge({"type": "SSH_ADMIN"})
    assert transport == "ssh"
    assert kind == "access"


# ── Kind classification ──────────────────────────────────────────────

@pytest.mark.parametrize("etype,expected_kind", [
    ("uplink", "uplink"),
    ("same_subnet", "network"),
    ("lan", "network"),
    ("internet_facing", "network"),
    ("domain_member", "domain"),
    ("trust", "domain"),
    ("pivot", "pivot"),
    ("lateral", "lateral"),
    ("service_dep", "service"),
    ("shell", "access"),
    ("c2_session", "access"),
    ("local_admin", "access"),
    ("auth_path", "access"),
])
def test_kind_classification(etype, expected_kind):
    _, kind = classify_edge({"type": etype})
    assert kind == expected_kind


def test_unknown_type_falls_to_other():
    _, kind = classify_edge({"type": "totally_made_up"})
    assert kind == "other"


def test_empty_type_falls_to_other():
    transport, kind = classify_edge({})
    assert transport == ""
    assert kind == "other"


# ── Generic admin falls back to SMB, refined by access_roles ─────────

class TestGenericAdminTransport:
    def test_local_admin_defaults_to_smb(self):
        transport, kind = classify_edge({"type": "local_admin"})
        assert transport == "smb"
        assert kind == "access"

    def test_domain_admin_defaults_to_smb(self):
        transport, _ = classify_edge({"type": "domain_admin"})
        assert transport == "smb"

    def test_local_admin_with_winrm_role_picks_winrm(self):
        """access_roles[0] = winrm_admin → transport=winrm even though type=local_admin."""
        transport, _ = classify_edge({
            "type": "local_admin",
            "access_roles": ["winrm_admin", "local_admin"],
        })
        assert transport == "winrm"

    def test_local_admin_with_ssh_role_picks_ssh(self):
        transport, _ = classify_edge({
            "type": "local_admin",
            "access_roles": ["ssh_admin"],
        })
        assert transport == "ssh"

    def test_local_admin_with_unrecognised_role_keeps_smb(self):
        transport, _ = classify_edge({
            "type": "local_admin",
            "access_roles": ["whatever"],
        })
        assert transport == "smb"


# ── Shell / auth_path don't claim a transport ────────────────────────

class TestNeutralTransport:
    def test_shell_has_no_transport_claim(self):
        """Shell is too generic — we don't pretend we know the protocol."""
        transport, kind = classify_edge({"type": "shell"})
        assert transport == ""
        assert kind == "access"

    def test_auth_path_has_no_transport(self):
        transport, kind = classify_edge({"type": "auth_path"})
        assert transport == ""
        assert kind == "access"

    def test_uplink_has_no_transport(self):
        """Uplink is the attacker's entry, transport is whatever the WAN allows."""
        transport, _ = classify_edge({"type": "uplink"})
        assert transport == ""


# ── Smart Build common patterns ──────────────────────────────────────

class TestSmartBuildPatterns:
    def test_p1_cred_validation_winrm(self):
        """P1 produces edges where type comes from CredHostNote.access[0]."""
        edge = {"type": "winrm_admin", "source": "cred_validation",
                "access_roles": ["winrm_admin"]}
        transport, kind = classify_edge(edge)
        assert transport == "winrm"
        assert kind == "access"

    def test_p3_c2_session_routes_through_pivot(self):
        edge = {"type": "c2_session", "source": "auto"}
        transport, kind = classify_edge(edge)
        assert transport == "c2"
        assert kind == "access"

    def test_p5_subnet_is_network(self):
        edge = {"type": "same_subnet", "source": "auto"}
        transport, kind = classify_edge(edge)
        assert transport == ""
        assert kind == "network"

    def test_p6_pivot_via_vpn_gw(self):
        edge = {"type": "pivot", "source": "auto_pivot"}
        transport, kind = classify_edge(edge)
        assert transport == ""
        assert kind == "pivot"

    def test_dc_to_member_is_domain(self):
        edge = {"type": "domain_member", "source": "auto"}
        transport, kind = classify_edge(edge)
        assert transport == "ldap"
        assert kind == "domain"
