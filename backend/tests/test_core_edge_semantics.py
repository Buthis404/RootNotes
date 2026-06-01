"""Unit tests for app.core.edge_semantics — edge transport/kind classifier."""
from app.core.edge_semantics import classify_edge


class TestClassifyEdgeSsh:
    def test_ssh(self):
        t, k = classify_edge({"type": "ssh"})
        assert t == "ssh"
        assert k == "access"

    def test_ssh_user(self):
        t, k = classify_edge({"type": "ssh_user"})
        assert t == "ssh"
        assert k == "access"

    def test_ssh_admin(self):
        t, k = classify_edge({"type": "ssh_admin"})
        assert t == "ssh"
        assert k == "access"


class TestClassifyEdgeWinrm:
    def test_winrm(self):
        t, k = classify_edge({"type": "winrm"})
        assert t == "winrm"
        assert k == "access"

    def test_winrm_admin(self):
        t, k = classify_edge({"type": "winrm_admin"})
        assert t == "winrm"
        assert k == "access"

    def test_winrm_user(self):
        t, k = classify_edge({"type": "winrm_user"})
        assert t == "winrm"
        assert k == "access"


class TestClassifyEdgeSmb:
    def test_smb(self):
        t, k = classify_edge({"type": "smb"})
        assert t == "smb"
        assert k == "access"

    def test_smb_admin(self):
        t, k = classify_edge({"type": "smb_admin"})
        assert t == "smb"
        assert k == "access"

    def test_smb_user(self):
        t, k = classify_edge({"type": "smb_user"})
        assert t == "smb"
        assert k == "access"


class TestClassifyEdgeRdp:
    def test_rdp(self):
        t, k = classify_edge({"type": "rdp"})
        assert t == "rdp"
        assert k == "access"

    def test_rdp_admin(self):
        t, k = classify_edge({"type": "rdp_admin"})
        assert t == "rdp"
        assert k == "access"

    def test_rdp_user(self):
        t, k = classify_edge({"type": "rdp_user"})
        assert t == "rdp"
        assert k == "access"


class TestClassifyEdgeC2:
    def test_c2_session(self):
        t, k = classify_edge({"type": "c2_session"})
        assert t == "c2"
        assert k == "access"


class TestClassifyEdgeLdap:
    def test_ldap(self):
        t, k = classify_edge({"type": "ldap"})
        assert t == "ldap"
        assert k == "other"

    def test_domain_member(self):
        t, k = classify_edge({"type": "domain_member"})
        assert t == "ldap"
        assert k == "domain"


class TestClassifyEdgeMssql:
    def test_mssql(self):
        t, k = classify_edge({"type": "mssql"})
        assert t == "mssql"
        assert k == "other"

    def test_mssql_admin(self):
        t, k = classify_edge({"type": "mssql_admin"})
        assert t == "mssql"
        assert k == "access"


class TestClassifyEdgeHttp:
    def test_http_admin(self):
        t, k = classify_edge({"type": "http_admin"})
        assert t == "http"
        assert k == "access"

    def test_web(self):
        t, k = classify_edge({"type": "web"})
        assert t == "http"
        assert k == "other"

    def test_web_admin(self):
        t, k = classify_edge({"type": "web_admin"})
        assert t == "http"
        assert k == "other"


class TestClassifyEdgeNetworkKinds:
    def test_uplink(self):
        t, k = classify_edge({"type": "uplink"})
        assert k == "uplink"

    def test_same_subnet(self):
        t, k = classify_edge({"type": "same_subnet"})
        assert k == "network"

    def test_lan(self):
        t, k = classify_edge({"type": "lan"})
        assert k == "network"

    def test_internet_facing(self):
        t, k = classify_edge({"type": "internet_facing"})
        assert k == "network"

    def test_trust(self):
        t, k = classify_edge({"type": "trust"})
        assert k == "domain"

    def test_pivot(self):
        t, k = classify_edge({"type": "pivot"})
        assert k == "pivot"

    def test_lateral(self):
        t, k = classify_edge({"type": "lateral"})
        assert k == "lateral"

    def test_service_dep(self):
        t, k = classify_edge({"type": "service_dep"})
        assert k == "service"

    def test_shell(self):
        t, k = classify_edge({"type": "shell"})
        assert k == "access"
        assert t == ""

    def test_auth_path(self):
        t, k = classify_edge({"type": "auth_path"})
        assert k == "access"
        assert t == ""


class TestClassifyEdgeGenericAccess:
    def test_local_admin_default_smb(self):
        t, k = classify_edge({"type": "local_admin"})
        assert t == "smb"
        assert k == "access"

    def test_domain_admin_default_smb(self):
        t, k = classify_edge({"type": "domain_admin"})
        assert t == "smb"
        assert k == "access"

    def test_local_admin_with_access_roles_winrm(self):
        t, k = classify_edge({"type": "local_admin", "access_roles": ["winrm_admin"]})
        assert t == "winrm"
        assert k == "access"

    def test_local_admin_with_access_roles_ssh(self):
        t, k = classify_edge({"type": "local_admin", "access_roles": ["ssh_admin"]})
        assert t == "ssh"

    def test_local_admin_with_empty_roles(self):
        t, k = classify_edge({"type": "local_admin", "access_roles": []})
        assert t == "smb"

    def test_local_admin_with_unknown_roles(self):
        t, k = classify_edge({"type": "local_admin", "access_roles": ["unknown_role"]})
        assert t == "smb"


class TestClassifyEdgeFallback:
    def test_unknown_type(self):
        t, k = classify_edge({"type": "something_else"})
        assert t == ""
        assert k == "other"

    def test_empty_type(self):
        t, k = classify_edge({"type": ""})
        assert t == ""
        assert k == "other"

    def test_none_type(self):
        t, k = classify_edge({})
        assert t == ""
        assert k == "other"

    def test_whitespace_type(self):
        t, k = classify_edge({"type": "  ssh  "})
        assert t == "ssh"
        assert k == "access"

    def test_case_insensitive(self):
        t, k = classify_edge({"type": "SSH"})
        assert t == "ssh"
        assert k == "access"
