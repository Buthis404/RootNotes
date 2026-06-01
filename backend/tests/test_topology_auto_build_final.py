import pytest


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200, f"login: {r.status_code} {r.text}"
    r = module_client.post("/api/projects", json={"name": "TopologyABTest", "added": "2025-01-01T00:00:00Z", "status": "active"})
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "TopologyABTest")
    yield


_state = {}


class TestTopologyAutoBuildEndpoint:
    def test_auto_build_no_hosts(self, module_client):
        pid = _state["pid"]
        r = module_client.post(f"/api/projects/{pid}/topology/auto-build", json={})
        assert r.status_code in (200, 404)


class TestTopologyNodeTypes:
    def test_node_type_for_attacker(self):
        from app.routers.topology._auto_build import _node_type_for
        assert _node_type_for({"is_attacker": True, "role": "", "device_type": "", "tags": [], "os": ""}) == "attacker"

    def test_node_type_for_router_device(self):
        from app.routers.topology._auto_build import _node_type_for
        assert _node_type_for({"is_attacker": False, "role": "", "device_type": "router", "tags": [], "os": ""}) == "router"

    def test_node_type_for_firewall_tag(self):
        from app.routers.topology._auto_build import _node_type_for
        assert _node_type_for({"is_attacker": False, "role": "", "device_type": "", "tags": ["firewall"], "os": ""}) == "router"

    def test_node_type_for_cisco_os(self):
        from app.routers.topology._auto_build import _node_type_for
        assert _node_type_for({"is_attacker": False, "role": "", "device_type": "", "tags": [], "os": "Cisco IOS"}) == "router"

    def test_node_type_for_windows_workstation(self):
        from app.routers.topology._auto_build import _node_type_for
        assert _node_type_for({"is_attacker": False, "role": "", "device_type": "", "tags": [], "os": "Windows 10"}) == "workstation"

    def test_node_type_for_server(self):
        from app.routers.topology._auto_build import _node_type_for
        assert _node_type_for({"is_attacker": False, "role": "", "device_type": "", "tags": [], "os": "Linux"}) == "server"


class TestAnnotateIpSubnet:
    def test_with_scope(self):
        import ipaddress
        from app.routers.topology._auto_build import _annotate_ip_subnet
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        result = _annotate_ip_subnet("10.0.0.5", nets)
        assert "10.0.0" in result

    def test_no_scope(self):
        from app.routers.topology._auto_build import _annotate_ip_subnet
        result = _annotate_ip_subnet("192.168.1.5", [])
        assert "192.168.1" in result

    def test_invalid_ip(self):
        from app.routers.topology._auto_build import _annotate_ip_subnet
        result = _annotate_ip_subnet("invalid", [])
        assert result is not None
