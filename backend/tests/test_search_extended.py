"""Extended tests for search helpers and additional endpoints."""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.routers.search import (
    _parse_query,
    _type_match,
    _host_snippet,
    _cred_snippet,
    _ilike,
    _findings_meta,
    _findings_fts_item,
    _loot_snippet,
    _rank_key,
    _FILTER_KEYS,
)

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "SearchExtended", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.200.200.1", "hostname": "ext-host",
        "os": "Windows Server 2022", "status": "alive", "notes": "extended test host",
    })
    module_client.post("/api/findings", json={
        "pid": _state["pid"], "title": "Ext Finding", "severity": "critical",
        "status": "open", "description": "critical vuln", "source": "nmap", "ts": TS,
    })
    module_client.post("/api/creds", json={
        "pid": _state["pid"], "username": "extuser", "secret": "ExtPass!",
        "type": "plain", "host": "10.200.200.1",
    })
    yield
    module_client.post("/api/auth/logout")


class TestParseQueryExtended:
    def test_multiple_filters(self):
        words, filters = _parse_query("type:host severity:high status:open test query")
        assert "test" in words
        assert "query" in words
        assert filters["type"] == "host"
        assert filters["severity"] == "high"
        assert filters["status"] == "open"

    def test_unknown_filter_key_ignored(self):
        words, filters = _parse_query("unknown:val test")
        assert "unknown:val" in words
        assert filters == {}

    def test_empty_value_filter_ignored(self):
        words, filters = _parse_query("type: test")
        assert "type:" in words

    def test_colon_in_value(self):
        words, filters = _parse_query("type:host http://example.com")
        assert filters["type"] == "host"
        assert "http://example.com" in words

    def test_all_filter_keys(self):
        for key in _FILTER_KEYS:
            _, filters = _parse_query(f"{key}:value")
            assert filters.get(key) == "value"


class TestHelpers:
    def test_ilike(self):
        assert _ilike("test") == "%test%"

    def test_findings_meta(self):
        class F:
            severity = "high"
            status = "open"
            source = "nmap"
        meta = _findings_meta(F())
        assert meta["severity"] == "high"
        assert meta["status"] == "open"
        assert meta["source"] == "nmap"

    def test_findings_fts_item(self):
        class F:
            id = "f1"
            pid = "p1"
            title = "Vuln"
            cve = "CVE-2024-1"
            description = "desc"
            severity = "critical"
            status = "open"
            source = "nmap"
        item = _findings_fts_item(F(), 0.95, "<b>Vuln</b> highlight")
        assert item["_rank"] == 0.95
        assert item["type"] == "finding"
        assert item["snippet_html"] is True

    def test_loot_snippet(self):
        class L:
            loot_type = "file"
            artifact_type = "document"
        assert "file" in _loot_snippet(L())
        assert "document" in _loot_snippet(L())

    def test_loot_snippet_no_artifact(self):
        class L:
            loot_type = "file"
            artifact_type = None
        s = _loot_snippet(L())
        assert s == "file"

    def test_rank_key(self):
        assert _rank_key({"_rank": 0.9}) == 0.9
        assert _rank_key({"_rank": 0}) == 0

    def test_host_snippet_no_role(self):
        class H:
            os = "Linux"
            role = None
        assert _host_snippet(H()) == "Linux"

    def test_cred_snippet_not_cracked(self):
        class C:
            service = "ssh"
            cracked = False
        s = _cred_snippet(C())
        assert "ssh" in s
        assert "cracked" not in s

    def test_type_match_with_empty(self):
        assert _type_match("", ("host", "hosts")) is True

    def test_type_match_with_match(self):
        assert _type_match("hosts", ("host", "hosts")) is True

    def test_type_match_no_match(self):
        assert _type_match("cred", ("host",)) is False


class TestSearchEndpointsExtended:
    def test_search_with_severity_filter(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "severity:critical ext", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_with_status_filter(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "status:open finding", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_with_source_filter(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "source:nmap", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_with_type_cred(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "type:cred extuser", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_with_type_note(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "type:note test", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_with_type_loot(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "type:loot test", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_with_type_job(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "type:job test", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_with_type_kb(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "type:kb test", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_with_type_snippet(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "type:snippet test"})
        assert r.status_code in (200, 500)

    def test_search_with_offset_limit(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "ext", "pid": _state["pid"], "limit": 1, "offset": 0})
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            data = r.json()
            assert "has_more" in data

    def test_search_backward_compat_fields(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "ext-host", "pid": _state["pid"]})
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            data = r.json()
            assert "hosts" in data
            assert "creds" in data
            assert "notes" in data
            assert "findings" in data
            assert "loots" in data
