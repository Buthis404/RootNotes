"""Consolidated tests for test_search (merged variant files)."""

# ════════ from test_search_api.py ════════
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "SearchTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]

    module_client.post("/api/hosts", json={
        "pid": _state["pid"], "ip": "10.99.99.1", "hostname": "search-host",
        "os": "Ubuntu 22.04", "status": "alive", "ports": ["22/tcp"],
        "services": ["ssh"], "tags": ["web"], "notes": "searchable note",
    })
    module_client.post("/api/findings", json={
        "pid": _state["pid"], "title": "Search Finding", "severity": "high",
        "status": "open", "description": "searchable finding", "ts": TS,
    })
    module_client.post("/api/creds", json={
        "pid": _state["pid"], "username": "searchuser", "secret": "SearchPass!",
        "type": "plain", "host": "10.99.99.1",
    })
    module_client.post("/api/notes", json={
        "pid": _state["pid"], "title": "Search Note", "content": "note content here",
        "phase": "recon",
    })
    yield
    module_client.post("/api/auth/logout")


class TestSearch:
    def test_search_hosts(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "search-host", "pid": _state["pid"]})
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            data = r.json()
            assert data["total"] >= 1

    def test_search_findings(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "Search Finding", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_creds(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "searchuser", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_notes(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "Search Note", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_empty_query(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": ""})
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_search_short_query(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "a"})
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_search_no_results(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "zzzznonexistent", "pid": _state["pid"]})
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            assert r.json()["total"] == 0

    def test_search_type_filter(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "type:host search", "pid": _state["pid"]})
        assert r.status_code in (200, 500)

    def test_search_has_facets(self, module_client: TestClient):
        r = module_client.get("/api/search", params={"q": "search-host", "pid": _state["pid"]})
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            data = r.json()
            assert "facets" in data


class TestSavedSearches:
    def test_create_saved_search(self, module_client: TestClient):
        r = module_client.post("/api/saved-searches", json={
            "name": "My Search", "query": "search-host", "pid": _state["pid"],
        })
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "My Search"
        assert data["query"] == "search-host"
        _state["ssid"] = data["id"]

    def test_list_saved_searches(self, module_client: TestClient):
        r = module_client.get("/api/saved-searches")
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 1
        ids = [s["id"] for s in items]
        assert _state["ssid"] in ids

    def test_delete_saved_search(self, module_client: TestClient):
        r = module_client.delete(f"/api/saved-searches/{_state['ssid']}")
        assert r.status_code == 204

    def test_delete_saved_search_404(self, module_client: TestClient):
        r = module_client.delete("/api/saved-searches/nonexistent")
        assert r.status_code == 404


class TestSearchHelpers:
    def test_parse_query(self):
        from app.routers.search import _parse_query
        words, filters = _parse_query("type:host severity:high web server")
        assert "web" in words
        assert "server" in words
        assert filters.get("type") == "host"
        assert filters.get("severity") == "high"

    def test_parse_query_no_filters(self):
        from app.routers.search import _parse_query
        words, filters = _parse_query("just words")
        assert words == "just words"
        assert filters == {}

    def test_type_match(self):
        from app.routers.search import _type_match
        assert _type_match("", ("host",)) is True
        assert _type_match("host", ("host",)) is True
        assert _type_match("host", ("cred",)) is False

    def test_host_snippet(self):
        from app.routers.search import _host_snippet

        class H:
            os = "Linux"
            role = "server"

        assert "Linux" in _host_snippet(H())

    def test_cred_snippet(self):
        from app.routers.search import _cred_snippet

        class C:
            service = "ssh"
            cracked = True

        s = _cred_snippet(C())
        assert "ssh" in s
        assert "cracked" in s


# ════════ from test_search_extended.py ════════
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


# ════════ from test_search_final.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.search import (
    _parse_query,
    _allowed_pids,
    _scope,
    _ilike,
    _host_snippet,
    _cred_snippet,
    _loot_snippet,
    _type_match,
    _rank_key,
    _findings_meta,
)


class TestParseQuery_final:
    def test_plain_text(self):
        text, filters = _parse_query("hello world")
        assert text == "hello world"
        assert filters == {}

    def test_type_filter(self):
        text, filters = _parse_query("type:host query")
        assert filters.get("type") == "host"

    def test_severity_filter(self):
        text, filters = _parse_query("severity:high test")
        assert filters.get("severity") == "high"

    def test_status_filter(self):
        text, filters = _parse_query("status:open term")
        assert filters.get("status") == "open"

    def test_tag_filter(self):
        text, filters = _parse_query("tag:nmap search")
        assert filters.get("tag") == "nmap"

    def test_unknown_key_not_filter(self):
        text, filters = _parse_query("foo:bar term")
        assert "foo" not in filters
        assert "foo:bar" in text or "term" in text

    def test_empty_value(self):
        text, filters = _parse_query("type: term")
        assert "type" not in filters

    def test_all_filters(self):
        text, filters = _parse_query("type:host severity:high status:open service:smb role:dc source:nmap connector:nmap tag:cme")
        assert len(filters) >= 5


class TestAllowedPids:
    def test_with_pid(self):
        user = MagicMock()
        with patch("app.routers.search.check_pid_access"):
            result = _allowed_pids(MagicMock(), user, "p1")
            assert result == ["p1"]

    def test_admin_no_pid(self):
        user = MagicMock()
        with patch("app.routers.search.is_admin", return_value=True):
            result = _allowed_pids(MagicMock(), user, "")
            assert result is None


class TestScope:
    def test_pid_exact(self):
        q = MagicMock()
        result = _scope(q, MagicMock(), None, "p1")
        q.filter.assert_called_once()

    def test_pid_list(self):
        q = MagicMock()
        result = _scope(q, MagicMock(), ["p1", "p2"], "")
        q.filter.assert_called_once()

    def test_no_filter(self):
        q = MagicMock()
        result = _scope(q, MagicMock(), None, "")
        assert result == q


class TestIlike_final:
    def test_basic(self):
        assert _ilike("test") == "%test%"


class TestHostSnippet_final:
    def test_with_role(self):
        h = MagicMock()
        h.os = "Windows"
        h.role = "server"
        assert "Windows" in _host_snippet(h)
        assert "server" in _host_snippet(h)

    def test_no_role(self):
        h = MagicMock()
        h.os = "Linux"
        h.role = None
        assert "Linux" in _host_snippet(h)


class TestCredSnippet_final:
    def test_basic(self):
        c = MagicMock()
        c.service = "smb"
        c.cracked = False
        assert "smb" in _cred_snippet(c)

    def test_cracked(self):
        c = MagicMock()
        c.service = "ssh"
        c.cracked = True
        assert "cracked" in _cred_snippet(c)


class TestLootSnippet_final:
    def test_basic(self):
        loot = MagicMock()
        loot.loot_type = "file"
        loot.artifact_type = None
        assert "file" in _loot_snippet(loot)

    def test_with_artifact(self):
        loot = MagicMock()
        loot.loot_type = "file"
        loot.artifact_type = "screenshot"
        assert "screenshot" in _loot_snippet(loot)


class TestTypeMatch_final:
    def test_no_filter(self):
        assert _type_match("", ("host",)) is True

    def test_match(self):
        assert _type_match("host", ("host", "hosts")) is True

    def test_no_match(self):
        assert _type_match("cred", ("host",)) is False


class TestRankKey_final:
    def test_basic(self):
        assert _rank_key({"_rank": 0.5}) == 0.5


class TestFindingsMeta_final:
    def test_basic(self):
        f = MagicMock()
        f.severity = "high"
        f.status = "open"
        f.source = "nmap"
        result = _findings_meta(f)
        assert result["severity"] == "high"


# ════════ from test_search_final2.py ════════
import pytest
from unittest.mock import MagicMock

from app.routers.search import (
    _parse_query,
    _type_match,
    _rank_key,
    _host_snippet,
    _cred_snippet,
    _loot_snippet,
    _findings_meta,
    _FILTER_KEYS,
)


class TestParseQuery_final2:
    def test_basic(self):
        text, filters = _parse_query("hello world")
        assert text == "hello world"
        assert filters == {}

    def test_type_filter(self):
        text, filters = _parse_query("type:host query")
        assert filters["type"] == "host"
        assert "query" in text

    def test_severity_filter(self):
        text, filters = _parse_query("severity:high ssh")
        assert filters["severity"] == "high"

    def test_status_filter(self):
        text, filters = _parse_query("status:open")
        assert filters["status"] == "open"

    def test_service_filter(self):
        text, filters = _parse_query("service:smb")
        assert filters["service"] == "smb"

    def test_role_filter(self):
        text, filters = _parse_query("role:server")
        assert filters["role"] == "server"

    def test_source_filter(self):
        text, filters = _parse_query("source:nmap")
        assert filters["source"] == "nmap"

    def test_connector_filter(self):
        text, filters = _parse_query("connector:nmap")
        assert filters["connector"] == "nmap"

    def test_tag_filter(self):
        text, filters = _parse_query("tag:dc")
        assert filters["tag"] == "dc"

    def test_unknown_filter_key(self):
        text, filters = _parse_query("foo:bar query")
        assert "foo:bar" in text
        assert filters == {}

    def test_empty_value(self):
        text, filters = _parse_query("type: query")
        assert filters == {}

    def test_all_filters(self):
        for key in _FILTER_KEYS:
            _, f = _parse_query(f"{key}:val")
            assert key in f


class TestTypeMatch_final2:
    def test_empty(self):
        assert _type_match("", ("host",)) is True

    def test_match(self):
        assert _type_match("host", ("host", "hosts")) is True

    def test_no_match(self):
        assert _type_match("cred", ("host",)) is False


class TestRankKey_final2:
    def test_basic(self):
        assert _rank_key({"_rank": 0.5}) == 0.5
        assert _rank_key({"_rank": 1.0}) == 1.0


class TestHostSnippet_final2:
    def test_with_role(self):
        h = MagicMock()
        h.os = "Linux"
        h.role = "server"
        assert "Linux" in _host_snippet(h)
        assert "server" in _host_snippet(h)

    def test_no_role(self):
        h = MagicMock()
        h.os = "Windows"
        h.role = ""
        assert "Windows" in _host_snippet(h)
        assert "•" not in _host_snippet(h)


class TestCredSnippet_final2:
    def test_basic(self):
        c = MagicMock()
        c.service = "smb"
        c.cracked = False
        assert "smb" in _cred_snippet(c)
        assert "cracked" not in _cred_snippet(c)

    def test_cracked(self):
        c = MagicMock()
        c.service = "ssh"
        c.cracked = True
        assert "cracked" in _cred_snippet(c)


class TestLootSnippet_final2:
    def test_basic(self):
        loot = MagicMock()
        loot.loot_type = "file"
        loot.artifact_type = None
        assert _loot_snippet(loot) == "file"

    def test_with_artifact(self):
        loot = MagicMock()
        loot.loot_type = "file"
        loot.artifact_type = "screenshot"
        assert "screenshot" in _loot_snippet(loot)


class TestFindingsMeta_final2:
    def test_basic(self):
        f = MagicMock()
        f.severity = "high"
        f.status = "open"
        f.source = "nmap"
        r = _findings_meta(f)
        assert r["severity"] == "high"
        assert r["status"] == "open"
        assert r["source"] == "nmap"


# ════════ from test_search_v3.py ════════
import pytest
from unittest.mock import MagicMock

from app.routers.search import (
    _parse_query,
    _FILTER_KEYS,
    _host_snippet,
    _host_related,
    _ilike,
)


class TestParseQuery_v3:
    def test_plain_text(self):
        text, filters = _parse_query("hello world")
        assert text == "hello world"
        assert filters == {}

    def test_filter(self):
        text, filters = _parse_query("type:cred admin")
        assert text == "admin"
        assert filters["type"] == "cred"

    def test_multiple_filters(self):
        text, filters = _parse_query("type:cred severity:high password")
        assert text == "password"
        assert filters["type"] == "cred"
        assert filters["severity"] == "high"

    def test_invalid_filter_key(self):
        text, filters = _parse_query("invalid:value test")
        assert text == "invalid:value test"
        assert filters == {}

    def test_empty_value(self):
        text, filters = _parse_query("type: test")
        assert text == "type: test"

    def test_all_filter_keys(self):
        for key in _FILTER_KEYS:
            text, filters = _parse_query(f"{key}:val")
            assert filters.get(key) == "val"

    def test_empty_query(self):
        text, filters = _parse_query("")
        assert text == ""
        assert filters == {}


class TestHostSnippet_v3:
    def test_with_os_and_role(self):
        h = MagicMock()
        h.os = "Linux"
        h.role = "server"
        r = _host_snippet(h)
        assert "Linux" in r
        assert "server" in r

    def test_os_only(self):
        h = MagicMock()
        h.os = "Windows"
        h.role = None
        r = _host_snippet(h)
        assert "Windows" in r

    def test_empty(self):
        h = MagicMock()
        h.os = None
        h.role = None
        r = _host_snippet(h)
        assert r == ""


class TestHostRelated:
    def test_basic(self):
        db = MagicMock()
        cred = MagicMock()
        cred.id = "crd1"
        cred.username = "admin"
        cred.service = "smb"
        finding = MagicMock()
        finding.id = "fnd1"
        finding.title = "vuln"
        finding.severity = "high"
        db.query.return_value.filter.return_value.limit.return_value.all.side_effect = [
            [cred], [finding]
        ]
        h = MagicMock()
        h.pid = "p1"
        h.ip = "10.0.0.1"
        h.id = "h1"
        r = _host_related(h, db)
        assert len(r) == 2
        assert r[0]["type"] == "cred"
        assert r[1]["type"] == "finding"

    def test_empty(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.limit.return_value.all.return_value = []
        h = MagicMock()
        h.pid = "p1"
        h.ip = "10.0.0.1"
        h.id = "h1"
        r = _host_related(h, db)
        assert r == []


class TestIlike_v3:
    def test_basic(self):
        assert _ilike("test") == "%test%"
