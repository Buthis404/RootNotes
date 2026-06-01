"""Unit tests for app.core.ai_tools — tool definitions and dispatch."""
import asyncio

import pytest
from unittest.mock import MagicMock, patch

from app.core.ai_tools import (
    TOOL_DEFS,
    TOOLS_ANTHROPIC,
    TOOLS_OPENAI,
    _TOOL_MAP,
    _tool_def_to_anthropic,
    _tool_def_to_openai,
    execute_tool,
)


class TestToolDefs:
    def test_not_empty(self):
        assert len(TOOL_DEFS) > 0

    def test_all_have_name(self):
        for td in TOOL_DEFS:
            assert "name" in td
            assert td["name"]

    def test_all_have_description(self):
        for td in TOOL_DEFS:
            assert "description" in td
            assert td["description"]

    def test_all_have_params(self):
        for td in TOOL_DEFS:
            assert "params" in td

    def test_all_have_required(self):
        for td in TOOL_DEFS:
            assert "required" in td

    def test_known_tools(self):
        names = {td["name"] for td in TOOL_DEFS}
        expected = {
            "list_hosts", "get_host", "list_creds", "list_findings",
            "create_finding", "add_host_tag", "list_jobs", "get_job_output",
            "get_scope", "list_activities", "run_playbook", "create_note",
        }
        assert names == expected


class TestToolDefToOpenai:
    def test_basic(self):
        td = {"name": "test", "description": "desc", "params": {}, "required": []}
        result = _tool_def_to_openai(td)
        assert result["type"] == "function"
        assert result["function"]["name"] == "test"
        assert "parameters" in result["function"]

    def test_required_propagated(self):
        td = {"name": "test", "description": "desc", "params": {"x": {"type": "string"}}, "required": ["x"]}
        result = _tool_def_to_openai(td)
        assert result["function"]["parameters"]["required"] == ["x"]


class TestToolDefToAnthropic:
    def test_basic(self):
        td = {"name": "test", "description": "desc", "params": {}, "required": []}
        result = _tool_def_to_anthropic(td)
        assert result["name"] == "test"
        assert "input_schema" in result

    def test_required_propagated(self):
        td = {"name": "test", "description": "desc", "params": {}, "required": ["x"]}
        result = _tool_def_to_anthropic(td)
        assert result["input_schema"]["required"] == ["x"]


class TestToolsOpenai:
    def test_all_converted(self):
        assert len(TOOLS_OPENAI) == len(TOOL_DEFS)
        for t in TOOLS_OPENAI:
            assert t["type"] == "function"
            assert "function" in t


class TestToolsAnthropic:
    def test_all_converted(self):
        assert len(TOOLS_ANTHROPIC) == len(TOOL_DEFS)
        for t in TOOLS_ANTHROPIC:
            assert "name" in t
            assert "input_schema" in t


class TestToolMap:
    def test_all_tools_mapped(self):
        names = {td["name"] for td in TOOL_DEFS}
        assert set(_TOOL_MAP.keys()) == names

    def test_all_callables(self):
        for name, fn in _TOOL_MAP.items():
            assert callable(fn)


class TestExecuteTool:
    def test_unknown_tool_returns_error(self):
        db = MagicMock()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(execute_tool(db, "p1", "nonexistent_tool", {}))
            assert "error" in result
            assert "Unknown tool" in result["error"]
        finally:
            loop.close()

    def test_tool_exception_returns_error(self):
        db = MagicMock()
        db.query.side_effect = Exception("DB error")
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                execute_tool(db, "p1", "list_hosts", {})
            )
            assert "error" in result
        finally:
            loop.close()


class TestToolListHosts:
    def test_basic(self):
        from app.core.ai_tools import tool_list_hosts
        h = MagicMock(
            id="h1", ip="10.0.0.1", hostname="srv1", os="Linux",
            status="up", ports=["22/tcp"], tags=["web"], is_attacker=False,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [h]
        result = tool_list_hosts(db, "p1")
        assert len(result) == 1
        assert result[0]["id"] == "h1"
        assert result[0]["ports"] == ["22/tcp"]

    def test_empty(self):
        from app.core.ai_tools import tool_list_hosts
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        result = tool_list_hosts(db, "p1")
        assert result == []


class TestToolGetHost:
    def test_found(self):
        from app.core.ai_tools import tool_get_host
        h = MagicMock(
            id="h1", ip="10.0.0.1", ips=["10.0.0.1"], hostname="srv1",
            os="Linux", status="up", ports=["22/tcp"], services=["ssh"],
            tags=[], notes="test note", domain="corp.local", role="server",
            is_attacker=False, import_source="nmap",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = h
        result = tool_get_host(db, "p1", host_id="h1")
        assert result["id"] == "h1"
        assert result["ports"] == ["22/tcp"]

    def test_not_found(self):
        from app.core.ai_tools import tool_get_host
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = tool_get_host(db, "p1", host_id="missing")
        assert "error" in result


class TestToolListCreds:
    def test_basic(self):
        from app.core.ai_tools import tool_list_creds
        c = MagicMock(
            id="c1", username="admin", domain="corp.local", type="plain",
            service="ssh", host="10.0.0.1", tags=[], host_ids=[],
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [c]
        result = tool_list_creds(db, "p1")
        assert len(result) == 1
        assert result[0]["username"] == "admin"

    def test_query_filter(self):
        from app.core.ai_tools import tool_list_creds
        c1 = MagicMock(username="admin", domain="corp.local")
        c2 = MagicMock(username="guest", domain="other.local")
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [c1, c2]
        result = tool_list_creds(db, "p1", query="admin")
        assert len(result) == 1


class TestToolListFindings:
    def test_basic(self):
        from app.core.ai_tools import tool_list_findings
        f = MagicMock(
            id="f1", title="XSS", severity="high", status="open",
            host_id="h1", cve="CVE-2024-0001", cvss=7.5, description="A long description",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [f]
        result = tool_list_findings(db, "p1")
        assert len(result) == 1
        assert result[0]["title"] == "XSS"


class TestToolAddHostTag:
    def test_add_new_tag(self):
        from app.core.ai_tools import tool_add_host_tag
        h = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1", tags=["existing"])
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = h
        result = tool_add_host_tag(db, "p1", host_id="h1", tag="new_tag")
        assert "new_tag" in result["tags"]

    def test_duplicate_tag(self):
        from app.core.ai_tools import tool_add_host_tag
        h = MagicMock(id="h1", ip="10.0.0.1", hostname="srv1", tags=["existing"])
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = h
        result = tool_add_host_tag(db, "p1", host_id="h1", tag="existing")
        assert result["tags"].count("existing") == 1

    def test_host_not_found(self):
        from app.core.ai_tools import tool_add_host_tag
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = tool_add_host_tag(db, "p1", host_id="missing", tag="tag")
        assert "error" in result


class TestToolGetScope:
    def test_basic(self):
        from app.core.ai_tools import tool_get_scope
        s = MagicMock(id="s1", value="10.0.0.0/24", scope_type="cidr", in_scope=True, description="test")
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [s]
        result = tool_get_scope(db, "p1")
        assert len(result) == 1
        assert result[0]["value"] == "10.0.0.0/24"


class TestToolListActivities:
    def test_basic(self):
        from app.core.ai_tools import tool_list_activities
        a = MagicMock(
            id="a1", host_id="h1", title="Scan completed",
            activity_type="scan", summary="done", status="completed", ts="2026-01-01T00:00:00Z",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [a]
        result = tool_list_activities(db, "p1")
        assert len(result) == 1


class TestToolGetJobOutput:
    def test_found(self):
        from app.core.ai_tools import tool_get_job_output
        j = MagicMock(
            id="j1", title="Nmap Scan", status="done",
            output="x" * 4000, result_json={"hosts": 5},
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = j
        result = tool_get_job_output(db, "p1", job_id="j1")
        assert result["id"] == "j1"
        assert result["output_truncated"] is True

    def test_not_found(self):
        from app.core.ai_tools import tool_get_job_output
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = tool_get_job_output(db, "p1", job_id="missing")
        assert "error" in result


class TestToolListJobs:
    def test_basic(self):
        from app.core.ai_tools import tool_list_jobs
        j = MagicMock(
            id="j1", title="Scan", status="done",
            connector_key="nmap", operation="scan",
            created_at="2026-01-01", finished_at="2026-01-01",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [j]
        result = tool_list_jobs(db, "p1")
        assert len(result) == 1
