"""Tests for C2 Adaptix helper functions."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.routers.c2._adaptix import (
    _adaptix_os_for_target,
    _adaptix_ctx_agent,
    _adaptix_target_note,
    _adaptix_target_to_host,
    _adaptix_agent_to_host,
    _adaptix_cred_result,
    _astr,
    _parse_adaptix_agent,
    _normalize_c2_cred,
    _normalize_choice_list,
    _normalize_param_type,
    _normalize_param,
    _extract_command_params,
    _build_template_from_command,
    _parse_template_placeholders,
    _axscript_command_entry,
    _process_catalog_entry,
    _normalize_axscript_catalog,
    _find_completed_adaptix_task,
    _adaptix_base,
    _adaptix_fetch_targets_dict,
    _adaptix_fetch_raw_creds_list,
    _ADAPTIX_DEAD_MARKS,
)


class TestAdaptixOsForTarget:
    def test_uses_os_desk_first(self):
        t = {"t_os_desk": "Windows 10 Pro", "t_os": 2}
        assert _adaptix_os_for_target(t) == "Windows 10 Pro"

    def test_falls_back_to_os_int(self):
        assert _adaptix_os_for_target({"t_os": 1}) == "Windows"
        assert _adaptix_os_for_target({"t_os": 2}) == "Linux"
        assert _adaptix_os_for_target({"t_os": 99}) == ""

    def test_empty_string_falls_back(self):
        t = {"t_os_desk": "  ", "t_os": 1}
        assert _adaptix_os_for_target(t) == "Windows"


class TestAdaptixCtxAgent:
    def test_finds_live_agent(self):
        agents = {"a1": {"a_mark": "Alive", "a_pid": 123}, "a2": {"a_mark": "Terminated"}}
        t = {"t_agents": ["a2", "a1"]}
        result = _adaptix_ctx_agent(t, agents)
        assert result["a_mark"] == "Alive"

    def test_returns_empty_when_all_terminated(self):
        agents = {"a1": {"a_mark": "Terminated"}}
        t = {"t_agents": ["a1"]}
        assert _adaptix_ctx_agent(t, agents) == {}

    def test_returns_empty_when_no_agents(self):
        assert _adaptix_ctx_agent({}, {}) == {}

    def test_missing_agent_id(self):
        agents = {}
        t = {"t_agents": ["missing"]}
        assert _adaptix_ctx_agent(t, agents) == {}


class TestAdaptixTargetNote:
    def test_full_note(self):
        t = {"t_info": "Info text"}
        agent = {"a_process": "cmd.exe", "a_pid": 999, "a_arch": "x64", "a_impersonated": "DOMAIN\\admin"}
        note = _adaptix_target_note(t, agent, "corp.local", ["a1", "a2"])
        assert "Info text" in note
        assert "Domain: corp.local" in note
        assert "cmd.exe" in note
        assert "PID 999" in note
        assert "Arch: x64" in note
        assert "Impersonated: DOMAIN\\admin" in note
        assert "Agent IDs: a1, a2" in note

    def test_minimal_note(self):
        note = _adaptix_target_note({}, {}, "", [])
        assert note == ""

    def test_no_domain(self):
        t = {"t_info": "hello"}
        note = _adaptix_target_note(t, {}, "", [])
        assert note == "hello"


class TestAdaptixTargetToHost:
    def test_basic_conversion(self):
        t = {"t_address": "10.0.0.1", "t_computer": "PC1", "t_os_desk": "Win10", "t_domain": "corp", "t_agents": [], "t_alive": True}
        result = _adaptix_target_to_host(t, {})
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "PC1"
        assert result["os"] == "Win10"
        assert result["domain"] == "corp"
        assert result["source"] == "adaptix"

    def test_no_ip_returns_none(self):
        t = {"t_address": "", "t_agents": []}
        assert _adaptix_target_to_host(t, {}) is None

    def test_with_agent_context(self):
        agents = {"a1": {"a_mark": "Alive", "a_username": "admin", "a_arch": "x64", "a_process": "explorer", "a_pid": 42}}
        t = {"t_address": "10.0.0.5", "t_agents": ["a1"], "t_alive": True}
        result = _adaptix_target_to_host(t, agents)
        assert result["username"] == "admin"
        assert result["arch"] == "x64"
        assert result["beacon_id"] == "a1"


class TestAdaptixAgentToHost:
    def test_basic_conversion(self):
        a = {"a_internal_ip": "10.0.0.2", "a_computer": "SRV1", "a_os_desc": "Linux", "a_mark": "Alive", "a_domain": "dmz", "a_id": "agent1", "a_listener": "http"}
        result = _adaptix_agent_to_host(a, set())
        assert result["ip"] == "10.0.0.2"
        assert result["hostname"] == "SRV1"
        assert result["alive"] is True

    def test_skips_seen_ip(self):
        a = {"a_internal_ip": "10.0.0.2", "a_mark": "Alive"}
        assert _adaptix_agent_to_host(a, {"10.0.0.2"}) is None

    def test_no_ip_returns_none(self):
        a = {"a_internal_ip": "", "a_external_ip": ""}
        assert _adaptix_agent_to_host(a, set()) is None

    def test_terminated_agent(self):
        a = {"a_internal_ip": "10.0.0.3", "a_mark": "Terminated", "a_id": "a1"}
        result = _adaptix_agent_to_host(a, set())
        assert result["alive"] is False
        assert result["beacon_id"] == ""

    def test_uses_external_ip_fallback(self):
        a = {"a_external_ip": "1.2.3.4", "a_mark": "Alive", "a_id": "x"}
        result = _adaptix_agent_to_host(a, set())
        assert result["ip"] == "1.2.3.4"


class TestAdaptixCredResult:
    def test_basic_cred(self):
        c = {"c_username": "admin", "c_password": "hash123", "c_type": "ntlm", "c_realm": "CORP"}
        result = _adaptix_cred_result(c)
        assert result["username"] == "admin"
        assert result["type"] == "hash"
        assert result["realm"] == "CORP"

    def test_empty_cred(self):
        assert _adaptix_cred_result(None) is None
        assert _adaptix_cred_result({}) is None

    def test_no_username(self):
        assert _adaptix_cred_result({"c_password": "x"}) is None

    def test_plain_type(self):
        c = {"c_username": "user", "c_password": "pass", "c_type": "plaintext"}
        result = _adaptix_cred_result(c)
        assert result["type"] == "plain"


class TestAstr:
    def test_basic(self):
        assert _astr({"a_id": "  hello  "}, "a_id") == "hello"

    def test_missing_key(self):
        assert _astr({}, "missing") == ""


class TestParseAdaptixAgent:
    def test_healthy_agent(self):
        import time
        now = int(time.time())
        a = {"a_internal_ip": "10.0.0.1", "a_computer": "PC1", "a_mark": "Alive", "a_last_tick": now, "a_id": "a1", "a_username": "user", "a_arch": "x64"}
        result = _parse_adaptix_agent(a, now, 600)
        assert result["alive"] is True
        assert result["ip"] == "10.0.0.1"

    def test_dead_mark(self):
        a = {"a_mark": "terminated", "a_id": "a1"}
        result = _parse_adaptix_agent(a, 0, 600)
        assert result["alive"] is False

    def test_stale_agent(self):
        a = {"a_mark": "", "a_last_tick": 1000000001, "a_id": "a1"}
        result = _parse_adaptix_agent(a, 1000000700, 600)
        assert result["alive"] is False
        assert result["stale_seconds"] == 699

    def test_invalid_last_tick(self):
        a = {"a_mark": "", "a_last_tick": "invalid", "a_id": "a1"}
        result = _parse_adaptix_agent(a, 0, 600)
        assert result["alive"] is True


class TestNormalizeC2Cred:
    def test_basic(self):
        raw = {"c_creds_id": "cr1", "c_username": "admin", "c_password": "pass", "c_realm": "CORP", "c_host": "10.0.0.1", "c_type": "plain"}
        result = _normalize_c2_cred(raw, "int1")
        assert result["id"] == "cr1"
        assert result["integration_id"] == "int1"
        assert result["username"] == "admin"


class TestNormalizeChoiceList:
    def test_list_of_strings(self):
        result = _normalize_choice_list(["a", "b", "c"])
        assert len(result) == 3
        assert result[0] == {"value": "a", "label": "a"}

    def test_dict_with_choices(self):
        raw = {"choices": [{"value": "x", "label": "X"}]}
        result = _normalize_choice_list(raw)
        assert result[0]["value"] == "x"

    def test_dict_with_options(self):
        raw = {"options": [{"id": 1, "name": "opt1"}]}
        result = _normalize_choice_list(raw)
        assert result[0]["value"] == "1"

    def test_none_returns_empty(self):
        assert _normalize_choice_list(None) == []

    def test_dict_with_name_key(self):
        raw = [{"name": "item1"}]
        result = _normalize_choice_list(raw)
        assert result[0]["value"] == "item1"

    def test_skips_none_value(self):
        raw = [{"value": None}]
        result = _normalize_choice_list(raw)
        assert len(result) == 0


class TestNormalizeParamType:
    def test_with_choices(self):
        assert _normalize_param_type("text", [{}]) == "choice"

    def test_boolean_variants(self):
        for t in ("bool", "boolean", "checkbox", "switch"):
            assert _normalize_param_type(t, []) == "boolean"

    def test_number_variants(self):
        for t in ("int", "integer", "number", "float"):
            assert _normalize_param_type(t, []) == "number"

    def test_choice_variants(self):
        for t in ("select", "enum", "choice", "radio"):
            assert _normalize_param_type(t, []) == "choice"

    def test_textarea_variants(self):
        for t in ("textarea", "multiline", "textblock"):
            assert _normalize_param_type(t, []) == "textarea"

    def test_default_text(self):
        assert _normalize_param_type("", []) == "text"
        assert _normalize_param_type("unknown", []) == "text"


class TestNormalizeParam:
    def test_basic(self):
        raw = {"name": "param1", "type": "text", "required": True, "default": "val"}
        result = _normalize_param(raw, 0)
        assert result["key"] == "param1"
        assert result["type"] == "text"
        assert result["required"] is True
        assert result["default"] == "val"

    def test_fallback_key(self):
        raw = {}
        result = _normalize_param(raw, 3)
        assert result["key"] == "arg_4"

    def test_extracts_description(self):
        raw = {"name": "p", "description": "help text"}
        result = _normalize_param(raw, 0)
        assert result["description"] == "help text"

    def test_raw_string_param(self):
        result = _normalize_param({"name": "simple_name"}, 0)
        assert result["key"] == "simple_name"


class TestExtractCommandParams:
    def test_from_parameters_key(self):
        cmd = {"parameters": [{"name": "p1"}, {"name": "p2"}]}
        result = _extract_command_params(cmd)
        assert len(result) == 2

    def test_from_params_key(self):
        cmd = {"params": [{"name": "x"}]}
        result = _extract_command_params(cmd)
        assert len(result) == 1

    def test_empty(self):
        assert _extract_command_params({}) == []

    def test_non_list(self):
        assert _extract_command_params({"parameters": "not a list"}) == []

    def test_string_items(self):
        cmd = {"parameters": ["arg1", "arg2"]}
        result = _extract_command_params(cmd)
        assert len(result) == 2
        assert result[0]["key"] == "arg1"


class TestBuildTemplateFromCommand:
    def test_explicit_template(self):
        cmd = {"template": "run {{ARG}}"}
        assert _build_template_from_command("cmd", cmd, []) == "run {{ARG}}"

    def test_cmdline_fallback(self):
        cmd = {"cmdline": "execute --target"}
        assert _build_template_from_command("cmd", cmd, []) == "execute --target"

    def test_no_params_returns_name(self):
        assert _build_template_from_command("mycmd", {}, []) == "mycmd"

    def test_with_params(self):
        params = [{"key": "target", "label": "T"}]
        result = _build_template_from_command("mycmd", {}, params)
        assert "mycmd" in result
        assert "{{TARGET}}" in result


class TestParseTemplatePlaceholders:
    def test_discovers_new_placeholder(self):
        template = "run {{TARGET}} with {{METHOD}}"
        params = [{"key": "target", "label": "T"}]
        result = _parse_template_placeholders(template, params)
        keys = [p["key"] for p in result]
        assert "target" in keys
        assert "method" in keys

    def test_no_duplicates(self):
        template = "{{FOO}} {{FOO}}"
        params = [{"key": "foo", "label": "F"}]
        result = _parse_template_placeholders(template, params)
        assert len(result) == 1

    def test_no_placeholders(self):
        result = _parse_template_placeholders("no placeholders", [])
        assert result == []


class TestAxscriptCommandEntry:
    def test_valid_command(self):
        cmd = {"name": "whoami", "description": "Get user", "parameters": []}
        result = _axscript_command_entry(0, 0, 0, cmd, "General", "", "script1")
        assert result is not None
        assert result["name"] == "whoami"
        assert result["group"] == "General"

    def test_non_dict_returns_none(self):
        assert _axscript_command_entry(0, 0, 0, "not a dict", "G", "", "") is None

    def test_empty_name_returns_none(self):
        assert _axscript_command_entry(0, 0, 0, {}, "G", "", "") is None

    def test_uses_cmd_key(self):
        cmd = {"cmd": "exec"}
        result = _axscript_command_entry(0, 0, 0, cmd, "G", "", "")
        assert result["name"] == "exec"


class TestProcessCatalogEntry:
    def test_processes_groups(self):
        entry = {
            "Agent": "agent1",
            "Groups": [
                {"group_name": "Recon", "commands": [{"name": "portscan"}]}
            ],
        }
        result = []
        _process_catalog_entry(0, entry, result)
        assert len(result) == 1
        assert result[0]["name"] == "portscan"

    def test_skips_non_dict_groups(self):
        entry = {"Groups": ["not a dict"]}
        result = []
        _process_catalog_entry(0, entry, result)
        assert len(result) == 0


class TestNormalizeAxscriptCatalog:
    def test_full_catalog(self):
        catalog = [
            {
                "Agent": "a1",
                "Groups": [
                    {"group_name": "G1", "commands": [{"name": "cmd1"}, {"name": "cmd2"}]},
                    {"group_name": "G2", "commands": [{"name": "cmd3"}]},
                ],
            }
        ]
        result = _normalize_axscript_catalog(catalog)
        assert len(result) == 3

    def test_empty_catalog(self):
        assert _normalize_axscript_catalog([]) == []

    def test_none_catalog(self):
        assert _normalize_axscript_catalog(None) == []


class TestFindCompletedAdaptixTask:
    def test_completed_task(self):
        tasks = [
            {"a_cmdline": "whoami", "a_completed": True, "a_text": "admin"},
        ]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is True
        assert latest is not None
        assert updates["output"] == "admin"

    def test_incomplete_task(self):
        tasks = [{"a_cmdline": "whoami", "a_completed": False}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is False
        assert latest is not None
        assert updates == {}

    def test_no_matching_task(self):
        tasks = [{"a_cmdline": "other", "a_completed": True}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is False
        assert latest is None
        assert updates == {}

    def test_completed_with_message_fallback(self):
        tasks = [{"a_cmdline": "ls", "a_completed": True, "a_message": "output msg"}]
        done, _, updates = _find_completed_adaptix_task(tasks, "ls")
        assert done is True
        assert updates["output"] == "output msg"


class TestAdaptixBase:
    def test_default_endpoint(self):
        cfg = {"url": "http://localhost:8080"}
        assert _adaptix_base(cfg) == "http://localhost:8080/endpoint"

    def test_custom_endpoint(self):
        cfg = {"url": "http://host:80", "endpoint": "/custom"}
        assert _adaptix_base(cfg) == "http://host:80/custom"

    def test_strips_trailing_slash(self):
        cfg = {"url": "http://host/"}
        assert _adaptix_base(cfg) == "http://host/endpoint"


class TestDeadMarks:
    def test_known_marks(self):
        assert "terminated" in _ADAPTIX_DEAD_MARKS
        assert "dead" in _ADAPTIX_DEAD_MARKS
        assert "killed" in _ADAPTIX_DEAD_MARKS
        assert "inactive" in _ADAPTIX_DEAD_MARKS


class TestAdaptixFetchTargetsDict:
    @pytest.mark.asyncio
    async def test_success(self):
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"t_target_id": "t1", "t_address": "10.0.0.1"}]
        client.get.return_value = resp
        result = await _adaptix_fetch_targets_dict(client, "http://base", {})
        assert "t1" in result

    @pytest.mark.asyncio
    async def test_exception_returns_empty(self):
        client = AsyncMock()
        client.get.side_effect = Exception("fail")
        result = await _adaptix_fetch_targets_dict(client, "http://base", {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_non_200_returns_empty(self):
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 403
        client.get.return_value = resp
        result = await _adaptix_fetch_targets_dict(client, "http://base", {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_non_list_response(self):
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"error": "not a list"}
        client.get.return_value = resp
        result = await _adaptix_fetch_targets_dict(client, "http://base", {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_skips_no_id(self):
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"t_address": "10.0.0.1"}]
        client.get.return_value = resp
        result = await _adaptix_fetch_targets_dict(client, "http://base", {})
        assert result == {}


class TestAdaptixFetchRawCredsList:
    @pytest.mark.asyncio
    async def test_success(self):
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"c_username": "admin"}]
        client.get.return_value = resp
        result = await _adaptix_fetch_raw_creds_list(client, "http://base", {})
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_failure_returns_empty(self):
        client = AsyncMock()
        client.get.side_effect = Exception("fail")
        result = await _adaptix_fetch_raw_creds_list(client, "http://base", {})
        assert result == []
