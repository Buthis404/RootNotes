"""Consolidated tests for test_c2_adaptix (merged variant files)."""

# ════════ from test_c2_adaptix_api.py ════════
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


class TestAdaptixOsForTarget_api:
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


class TestAdaptixCtxAgent_api:
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


class TestAdaptixTargetNote_api:
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


class TestAdaptixTargetToHost_api:
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


class TestAdaptixAgentToHost_api:
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


class TestAdaptixCredResult_api:
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


class TestAstr_api:
    def test_basic(self):
        assert _astr({"a_id": "  hello  "}, "a_id") == "hello"

    def test_missing_key(self):
        assert _astr({}, "missing") == ""


class TestParseAdaptixAgent_api:
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


class TestNormalizeC2Cred_api:
    def test_basic(self):
        raw = {"c_creds_id": "cr1", "c_username": "admin", "c_password": "pass", "c_realm": "CORP", "c_host": "10.0.0.1", "c_type": "plain"}
        result = _normalize_c2_cred(raw, "int1")
        assert result["id"] == "cr1"
        assert result["integration_id"] == "int1"
        assert result["username"] == "admin"


class TestNormalizeChoiceList_api:
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


class TestNormalizeParamType_api:
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


class TestNormalizeParam_api:
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


class TestExtractCommandParams_api:
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


class TestBuildTemplateFromCommand_api:
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


class TestParseTemplatePlaceholders_api:
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


class TestAxscriptCommandEntry_api:
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


class TestProcessCatalogEntry_api:
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


class TestNormalizeAxscriptCatalog_api:
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


class TestFindCompletedAdaptixTask_api:
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


class TestAdaptixBase_api:
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


# ════════ from test_c2_adaptix_extended.py ════════
import pytest

from app.routers.c2._adaptix import (
    _adaptix_os_for_target,
    _adaptix_ctx_agent,
    _adaptix_target_note,
    _adaptix_target_to_host,
    _adaptix_agent_to_host,
    _adaptix_cred_result,
    _normalize_c2_cred,
    _normalize_choice_list,
    _normalize_param_type,
    _normalize_param,
    _extract_command_params,
    _build_template_from_command,
    _parse_template_placeholders,
    _axscript_command_entry,
    _normalize_axscript_catalog,
    _find_completed_adaptix_task,
    _parse_adaptix_agent,
    _astr,
)


class TestAdaptixOsForTarget_extended:
    def test_from_desk(self):
        assert _adaptix_os_for_target({"t_os_desk": "Windows 10"}) == "Windows 10"

    def test_from_int_windows(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 1}) == "Windows"

    def test_from_int_linux(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 2}) == "Linux"

    def test_unknown_int(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 99}) == ""

    def test_empty(self):
        assert _adaptix_os_for_target({}) == ""


class TestAdaptixCtxAgent_extended:
    def test_finds_active(self):
        agents = {"a1": {"a_mark": "Alive"}, "a2": {"a_mark": "Terminated"}}
        result = _adaptix_ctx_agent({"t_agents": ["a1", "a2"]}, agents)
        assert result == {"a_mark": "Alive"}

    def test_all_terminated(self):
        agents = {"a1": {"a_mark": "Terminated"}}
        result = _adaptix_ctx_agent({"t_agents": ["a1"]}, agents)
        assert result == {}

    def test_no_agents(self):
        result = _adaptix_ctx_agent({"t_agents": []}, {})
        assert result == {}


class TestAdaptixTargetNote_extended:
    def test_full_note(self):
        note = _adaptix_target_note(
            {"t_info": "info"},
            {"a_process": "proc", "a_pid": 123, "a_arch": "x64", "a_impersonated": "admin"},
            "dom",
            ["a1"],
        )
        assert "info" in note
        assert "Domain: dom" in note
        assert "proc" in note


class TestAdaptixTargetToHost_extended:
    def test_basic(self):
        result = _adaptix_target_to_host(
            {"t_address": "10.0.0.1", "t_computer": "PC1", "t_os": 1, "t_os_desk": "",
             "t_domain": "dom", "t_agents": [], "t_alive": True},
            {},
        )
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "PC1"

    def test_no_ip_returns_none(self):
        result = _adaptix_target_to_host({"t_address": ""}, {})
        assert result is None


class TestAdaptixAgentToHost_extended:
    def test_basic(self):
        result = _adaptix_agent_to_host(
            {"a_internal_ip": "10.0.0.2", "a_external_ip": "", "a_mark": "Alive",
             "a_computer": "PC2", "a_os_desc": "Linux", "a_username": "root",
             "a_arch": "x64", "a_process": "implant", "a_pid": 99, "a_id": "ag1"},
            set(),
        )
        assert result["ip"] == "10.0.0.2"
        assert result["alive"] is True

    def test_seen_ip_skipped(self):
        result = _adaptix_agent_to_host(
            {"a_internal_ip": "10.0.0.2", "a_external_ip": "", "a_mark": ""},
            {"10.0.0.2"},
        )
        assert result is None

    def test_no_ip_returns_none(self):
        result = _adaptix_agent_to_host({"a_internal_ip": "", "a_external_ip": ""}, set())
        assert result is None


class TestAdaptixCredResult_extended:
    def test_basic(self):
        result = _adaptix_cred_result({"c_username": "admin", "c_password": "pass", "c_type": "hash_ntlm"})
        assert result["username"] == "admin"
        assert result["type"] == "hash"

    def test_empty_returns_none(self):
        assert _adaptix_cred_result({}) is None

    def test_no_username_returns_none(self):
        assert _adaptix_cred_result({"c_username": ""}) is None


class TestNormalizeC2Cred_extended:
    def test_basic(self):
        result = _normalize_c2_cred({"c_creds_id": "c1", "c_username": "u", "c_password": "p",
                                      "c_realm": "dom", "c_host": "10.0.0.1", "c_type": "plain"}, "iid1")
        assert result["integration_id"] == "iid1"
        assert result["username"] == "u"


class TestNormalizeChoiceList_extended:
    def test_list_of_strings(self):
        result = _normalize_choice_list(["a", "b"])
        assert result == [{"value": "a", "label": "a"}, {"value": "b", "label": "b"}]

    def test_dict_with_choices(self):
        result = _normalize_choice_list({"choices": ["x"]})
        assert result == [{"value": "x", "label": "x"}]

    def test_dict_items(self):
        result = _normalize_choice_list([{"value": 1, "label": "One"}])
        assert result[0]["value"] == "1"

    def test_none_value_skipped(self):
        result = _normalize_choice_list([{"value": None}])
        assert result == []


class TestNormalizeParamType_extended:
    def test_bool(self):
        assert _normalize_param_type("bool", []) == "boolean"

    def test_with_choices(self):
        assert _normalize_param_type("text", [{"value": "a"}]) == "choice"

    def test_number(self):
        assert _normalize_param_type("int", []) == "number"

    def test_textarea(self):
        assert _normalize_param_type("multiline", []) == "textarea"

    def test_default_text(self):
        assert _normalize_param_type("", []) == "text"


class TestExtractCommandParams_extended:
    def test_from_parameters(self):
        result = _extract_command_params({"parameters": [{"name": "arg1", "type": "text"}]})
        assert len(result) == 1
        assert result[0]["key"] == "arg1"

    def test_non_list_returns_empty(self):
        assert _extract_command_params({"parameters": "bad"}) == []

    def test_string_items(self):
        result = _extract_command_params({"params": ["simple_arg"]})
        assert len(result) == 1


class TestBuildTemplateFromCommand_extended:
    def test_explicit_template(self):
        result = _build_template_from_command("run", {"template": "run --target {IP}"}, [])
        assert result == "run --target {IP}"

    def test_auto_template(self):
        result = _build_template_from_command("run", {}, [{"key": "IP", "label": "IP"}])
        assert "{IP}" in result

    def test_no_params(self):
        result = _build_template_from_command("run", {}, [])
        assert result == "run"


class TestParseTemplatePlaceholders_extended:
    def test_finds_new_placeholders(self):
        result = _parse_template_placeholders("cmd {{NEW_VAR}}", [])
        assert any(p["key"] == "new_var" for p in result)

    def test_skips_known(self):
        params = [{"key": "known", "label": "known", "type": "text", "raw_type": "",
                    "required": False, "default": "", "placeholder": "", "description": "",
                    "choices": [], "position": 0}]
        result = _parse_template_placeholders("cmd {{KNOWN}}", params)
        assert len(result) == 1


class TestAxscriptCommandEntry_extended:
    def test_non_dict_returns_none(self):
        assert _axscript_command_entry(0, 0, 0, "string", "g", "d", "s") is None

    def test_empty_name_returns_none(self):
        assert _axscript_command_entry(0, 0, 0, {}, "g", "d", "s") is None

    def test_valid_entry(self):
        cmd = {"name": "test_cmd", "parameters": []}
        result = _axscript_command_entry(0, 0, 0, cmd, "group", "desc", "script")
        assert result["name"] == "test_cmd"
        assert result["group"] == "group"


class TestNormalizeAxscriptCatalog_extended:
    def test_empty(self):
        assert _normalize_axscript_catalog([]) == []

    def test_with_groups(self):
        catalog = [{"Agent": "test", "Groups": [{"group_name": "g1", "commands": [
            {"name": "cmd1", "parameters": []}
        ]}]}]
        result = _normalize_axscript_catalog(catalog)
        assert len(result) == 1
        assert result[0]["name"] == "cmd1"


class TestFindCompletedAdaptixTask_extended:
    def test_completed(self):
        tasks = [{"a_cmdline": "whoami", "a_completed": True, "a_text": "admin"}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is True
        assert latest is not None

    def test_not_completed(self):
        tasks = [{"a_cmdline": "whoami", "a_completed": False}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is False

    def test_no_match(self):
        tasks = [{"a_cmdline": "id", "a_completed": True}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is False
        assert latest is None


class TestParseAdaptixAgent_extended:
    def test_alive(self):
        import time
        now = int(time.time())
        a = {"a_mark": "Alive", "a_internal_ip": "10.0.0.1", "a_computer": "PC",
             "a_username": "u", "a_domain": "d", "a_os_desc": "Win", "a_arch": "x64",
             "a_process": "p", "a_id": "id1", "a_listener": "tcp",
             "a_last_seen": "", "a_last_tick": now}
        result = _parse_adaptix_agent(a, now + 1, 600)
        assert result["alive"] is True

    def test_dead_mark(self):
        a = {"a_mark": "Terminated", "a_internal_ip": "10.0.0.1", "a_computer": "",
             "a_username": "", "a_domain": "", "a_os_desc": "", "a_arch": "",
             "a_process": "", "a_id": "", "a_listener": "",
             "a_last_seen": "", "a_last_tick": 0}
        import time
        result = _parse_adaptix_agent(a, int(time.time()), 600)
        assert result["alive"] is False


class TestAstr_extended:
    def test_returns_stripped(self):
        assert _astr({"key": "  val  "}, "key") == "val"

    def test_missing_key(self):
        assert _astr({}, "key") == ""


# ════════ from test_c2_adaptix_final.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._adaptix import (
    _adaptix_os_for_target,
    _adaptix_target_to_host,
    _adaptix_agent_to_host,
    _adaptix_cred_result,
    _normalize_c2_cred,
    _normalize_choice_list,
    _normalize_param_type,
    _normalize_param,
    _build_template_from_command,
    _parse_template_placeholders,
    _axscript_command_entry,
    _normalize_axscript_catalog,
    _find_completed_adaptix_task,
    _parse_adaptix_agent,
    _adaptix_base,
)


class TestAdaptixOsForTarget_final:
    def test_desk_present(self):
        assert _adaptix_os_for_target({"t_os_desk": "Windows 10", "t_os": 1}) == "Windows 10"

    def test_fallback_windows(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 1}) == "Windows"

    def test_fallback_linux(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 2}) == "Linux"

    def test_fallback_unknown(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 99}) == ""


class TestAdaptixTargetToHost_final:
    def test_basic(self):
        t = {"t_address": "10.0.0.1", "t_computer": "SRV1", "t_os_desk": "Windows", "t_os": 1, "t_domain": "corp", "t_agents": ["a1"], "t_alive": True, "t_info": "info"}
        agents_by_id = {"a1": {"a_mark": "", "a_username": "admin", "a_arch": "x64", "a_process": "implant", "a_pid": 42, "a_impersonated": ""}}
        result = _adaptix_target_to_host(t, agents_by_id)
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "SRV1"

    def test_no_ip(self):
        t = {"t_address": ""}
        assert _adaptix_target_to_host(t, {}) is None


class TestAdaptixAgentToHost_final:
    def test_basic(self):
        a = {"a_internal_ip": "10.0.0.2", "a_external_ip": "", "a_mark": "", "a_computer": "WS1", "a_os_desc": "Linux", "a_domain": "", "a_username": "user", "a_arch": "x86", "a_process": "beacon", "a_pid": 1, "a_id": "ag1", "a_listener": "l1"}
        result = _adaptix_agent_to_host(a, set())
        assert result["ip"] == "10.0.0.2"
        assert result["alive"] is True

    def test_dead_mark(self):
        a = {"a_internal_ip": "10.0.0.3", "a_external_ip": "", "a_mark": "Terminated", "a_computer": "", "a_os_desc": "", "a_domain": "", "a_username": "", "a_arch": "", "a_process": "", "a_pid": None, "a_id": "ag2", "a_listener": ""}
        result = _adaptix_agent_to_host(a, set())
        assert result["alive"] is False
        assert result["beacon_id"] == ""

    def test_seen_ip(self):
        a = {"a_internal_ip": "10.0.0.1", "a_external_ip": ""}
        assert _adaptix_agent_to_host(a, {"10.0.0.1"}) is None

    def test_no_ip(self):
        assert _adaptix_agent_to_host({"a_internal_ip": "", "a_external_ip": ""}, set()) is None


class TestAdaptixCredResult_final:
    def test_basic(self):
        c = {"c_username": "admin", "c_password": "pass", "c_type": "plain", "c_realm": "corp", "c_host": "10.0.0.1"}
        result = _adaptix_cred_result(c)
        assert result["username"] == "admin"
        assert result["type"] == "plain"

    def test_hash(self):
        c = {"c_username": "admin", "c_password": "abc", "c_type": "ntlm", "c_realm": "", "c_host": ""}
        result = _adaptix_cred_result(c)
        assert result["type"] == "hash"

    def test_empty_username(self):
        assert _adaptix_cred_result({"c_username": ""}) is None

    def test_none(self):
        assert _adaptix_cred_result(None) is None


class TestNormalizeC2Cred_final:
    def test_basic(self):
        result = _normalize_c2_cred({"c_creds_id": "cr1", "c_username": "admin", "c_password": "p", "c_realm": "corp", "c_host": "10.0.0.1", "c_type": "plain"}, "int1")
        assert result["integration_id"] == "int1"
        assert result["source"] == "c2"


class TestNormalizeChoiceList_final:
    def test_dict_choices(self):
        result = _normalize_choice_list({"choices": [{"value": "a", "label": "A"}]})
        assert len(result) == 1
        assert result[0]["value"] == "a"

    def test_list(self):
        result = _normalize_choice_list(["x", "y"])
        assert len(result) == 2

    def test_none(self):
        assert _normalize_choice_list(None) == []

    def test_dict_with_name(self):
        result = _normalize_choice_list([{"name": "test", "title": "Test"}])
        assert result[0]["value"] == "test"


class TestNormalizeParamType_final:
    def test_choice(self):
        assert _normalize_param_type("text", [{"value": "a"}]) == "choice"

    def test_boolean(self):
        assert _normalize_param_type("bool", []) == "boolean"

    def test_number(self):
        assert _normalize_param_type("int", []) == "number"

    def test_textarea(self):
        assert _normalize_param_type("textarea", []) == "textarea"

    def test_default(self):
        assert _normalize_param_type("custom", []) == "text"


class TestNormalizeParam_final:
    def test_basic(self):
        result = _normalize_param({"name": "param1", "type": "text"}, 0)
        assert result["key"] == "param1"
        assert result["type"] == "text"

    def test_fallback_key(self):
        result = _normalize_param({}, 3)
        assert result["key"] == "arg_4"


class TestBuildTemplateFromCommand_final:
    def test_explicit_template(self):
        result = _build_template_from_command("cmd", {"template": "run {{ARG}}"}, [])
        assert result == "run {{ARG}}"

    def test_no_template_no_params(self):
        result = _build_template_from_command("cmd", {}, [])
        assert result == "cmd"

    def test_generated(self):
        result = _build_template_from_command("cmd", {}, [{"key": "arg1", "label": "Arg1", "type": "text", "raw_type": "", "required": False, "default": "", "placeholder": "", "description": "", "choices": [], "position": 0}])
        assert "{{ARG1}}" in result


class TestParseTemplatePlaceholders_final:
    def test_finds_new(self):
        params = []
        result = _parse_template_placeholders("cmd {{HOST}} {{PORT}}", params)
        assert len(result) == 2

    def test_no_new(self):
        params = [{"key": "host"}]
        result = _parse_template_placeholders("cmd", params)
        assert len(result) == 1


class TestAxscriptCommandEntry_final:
    def test_valid(self):
        result = _axscript_command_entry(0, 0, 0, {"name": "cmd1"}, "group1", "desc", "script1")
        assert result is not None
        assert result["name"] == "cmd1"

    def test_no_name(self):
        result = _axscript_command_entry(0, 0, 0, {}, "group", "desc", "script")
        assert result is None

    def test_not_dict(self):
        assert _axscript_command_entry(0, 0, 0, "not a dict", "g", "d", "s") is None


class TestNormalizeAxscriptCatalog_final:
    def test_basic(self):
        catalog = [{"Agent": "test", "Groups": [{"group_name": "g1", "commands": [{"name": "cmd1"}]}]}]
        result = _normalize_axscript_catalog(catalog)
        assert len(result) == 1

    def test_empty(self):
        assert _normalize_axscript_catalog([]) == []

    def test_none(self):
        assert _normalize_axscript_catalog(None) == []


class TestFindCompletedAdaptixTask_final:
    def test_completed(self):
        tasks = [{"a_cmdline": "whoami", "a_completed": True, "a_text": "admin", "a_message": ""}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is True
        assert latest is not None

    def test_no_match(self):
        tasks = [{"a_cmdline": "id", "a_completed": True}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is False

    def test_incomplete_latest(self):
        tasks = [{"a_cmdline": "whoami", "a_completed": False, "a_text": "", "a_message": ""}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is False
        assert latest is not None


class TestParseAdaptixAgent_final:
    def test_terminated(self):
        a = {"a_mark": "Terminated", "a_internal_ip": "10.0.0.1", "a_external_ip": "", "a_computer": "WS1", "a_username": "u", "a_domain": "", "a_os_desc": "", "a_arch": "", "a_process": "", "a_id": "ag1", "a_listener": "", "a_last_tick": 0}
        result = _parse_adaptix_agent(a, 0, 600)
        assert result["alive"] is False

    def test_stale(self):
        a = {"a_mark": "", "a_internal_ip": "10.0.0.1", "a_external_ip": "", "a_computer": "", "a_username": "", "a_domain": "", "a_os_desc": "", "a_arch": "", "a_process": "", "a_id": "", "a_listener": "", "a_last_tick": 1999000000}
        result = _parse_adaptix_agent(a, 2000000000, 600)
        assert result["alive"] is False

    def test_alive(self):
        a = {"a_mark": "", "a_internal_ip": "10.0.0.1", "a_external_ip": "", "a_computer": "", "a_username": "", "a_domain": "", "a_os_desc": "", "a_arch": "", "a_process": "", "a_id": "", "a_listener": "", "a_last_tick": 0}
        result = _parse_adaptix_agent(a, 0, 600)
        assert result["alive"] is True


class TestAdaptixBase_final:
    def test_default_endpoint(self):
        result = _adaptix_base({"url": "http://localhost:8080"})
        assert result == "http://localhost:8080/endpoint"

    def test_custom_endpoint(self):
        result = _adaptix_base({"url": "http://localhost:8080", "endpoint": "/api"})
        assert result == "http://localhost:8080/api"


# ════════ from test_c2_adaptix_final2.py ════════
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from app.routers.c2._adaptix import (
    _adaptix_os_for_target,
    _adaptix_ctx_agent,
    _adaptix_target_note,
    _adaptix_target_to_host,
    _adaptix_agent_to_host,
    _adaptix_cred_result,
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
    _parse_adaptix_agent,
    _adaptix_base,
    _adaptix_fetch_targets_dict,
    _adaptix_fetch_raw_creds_list,
    _astr,
)


class TestAdaptixCtxAgent_final2:
    def test_finds_active_agent(self):
        t = {"t_agents": ["a1", "a2"]}
        agents = {"a1": {"a_mark": "Active"}, "a2": {"a_mark": "Terminated"}}
        assert _adaptix_ctx_agent(t, agents)["a_mark"] == "Active"

    def test_all_terminated(self):
        t = {"t_agents": ["a1"]}
        agents = {"a1": {"a_mark": "Terminated"}}
        assert _adaptix_ctx_agent(t, agents) == {}

    def test_no_agents(self):
        assert _adaptix_ctx_agent({}, {}) == {}

    def test_none_agents(self):
        assert _adaptix_ctx_agent({"t_agents": None}, {}) == {}


class TestAdaptixTargetNote_final2:
    def test_full(self):
        t = {"t_info": "info"}
        ctx = {"a_process": "proc", "a_pid": 123, "a_arch": "x64", "a_impersonated": "admin"}
        result = _adaptix_target_note(t, ctx, "corp.local", ["a1", "a2"])
        assert "info" in result
        assert "corp.local" in result
        assert "proc" in result
        assert "a1, a2" in result

    def test_empty(self):
        assert _adaptix_target_note({}, {}, "", []) == ""


class TestAdaptixAgentToHost_final2:
    def test_seen_ip_skipped(self):
        a = {"a_internal_ip": "1.1.1.1", "a_external_ip": "", "a_mark": "Active"}
        assert _adaptix_agent_to_host(a, {"1.1.1.1"}) is None

    def test_no_ip(self):
        assert _adaptix_agent_to_host({"a_internal_ip": "", "a_external_ip": ""}, set()) is None

    def test_basic(self):
        a = {"a_internal_ip": "10.0.0.1", "a_computer": "SRV", "a_os_desc": "Win",
             "a_domain": "corp", "a_username": "admin", "a_arch": "x64",
             "a_process": "proc", "a_pid": 1, "a_mark": "", "a_listener": "l1",
             "a_id": "id1"}
        r = _adaptix_agent_to_host(a, set())
        assert r["ip"] == "10.0.0.1"
        assert r["alive"] is True
        assert r["source"] == "adaptix"

    def test_dead_agent(self):
        a = {"a_internal_ip": "10.0.0.1", "a_mark": "Terminated", "a_id": "id1"}
        r = _adaptix_agent_to_host(a, set())
        assert r["alive"] is False
        assert r["beacon_id"] == ""


class TestAdaptixCredResult_final2:
    def test_empty(self):
        assert _adaptix_cred_result({}) is None
        assert _adaptix_cred_result(None) is None

    def test_no_username(self):
        assert _adaptix_cred_result({"c_password": "x"}) is None

    def test_hash_type(self):
        r = _adaptix_cred_result({"c_username": "u", "c_password": "hash", "c_type": "ntlm_hash"})
        assert r["type"] == "hash"

    def test_plain_type(self):
        r = _adaptix_cred_result({"c_username": "u", "c_password": "pass", "c_type": "plain"})
        assert r["type"] == "plain"


class TestNormalizeC2Cred_final2:
    def test_basic(self):
        r = _normalize_c2_cred({"c_creds_id": "c1", "c_username": "u", "c_password": "p",
                                "c_realm": "corp", "c_host": "10.0.0.1", "c_type": "plain"}, "int1")
        assert r["source"] == "c2"
        assert r["integration_id"] == "int1"


class TestNormalizeChoiceList_final2:
    def test_dict_choices(self):
        r = _normalize_choice_list({"choices": [{"value": "a", "label": "A"}, {"value": "b", "label": "B"}]})
        assert len(r) == 2

    def test_list_items(self):
        r = _normalize_choice_list(["x", "y"])
        assert len(r) == 2

    def test_dict_items(self):
        r = _normalize_choice_list([{"id": "1", "name": "test"}])
        assert len(r) == 1
        assert r[0]["value"] == "1"

    def test_none_value_skipped(self):
        r = _normalize_choice_list([{"key": None}])
        assert len(r) == 0

    def test_options_key(self):
        r = _normalize_choice_list({"options": ["a"]})
        assert len(r) == 1

    def test_values_key(self):
        r = _normalize_choice_list({"values": ["a"]})
        assert len(r) == 1


class TestNormalizeParamType_final2:
    def test_with_choices(self):
        assert _normalize_param_type("text", [{"value": "a"}]) == "choice"

    def test_bool_variants(self):
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
        assert _normalize_param_type("unknown", []) == "text"


class TestNormalizeParam_final2:
    def test_all_keys(self):
        p = _normalize_param({"name": "n", "label": "l", "type": "int", "required": True,
                               "default": 5, "placeholder": "ph", "description": "desc"}, 0)
        assert p["key"] == "n"
        assert p["type"] == "number"
        assert p["required"] is True

    def test_fallback_key(self):
        p = _normalize_param({}, 2)
        assert p["key"] == "arg_3"


class TestExtractCommandParams_final2:
    def test_various_keys(self):
        for key in ("parameters", "params", "args", "fields", "options"):
            r = _extract_command_params({key: [{"name": "x"}]})
            assert len(r) == 1

    def test_non_list(self):
        assert _extract_command_params({"parameters": "bad"}) == []

    def test_string_items(self):
        r = _extract_command_params({"parameters": ["x"]})
        assert len(r) == 1


class TestBuildTemplateFromCommand_final2:
    def test_template_present(self):
        assert _build_template_from_command("n", {"template": "tpl"}, []) == "tpl"

    def test_cmdline_present(self):
        assert _build_template_from_command("n", {"cmdline": "cmd"}, []) == "cmd"

    def test_no_params(self):
        assert _build_template_from_command("run", {}, []) == "run"

    def test_with_params(self):
        r = _build_template_from_command("run", {}, [{"key": "ARG1"}])
        assert "{{ARG1}}" in r


class TestParseTemplatePlaceholders_final2:
    def test_adds_unknown(self):
        r = _parse_template_placeholders("{{FOO}}", [])
        assert len(r) == 1
        assert r[0]["key"] == "foo"

    def test_skips_known(self):
        r = _parse_template_placeholders("{{FOO}}", [{"key": "foo"}])
        assert len(r) == 1


class TestAxscriptCommandEntry_final2:
    def test_not_dict(self):
        assert _axscript_command_entry(0, 0, 0, "string", "g", "d", "s") is None

    def test_no_name(self):
        assert _axscript_command_entry(0, 0, 0, {}, "g", "d", "s") is None

    def test_valid(self):
        r = _axscript_command_entry(0, 0, 0, {"name": "cmd1"}, "g", "d", "s")
        assert r["name"] == "cmd1"
        assert r["group"] == "g"


class TestProcessCatalogEntry_final2:
    def test_with_groups(self):
        entry = {"Agent": "a1", "groups": [
            {"group_name": "g1", "commands": [{"name": "c1"}]},
            {"group_name": "g2", "commands": [{"name": "c2"}]},
        ]}
        result = []
        _process_catalog_entry(0, entry, result)
        assert len(result) == 2

    def test_non_dict_group(self):
        entry = {"groups": ["not_a_dict"]}
        result = []
        _process_catalog_entry(0, entry, result)
        assert len(result) == 0


class TestNormalizeAxscriptCatalog_final2:
    def test_empty(self):
        assert _normalize_axscript_catalog([]) == []

    def test_full(self):
        r = _normalize_axscript_catalog([
            {"Agent": "a", "Groups": [
                {"group_name": "g", "commands": [{"name": "c"}]}
            ]}
        ])
        assert len(r) == 1


class TestFindCompletedTask:
    def test_completed(self):
        tasks = [{"a_cmdline": "whoami", "a_completed": True, "a_text": "root"}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is True
        assert updates["output"] == "root"

    def test_not_completed(self):
        tasks = [{"a_cmdline": "whoami", "a_completed": False}]
        done, latest, updates = _find_completed_adaptix_task(tasks, "whoami")
        assert done is False
        assert latest is not None
        assert updates == {}

    def test_no_match(self):
        done, latest, updates = _find_completed_adaptix_task([], "whoami")
        assert done is False
        assert latest is None


class TestParseAdaptixAgent_final2:
    def test_alive(self):
        a = {"a_mark": "Active", "a_last_tick": 0, "a_internal_ip": "10.0.0.1",
             "a_computer": "SRV", "a_username": "u", "a_domain": "d",
             "a_os_desc": "Win", "a_arch": "x64", "a_process": "p",
             "a_id": "id1", "a_listener": "l1", "a_last_seen": "now"}
        r = _parse_adaptix_agent(a, 0, 600)
        assert r["alive"] is True
        assert r["ip"] == "10.0.0.1"

    def test_dead_mark(self):
        a = {"a_mark": "dead", "a_last_tick": 0, "a_internal_ip": "10.0.0.1"}
        r = _parse_adaptix_agent(a, 0, 600)
        assert r["alive"] is False

    def test_stale(self):
        now = 2000_000_000
        a = {"a_mark": "Active", "a_last_tick": now - 700, "a_internal_ip": "10.0.0.1"}
        r = _parse_adaptix_agent(a, now, 600)
        assert r["alive"] is False
        assert r["stale_seconds"] is not None

    def test_invalid_tick(self):
        a = {"a_mark": "Active", "a_last_tick": "bad", "a_internal_ip": "10.0.0.1"}
        r = _parse_adaptix_agent(a, 0, 600)
        assert r["last_tick"] is None


class TestAdaptixBase_final2:
    def test_default_endpoint(self):
        cfg = {"url": "http://host", "endpoint": ""}
        assert _adaptix_base(cfg) == "http://host/endpoint"

    def test_custom_endpoint(self):
        cfg = {"url": "http://host/", "endpoint": "/custom"}
        assert _adaptix_base(cfg) == "http://host/custom"


class TestAstr_final2:
    def test_basic(self):
        assert _astr({"k": " val "}, "k") == "val"

    def test_missing(self):
        assert _astr({}, "k") == ""


@pytest.mark.asyncio
class TestFetchTargetsDict:
    async def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"t_target_id": "t1", "t_address": "10.0.0.1"}]
        client = AsyncMock()
        client.get.return_value = mock_resp
        r = await _adaptix_fetch_targets_dict(client, "http://base", {})
        assert "t1" in r

    async def test_failure(self):
        client = AsyncMock()
        client.get.side_effect = Exception("fail")
        r = await _adaptix_fetch_targets_dict(client, "http://base", {})
        assert r == {}


@pytest.mark.asyncio
class TestFetchRawCredsList:
    async def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"c_username": "u"}]
        client = AsyncMock()
        client.get.return_value = mock_resp
        r = await _adaptix_fetch_raw_creds_list(client, "http://base", {})
        assert len(r) == 1

    async def test_failure(self):
        client = AsyncMock()
        client.get.side_effect = Exception("fail")
        r = await _adaptix_fetch_raw_creds_list(client, "http://base", {})
        assert r == []


# ════════ from test_c2_adaptix_v3.py ════════
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from app.routers.c2._adaptix import (
    _parse_adaptix_agent,
    _astr,
    _normalize_c2_cred,
    _normalize_choice_list,
    _normalize_param_type,
    _normalize_param,
    _normalize_axscript_catalog,
    _adaptix_target_to_host,
    _adaptix_agent_to_host,
    _adaptix_cred_result,
    _adaptix_base,
)


class TestParseAdaptixAgent_v3:
    def test_basic(self):
        a = {
            "a_id": "ag1", "a_mark": "active", "a_last_tick": 1700000000,
            "a_internal_ip": "10.0.0.1", "a_external_ip": "",
            "a_computer": "SRV", "a_username": "admin", "a_domain": "corp",
            "a_os_desc": "Windows 10", "a_arch": "x64", "a_process": "cmd.exe",
            "a_listener": "http", "a_last_seen": "now",
        }
        import time
        r = _parse_adaptix_agent(a, int(time.time()), 600)
        assert r["ip"] == "10.0.0.1"
        assert r["hostname"] == "SRV"
        assert r["agent_id"] == "ag1"

    def test_dead_mark(self):
        a = {"a_id": "ag1", "a_mark": "dead", "a_last_tick": 0,
             "a_internal_ip": "10.0.0.1", "a_external_ip": "",
             "a_computer": "", "a_username": "", "a_domain": "",
             "a_os_desc": "", "a_arch": "", "a_process": "",
             "a_listener": "", "a_last_seen": ""}
        r = _parse_adaptix_agent(a, 1700000000, 600)
        assert r["alive"] is False

    def test_stale(self):
        a = {"a_id": "ag1", "a_mark": "", "a_last_tick": 1700000000,
             "a_internal_ip": "10.0.0.1", "a_external_ip": "",
             "a_computer": "", "a_username": "", "a_domain": "",
             "a_os_desc": "", "a_arch": "", "a_process": "",
             "a_listener": "", "a_last_seen": ""}
        r = _parse_adaptix_agent(a, 1700001000, 600)
        assert r["alive"] is False
        assert r["stale_seconds"] is not None

    def test_invalid_last_tick(self):
        a = {"a_id": "ag1", "a_mark": "", "a_last_tick": "invalid",
             "a_internal_ip": "10.0.0.1", "a_external_ip": "",
             "a_computer": "", "a_username": "", "a_domain": "",
             "a_os_desc": "", "a_arch": "", "a_process": "",
             "a_listener": "", "a_last_seen": ""}
        r = _parse_adaptix_agent(a, 1700000000, 600)
        assert r["last_tick"] is None

    def test_external_ip_fallback(self):
        a = {"a_id": "ag1", "a_mark": "", "a_last_tick": 0,
             "a_internal_ip": "", "a_external_ip": "1.1.1.1",
             "a_computer": "", "a_username": "", "a_domain": "",
             "a_os_desc": "", "a_arch": "", "a_process": "",
             "a_listener": "", "a_last_seen": ""}
        r = _parse_adaptix_agent(a, 0, 600)
        assert r["ip"] == "1.1.1.1"


class TestAstr_v3:
    def test_basic(self):
        assert _astr({"key": "value"}, "key") == "value"

    def test_none(self):
        assert _astr({}, "key") == ""

    def test_whitespace(self):
        assert _astr({"key": "  val  "}, "key") == "val"


class TestNormalizeC2Cred_v3:
    def test_basic(self):
        r = _normalize_c2_cred({"c_creds_id": "1", "c_username": "admin", "c_password": "pass",
                                 "c_realm": "corp", "c_host": "10.0.0.1", "c_type": "plain"}, "i1")
        assert r["id"] == "1"
        assert r["source"] == "c2"
        assert r["integration_id"] == "i1"
        assert r["username"] == "admin"


class TestNormalizeChoiceList_v3:
    def test_list_of_strings(self):
        r = _normalize_choice_list(["a", "b", "c"])
        assert len(r) == 3
        assert r[0]["value"] == "a"

    def test_list_of_dicts(self):
        r = _normalize_choice_list([{"value": "v1", "label": "Label 1"}])
        assert r[0]["value"] == "v1"
        assert r[0]["label"] == "Label 1"

    def test_dict_with_choices(self):
        r = _normalize_choice_list({"choices": ["x"]})
        assert len(r) == 1

    def test_dict_with_options(self):
        r = _normalize_choice_list({"options": [{"id": "1", "name": "n"}]})
        assert r[0]["value"] == "1"

    def test_none(self):
        assert _normalize_choice_list(None) == []

    def test_skips_none_values(self):
        r = _normalize_choice_list([{"label": "x"}])
        assert len(r) == 0


class TestNormalizeParamType_v3:
    def test_bool(self):
        assert _normalize_param_type("bool", []) == "boolean"

    def test_number(self):
        assert _normalize_param_type("int", []) == "number"

    def test_choice(self):
        assert _normalize_param_type("select", []) == "choice"

    def test_with_choices(self):
        assert _normalize_param_type("text", [{"value": "a"}]) == "choice"

    def test_textarea(self):
        assert _normalize_param_type("textarea", []) == "textarea"

    def test_default(self):
        assert _normalize_param_type("string", []) == "text"


class TestNormalizeParam_v3:
    def test_basic(self):
        r = _normalize_param({"key": "my_param", "type": "text", "default": "val", "required": True}, 0)
        assert r["key"] == "my_param"
        assert r["type"] == "text"

    def test_name_fallback(self):
        r = _normalize_param({"name": "p1", "type": "int"}, 1)
        assert r["key"] == "p1"

    def test_with_choices(self):
        r = _normalize_param({"key": "p", "choices": ["a", "b"]}, 0)
        assert r["type"] == "choice"
        assert len(r["choices"]) == 2


class TestAdaptixTargetToHost_v3:
    def test_basic(self):
        t = {"t_id": "t1", "t_address": "10.0.0.1", "t_computer": "srv", "t_os": "Win"}
        r = _adaptix_target_to_host(t, {})
        assert r is not None
        assert r["ip"] == "10.0.0.1"

    def test_no_address(self):
        t = {"t_id": "t1", "t_address": ""}
        r = _adaptix_target_to_host(t, {})
        assert r is None

    def test_with_agents(self):
        t = {"t_id": "t1", "t_address": "10.0.0.1", "t_agents": ["ag1"]}
        r = _adaptix_target_to_host(t, {})
        assert r is not None


class TestAdaptixAgentToHost_v3:
    def test_new_ip(self):
        a = {"a_internal_ip": "10.0.0.2", "a_external_ip": "",
             "a_mark": "active", "a_computer": "srv", "a_username": "",
             "a_domain": "", "a_os_desc": "", "a_arch": "", "a_process": "",
             "a_listener": "", "a_pid": None}
        r = _adaptix_agent_to_host(a, {"10.0.0.1"})
        assert r is not None
        assert r["ip"] == "10.0.0.2"

    def test_existing_ip(self):
        a = {"a_internal_ip": "10.0.0.1", "a_external_ip": "",
             "a_mark": "active"}
        r = _adaptix_agent_to_host(a, {"10.0.0.1"})
        assert r is None


class TestAdaptixCredResult_v3:
    def test_basic(self):
        r = _adaptix_cred_result({"c_username": "admin", "c_password": "pass", "c_realm": "corp", "c_host": "10.0.0.1"})
        assert r is not None
        assert r["username"] == "admin"

    def test_empty(self):
        assert _adaptix_cred_result({}) is None

    def test_no_username(self):
        assert _adaptix_cred_result({"c_password": "x"}) is None


class TestAdaptixBase_v3:
    def test_basic(self):
        r = _adaptix_base({"url": "http://localhost:8080"})
        assert "localhost:8080" in r


class TestNormalizeAxscriptCatalog_v3:
    def test_basic(self):
        data = [
            {"Agent": "test", "Groups": [
                {"group_name": "General", "commands": [
                    {"name": "cmd1", "description": "desc", "parameters": []}
                ]}
            ]}
        ]
        r = _normalize_axscript_catalog(data)
        assert len(r) == 1

    def test_empty(self):
        assert _normalize_axscript_catalog([]) == []

    def test_no_groups(self):
        r = _normalize_axscript_catalog([{"Agent": "test"}])
        assert r == []
