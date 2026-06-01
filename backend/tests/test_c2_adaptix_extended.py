"""Extended tests for app.routers.c2._adaptix — helper functions."""
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


class TestAdaptixOsForTarget:
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


class TestAdaptixCtxAgent:
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


class TestAdaptixTargetNote:
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


class TestAdaptixTargetToHost:
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


class TestAdaptixAgentToHost:
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


class TestAdaptixCredResult:
    def test_basic(self):
        result = _adaptix_cred_result({"c_username": "admin", "c_password": "pass", "c_type": "hash_ntlm"})
        assert result["username"] == "admin"
        assert result["type"] == "hash"

    def test_empty_returns_none(self):
        assert _adaptix_cred_result({}) is None

    def test_no_username_returns_none(self):
        assert _adaptix_cred_result({"c_username": ""}) is None


class TestNormalizeC2Cred:
    def test_basic(self):
        result = _normalize_c2_cred({"c_creds_id": "c1", "c_username": "u", "c_password": "p",
                                      "c_realm": "dom", "c_host": "10.0.0.1", "c_type": "plain"}, "iid1")
        assert result["integration_id"] == "iid1"
        assert result["username"] == "u"


class TestNormalizeChoiceList:
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


class TestNormalizeParamType:
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


class TestExtractCommandParams:
    def test_from_parameters(self):
        result = _extract_command_params({"parameters": [{"name": "arg1", "type": "text"}]})
        assert len(result) == 1
        assert result[0]["key"] == "arg1"

    def test_non_list_returns_empty(self):
        assert _extract_command_params({"parameters": "bad"}) == []

    def test_string_items(self):
        result = _extract_command_params({"params": ["simple_arg"]})
        assert len(result) == 1


class TestBuildTemplateFromCommand:
    def test_explicit_template(self):
        result = _build_template_from_command("run", {"template": "run --target {IP}"}, [])
        assert result == "run --target {IP}"

    def test_auto_template(self):
        result = _build_template_from_command("run", {}, [{"key": "IP", "label": "IP"}])
        assert "{IP}" in result

    def test_no_params(self):
        result = _build_template_from_command("run", {}, [])
        assert result == "run"


class TestParseTemplatePlaceholders:
    def test_finds_new_placeholders(self):
        result = _parse_template_placeholders("cmd {{NEW_VAR}}", [])
        assert any(p["key"] == "new_var" for p in result)

    def test_skips_known(self):
        params = [{"key": "known", "label": "known", "type": "text", "raw_type": "",
                    "required": False, "default": "", "placeholder": "", "description": "",
                    "choices": [], "position": 0}]
        result = _parse_template_placeholders("cmd {{KNOWN}}", params)
        assert len(result) == 1


class TestAxscriptCommandEntry:
    def test_non_dict_returns_none(self):
        assert _axscript_command_entry(0, 0, 0, "string", "g", "d", "s") is None

    def test_empty_name_returns_none(self):
        assert _axscript_command_entry(0, 0, 0, {}, "g", "d", "s") is None

    def test_valid_entry(self):
        cmd = {"name": "test_cmd", "parameters": []}
        result = _axscript_command_entry(0, 0, 0, cmd, "group", "desc", "script")
        assert result["name"] == "test_cmd"
        assert result["group"] == "group"


class TestNormalizeAxscriptCatalog:
    def test_empty(self):
        assert _normalize_axscript_catalog([]) == []

    def test_with_groups(self):
        catalog = [{"Agent": "test", "Groups": [{"group_name": "g1", "commands": [
            {"name": "cmd1", "parameters": []}
        ]}]}]
        result = _normalize_axscript_catalog(catalog)
        assert len(result) == 1
        assert result[0]["name"] == "cmd1"


class TestFindCompletedAdaptixTask:
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


class TestParseAdaptixAgent:
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


class TestAstr:
    def test_returns_stripped(self):
        assert _astr({"key": "  val  "}, "key") == "val"

    def test_missing_key(self):
        assert _astr({}, "key") == ""
