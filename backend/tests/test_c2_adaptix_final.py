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


class TestAdaptixOsForTarget:
    def test_desk_present(self):
        assert _adaptix_os_for_target({"t_os_desk": "Windows 10", "t_os": 1}) == "Windows 10"

    def test_fallback_windows(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 1}) == "Windows"

    def test_fallback_linux(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 2}) == "Linux"

    def test_fallback_unknown(self):
        assert _adaptix_os_for_target({"t_os_desk": "", "t_os": 99}) == ""


class TestAdaptixTargetToHost:
    def test_basic(self):
        t = {"t_address": "10.0.0.1", "t_computer": "SRV1", "t_os_desk": "Windows", "t_os": 1, "t_domain": "corp", "t_agents": ["a1"], "t_alive": True, "t_info": "info"}
        agents_by_id = {"a1": {"a_mark": "", "a_username": "admin", "a_arch": "x64", "a_process": "implant", "a_pid": 42, "a_impersonated": ""}}
        result = _adaptix_target_to_host(t, agents_by_id)
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "SRV1"

    def test_no_ip(self):
        t = {"t_address": ""}
        assert _adaptix_target_to_host(t, {}) is None


class TestAdaptixAgentToHost:
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


class TestAdaptixCredResult:
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


class TestNormalizeC2Cred:
    def test_basic(self):
        result = _normalize_c2_cred({"c_creds_id": "cr1", "c_username": "admin", "c_password": "p", "c_realm": "corp", "c_host": "10.0.0.1", "c_type": "plain"}, "int1")
        assert result["integration_id"] == "int1"
        assert result["source"] == "c2"


class TestNormalizeChoiceList:
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


class TestNormalizeParamType:
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


class TestNormalizeParam:
    def test_basic(self):
        result = _normalize_param({"name": "param1", "type": "text"}, 0)
        assert result["key"] == "param1"
        assert result["type"] == "text"

    def test_fallback_key(self):
        result = _normalize_param({}, 3)
        assert result["key"] == "arg_4"


class TestBuildTemplateFromCommand:
    def test_explicit_template(self):
        result = _build_template_from_command("cmd", {"template": "run {{ARG}}"}, [])
        assert result == "run {{ARG}}"

    def test_no_template_no_params(self):
        result = _build_template_from_command("cmd", {}, [])
        assert result == "cmd"

    def test_generated(self):
        result = _build_template_from_command("cmd", {}, [{"key": "arg1", "label": "Arg1", "type": "text", "raw_type": "", "required": False, "default": "", "placeholder": "", "description": "", "choices": [], "position": 0}])
        assert "{{ARG1}}" in result


class TestParseTemplatePlaceholders:
    def test_finds_new(self):
        params = []
        result = _parse_template_placeholders("cmd {{HOST}} {{PORT}}", params)
        assert len(result) == 2

    def test_no_new(self):
        params = [{"key": "host"}]
        result = _parse_template_placeholders("cmd", params)
        assert len(result) == 1


class TestAxscriptCommandEntry:
    def test_valid(self):
        result = _axscript_command_entry(0, 0, 0, {"name": "cmd1"}, "group1", "desc", "script1")
        assert result is not None
        assert result["name"] == "cmd1"

    def test_no_name(self):
        result = _axscript_command_entry(0, 0, 0, {}, "group", "desc", "script")
        assert result is None

    def test_not_dict(self):
        assert _axscript_command_entry(0, 0, 0, "not a dict", "g", "d", "s") is None


class TestNormalizeAxscriptCatalog:
    def test_basic(self):
        catalog = [{"Agent": "test", "Groups": [{"group_name": "g1", "commands": [{"name": "cmd1"}]}]}]
        result = _normalize_axscript_catalog(catalog)
        assert len(result) == 1

    def test_empty(self):
        assert _normalize_axscript_catalog([]) == []

    def test_none(self):
        assert _normalize_axscript_catalog(None) == []


class TestFindCompletedAdaptixTask:
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


class TestParseAdaptixAgent:
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


class TestAdaptixBase:
    def test_default_endpoint(self):
        result = _adaptix_base({"url": "http://localhost:8080"})
        assert result == "http://localhost:8080/endpoint"

    def test_custom_endpoint(self):
        result = _adaptix_base({"url": "http://localhost:8080", "endpoint": "/api"})
        assert result == "http://localhost:8080/api"
