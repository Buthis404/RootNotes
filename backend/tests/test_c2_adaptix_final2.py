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


class TestAdaptixCtxAgent:
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


class TestAdaptixTargetNote:
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


class TestAdaptixAgentToHost:
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


class TestAdaptixCredResult:
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


class TestNormalizeC2Cred:
    def test_basic(self):
        r = _normalize_c2_cred({"c_creds_id": "c1", "c_username": "u", "c_password": "p",
                                "c_realm": "corp", "c_host": "10.0.0.1", "c_type": "plain"}, "int1")
        assert r["source"] == "c2"
        assert r["integration_id"] == "int1"


class TestNormalizeChoiceList:
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


class TestNormalizeParamType:
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


class TestNormalizeParam:
    def test_all_keys(self):
        p = _normalize_param({"name": "n", "label": "l", "type": "int", "required": True,
                               "default": 5, "placeholder": "ph", "description": "desc"}, 0)
        assert p["key"] == "n"
        assert p["type"] == "number"
        assert p["required"] is True

    def test_fallback_key(self):
        p = _normalize_param({}, 2)
        assert p["key"] == "arg_3"


class TestExtractCommandParams:
    def test_various_keys(self):
        for key in ("parameters", "params", "args", "fields", "options"):
            r = _extract_command_params({key: [{"name": "x"}]})
            assert len(r) == 1

    def test_non_list(self):
        assert _extract_command_params({"parameters": "bad"}) == []

    def test_string_items(self):
        r = _extract_command_params({"parameters": ["x"]})
        assert len(r) == 1


class TestBuildTemplateFromCommand:
    def test_template_present(self):
        assert _build_template_from_command("n", {"template": "tpl"}, []) == "tpl"

    def test_cmdline_present(self):
        assert _build_template_from_command("n", {"cmdline": "cmd"}, []) == "cmd"

    def test_no_params(self):
        assert _build_template_from_command("run", {}, []) == "run"

    def test_with_params(self):
        r = _build_template_from_command("run", {}, [{"key": "ARG1"}])
        assert "{{ARG1}}" in r


class TestParseTemplatePlaceholders:
    def test_adds_unknown(self):
        r = _parse_template_placeholders("{{FOO}}", [])
        assert len(r) == 1
        assert r[0]["key"] == "foo"

    def test_skips_known(self):
        r = _parse_template_placeholders("{{FOO}}", [{"key": "foo"}])
        assert len(r) == 1


class TestAxscriptCommandEntry:
    def test_not_dict(self):
        assert _axscript_command_entry(0, 0, 0, "string", "g", "d", "s") is None

    def test_no_name(self):
        assert _axscript_command_entry(0, 0, 0, {}, "g", "d", "s") is None

    def test_valid(self):
        r = _axscript_command_entry(0, 0, 0, {"name": "cmd1"}, "g", "d", "s")
        assert r["name"] == "cmd1"
        assert r["group"] == "g"


class TestProcessCatalogEntry:
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


class TestNormalizeAxscriptCatalog:
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


class TestParseAdaptixAgent:
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


class TestAdaptixBase:
    def test_default_endpoint(self):
        cfg = {"url": "http://host", "endpoint": ""}
        assert _adaptix_base(cfg) == "http://host/endpoint"

    def test_custom_endpoint(self):
        cfg = {"url": "http://host/", "endpoint": "/custom"}
        assert _adaptix_base(cfg) == "http://host/custom"


class TestAstr:
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
