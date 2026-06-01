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


class TestParseAdaptixAgent:
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


class TestAstr:
    def test_basic(self):
        assert _astr({"key": "value"}, "key") == "value"

    def test_none(self):
        assert _astr({}, "key") == ""

    def test_whitespace(self):
        assert _astr({"key": "  val  "}, "key") == "val"


class TestNormalizeC2Cred:
    def test_basic(self):
        r = _normalize_c2_cred({"c_creds_id": "1", "c_username": "admin", "c_password": "pass",
                                 "c_realm": "corp", "c_host": "10.0.0.1", "c_type": "plain"}, "i1")
        assert r["id"] == "1"
        assert r["source"] == "c2"
        assert r["integration_id"] == "i1"
        assert r["username"] == "admin"


class TestNormalizeChoiceList:
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


class TestNormalizeParamType:
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


class TestNormalizeParam:
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


class TestAdaptixTargetToHost:
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


class TestAdaptixAgentToHost:
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


class TestAdaptixCredResult:
    def test_basic(self):
        r = _adaptix_cred_result({"c_username": "admin", "c_password": "pass", "c_realm": "corp", "c_host": "10.0.0.1"})
        assert r is not None
        assert r["username"] == "admin"

    def test_empty(self):
        assert _adaptix_cred_result({}) is None

    def test_no_username(self):
        assert _adaptix_cred_result({"c_password": "x"}) is None


class TestAdaptixBase:
    def test_basic(self):
        r = _adaptix_base({"url": "http://localhost:8080"})
        assert "localhost:8080" in r


class TestNormalizeAxscriptCatalog:
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
