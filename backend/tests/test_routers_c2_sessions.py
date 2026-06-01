"""Tests for C2 sessions router — pure unit tests for helper functions."""
from app.routers.c2._sessions import _c2_deduplicate_agents, _c2_format_session_entry


class TestC2DeduplicateAgents:
    def test_deduplicate_keeps_alive(self):
        agents = [
            {"ip": "10.0.0.1", "username": "admin", "alive": True, "last_seen": "2025-01-02"},
            {"ip": "10.0.0.1", "username": "admin", "alive": False, "last_seen": "2025-01-01"},
        ]
        result = _c2_deduplicate_agents(agents)
        assert len(result) == 1
        key = list(result.keys())[0]
        assert result[key]["alive"] is True

    def test_deduplicate_prefers_alive(self):
        agents = [
            {"ip": "10.0.0.1", "username": "user", "alive": False, "last_seen": "2025-01-01"},
            {"ip": "10.0.0.1", "username": "user", "alive": True, "last_seen": "2025-01-01"},
        ]
        result = _c2_deduplicate_agents(agents)
        key = list(result.keys())[0]
        assert result[key]["alive"] is True

    def test_empty_ip_skipped(self):
        agents = [{"ip": "", "username": "admin"}]
        result = _c2_deduplicate_agents(agents)
        assert len(result) == 0

    def test_empty_list(self):
        result = _c2_deduplicate_agents([])
        assert result == {}


class TestC2FormatSessionEntry:
    def test_format_basic(self):
        cfg = {"id": "int1", "name": "Test", "type": "sliver"}
        agent = {
            "ip": "10.0.0.1", "hostname": "srv", "username": "admin",
            "domain": "corp", "os": "Windows", "arch": "x64",
            "process": "cmd.exe", "beacon_id": "b1", "listener": "l1",
            "alive": True, "mark": "", "last_seen": "2025-01-01",
        }
        entry = _c2_format_session_entry(cfg, "10.0.0.1", "admin", agent, None)
        assert entry["ip"] == "10.0.0.1"
        assert entry["integration_id"] == "int1"
        assert entry["privilege_label"] == "admin"

    def test_format_with_host(self):
        from unittest.mock import MagicMock
        cfg = {"id": "int2", "name": "Mythic", "type": "mythic"}
        agent = {
            "ip": "10.0.0.2", "hostname": "dc", "username": "admin",
            "os": "Windows", "arch": "x64", "process": "ps",
            "alive": True, "last_seen": "2025-01-01",
        }
        host = MagicMock()
        host.id = "h1"
        host.os = "Windows"
        entry = _c2_format_session_entry(cfg, "10.0.0.2", "admin", agent, host)
        assert entry["matched_host_id"] == "h1"
