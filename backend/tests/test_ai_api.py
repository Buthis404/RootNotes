"""Tests for AI API endpoints and helper functions."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
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
    r = module_client.post("/api/projects", json={"name": "AITest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestMaskConfig:
    def test_masks_long_key(self):
        from app.routers.ai import _mask_config
        cfg = {"providers": [{"api_key": "sk-1234567890abcdef"}]}
        masked = _mask_config(cfg)
        assert masked["providers"][0]["api_key"] == "****cdef"

    def test_masks_short_key(self):
        from app.routers.ai import _mask_config
        cfg = {"providers": [{"api_key": "abc"}]}
        masked = _mask_config(cfg)
        assert masked["providers"][0]["api_key"] == "****"

    def test_no_key(self):
        from app.routers.ai import _mask_config
        cfg = {"providers": [{}]}
        masked = _mask_config(cfg)
        assert "api_key" not in masked["providers"][0]

    def test_empty_key(self):
        from app.routers.ai import _mask_config
        cfg = {"providers": [{"api_key": ""}]}
        masked = _mask_config(cfg)
        assert masked["providers"][0]["api_key"] == ""

    def test_deepcopy(self):
        from app.routers.ai import _mask_config
        cfg = {"providers": [{"api_key": "sk-secret123"}]}
        masked = _mask_config(cfg)
        assert cfg["providers"][0]["api_key"] == "sk-secret123"


class TestIsAiEnabled:
    def test_default_true(self):
        from app.routers.ai import _is_ai_enabled
        assert _is_ai_enabled({}) is True

    def test_explicit_true(self):
        from app.routers.ai import _is_ai_enabled
        assert _is_ai_enabled({"ai_enabled": True}) is True

    def test_explicit_false(self):
        from app.routers.ai import _is_ai_enabled
        assert _is_ai_enabled({"ai_enabled": False}) is False


class TestBuildSystemPrompt:
    def test_includes_project_stats(self):
        from app.routers.ai import _build_system_prompt
        db = MagicMock()
        db.query.return_value.filter.return_value.count.return_value = 5
        prompt = _build_system_prompt(db, "pid1")
        assert "5 hosts" in prompt
        assert "5 credentials" in prompt
        assert "5 findings" in prompt

    def test_includes_today_date(self):
        from app.routers.ai import _build_system_prompt
        db = MagicMock()
        db.query.return_value.filter.return_value.count.return_value = 0
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        prompt = _build_system_prompt(db, "pid1")
        assert today in prompt


class TestGetAiStatus:
    def test_returns_status(self, module_client: TestClient):
        with patch("app.routers.ai.get_config", return_value={"ai_enabled": True, "providers": [{"enabled": True}]}):
            r = module_client.get("/api/ai/status")
            assert r.status_code == 200
            data = r.json()
            assert data["enabled"] is True
            assert data["has_providers"] is True

    def test_disabled(self, module_client: TestClient):
        with patch("app.routers.ai.get_config", return_value={"ai_enabled": False, "providers": []}):
            r = module_client.get("/api/ai/status")
            assert r.status_code == 200
            assert r.json()["enabled"] is False


class TestGetAiConfig:
    def test_returns_masked_config(self, module_client: TestClient):
        with patch("app.routers.ai.get_config", return_value={"providers": [{"api_key": "sk-12345678"}]}):
            r = module_client.get("/api/ai/config")
            assert r.status_code == 200
            data = r.json()
            assert data["providers"][0]["api_key"] != "sk-12345678"


class TestUpdateAiConfig:
    def test_admin_can_update(self, module_client: TestClient):
        with patch("app.routers.ai.save_config") as m_save:
            r = module_client.put("/api/ai/config", json={"providers": [], "ai_enabled": True})
            assert r.status_code == 200
            m_save.assert_called_once()
            data = r.json()
            assert data["ai_enabled"] is True

    def test_normalizes_ai_enabled(self, module_client: TestClient):
        with patch("app.routers.ai.save_config"):
            r = module_client.put("/api/ai/config", json={"providers": []})
            assert r.status_code == 200
            assert r.json()["ai_enabled"] is True

    def test_sets_false(self, module_client: TestClient):
        with patch("app.routers.ai.save_config"):
            r = module_client.put("/api/ai/config", json={"providers": [], "ai_enabled": False})
            assert r.status_code == 200
            assert r.json()["ai_enabled"] is False


class TestAiChat:
    def test_disabled_returns_503(self, module_client: TestClient):
        with patch("app.routers.ai.get_config", return_value={"ai_enabled": False, "providers": []}):
            r = module_client.post(f"/api/projects/{_state['pid']}/ai/chat", json={
                "message": "hello",
            })
            assert r.status_code == 503

    def test_success_response(self, module_client: TestClient):
        cfg = {"ai_enabled": True, "providers": [{"enabled": True}], "max_tool_calls": 5, "agent_mode": False}
        with patch("app.routers.ai.get_config", return_value=cfg), \
             patch("app.routers.ai.call_llm", new_callable=AsyncMock, return_value={
                 "content": "Hello response", "provider_id": "openai", "tool_calls": []
             }):
            r = module_client.post(f"/api/projects/{_state['pid']}/ai/chat", json={
                "message": "hello", "agent_mode": False,
            })
            assert r.status_code == 200
            data = r.json()
            assert data["answer"] == "Hello response"
            assert data["provider_used"] == "openai"

    def test_chat_with_history(self, module_client: TestClient):
        cfg = {"ai_enabled": True, "providers": [{"enabled": True}], "max_tool_calls": 5, "agent_mode": False}
        with patch("app.routers.ai.get_config", return_value=cfg), \
             patch("app.routers.ai.call_llm", new_callable=AsyncMock, return_value={
                 "content": "response", "provider_id": "test", "tool_calls": []
             }):
            r = module_client.post(f"/api/projects/{_state['pid']}/ai/chat", json={
                "message": "followup",
                "history": [{"role": "user", "content": "first message"}],
                "agent_mode": False,
            })
            assert r.status_code == 200

    def test_chat_error_returns_500(self, module_client: TestClient):
        cfg = {"ai_enabled": True, "providers": [{"enabled": True}], "max_tool_calls": 5, "agent_mode": True}
        with patch("app.routers.ai.get_config", return_value=cfg), \
             patch("app.routers.ai.call_llm", new_callable=AsyncMock, side_effect=Exception("LLM down")):
            r = module_client.post(f"/api/projects/{_state['pid']}/ai/chat", json={
                "message": "hello",
            })
            assert r.status_code == 500


class TestExecuteToolCall:
    @pytest.mark.asyncio
    async def test_parses_string_args(self):
        from app.routers.ai import _execute_tool_call
        tc = {"id": "call_1", "function": {"name": "test_tool", "arguments": '{"key": "value"}'}}
        log = []
        with patch("app.routers.ai.execute_tool", new_callable=AsyncMock, return_value={"ok": True}):
            result = await _execute_tool_call(tc, MagicMock(), "pid1", log)
        assert result["role"] == "tool"
        assert result["tool_call_id"] == "call_1"
        assert len(log) == 1

    @pytest.mark.asyncio
    async def test_handles_invalid_json(self):
        from app.routers.ai import _execute_tool_call
        tc = {"id": "c1", "function": {"name": "t", "arguments": "not json"}}
        log = []
        with patch("app.routers.ai.execute_tool", new_callable=AsyncMock, return_value={}):
            result = await _execute_tool_call(tc, MagicMock(), "pid1", log)
        assert result["role"] == "tool"

    @pytest.mark.asyncio
    async def test_dict_args(self):
        from app.routers.ai import _execute_tool_call
        tc = {"id": "c1", "function": {"name": "t", "arguments": {"key": "val"}}}
        log = []
        with patch("app.routers.ai.execute_tool", new_callable=AsyncMock, return_value={}):
            result = await _execute_tool_call(tc, MagicMock(), "pid1", log)
        assert result["role"] == "tool"
