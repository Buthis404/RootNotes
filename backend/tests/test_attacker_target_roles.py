"""
Tests for attacker SSH target role flags (is_operator / runs_pivot).
"""
import pytest
from fastapi import HTTPException

from app.routers.system_modules import AttackerSSHTargetBody, _validate_attacker_target


def _body(**overrides):
    base = dict(
        name="t1", host="10.0.0.5", port=22, username="ops",
        password="x", private_key="", known_hosts_policy="accept_new",
        proxy_type="none", proxy_host="", proxy_port=1080,
        proxy_username="", proxy_password="", proxy_private_key="",
        exec_proxy_type="none", exec_proxy_host="", exec_proxy_port=1080,
        exec_proxy_username="", exec_proxy_password="",
        exec_jump_host="", exec_jump_port=22, exec_jump_username="",
        project_ids=[], enabled=True,
        is_operator=True, runs_pivot=True,
    )
    base.update(overrides)
    return AttackerSSHTargetBody(**base)


def test_validator_accepts_default_both_roles(monkeypatch):
    # _validate_attacker_target calls _require_attacker_module_enabled —
    # short-circuit that check for unit testing.
    from app.routers import system_modules as sm
    monkeypatch.setattr(sm, "_require_attacker_module_enabled", lambda: None)
    _validate_attacker_target(_body())  # should not raise


def test_validator_rejects_neither_role(monkeypatch):
    from app.routers import system_modules as sm
    monkeypatch.setattr(sm, "_require_attacker_module_enabled", lambda: None)
    with pytest.raises(HTTPException) as exc:
        _validate_attacker_target(_body(is_operator=False, runs_pivot=False))
    assert exc.value.status_code == 400
    assert "operator host" in str(exc.value.detail).lower() or "pivot" in str(exc.value.detail).lower()


def test_validator_accepts_operator_only(monkeypatch):
    from app.routers import system_modules as sm
    monkeypatch.setattr(sm, "_require_attacker_module_enabled", lambda: None)
    _validate_attacker_target(_body(is_operator=True, runs_pivot=False))


def test_validator_accepts_pivot_only(monkeypatch):
    from app.routers import system_modules as sm
    monkeypatch.setattr(sm, "_require_attacker_module_enabled", lambda: None)
    _validate_attacker_target(_body(is_operator=False, runs_pivot=True))


def test_decrypt_target_fills_role_defaults():
    """Old targets stored before role flags existed should be treated as
    both-True for backwards compatibility."""
    from app.plugins.state import _decrypt_target
    legacy = {"id": "old", "name": "legacy", "host": "x", "port": 22,
              "username": "u", "password": "", "private_key": ""}
    out = _decrypt_target(legacy)
    assert out["is_operator"] is True
    assert out["runs_pivot"] is True


def test_decrypt_target_preserves_explicit_role_flags():
    from app.plugins.state import _decrypt_target
    explicit = {"id": "new", "name": "pivot-only", "host": "x", "port": 22,
                "username": "u", "password": "", "private_key": "",
                "is_operator": False, "runs_pivot": True}
    out = _decrypt_target(explicit)
    assert out["is_operator"] is False
    assert out["runs_pivot"] is True
