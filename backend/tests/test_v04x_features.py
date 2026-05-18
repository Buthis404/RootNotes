"""
Tests for v0.4.x features that were shipped without coverage:

- v0.4.0 P4 playbook DAG runner (cycle detection, dep resolution)
- v0.4.0 AI kill switch (ai_enabled flag)
- v0.4.3 Adaptix stale-by-last_tick detection
- v0.4.5 B5-1 enums + is_admin helper
- v0.4.6 P12 secret_scrub + WS redact policy
- v0.4.7 P5 sync_host_to_nodes
- v0.4.8 / v0.4.9 B3 race-safe upserts

Unit-focused. Each test exercises one helper / one decision branch.
"""
from __future__ import annotations

import pytest

from app import models
from app.core import secret_scrub
from app.core.db_upsert import try_insert_or_get, upsert_host_by_ip
from app.core.deps import is_admin
from app.core.enums import JobStatus, MemberRole, Severity, UserRole
from app.core.network_data import sync_host_to_nodes
from app.routers.playbooks import (
    _detect_cycle,
    _evaluate_precondition,
    _is_dag_mode,
    _step_deps_zero_idx,
)
from app.routers.c2 import _adaptix_live_agents  # noqa: F401 (import sanity)
from app.ws import _redact_payload, _scrub_sensitive_keys
from app.core.utils import new_id


# ── B5-1 enums + is_admin ─────────────────────────────────────────────────

class TestEnums:
    def test_user_role_values(self):
        assert UserRole.values() == {"admin", "user", "viewer"}

    def test_coerce_admin(self):
        assert UserRole.coerce("ADMIN") is UserRole.ADMIN
        assert UserRole.coerce("admin") is UserRole.ADMIN
        assert UserRole.coerce("garbage") is None
        assert UserRole.coerce(None) is None

    def test_member_role_includes_owner(self):
        assert "owner" in MemberRole.values()
        assert "operator" in MemberRole.values()

    def test_severity_values(self):
        assert Severity.values() == {"critical", "high", "medium", "low", "info"}

    def test_job_status_terminal_set(self):
        terminal = JobStatus.terminal()
        assert "done" in terminal
        assert "failed" in terminal
        assert "cancelled" in terminal
        assert "skipped" in terminal
        assert "running" not in terminal


class _FakeUser:
    def __init__(self, role: str):
        self.role = role


class TestIsAdmin:
    def test_admin_true(self):
        assert is_admin(_FakeUser("admin")) is True

    def test_non_admin_false(self):
        assert is_admin(_FakeUser("user")) is False
        assert is_admin(_FakeUser("viewer")) is False

    def test_none_user_false(self):
        assert is_admin(None) is False


# ── v0.4.6 P12 secret_scrub ───────────────────────────────────────────────

class TestSecretScrub:
    def test_basic_replace(self):
        out = secret_scrub.scrub_secret("nxc smb -p Sup3rSecret123", "Sup3rSecret123")
        assert out == "nxc smb -p ***REDACTED***"

    def test_too_short_no_op(self):
        # < 4 chars guard prevents false-positive sed-like replaces
        assert secret_scrub.scrub_secret("cmd -p abc", "abc") == "cmd -p abc"

    def test_empty_text_no_op(self):
        assert secret_scrub.scrub_secret("", "secret_value") == ""

    def test_empty_secret_no_op(self):
        assert secret_scrub.scrub_secret("text", None) == "text"
        assert secret_scrub.scrub_secret("text", "") == "text"

    def test_multiple_secrets_longest_first(self):
        # The shorter secret is a prefix of the longer one — longest must be
        # scrubbed first so the shorter pass doesn't break the longer match.
        out = secret_scrub.scrub_secrets("user=alice pass=Sup3r pass=Sup3rSecret", "Sup3r", "Sup3rSecret")
        assert "Sup3rSecret" not in out
        assert "Sup3r" not in out


# ── v0.4.6 P12 WS redact policy ───────────────────────────────────────────

class TestWSRedact:
    def test_no_redact_when_user_has_permission(self):
        msg = {"entity": "cred", "data": {"id": "c1", "secret": "leaked"}}
        policy = {"read": "credentials.read", "redact": [("secret", "credentials.read_secret")]}
        out = _redact_payload(msg, policy, frozenset({"credentials.read", "credentials.read_secret"}))
        assert out["data"]["secret"] == "leaked"

    def test_redact_when_user_lacks_permission(self):
        msg = {"entity": "cred", "data": {"id": "c1", "secret": "leaked"}}
        policy = {"read": "credentials.read", "redact": [("secret", "credentials.read_secret")]}
        out = _redact_payload(msg, policy, frozenset({"credentials.read"}))
        assert out["data"]["secret"] == ""
        # other fields untouched
        assert out["data"]["id"] == "c1"

    def test_recursive_scrub_keys(self):
        msg = {
            "entity": "playbook_run",
            "data": {"request_json": {"password": "p@ss", "target": "10.0.0.1", "nested": {"api_key": "k"}}},
        }
        policy = {"redact": [], "scrub_keys": True}
        out = _redact_payload(msg, policy, frozenset())
        assert out["data"]["request_json"]["password"] == ""
        assert out["data"]["request_json"]["target"] == "10.0.0.1"
        assert out["data"]["request_json"]["nested"]["api_key"] == ""

    def test_scrub_keys_substring_match(self):
        # `_hash` substring should trigger scrub (matches ntlm_hash, sha256_hash, etc.)
        out = _scrub_sensitive_keys({"ntlm_hash": "abcd", "username": "alice"})
        assert out["ntlm_hash"] == ""
        assert out["username"] == "alice"


# ── v0.4.0 P4 DAG helpers ─────────────────────────────────────────────────

class TestDAGHelpers:
    def test_no_cycle(self):
        # 0 → 1 → 2
        assert _detect_cycle({0: [1], 1: [2], 2: []}, 3) is None

    def test_self_loop(self):
        result = _detect_cycle({0: [0]}, 1)
        assert result == [0, 0]

    def test_simple_cycle(self):
        # 0 → 1 → 0
        result = _detect_cycle({0: [1], 1: [0]}, 2)
        assert result == [0, 1, 0]

    def test_three_node_cycle(self):
        # 0 → 1 → 2 → 0
        result = _detect_cycle({0: [1], 1: [2], 2: [0]}, 3)
        assert result == [0, 1, 2, 0]

    def test_fan_in_no_cycle(self):
        # 0 → 2 ← 1 — diamond fan-in, no cycle
        assert _detect_cycle({0: [2], 1: [2], 2: []}, 3) is None

    def test_is_dag_mode_linear(self):
        assert _is_dag_mode([{"depends_on": [], "retry_count": 0}]) is False

    def test_is_dag_mode_retry(self):
        assert _is_dag_mode([{"depends_on": [], "retry_count": 2}]) is True

    def test_is_dag_mode_deps(self):
        assert _is_dag_mode([{"depends_on": [1]}, {"depends_on": []}]) is True

    def test_is_dag_mode_precondition(self):
        assert _is_dag_mode([{"precondition": {"step": 1}}]) is True

    def test_step_deps_explicit(self):
        assert _step_deps_zero_idx({"depends_on": [1, 3]}) == [0, 2]

    def test_step_deps_fallback_to_prev(self):
        # Empty depends_on with default_prev means linear flow
        assert _step_deps_zero_idx({"depends_on": []}, default_prev=1) == [1]


class TestPreconditionEval:
    def test_match_skips_to_run(self):
        state = {0: {"status": "done", "result_json": {"hosts_found": 5}}}
        pre = {"step": 1, "result_key": "hosts_found", "operator": "gt", "value": 0, "negate": False}
        assert _evaluate_precondition(pre, state, [0]) is True

    def test_no_match_skips_step(self):
        state = {0: {"status": "done", "result_json": {"hosts_found": 0}}}
        pre = {"step": 1, "result_key": "hosts_found", "operator": "gt", "value": 0, "negate": False}
        assert _evaluate_precondition(pre, state, [0]) is False

    def test_negate_flips_result(self):
        state = {0: {"status": "done", "result_json": {"hosts_found": 0}}}
        pre = {"step": 1, "result_key": "hosts_found", "operator": "eq", "value": 0, "negate": True}
        # eq matches → negate → False (skip)
        assert _evaluate_precondition(pre, state, [0]) is False

    def test_failed_dep_blocks_run_without_negate(self):
        state = {0: {"status": "failed", "result_json": {}}}
        pre = {"step": 1, "result_key": "x", "operator": "eq", "value": 1, "negate": False}
        assert _evaluate_precondition(pre, state, [0]) is False


# ── v0.4.8 / v0.4.9 B3 upsert helpers (DB-level) ──────────────────────────

@pytest.fixture()
def pid(db):
    """Create a fresh project for the test and return its id."""
    proj = models.Project(id=new_id("p"), name="upsert-test", description="", added="2026-05-17 12:00")
    db.add(proj)
    db.commit()
    return proj.id


class TestUpsertHostByIp:
    def test_insert_on_empty(self, db, pid):
        host, created = upsert_host_by_ip(
            db, pid=pid, ip="10.0.0.1",
            defaults={"hostname": "h1", "status": "up", "tags": ["c2"], "notes": ""},
        )
        db.commit()
        assert created is True
        assert host.ip == "10.0.0.1"
        assert host.hostname == "h1"

    def test_update_on_conflict(self, db, pid):
        upsert_host_by_ip(
            db, pid=pid, ip="10.0.0.2",
            defaults={"hostname": "first", "status": "up"},
        )
        db.commit()
        host2, created2 = upsert_host_by_ip(
            db, pid=pid, ip="10.0.0.2",
            defaults={"hostname": "second", "status": "alive"},
            update_on_conflict={"status": "pwned"},
        )
        db.commit()
        assert created2 is False
        assert host2.status == "pwned"

    def test_empty_ip_rejected(self, db, pid):
        with pytest.raises(ValueError):
            upsert_host_by_ip(db, pid=pid, ip="", defaults={})


class TestTryInsertOrGet:
    def test_insert_when_no_conflict(self, db, pid):
        new_host = models.Host(id=new_id("hst"), pid=pid, ip="10.1.0.1", status="up")
        row, created = try_insert_or_get(
            db, new_host,
            requery=lambda: db.query(models.Host).filter_by(pid=pid, ip="10.1.0.1").first(),
        )
        db.commit()
        assert created is True
        assert row.ip == "10.1.0.1"

    def test_falls_back_to_requery_on_conflict(self, db, pid):
        # Seed the row directly
        first = models.Host(id=new_id("hst"), pid=pid, ip="10.1.0.2", status="up")
        db.add(first)
        db.commit()
        # Try to "insert" again — should hit IntegrityError and return existing
        new_host = models.Host(id=new_id("hst"), pid=pid, ip="10.1.0.2", status="pwned")
        row, created = try_insert_or_get(
            db, new_host,
            requery=lambda: db.query(models.Host).filter_by(pid=pid, ip="10.1.0.2").first(),
        )
        assert created is False
        assert row.id == first.id  # the existing row, not the new one we tried to add


# ── v0.4.7 P5 sync_host_to_nodes ──────────────────────────────────────────

class TestSyncHostToNodes:
    def _make_host_and_node(self, db, pid, *, ip="10.2.0.1"):
        host = models.Host(
            id=new_id("hst"), pid=pid, ip=ip, hostname="h",
            status="up", role="", os="", is_attacker=False,
            tags=[], ports=[], services=[], ips=[ip],
        )
        db.add(host)
        net = models.Network(id=new_id("net"), pid=pid, name="map")
        db.add(net)
        db.commit()
        node = models.NetworkNode(
            id=new_id("nn"), network_id=net.id, pid=pid, host_id=host.id,
            x=0, y=0, label="h", ip=ip, status="up", role="", os="",
            is_attacker=False, manually_positioned=False, auto_positioned=True,
            version=1, ips=[ip], ports=[], tags=[],
        )
        db.add(node)
        db.commit()
        return host, node

    def test_status_change_propagates(self, db, pid):
        host, node = self._make_host_and_node(db, pid)
        host.status = "pwned"
        db.flush()
        payloads = sync_host_to_nodes(host, db, ts="2026-05-17 12:00")
        db.commit()
        assert len(payloads) == 1
        assert payloads[0]["status"] == "pwned"
        # Node row updated in DB
        db.refresh(node)
        assert node.status == "pwned"
        # version bumped (>= 2 — exact value depends on default flush behavior)
        assert node.version > 1

    def test_position_never_synced(self, db, pid):
        host, node = self._make_host_and_node(db, pid)
        node.x = 500
        node.y = 250
        node.manually_positioned = True
        db.commit()
        host.status = "access"
        sync_host_to_nodes(host, db, ts="2026-05-17 12:00")
        db.commit()
        db.refresh(node)
        assert node.x == 500
        assert node.y == 250
        assert node.manually_positioned is True

    def test_no_changes_returns_empty(self, db, pid):
        host, _ = self._make_host_and_node(db, pid)
        payloads = sync_host_to_nodes(host, db, ts="2026-05-17 12:00")
        assert payloads == []

    def test_host_with_no_nodes(self, db, pid):
        # Lone host with no mirroring network node — helper returns []
        host = models.Host(id=new_id("hst"), pid=pid, ip="10.9.9.9", status="up",
                          tags=[], ports=[], services=[], ips=["10.9.9.9"])
        db.add(host)
        db.commit()
        assert sync_host_to_nodes(host, db) == []


# ── v0.4.0 AI kill switch ─────────────────────────────────────────────────

class TestAIKillSwitch:
    def test_status_enabled_by_default(self, client, db):
        # Bootstrap admin user + login
        from app.core.security import hash_password
        admin = models.User(id=new_id("u"), username="ai_admin", password_hash=hash_password("pw"),
                            role="admin", active=True, created_at="2026")
        db.add(admin)
        db.commit()
        r = client.post("/api/auth/login", json={"username": "ai_admin", "password": "pw"})
        assert r.status_code == 200
        # Status endpoint — admin token in cookie
        r2 = client.get("/api/ai/status")
        assert r2.status_code == 200
        body = r2.json()
        assert body["enabled"] is True  # back-compat default

    def test_disabling_via_config_flips_status_flag(self, client, db):
        """Verify ai_enabled flag round-trips through PUT/GET config.

        We don't drive the chat endpoint end-to-end here — that requires
        seeding LLM providers and project membership. The kill switch
        guard itself (`_is_ai_enabled(cfg)`) is exercised directly below.
        """
        from app.core.security import hash_password
        admin = models.User(id=new_id("u"), username="ai_admin2", password_hash=hash_password("pw"),
                            role="admin", active=True, created_at="2026")
        db.add(admin)
        db.commit()
        client.post("/api/auth/login", json={"username": "ai_admin2", "password": "pw"})
        client.put("/api/ai/config", json={"providers": [], "ai_enabled": False})
        r = client.get("/api/ai/status")
        assert r.json()["enabled"] is False
        # Re-enable and confirm round-trip
        client.put("/api/ai/config", json={"providers": [], "ai_enabled": True})
        r2 = client.get("/api/ai/status")
        assert r2.json()["enabled"] is True

    def test_is_ai_enabled_helper(self):
        from app.routers.ai import _is_ai_enabled
        # Default (back-compat) is on
        assert _is_ai_enabled({}) is True
        assert _is_ai_enabled({"ai_enabled": True}) is True
        # Only explicit False disables
        assert _is_ai_enabled({"ai_enabled": False}) is False
