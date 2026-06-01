"""Tests for app.core.candidate_scanner — scanning rule functions and persistence."""

import pytest
from unittest.mock import MagicMock, patch

from app.core.candidate_scanner import (
    CandidateResult,
    _cred_label,
    _scan_r1_r2,
    _scan_r3,
    _scan_r4,
    _scan_r5,
    _scan_r6,
    _scan_r7_r8_r9,
    _persist,
    _recommendation_for,
    _JOB_RULE_MAP,
)


def _mock_chn(cred_id="c1", host_id="h1", access=None):
    chn = MagicMock()
    chn.cred_id = cred_id
    chn.host_id = host_id
    chn.access = access or []
    return chn


def _mock_cred(id="c1", username="admin"):
    c = MagicMock()
    c.id = id
    c.username = username
    return c


def _mock_host(id="h1", hostname="dc01", ip="10.0.0.1", role="domain_controller"):
    h = MagicMock()
    h.id = id
    h.hostname = hostname
    h.ip = ip
    h.role = role
    return h


class TestCandidateResult:
    def test_defaults(self):
        r = CandidateResult()
        assert r.created == 0
        assert r.updated == 0
        assert r.skipped == 0
        assert r.candidates == []


class TestCredLabel:
    def test_found_cred(self):
        creds = {"c1": _mock_cred("c1", "admin")}
        assert _cred_label(creds, "c1") == "admin"

    def test_missing_cred_returns_id(self):
        assert _cred_label({}, "c99") == "c99"


class TestScanR1R2:
    def test_reused_admin_cred(self):
        chns = [
            _mock_chn("c1", "h1", ["local_admin"]),
            _mock_chn("c1", "h2", ["local_admin"]),
            _mock_chn("c1", "h3", ["local_admin"]),
        ]
        creds = {"c1": _mock_cred("c1", "admin")}
        results = _scan_r1_r2(chns, creds)
        rules = [r["rule"] for r in results]
        assert "reused_admin_cred" in rules
        r = [x for x in results if x["rule"] == "reused_admin_cred"][0]
        assert r["severity"] == "high"
        assert "admin" in r["title"]

    def test_valid_on_many_hosts(self):
        chns = [
            _mock_chn("c1", f"h{i}", ["read"]) for i in range(6)
        ]
        creds = {"c1": _mock_cred("c1", "user")}
        results = _scan_r1_r2(chns, creds)
        rules = [r["rule"] for r in results]
        assert "valid_on_many_hosts" in rules

    def test_no_findings_below_threshold(self):
        chns = [
            _mock_chn("c1", "h1", ["local_admin"]),
            _mock_chn("c1", "h2", ["local_admin"]),
        ]
        creds = {"c1": _mock_cred("c1", "admin")}
        results = _scan_r1_r2(chns, creds)
        rules = [r["rule"] for r in results]
        assert "reused_admin_cred" not in rules

    def test_empty_chns(self):
        assert _scan_r1_r2([], {}) == []

    def test_dedup_host_ids(self):
        chns = [
            _mock_chn("c1", "h1", ["local_admin"]),
            _mock_chn("c1", "h1", ["local_admin"]),
            _mock_chn("c1", "h2", ["local_admin"]),
            _mock_chn("c1", "h3", ["local_admin"]),
        ]
        creds = {"c1": _mock_cred("c1", "admin")}
        results = _scan_r1_r2(chns, creds)
        r = [x for x in results if x["rule"] == "reused_admin_cred"][0]
        assert "3 hosts" in r["title"]


class TestScanR3:
    def test_privileged_on_sensitive(self):
        chns = [_mock_chn("c1", "h1", ["local_admin"])]
        hosts = {"h1": _mock_host("h1", role="domain_controller")}
        creds = {"c1": _mock_cred("c1", "admin")}
        results = _scan_r3(chns, hosts, creds)
        assert len(results) == 1
        assert results[0]["rule"] == "privileged_on_sensitive"
        assert results[0]["severity"] == "critical"

    def test_server_role(self):
        chns = [_mock_chn("c1", "h1", ["local_admin"])]
        hosts = {"h1": _mock_host("h1", role="server")}
        creds = {"c1": _mock_cred("c1", "admin")}
        results = _scan_r3(chns, hosts, creds)
        assert len(results) == 1
        assert results[0]["severity"] == "high"

    def test_non_sensitive_role_excluded(self):
        chns = [_mock_chn("c1", "h1", ["local_admin"])]
        hosts = {"h1": _mock_host("h1", role="workstation")}
        creds = {"c1": _mock_cred("c1", "admin")}
        assert _scan_r3(chns, hosts, creds) == []

    def test_non_admin_access_excluded(self):
        chns = [_mock_chn("c1", "h1", ["read"])]
        hosts = {"h1": _mock_host("h1", role="server")}
        creds = {"c1": _mock_cred("c1", "admin")}
        assert _scan_r3(chns, hosts, creds) == []


class TestScanR4:
    def test_da_context(self):
        chns = [_mock_chn("c1", "h1", ["domain_admin"])]
        hosts = {"h1": _mock_host("h1")}
        creds = {"c1": _mock_cred("c1", "da")}
        results = _scan_r4(chns, hosts, creds)
        assert len(results) == 1
        assert results[0]["rule"] == "da_context"
        assert results[0]["severity"] == "critical"

    def test_non_da_excluded(self):
        chns = [_mock_chn("c1", "h1", ["local_admin"])]
        hosts = {"h1": _mock_host("h1")}
        creds = {"c1": _mock_cred("c1", "admin")}
        assert _scan_r4(chns, hosts, creds) == []


class TestScanR5:
    def test_with_verified_edges(self):
        network = MagicMock()
        network.id = "net1"
        db = MagicMock()

        with patch("app.core.candidate_scanner.get_edges", return_value=[
            {"id": "e1", "from": "n1", "to": "n2", "type": "ssh", "verified": True},
        ]), patch("app.core.candidate_scanner.get_nodes", return_value=[
            {"id": "n1", "label": "host1", "ip": "10.0.0.1"},
            {"id": "n2", "label": "host2", "ip": "10.0.0.2", "host_id": "h2"},
        ]):
            results = _scan_r5(network, db)
            assert len(results) == 1
            assert results[0]["rule"] == "lateral_path_confirmed"

    def test_no_network(self):
        assert _scan_r5(None, MagicMock()) == []

    def test_unverified_edge_excluded(self):
        network = MagicMock()
        network.id = "net1"
        db = MagicMock()

        with patch("app.core.candidate_scanner.get_edges", return_value=[
            {"id": "e1", "from": "n1", "to": "n2", "type": "ssh", "verified": False},
        ]), patch("app.core.candidate_scanner.get_nodes", return_value=[]):
            results = _scan_r5(network, db)
            assert len(results) == 0


class TestScanR6:
    def test_c2_on_dc(self):
        act = MagicMock()
        act.host_id = "h1"
        act.activity_type = "c2"
        act.ts = "2024-01-01"
        hosts = {"h1": _mock_host("h1", role="domain_controller")}
        results = _scan_r6([act], hosts)
        assert len(results) == 1
        assert results[0]["rule"] == "live_session_sensitive"
        assert results[0]["severity"] == "critical"

    def test_non_c2_excluded(self):
        act = MagicMock()
        act.activity_type = "scan"
        hosts = {"h1": _mock_host("h1", role="domain_controller")}
        assert _scan_r6([act], hosts) == []

    def test_non_sensitive_host_excluded(self):
        act = MagicMock()
        act.host_id = "h1"
        act.activity_type = "c2"
        act.ts = "2024-01-01"
        hosts = {"h1": _mock_host("h1", role="workstation")}
        assert _scan_r6([act], hosts) == []


class TestScanR7R8R9:
    def test_kerberoastable(self):
        job = MagicMock()
        job.id = "j1"
        job.title = "test"
        job.result_json = {
            "structured": {
                "finding_candidates": [
                    {"type": "kerberoastable_accounts", "title": "SPN found", "details": "desc"}
                ]
            }
        }
        results = _scan_r7_r8_r9([job])
        assert len(results) == 1
        assert results[0]["rule"] == "kerberoastable_accounts"

    def test_adcs_vulnerable(self):
        job = MagicMock()
        job.id = "j1"
        job.title = "test"
        job.result_json = {
            "structured": {
                "finding_candidates": [
                    {"type": "adcs_vulnerable_template", "title": "ESC1"}
                ]
            }
        }
        results = _scan_r7_r8_r9([job])
        assert len(results) == 1
        assert results[0]["severity"] == "critical"

    def test_unknown_type_skipped(self):
        job = MagicMock()
        job.id = "j1"
        job.title = "test"
        job.result_json = {
            "structured": {
                "finding_candidates": [
                    {"type": "unknown_type", "title": "x"}
                ]
            }
        }
        assert _scan_r7_r8_r9([job]) == []

    def test_dedup_same_proof(self):
        job = MagicMock()
        job.id = "j1"
        job.title = "test"
        job.result_json = {
            "structured": {
                "finding_candidates": [
                    {"type": "kerberoastable_accounts", "title": "a"},
                    {"type": "kerberoastable_accounts", "title": "a"},
                ]
            }
        }
        results = _scan_r7_r8_r9([job])
        assert len(results) == 1

    def test_no_result_json(self):
        job = MagicMock()
        job.id = "j1"
        job.result_json = None
        assert _scan_r7_r8_r9([job]) == []


class TestRecommendationFor:
    def test_all_known_types(self):
        for fc_type in _JOB_RULE_MAP:
            rec = _recommendation_for(fc_type)
            assert isinstance(rec, str)
            assert len(rec) > 0

    def test_unknown_type(self):
        rec = _recommendation_for("nonexistent")
        assert rec == "Review and escalate as appropriate."


class TestPersist:
    def test_creates_findings(self):
        db = MagicMock()
        candidates = [
            {"rule": "test", "title": "t1", "severity": "high", "description": "d",
             "recommendation": "r", "proof": "P1", "host_id": None},
        ]
        result = _persist(db, "pid", "2024-01-01T00:00:00Z", candidates, set())
        assert result.created == 1
        assert result.skipped == 0

    def test_skips_existing_proof(self):
        db = MagicMock()
        candidates = [
            {"rule": "test", "title": "t1", "severity": "high", "description": "d",
             "recommendation": "r", "proof": "P1", "host_id": None},
        ]
        result = _persist(db, "pid", "2024-01-01T00:00:00Z", candidates, {"P1"})
        assert result.created == 0
        assert result.skipped == 1

    def test_mixed_create_and_skip(self):
        db = MagicMock()
        candidates = [
            {"rule": "test", "title": "t1", "severity": "high", "description": "d",
             "recommendation": "r", "proof": "P1", "host_id": None},
            {"rule": "test", "title": "t2", "severity": "medium", "description": "d",
             "recommendation": "r", "proof": "P2", "host_id": None},
        ]
        result = _persist(db, "pid", "2024-01-01T00:00:00Z", candidates, {"P1"})
        assert result.created == 1
        assert result.skipped == 1
