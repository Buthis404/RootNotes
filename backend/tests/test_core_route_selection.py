"""Unit tests for app.core.route_selection — route-aware target selection."""
import ipaddress
from unittest.mock import MagicMock, patch

from app.core.route_selection import (
    _extract_target_networks,
    _route_score,
    annotate_targets_with_route_context,
    choose_route_aware_target,
)


class TestExtractTargetNetworks:
    def test_empty(self):
        assert _extract_target_networks("") == []

    def test_none(self):
        assert _extract_target_networks(None) == []

    def test_single_ip(self):
        result = _extract_target_networks("10.0.0.1")
        assert len(result) == 1
        assert result[0] == ipaddress.ip_network("10.0.0.1/32")

    def test_cidr(self):
        result = _extract_target_networks("10.0.0.0/24")
        assert len(result) >= 1
        assert any(str(n) == "10.0.0.0/24" for n in result)

    def test_url_extraction(self):
        result = _extract_target_networks("http://10.0.0.1/path")
        networks = [str(n) for n in result]
        assert "10.0.0.1/32" in networks

    def test_multiple_ips(self):
        result = _extract_target_networks("10.0.0.1 and 10.0.0.2")
        assert len(result) == 2

    def test_mixed_cidr_and_ip(self):
        result = _extract_target_networks("10.0.0.0/24 and 192.168.1.1")
        networks = [str(n) for n in result]
        assert "10.0.0.0/24" in networks
        assert "192.168.1.1/32" in networks

    def test_invalid_items_ignored(self):
        result = _extract_target_networks("999.999.999.999")
        assert len(result) == 0

    def test_url_with_hostname(self):
        result = _extract_target_networks("http://example.com/path")
        assert len(result) == 0

    def test_whitespace(self):
        result = _extract_target_networks("  ")
        assert len(result) == 0


class TestRouteScore:
    def test_empty_route(self):
        assert _route_score("", []) == 0

    def test_empty_targets(self):
        assert _route_score("10.0.0.0/24", []) == 0

    def test_exact_match(self):
        targets = [ipaddress.ip_network("10.0.0.1/32")]
        score = _route_score("10.0.0.0/24", targets)
        assert score == 24

    def test_no_match(self):
        targets = [ipaddress.ip_network("192.168.1.1/32")]
        score = _route_score("10.0.0.0/24", targets)
        assert score == 0

    def test_overlapping_networks(self):
        targets = [ipaddress.ip_network("10.0.0.0/16")]
        score = _route_score("10.0.0.0/24", targets)
        assert score == 24

    def test_invalid_route_cidr(self):
        targets = [ipaddress.ip_network("10.0.0.1/32")]
        assert _route_score("not-a-cidr", targets) == 0

    def test_wider_prefix_lower_score(self):
        targets = [ipaddress.ip_network("10.0.0.1/32")]
        score_24 = _route_score("10.0.0.0/24", targets)
        score_16 = _route_score("10.0.0.0/16", targets)
        assert score_24 > score_16


class TestAnnotateTargetsWithRouteContext:
    @patch("app.core.route_selection.models")
    def test_empty_targets(self, mock_models):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        result = annotate_targets_with_route_context("p1", [], db)
        assert result == []

    @patch("app.core.route_selection.models")
    def test_targets_annotated(self, mock_models):
        obs = MagicMock(collector_target_id="t1", route_cidr="10.0.0.0/24")
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [obs]
        targets = [{"id": "t1", "name": "target1"}]
        result = annotate_targets_with_route_context("p1", targets, db, "10.0.0.1")
        assert len(result) == 1
        assert result[0]["route_cidrs"] == ["10.0.0.0/24"]
        assert result[0]["route_count"] == 1
        assert result[0]["route_matched"] is True
        assert result[0]["route_match_score"] > 0

    @patch("app.core.route_selection.models")
    def test_sorted_by_score(self, mock_models):
        obs1 = MagicMock(collector_target_id="t1", route_cidr="10.0.0.0/24")
        obs2 = MagicMock(collector_target_id="t2", route_cidr="172.16.0.0/16")
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [obs1, obs2]
        targets = [
            {"id": "t2", "name": "b_target"},
            {"id": "t1", "name": "a_target"},
        ]
        result = annotate_targets_with_route_context("p1", targets, db, "10.0.0.1")
        assert result[0]["id"] == "t1"

    @patch("app.core.route_selection.models")
    def test_dedup_route_cidrs(self, mock_models):
        obs1 = MagicMock(collector_target_id="t1", route_cidr="10.0.0.0/24")
        obs2 = MagicMock(collector_target_id="t1", route_cidr="10.0.0.0/24")
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [obs1, obs2]
        targets = [{"id": "t1", "name": "target1"}]
        result = annotate_targets_with_route_context("p1", targets, db)
        assert result[0]["route_count"] == 1


class TestChooseRouteAwareTarget:
    @patch("app.core.route_selection.models")
    def test_returns_first_annotated(self, mock_models):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        targets = [{"id": "t1", "name": "target1"}]
        result = choose_route_aware_target("p1", targets, db)
        assert result is not None
        assert result["id"] == "t1"

    @patch("app.core.route_selection.models")
    def test_empty_targets(self, mock_models):
        db = MagicMock()
        result = choose_route_aware_target("p1", [], db)
        assert result is None
