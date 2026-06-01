import pytest
from unittest.mock import MagicMock


class TestRouteSelection:
    def test_choose_empty(self):
        from app.core.route_selection import choose_route_aware_target
        db = MagicMock()
        r = choose_route_aware_target("project1", [], db)
        assert r is None

    def test_annotate_empty(self):
        from app.core.route_selection import annotate_targets_with_route_context
        db = MagicMock()
        r = annotate_targets_with_route_context("project1", [], db)
        assert isinstance(r, list)
