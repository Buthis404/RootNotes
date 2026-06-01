import pytest
from unittest.mock import MagicMock, patch

from app.routers.import_bloodhound import (
    _host_short,
    _user_short,
    _get_items,
    _now,
    _edge_id,
    _DA_GROUP_NAMES,
    _HIGH_PRIV_ACES,
)


class TestHostShort:
    def test_fqdn(self):
        assert _host_short("SRV01.CORP.LOCAL") == "SRV01"

    def test_simple(self):
        assert _host_short("SRV01") == "SRV01"

    def test_empty(self):
        assert _host_short("") == ""

    def test_lowercase(self):
        assert _host_short("srv01.corp.local") == "SRV01"


class TestUserShort:
    def test_upn(self):
        assert _user_short("ADMIN@CORP.LOCAL") == "admin"

    def test_simple(self):
        assert _user_short("admin") == "admin"

    def test_empty(self):
        assert _user_short("") == ""


class TestGetItems:
    def test_data_key(self):
        assert _get_items({"data": [1, 2]}) == [1, 2]

    def test_computers_key(self):
        assert _get_items({"computers": [{"name": "SRV"}]}) == [{"name": "SRV"}]

    def test_users_key(self):
        assert _get_items({"users": [{"name": "admin"}]}) == [{"name": "admin"}]

    def test_groups_key(self):
        assert _get_items({"groups": [{"name": "DA"}]}) == [{"name": "DA"}]

    def test_sessions_key(self):
        assert _get_items({"sessions": [1]}) == [1]

    def test_empty(self):
        assert _get_items({}) == []


class TestNow:
    def test_returns_string(self):
        with patch("app.routers.import_bloodhound.ts_now", return_value="ts"):
            assert _now() == "ts"


class TestEdgeId:
    def test_format(self):
        eid = _edge_id()
        assert eid.startswith("bh_")
        assert len(eid) == 13


class TestConstants:
    def test_da_groups(self):
        assert "domain admins" in _DA_GROUP_NAMES
        assert "enterprise admins" in _DA_GROUP_NAMES

    def test_high_priv(self):
        assert "genericall" in _HIGH_PRIV_ACES
