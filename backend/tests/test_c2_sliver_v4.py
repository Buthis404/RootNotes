import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException

from app.routers.c2._sliver import (
    _sliver_parse_config,
    _sliver_connect,
    _sliver_format_host,
    _sliver_raise_compat,
)


class TestSliverConnect:
    @pytest.mark.asyncio
    async def test_version_warning(self):
        mock_client = AsyncMock()
        ver = MagicMock()
        ver.Major = 1
        ver.Minor = 7
        ver.Patch = 0
        mock_client.version = AsyncMock(return_value=ver)
        mock_client.close = AsyncMock()
        mock_sliver_class = MagicMock(return_value=mock_client)
        with patch("app.routers.c2._sliver._sliver_parse_config", return_value=MagicMock()):
            with patch("sliver.SliverClient", mock_sliver_class):
                r = await _sliver_connect({"token": "test"})
                assert r == mock_client

    @pytest.mark.asyncio
    async def test_version_compat(self):
        mock_client = AsyncMock()
        ver = MagicMock()
        ver.Major = 1
        ver.Minor = 6
        ver.Patch = 0
        mock_client.version = AsyncMock(return_value=ver)
        mock_client.close = AsyncMock()
        mock_sliver_class = MagicMock(return_value=mock_client)
        with patch("app.routers.c2._sliver._sliver_parse_config", return_value=MagicMock()):
            with patch("sliver.SliverClient", mock_sliver_class):
                r = await _sliver_connect({"token": "test"})
                assert r == mock_client

    @pytest.mark.asyncio
    async def test_version_exception(self):
        mock_client = AsyncMock()
        mock_client.version = AsyncMock(side_effect=Exception("rpc error"))
        mock_client.close = AsyncMock()
        mock_sliver_class = MagicMock(return_value=mock_client)
        with patch("app.routers.c2._sliver._sliver_parse_config", return_value=MagicMock()):
            with patch("sliver.SliverClient", mock_sliver_class):
                r = await _sliver_connect({"token": "test"})
                assert r == mock_client


class TestSliverSessions:
    @pytest.mark.asyncio
    async def test_interact_none(self):
        mock_client = AsyncMock()
        session = MagicMock()
        session.ID = "s1"
        mock_client.sessions = AsyncMock(return_value=[session])
        mock_client.interact_session = AsyncMock(return_value=None)
        mock_client.beacons = AsyncMock(return_value=[])
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            from app.routers.c2._sliver import _sliver_execute
            with pytest.raises(HTTPException) as exc_info:
                await _sliver_execute({"token": "t"}, "s1", "id", True, 12)
            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_beacon_interact_none(self):
        mock_client = AsyncMock()
        mock_client.sessions = AsyncMock(return_value=[])
        beacon = MagicMock()
        beacon.ID = "b1"
        mock_client.beacons = AsyncMock(return_value=[beacon])
        mock_client.interact_beacon = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            from app.routers.c2._sliver import _sliver_execute
            with pytest.raises(HTTPException) as exc_info:
                await _sliver_execute({"token": "t"}, "b1", "id", True, 12)
            assert exc_info.value.status_code == 404
