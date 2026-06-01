import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.exc import IntegrityError

from app.core.db_upsert import (
    _upsert_host_fallback,
    try_insert_or_get,
    _warn_once,
    _has_index,
)


class TestUpsertHostFallback:
    def test_new_host(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch("app.core.db_upsert.models") as mock_models:
            mock_host = MagicMock()
            mock_models.Host.return_value = mock_host
            r, created = _upsert_host_fallback(db, "pid1", "10.0.0.1", {"hostname": "srv"}, None)
            assert created is True
            db.add.assert_called_once()

    def test_existing_host(self):
        existing = MagicMock()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        r, created = _upsert_host_fallback(db, "pid1", "10.0.0.1", {"hostname": "srv"}, {"hostname": "new"})
        assert created is False
        assert r == existing

    def test_existing_no_update(self):
        existing = MagicMock()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        r, created = _upsert_host_fallback(db, "pid1", "10.0.0.1", {}, None)
        assert created is False


class TestTryInsertOrGet:
    def test_insert_success(self):
        db = MagicMock()
        new_row = MagicMock()
        requery = MagicMock(return_value=None)
        r, created = try_insert_or_get(db, new_row, requery)
        assert created is True
        assert r == new_row

    def test_conflict_returns_existing(self):
        db = MagicMock()
        existing = MagicMock()

        def mock_add(row):
            raise IntegrityError("", "", Exception())

        db.add = mock_add
        db.begin_nested = MagicMock()
        mock_nested = MagicMock()
        mock_nested.__enter__ = MagicMock()
        mock_nested.__exit__ = MagicMock(return_value=False)
        db.begin_nested.return_value = mock_nested

        def fake_add(row):
            raise IntegrityError("stmt", "params", Exception("conflict"))

        mock_nested.__enter__ = lambda s: None
        mock_nested.__exit__ = MagicMock(return_value=False)
        real_add_calls = []

        class FakeNested:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        db.begin_nested.return_value = FakeNested()
        db.add = fake_add
        db.flush = MagicMock()

        requery = MagicMock(return_value=existing)
        r, created = try_insert_or_get(db, MagicMock(), requery)
        assert created is False
        assert r == existing


class TestWarnOnce:
    def test_warn_once(self):
        import app.core.db_upsert as mod
        mod._warned_missing_index.clear()
        with patch("app.core.db_upsert.logger") as mock_logger:
            _warn_once("idx1")
            _warn_once("idx1")
            assert mock_logger.warning.call_count == 1
        mod._warned_missing_index.clear()


class TestHasIndex:
    def test_has_index(self):
        db = MagicMock()
        bind = MagicMock()
        db.get_bind.return_value = bind
        with patch("app.core.db_upsert.inspect") as mock_insp:
            mock_insp.return_value.get_indexes.return_value = [{"name": "idx1"}, {"name": "idx2"}]
            assert _has_index(db, "hosts", "idx1") is True

    def test_missing_index(self):
        db = MagicMock()
        bind = MagicMock()
        db.get_bind.return_value = bind
        with patch("app.core.db_upsert.inspect") as mock_insp:
            mock_insp.return_value.get_indexes.return_value = [{"name": "idx1"}]
            assert _has_index(db, "hosts", "idx2") is False

    def test_exception(self):
        db = MagicMock()
        bind = MagicMock()
        db.get_bind.return_value = bind
        with patch("app.core.db_upsert.inspect") as mock_insp:
            mock_insp.return_value.get_indexes.side_effect = Exception("no db")
            assert _has_index(db, "hosts", "idx1") is False
