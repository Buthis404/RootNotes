import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError

from app.core.errors import (
    AppError,
    app_error_handler,
    http_exception_handler,
    validation_exception_handler,
    _error_payload,
)


class TestErrorPayload:
    def test_basic(self):
        r = _error_payload("test_code", "test message")
        assert r["code"] == "test_code"
        assert r["message"] == "test message"
        assert r["detail"] == "test message"

    def test_with_details(self):
        r = _error_payload("code", "msg", details={"field": "value"})
        assert r["details"] == {"field": "value"}


class TestAppErrorHandler:
    def test_basic(self):
        exc = AppError("test_err", "Something went wrong", status=400)
        req = MagicMock(spec=Request)
        resp = app_error_handler(req, exc)
        assert resp.status_code == 400


class TestHttpExceptionHandler:
    @pytest.mark.asyncio
    async def test_string_detail(self):
        exc = HTTPException(status_code=404, detail="Not found")
        req = MagicMock(spec=Request)
        resp = await http_exception_handler(req, exc)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_none_detail(self):
        exc = HTTPException(status_code=500, detail=None)
        req = MagicMock(spec=Request)
        resp = await http_exception_handler(req, exc)
        assert resp.status_code == 500

    @pytest.mark.asyncio
    async def test_dict_detail(self):
        exc = HTTPException(status_code=400, detail={"field": "value"})
        req = MagicMock(spec=Request)
        resp = await http_exception_handler(req, exc)
        assert resp.status_code == 400


class TestValidationExceptionHandler:
    def test_basic(self):
        exc = MagicMock(spec=RequestValidationError)
        exc.errors.return_value = [{"loc": ("body", "name"), "msg": "field required", "type": "value_error"}]
        req = MagicMock(spec=Request)
        resp = validation_exception_handler(req, exc)
        assert resp.status_code == 422

    def test_empty_errors(self):
        exc = MagicMock(spec=RequestValidationError)
        exc.errors.return_value = []
        req = MagicMock(spec=Request)
        resp = validation_exception_handler(req, exc)
        assert resp.status_code == 422
