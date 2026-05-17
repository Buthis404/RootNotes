"""
Tests for the unified error contract (B5-3).

Every error response must carry:
  - `code`     stable machine identifier
  - `message`  human text
  - `details`  optional structured payload
  - `detail`   legacy mirror of `message` for backwards compatibility
"""
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.errors import AppError, install_error_handlers


@pytest.fixture
def app_with_routes():
    app = FastAPI()
    install_error_handlers(app)

    class Body(BaseModel):
        name: str
        port: int

    @app.get("/raises-bare-http-exc")
    def raises_http_exc():
        raise HTTPException(status_code=403, detail="Admin access required")

    @app.get("/raises-app-error")
    def raises_app_error():
        raise AppError(
            "module_disabled",
            "C2 module is off",
            status=404,
            details={"module": "c2_integration"},
        )

    @app.get("/raises-app-error-no-details")
    def raises_app_error_no_details():
        raise AppError("teapot", "I am a teapot", status=418)

    @app.post("/validates-body")
    def validates_body(body: Body):
        return {"ok": True}

    return TestClient(app)


# ── Bare HTTPException is wrapped with a status-derived code ──────────

def test_bare_http_exception_gets_status_derived_code(app_with_routes):
    r = app_with_routes.get("/raises-bare-http-exc")
    assert r.status_code == 403
    payload = r.json()
    assert payload["code"] == "forbidden"
    assert payload["message"] == "Admin access required"
    # Legacy field mirrors message
    assert payload["detail"] == "Admin access required"
    assert "details" not in payload


def test_500_gets_internal_error_code(app_with_routes):
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    def boom():
        raise HTTPException(status_code=500, detail="something broke")

    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/boom")
    assert r.status_code == 500
    assert r.json()["code"] == "internal_error"


# ── AppError carries its explicit code through ────────────────────────

def test_app_error_with_details(app_with_routes):
    r = app_with_routes.get("/raises-app-error")
    assert r.status_code == 404
    payload = r.json()
    assert payload["code"] == "module_disabled"
    assert payload["message"] == "C2 module is off"
    assert payload["details"] == {"module": "c2_integration"}
    assert payload["detail"] == "C2 module is off"


def test_app_error_without_details_omits_field(app_with_routes):
    r = app_with_routes.get("/raises-app-error-no-details")
    assert r.status_code == 418
    payload = r.json()
    assert payload["code"] == "teapot"
    assert payload["message"] == "I am a teapot"
    assert "details" not in payload


def test_uncommon_status_falls_back_to_generic_code(app_with_routes):
    """A status code not in the lookup table should not break — it gets
    a generic 'error' code rather than KeyError."""
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/weird")
    def weird():
        raise HTTPException(status_code=499, detail="client closed request")

    client = TestClient(app)
    r = client.get("/weird")
    assert r.status_code == 499
    assert r.json()["code"] == "error"


# ── RequestValidationError gets a summary + raw details array ─────────

def test_validation_error_contract(app_with_routes):
    r = app_with_routes.post("/validates-body", json={"name": "x"})  # missing port
    assert r.status_code == 422
    payload = r.json()
    assert payload["code"] == "validation_failed"
    # Summary message should reference the failing field
    assert "port" in payload["message"].lower()
    assert isinstance(payload["details"], list)
    assert payload["details"][0]["loc"][-1] == "port"


def test_validation_error_empty_payload(app_with_routes):
    r = app_with_routes.post("/validates-body", json={})
    assert r.status_code == 422
    payload = r.json()
    assert payload["code"] == "validation_failed"
    # Details enumerate every missing field
    locs = [tuple(e["loc"][-1:]) for e in payload["details"]]
    assert ("name",) in locs and ("port",) in locs


# ── AppError extends HTTPException (importers can still catch either) ──

def test_app_error_is_an_http_exception():
    err = AppError("x", "y", status=400)
    assert isinstance(err, HTTPException)
    assert err.status_code == 400
    assert err.detail == "y"
    assert err.code == "x"
    assert err.message == "y"
