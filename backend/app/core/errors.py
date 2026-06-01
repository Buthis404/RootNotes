"""
Unified error contract for the RootNotes HTTP API.

All errors are returned as JSON in this shape::

    {
      "code":    "<stable_snake_case_identifier>",
      "message": "<human-readable text>",
      "details": <optional object or array with structured info>,
      "detail":  "<same as message, kept for backwards compat>"
    }

`code` is the load-bearing field for clients — it never changes for a
given error condition, so the frontend can match on it without parsing
prose. `message` is informational and may be translated or rephrased
in future without breaking integrations. `details` is reserved for
structured payloads (e.g. per-field validation errors).

The legacy `detail` field (FastAPI's default `{detail: "..."}` shape)
is mirrored so existing clients keep working.

Routers should prefer `AppError` for new code:

    raise AppError("module_disabled", "C2 module is off", status=404)

For backwards compatibility ordinary `HTTPException` continues to
work — its `.detail` becomes `message`, and `code` is derived from
the status (`bad_request`, `forbidden`, etc).
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# Codes derived from HTTP status when a bare HTTPException is raised
# without an explicit code. New code should pass an explicit AppError.code.
_STATUS_DEFAULT_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    410: "gone",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_failed",
    423: "locked",
    429: "rate_limited",
    500: "internal_error",
    501: "not_implemented",
    502: "bad_gateway",
    503: "service_unavailable",
    504: "gateway_timeout",
}


class AppError(HTTPException):
    """HTTPException with a stable machine-readable code.

    `code` is the public contract — once a code is shipped, treat it as
    semver-pinned. Renaming a code is a breaking change for clients.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 400,
        details: Any = None,
    ):
        super().__init__(status_code=status, detail=message)
        self.code = code
        self.message = message
        self.details = details


def _error_payload(
    code: str,
    message: str,
    details: Any = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"code": code, "message": message, "detail": message}
    if details is not None:
        out["details"] = details
    return out


def app_error_handler(_request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_payload(exc.code, exc.message, exc.details),
    )


async def http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    """Catch-all for plain HTTPException — wraps them in the unified shape.

    `code` is derived from the status code; the original detail string
    becomes `message`. This is what lets the 342 existing
    `raise HTTPException(400, "...")` call sites keep working unchanged
    while still presenting a consistent JSON contract to clients.
    """
    # If somehow an AppError reaches here (shouldn't, the dedicated handler
    # catches it first), preserve its code.
    if isinstance(exc, AppError):
        return await app_error_handler(_request, exc)
    detail = exc.detail
    if isinstance(detail, str):
        message = detail
    elif detail is None:
        message = ""
    else:
        # FastAPI lets handlers put structured payloads in `detail`. Keep them
        # as-is under `details`, with a short human summary.
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(
                _STATUS_DEFAULT_CODES.get(exc.status_code, "error"),
                f"HTTP {exc.status_code}",
                details=detail,
            ),
        )
    code = _STATUS_DEFAULT_CODES.get(exc.status_code, "error")
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_payload(code, message),
    )


def validation_exception_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Format pydantic / FastAPI request validation errors.

    Default FastAPI shape is `{detail: [{loc, msg, type}, ...]}`. We move
    that array under `details` and add a one-line `message` summary.
    """
    raw_errors = exc.errors()
    summary = "Request validation failed"
    if raw_errors:
        first = raw_errors[0]
        loc = ".".join(str(p) for p in first.get("loc", []) if p != "body")
        msg = first.get("msg", "")
        summary = f"{loc}: {msg}" if loc else msg or summary
    return JSONResponse(
        status_code=422,
        content=_error_payload(
            "validation_failed",
            summary,
            details=raw_errors,
        ),
    )


def install_error_handlers(app) -> None:
    """Register all three handlers on a FastAPI app."""
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
