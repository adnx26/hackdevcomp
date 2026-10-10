"""Public error codes and their HTTP status mapping (owned by A)."""

from __future__ import annotations

from .enums import ErrorCode

HTTP_STATUS = {
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.LIMIT_EXCEEDED: 429,
    ErrorCode.NOT_READY: 409,
    ErrorCode.CONTEXT_CHANGED: 409,
    ErrorCode.APPROVAL_REQUIRED: 428,
    ErrorCode.SERVICE_UNAVAILABLE: 503,
}

# Only explicitly transient conditions default to retryable.
_DEFAULT_RETRYABLE = frozenset({ErrorCode.NOT_READY, ErrorCode.SERVICE_UNAVAILABLE})


class GatewayError(Exception):
    """An error safe to map onto the public envelope.

    ``detail`` is for tests and internal diagnostics only. It must never be
    returned to a client and must not contain raw content or model text.
    """

    def __init__(self, code: ErrorCode, detail: str = "", *, retryable: bool | None = None):
        super().__init__(f"{code.value}: {detail}" if detail else code.value)
        self.code = ErrorCode(code)
        self.detail = detail
        self.retryable = (self.code in _DEFAULT_RETRYABLE) if retryable is None else retryable

    @property
    def http_status(self) -> int:
        return HTTP_STATUS[self.code]

    def envelope(self, request_id: str) -> dict:
        return {
            "contract_version": "v1",
            "error": {"code": self.code.value, "retryable": self.retryable, "request_id": request_id},
        }


class ContractError(GatewayError):
    """Schema validation failure (always INVALID_REQUEST)."""

    def __init__(self, path: str, problem: str):
        super().__init__(ErrorCode.INVALID_REQUEST, f"{path}: {problem}")
        self.path = path
        self.problem = problem
