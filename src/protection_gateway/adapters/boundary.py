"""Transport checks, not canonical policy, contract or authorization definitions."""

import asyncio
import inspect
import json
import re
import uuid


MAX_RESPONSE_BYTES = 256 * 1024
SERVICE_TIMEOUT_SECONDS = 15
PUBLIC_ERROR_CODES = frozenset({
    "UNAUTHENTICATED", "FORBIDDEN", "NOT_FOUND", "INVALID_REQUEST",
    "LIMIT_EXCEEDED", "NOT_READY", "CONTEXT_CHANGED", "APPROVAL_REQUIRED", "SERVICE_UNAVAILABLE",
})


class AdapterError(Exception):
    def __init__(self, code, *, status=400, retryable=False):
        if code not in PUBLIC_ERROR_CODES:
            code, status, retryable = "SERVICE_UNAVAILABLE", 503, False
        super().__init__(code)
        self.code = code
        self.status = status
        self.retryable = retryable


async def resolve(value):
    return await asyncio.wait_for(value, SERVICE_TIMEOUT_SECONDS) if inspect.isawaitable(value) else value


def opaque_id(value):
    # IDs cannot become paths, URLs, markup or instructions in tool messages.
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise AdapterError("INVALID_REQUEST")
    return value


def exact_fields(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional):
        raise AdapterError("INVALID_REQUEST")
    if not set(required) <= set(value):
        raise AdapterError("INVALID_REQUEST")


def bounded_json(value):
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise AdapterError("SERVICE_UNAVAILABLE", status=503) from None
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise AdapterError("LIMIT_EXCEEDED", status=413)
    return encoded


def error_envelope(error, request_id=None):
    return {"contract_version": "v1", "error": {
        "code": error.code, "retryable": error.retryable,
        "request_id": request_id or uuid.uuid4().hex,
    }}


async def core_call(core, operation, context, request):
    """A's facade validates/authenticates *every* call, including in-process calls.

    A supplies v1 envelopes. Its typed exceptions should be translated to these
    envelopes in the facade; arbitrary exception messages are never forwarded.
    """
    method = getattr(core, operation, None) if core is not None else None
    if not callable(method):
        raise AdapterError("SERVICE_UNAVAILABLE", status=503)
    try:
        envelope = await resolve(method(context, request))
    except AdapterError:
        raise
    except Exception:
        raise AdapterError("SERVICE_UNAVAILABLE", status=503) from None
    if not isinstance(envelope, dict) or envelope.get("contract_version") != "v1":
        raise AdapterError("SERVICE_UNAVAILABLE", status=503)
    if "error" in envelope:
        # Retain only safe, bounded public error fields. HTTP status mapping
        # remains A's responsibility in its facade/HTTP routes.
        error = envelope["error"]
        if not isinstance(error, dict) or error.get("code") not in PUBLIC_ERROR_CODES:
            raise AdapterError("SERVICE_UNAVAILABLE", status=503)
        code = error["code"]
        # Mutations are never automatically retried by D.
        retryable = error.get("retryable") is True and operation == "get_scan_status"
        return error_envelope(AdapterError(code, retryable=retryable))
    if set(envelope) != {"contract_version", "data"} or not isinstance(envelope["data"], dict):
        raise AdapterError("SERVICE_UNAVAILABLE", status=503)
    bounded_json(envelope)
    return envelope


def public_status(envelope):
    """MCP progress contains metadata, never inspector prose/raw evidence."""
    if "error" in envelope:
        return envelope
    data = envelope["data"]
    states = {"QUEUED", "EXTRACTING", "INSPECTING", "DECIDED", "FAILED", "CANCELED"}
    decisions = {None, "ALLOW_UNDER_POLICY", "QUARANTINE", "REVIEW"}
    if data.get("state") not in states or data.get("decision") not in decisions:
        raise AdapterError("SERVICE_UNAVAILABLE", status=503)
    if (data["state"] == "DECIDED") != (data.get("decision") is not None):
        raise AdapterError("SERVICE_UNAVAILABLE", status=503)
    out = {"scan_id": opaque_id(data.get("scan_id")), "state": data["state"],
           "decision": data.get("decision")}
    for key in ("required_checks", "completed_checks", "reason_codes", "evidence_ids"):
        items = data.get(key, [])
        if not isinstance(items, list) or len(items) > 64:
            raise AdapterError("SERVICE_UNAVAILABLE", status=503)
        out[key] = [opaque_id(item) for item in items]
        if key == "reason_codes" and any(not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", s) for s in items):
            raise AdapterError("SERVICE_UNAVAILABLE", status=503)
    if not set(out["completed_checks"]) <= set(out["required_checks"]):
        raise AdapterError("SERVICE_UNAVAILABLE", status=503)
    if data.get("decision") == "ALLOW_UNDER_POLICY" and (
            not out["required_checks"] or set(out["completed_checks"]) != set(out["required_checks"])):
        raise AdapterError("SERVICE_UNAVAILABLE", status=503)
    expiry = data.get("expires_at")
    if expiry is not None:
        if not isinstance(expiry, str) or not re.fullmatch(r"[0-9T:Z.+-]{1,40}", expiry):
            raise AdapterError("SERVICE_UNAVAILABLE", status=503)
        out["expires_at"] = expiry
    return {"contract_version": "v1", "data": out}
