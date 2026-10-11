"""Model broker: the only path from a worker to a model provider.

The broker owns the provider credential and the single approved
provider/model configuration. A worker sends the typed inspection request
that C's workers build; it cannot name an endpoint, header, credential or
model. The broker renders that request into one provider call and returns the
model's reply parsed as a JSON object.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from .. import CONTRACT_VERSION
from .envelope import canonical_json
from .errors import Rejected, RuntimeUnavailable
from .roster import INSPECTOR_ROLES, ROLE_BEHAVIOR_TESTER

log = logging.getLogger("protection_gateway.runtime.model_broker")

# Approved data processors: provider -> (pinned endpoint, approved models).
APPROVED_PROVIDERS = {
    "kimi": ("https://api.moonshot.ai/v1", ("kimi-k3",)),
    "anthropic": ("https://api.anthropic.com", ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1")),
}

# The inspection request C's workers send (workers/inspection.py on their branch).
_REQUIRED_FIELDS = {"contract_version", "bindings", "system"}
_PAYLOAD_FIELDS = ("task_policy", "documents", "signals", "history", "response_contract", "fake_confidential_data", "tools")
_REQUEST_FIELDS = _REQUIRED_FIELDS | {"prompt_version", *_PAYLOAD_FIELDS}
_OUTPUT_RULE = "\n\nReply with exactly one JSON object and nothing else."
MAX_RESPONSE_CHARS = 200_000


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model: str
    max_output_tokens: int = 4096
    timeout_seconds: float = 60.0
    max_request_bytes: int = 512 * 1024
    job_token_budget: int = 200_000
    job_call_budget: int = 16
    reasoning_effort: str = "low"
    # "replay" serves recorded responses (development only; see replay.py). It is
    # part of the binding, so replayed scans never share the live configuration hash.
    inference: str = "live"

    def __post_init__(self):
        approved = APPROVED_PROVIDERS.get(self.provider)
        if approved is None or self.model not in approved[1]:
            raise RuntimeUnavailable("MODEL_CONFIGURATION_NOT_APPROVED")
        if self.reasoning_effort not in {"low", "high", "max"}:
            raise RuntimeUnavailable("MODEL_CONFIGURATION_NOT_APPROVED")
        if self.inference not in {"live", "replay"}:
            raise RuntimeUnavailable("MODEL_CONFIGURATION_NOT_APPROVED")

    @property
    def endpoint(self) -> str:
        return APPROVED_PROVIDERS[self.provider][0]

    def binding(self) -> dict:
        result = {"provider": self.provider, "model": self.model, "endpoint": self.endpoint, "max_output_tokens": self.max_output_tokens}
        if self.provider == "kimi":
            result["reasoning_effort"] = self.reasoning_effort
        if self.inference != "live":
            result["inference"] = self.inference
        return result

    def hash(self) -> str:
        """The value A places in an assignment's `model_configuration_hash`."""
        return hashlib.sha256(canonical_json(self.binding())).hexdigest()


class ModelTransport(Protocol):
    def generate(self, config: ModelConfig, *, system: str, user: str, max_output_tokens: int, timeout: float) -> dict:
        """Return {"stop_reason": str, "text": str, "usage": {"input_tokens": int, "output_tokens": int}}."""


@dataclass
class ModelCaller:
    """Who is calling, resolved by the gateway from the launch it performed — never asserted by the caller."""

    caller_id: str
    role: str
    assignment: Mapping[str, Any]
    is_active: Callable[[], None]  # raises Rejected when expired, revoked or canceled
    canceled: threading.Event
    remaining_seconds: Callable[[], float]
    lock: threading.Lock = field(default_factory=threading.Lock)
    calls: int = 0
    tokens: int = 0


def _parse_object(text: Any) -> dict:
    if not isinstance(text, str) or len(text) > MAX_RESPONSE_CHARS:
        raise Rejected("MODEL_RESPONSE_INVALID", 502)
    start, end = text.find("{"), text.rfind("}")
    try:
        value = json.loads(text[start:end + 1]) if start >= 0 and end > start else None
    except ValueError:
        value = None
    if not isinstance(value, dict):
        # A reply that is not the requested object is never treated as a clean inspection.
        raise Rejected("MODEL_RESPONSE_INVALID", 502)
    return value


class ModelBroker:
    def __init__(self, config: ModelConfig, transport: ModelTransport, core):
        self.config = config
        self._transport = transport
        self._core = core
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="model-broker")

    def generate(self, caller: ModelCaller, request: Any) -> dict:
        started = time.monotonic()
        reason = "OK"
        try:
            return self._generate(caller, request)
        except (Rejected, RuntimeUnavailable) as error:
            reason = error.reason_code
            raise
        finally:
            # IDs, durations and reason codes only: never prompts, outputs or secrets.
            log.info("model_call caller=%s role=%s reason=%s duration_ms=%d", caller.caller_id, caller.role, reason, (time.monotonic() - started) * 1000)

    def _generate(self, caller: ModelCaller, request: Any) -> dict:
        caller.is_active()
        if caller.role not in INSPECTOR_ROLES:
            raise Rejected("ROLE_NOT_PERMITTED")
        if caller.assignment.get("model_configuration_hash") != self.config.hash():
            raise Rejected("MODEL_CONFIGURATION_MISMATCH", 409)
        if not isinstance(request, dict):
            raise Rejected("INVALID_REQUEST", 400)
        if set(request) - _REQUEST_FIELDS:
            # Endpoints, headers, credentials, models and commands all land here.
            raise Rejected("UNEXPECTED_FIELD", 400)
        if _REQUIRED_FIELDS - set(request) or request["contract_version"] != CONTRACT_VERSION:
            raise Rejected("INVALID_REQUEST", 400)
        if not isinstance(request["system"], str) or not isinstance(request["bindings"], dict) or not request["bindings"]:
            raise Rejected("INVALID_REQUEST", 400)
        # Task binding: the request must be about the assignment this caller was launched for.
        if any(caller.assignment.get(key) != value for key, value in request["bindings"].items()):
            raise Rejected("BINDING_MISMATCH")
        tools = request.get("tools", [])
        if not isinstance(tools, list) or (tools and caller.role != ROLE_BEHAVIOR_TESTER):
            raise Rejected("TOOLS_NOT_PERMITTED")
        try:
            payload = canonical_json({name: request[name] for name in _PAYLOAD_FIELDS if name in request}).decode()
        except (TypeError, ValueError):
            raise Rejected("INVALID_REQUEST", 400) from None
        if len(payload) + len(request["system"]) > self.config.max_request_bytes:
            raise Rejected("LIMIT_EXCEEDED", 413)
        binding = {key: caller.assignment.get(key) for key in ("scan_id", "assignment_id", "task_session_id")}
        try:
            permitted = self._core.model_processing_permitted(binding, self.config.provider) is True
        except Exception:
            raise RuntimeUnavailable("PROCESSOR_PERMISSION_UNAVAILABLE") from None
        if not permitted:
            raise Rejected("PROCESSOR_NOT_PERMITTED")
        with caller.lock:
            remaining = self.config.job_token_budget - caller.tokens
            if caller.calls >= self.config.job_call_budget or remaining <= 0:
                raise Rejected("BUDGET_EXHAUSTED", 429)
            caller.calls += 1
        timeout = min(self.config.timeout_seconds, caller.remaining_seconds())
        if timeout <= 0:
            raise Rejected("CAPABILITY_EXPIRED", 401)
        future = self._pool.submit(
            self._transport.generate, self.config, system=request["system"] + _OUTPUT_RULE, user=payload,
            max_output_tokens=min(self.config.max_output_tokens, remaining), timeout=timeout,
        )
        deadline = time.monotonic() + timeout
        while True:
            try:
                response = future.result(timeout=0.1)
                break
            except concurrent.futures.TimeoutError:
                if caller.canceled.is_set():
                    future.cancel()
                    raise Rejected("CANCELED", 409) from None
                if time.monotonic() >= deadline:
                    future.cancel()
                    raise Rejected("MODEL_TIMEOUT", 504) from None
            except Exception:
                raise RuntimeUnavailable("MODEL_PROVIDER_ERROR") from None
        usage = response.get("usage") or {}
        with caller.lock:
            caller.tokens += int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
        # A response that finished after cancellation or expiry is discarded.
        caller.is_active()
        if response.get("stop_reason") != "end_turn":
            # Refusals and truncated output are incomplete, not empty-and-clean.
            raise Rejected("MODEL_RESPONSE_INCOMPLETE", 502)
        return _parse_object(response.get("text"))

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
