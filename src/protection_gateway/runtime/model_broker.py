"""Model broker: the only path from a worker or adapter to a model provider.

The broker owns the provider credential and the single approved
provider/model configuration. Callers send a typed request; they cannot name
an endpoint, header, credential, model or tool definition.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from .. import CONTRACT_VERSION
from .collector import TOOL_DEFINITIONS
from .envelope import canonical_json
from .errors import Rejected, RuntimeUnavailable
from .roster import ROLE_BEHAVIOR_TESTER, ROLE_DATA_TOOL_INSPECTOR, ROLE_INSTRUCTION_INSPECTOR

log = logging.getLogger("protection_gateway.runtime.model_broker")

ROLE_CONTROLLED_ASSISTANT = "controlled_assistant"

# Approved data processors: provider -> (pinned endpoint, approved models).
APPROVED_PROVIDERS = {
    "anthropic": ("https://api.anthropic.com", ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1")),
}

_REQUEST_FIELDS = {"contract_version", "system", "messages", "max_output_tokens", "tool_profile"}
_BLOCK_FIELDS = {
    "text": {"type", "text"},
    "tool_use": {"type", "id", "name", "input"},
    "tool_result": {"type", "tool_use_id", "content", "is_error"},
    # Returned by the provider and echoed back unchanged on the next turn.
    "thinking": {"type", "thinking", "signature"},
    "redacted_thinking": {"type", "data"},
}


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model: str
    max_output_tokens: int = 4096
    timeout_seconds: float = 60.0
    max_request_bytes: int = 512 * 1024
    job_token_budget: int = 200_000
    job_call_budget: int = 16

    def __post_init__(self):
        approved = APPROVED_PROVIDERS.get(self.provider)
        if approved is None or self.model not in approved[1]:
            raise RuntimeUnavailable("MODEL_CONFIGURATION_NOT_APPROVED")

    @property
    def endpoint(self) -> str:
        return APPROVED_PROVIDERS[self.provider][0]

    def binding(self) -> dict:
        return {"provider": self.provider, "model": self.model, "endpoint": self.endpoint, "max_output_tokens": self.max_output_tokens}

    def hash(self) -> str:
        """The value A places in an assignment's `model_configuration_hash`."""
        return hashlib.sha256(canonical_json(self.binding())).hexdigest()


class ModelTransport(Protocol):
    def generate(self, config: ModelConfig, *, system: str, messages: list, tools: list, max_output_tokens: int, timeout: float) -> dict:
        """Return {"stop_reason": str, "content": [blocks], "usage": {"input_tokens": int, "output_tokens": int}}."""


@dataclass
class ModelCaller:
    """Who is calling, resolved by the gateway — never asserted by the caller."""

    caller_id: str
    role: str
    binding: Mapping[str, Any]  # scan/task ids that A's processor-permission check understands
    model_configuration_hash: str
    is_active: Callable[[], None]  # raises Rejected when expired, revoked or canceled
    canceled: threading.Event
    remaining_seconds: Callable[[], float]
    lock: threading.Lock = field(default_factory=threading.Lock)
    calls: int = 0
    tokens: int = 0


def _validate_messages(messages: Any) -> None:
    if not isinstance(messages, list) or not messages:
        raise Rejected("INVALID_REQUEST", 400)
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"} or message["role"] not in ("user", "assistant"):
            raise Rejected("INVALID_REQUEST", 400)
        content = message["content"]
        if isinstance(content, str):
            continue
        if not isinstance(content, list):
            raise Rejected("INVALID_REQUEST", 400)
        for block in content:
            allowed = _BLOCK_FIELDS.get(block.get("type")) if isinstance(block, dict) else None
            if allowed is None or not set(block) <= allowed:
                raise Rejected("INVALID_REQUEST", 400)


class ModelBroker:
    def __init__(self, config: ModelConfig, transport: ModelTransport, core):
        self.config = config
        self._transport = transport
        self._core = core
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="model-broker")
        # Different caller roles get different tool schemas. Nobody supplies their own.
        self._tool_profiles: dict[str, list] = {"none": [], "dummy_tools_v1": TOOL_DEFINITIONS}
        self._role_profiles: dict[str, set[str]] = {
            ROLE_INSTRUCTION_INSPECTOR: {"none"},
            ROLE_DATA_TOOL_INSPECTOR: {"none"},
            ROLE_BEHAVIOR_TESTER: {"none", "dummy_tools_v1"},
            ROLE_CONTROLLED_ASSISTANT: {"none"},
        }

    def register_assistant_tool_profile(self, name: str, tools: list) -> None:
        """Composition-time only: D's gated tool schemas for the controlled assistant."""
        if name in self._tool_profiles:
            raise ValueError("tool profile already registered")
        self._tool_profiles[name] = list(tools)
        self._role_profiles[ROLE_CONTROLLED_ASSISTANT].add(name)

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
        profiles = self._role_profiles.get(caller.role)
        if profiles is None:
            raise Rejected("ROLE_NOT_PERMITTED")
        if caller.model_configuration_hash != self.config.hash():
            raise Rejected("MODEL_CONFIGURATION_MISMATCH", 409)
        if not isinstance(request, dict):
            raise Rejected("INVALID_REQUEST", 400)
        if set(request) - _REQUEST_FIELDS:
            # Endpoints, headers, credentials, models and commands all land here.
            raise Rejected("UNEXPECTED_FIELD", 400)
        if request.get("contract_version") != CONTRACT_VERSION:
            raise Rejected("CONTRACT_VERSION_MISMATCH", 400)
        system = request.get("system", "")
        max_output = request.get("max_output_tokens", self.config.max_output_tokens)
        profile = request.get("tool_profile", "none")
        if not isinstance(system, str) or not isinstance(max_output, int) or isinstance(max_output, bool) or max_output < 1:
            raise Rejected("INVALID_REQUEST", 400)
        _validate_messages(request.get("messages"))
        if profile not in profiles:
            raise Rejected("TOOL_PROFILE_NOT_PERMITTED")
        if len(canonical_json(request)) > self.config.max_request_bytes:
            raise Rejected("LIMIT_EXCEEDED", 413)
        try:
            permitted = self._core.model_processing_permitted(dict(caller.binding), self.config.provider) is True
        except Exception:
            raise RuntimeUnavailable("PROCESSOR_PERMISSION_UNAVAILABLE") from None
        if not permitted:
            raise Rejected("PROCESSOR_NOT_PERMITTED")
        with caller.lock:
            remaining = self.config.job_token_budget - caller.tokens
            if caller.calls >= self.config.job_call_budget or remaining <= 0:
                raise Rejected("BUDGET_EXHAUSTED", 429)
            caller.calls += 1
        max_output = min(max_output, self.config.max_output_tokens, remaining)
        timeout = min(self.config.timeout_seconds, caller.remaining_seconds())
        if timeout <= 0:
            raise Rejected("CAPABILITY_EXPIRED", 401)
        future = self._pool.submit(
            self._transport.generate, self.config,
            system=system, messages=request["messages"], tools=self._tool_profiles[profile], max_output_tokens=max_output, timeout=timeout,
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
        return {
            "contract_version": CONTRACT_VERSION,
            "stop_reason": response.get("stop_reason"),
            "content": response.get("content", []),
            "usage": {"input_tokens": int(usage.get("input_tokens", 0)), "output_tokens": int(usage.get("output_tokens", 0))},
        }

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


class AssistantModelClient:
    """`model_client` handed to D's controlled assistant adapter for one task session."""

    def __init__(self, broker: ModelBroker, caller: ModelCaller):
        self._broker = broker
        self._caller = caller

    def generate(self, model_request: Mapping[str, Any]) -> dict:
        return self._broker.generate(self._caller, model_request)

    def cancel(self) -> None:
        self._caller.canceled.set()
