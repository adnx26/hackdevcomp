"""Authoritative simulated-tool collector.

Gateway-owned. Workers reach it only through `simulated_tools.attempt`; they
can neither write nor sign events. Every attempt is recorded with A before
the worker hears the outcome, so a harmless final answer cannot hide an
earlier forbidden attempt. All effects are changes to per-run dummy state;
nothing here can deliver anything anywhere.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any, Mapping

from .. import CONTRACT_VERSION
from .capabilities import Grant
from .envelope import canonical_json, sha256_hex, utc_now
from .errors import Rejected, RuntimeUnavailable

MAX_ARGUMENT_BYTES = 16 * 1024
MAX_ATTEMPTS_PER_RUN = 64

# Fixed dummy tool set: name -> required string arguments.
DUMMY_TOOLS: dict[str, tuple[str, ...]] = {
    "read_email": ("email_id",),
    "send_email": ("to", "subject", "body"),
    "delete_email": ("email_id",),
    "read_file": ("path",),
    "fetch_url": ("url",),
    "make_payment": ("payee", "amount", "currency"),
}

TOOL_DEFINITIONS = [
    {
        "name": name,
        "description": f"Simulated {name.replace('_', ' ')} against dummy data.",
        "input_schema": {
            "type": "object",
            "properties": {argument: {"type": "string"} for argument in arguments},
            "required": list(arguments),
            "additionalProperties": False,
        },
    }
    for name, arguments in DUMMY_TOOLS.items()
]

OUTCOME_PROPOSED = "PROPOSED"
OUTCOME_DENIED = "DENIED"
OUTCOME_EXECUTED_DUMMY = "EXECUTED_DUMMY"
POLICY_PERMITTED = "PERMITTED"
POLICY_FORBIDDEN = "FORBIDDEN"


@dataclass(frozen=True)
class CollectorIdentity:
    """Passed to core.record_collector_event. Only the collector can construct a verifiable one."""

    collector_id: str
    key_id: str


class SimulatedToolCollector:
    def __init__(self, core, key: bytes | None = None):
        self._core = core
        self._key = key or secrets.token_bytes(32)
        self.identity = CollectorIdentity("pg.collector.v1", hashlib.sha256(self._key).hexdigest()[:16])
        self._state: dict[str, list] = {}

    def verify(self, event: Mapping[str, Any]) -> bool:
        """Lets A re-check that an event was produced by this collector."""
        unsigned = {k: v for k, v in event.items() if k != "signature"}
        expected = hmac.new(self._key, canonical_json(unsigned), hashlib.sha256).hexdigest()
        return isinstance(event.get("signature"), str) and hmac.compare_digest(event["signature"], expected)

    def _record(self, grant: Grant, operation: str, digest: str, outcome: str, policy_check: str) -> str:
        with grant.lock:
            grant.collector_sequence += 1
            sequence = grant.collector_sequence
        event = {
            "contract_version": CONTRACT_VERSION,
            "event_id": "evt_" + secrets.token_hex(12),
            "scan_id": grant.scan_id,
            "run_id": grant.run_id,
            "assignment_id": grant.assignment_id,
            "sequence": sequence,
            "operation": operation,
            "argument_digest": digest,
            "attempted_outcome": outcome,
            "policy_check": policy_check,
            "timestamp": utc_now(),
        }
        event["signature"] = hmac.new(self._key, canonical_json(event), hashlib.sha256).hexdigest()
        try:
            self._core.record_collector_event(self.identity, event)
        except Exception:
            # Telemetry that cannot be stored is an outage, never a clean run.
            raise RuntimeUnavailable("COLLECTOR_EVENT_NOT_RECORDED") from None
        return event["event_id"]

    def attempt(self, grant: Grant, operation: Any, arguments: Any) -> dict:
        grant.check_active()
        if not grant.record.uses_simulated_tools:
            raise Rejected("ROLE_NOT_PERMITTED")
        if grant.collector_sequence >= 2 * MAX_ATTEMPTS_PER_RUN:
            raise Rejected("TOOL_BUDGET_EXHAUSTED", 429)
        if not isinstance(operation, str) or not isinstance(arguments, dict):
            raise Rejected("INVALID_REQUEST", 400)
        encoded = canonical_json(arguments)
        if len(encoded) > MAX_ARGUMENT_BYTES:
            raise Rejected("LIMIT_EXCEEDED", 413)
        digest = sha256_hex(encoded)
        expected = DUMMY_TOOLS.get(operation)
        well_formed = expected is not None and set(arguments) == set(expected) and all(isinstance(v, str) for v in arguments.values())
        if not well_formed:
            # Still evidence: the run tried something outside the fixed tool set.
            name = operation if expected is not None else "UNKNOWN_OPERATION"
            event_id = self._record(grant, name, digest, OUTCOME_DENIED, POLICY_FORBIDDEN)
            return {"outcome": OUTCOME_DENIED, "policy_check": POLICY_FORBIDDEN, "event_ids": [event_id], "result": None}
        # The policy is the assignment's, exactly as A issued it; the worker cannot name another.
        binding = {key: grant.assignment.get(key) for key in ("scan_id", "task_session_id", "task_scope_version", "policy_id", "policy_version", "policy_hash")}
        try:
            permitted = self._core.check_simulated_operation(binding, operation, arguments) is True
        except Exception:
            raise RuntimeUnavailable("POLICY_CHECK_UNAVAILABLE") from None
        if not permitted:
            event_id = self._record(grant, operation, digest, OUTCOME_DENIED, POLICY_FORBIDDEN)
            return {"outcome": OUTCOME_DENIED, "policy_check": POLICY_FORBIDDEN, "event_ids": [event_id], "result": None}
        proposed = self._record(grant, operation, digest, OUTCOME_PROPOSED, POLICY_PERMITTED)
        self._state.setdefault(grant.run_id, []).append({"operation": operation, "argument_digest": digest})
        executed = self._record(grant, operation, digest, OUTCOME_EXECUTED_DUMMY, POLICY_PERMITTED)
        return {
            "outcome": OUTCOME_EXECUTED_DUMMY,
            "policy_check": POLICY_PERMITTED,
            "event_ids": [proposed, executed],
            "result": {"status": "simulated", "operation": operation},
        }

    def discard_run(self, run_id: str) -> None:
        self._state.pop(run_id, None)
