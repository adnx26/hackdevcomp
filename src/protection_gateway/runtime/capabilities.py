"""Short-lived, worker-specific grants.

A grant binds one launched worker process to one assignment attempt. Its
bearer tokens and message key are handed to that process over its stdin pipe
and are never logged, put on SLIM, or placed in the environment.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from .errors import Rejected
from .roster import WorkerRecord

MAX_GRANT_SECONDS = 300.0

KIND_RESOURCE = "resource"
KIND_MODEL = "model"
KIND_TOOLS = "tools"

_REQUIRED = ("assignment_id", "scan_id", "attempt", "deadline")


def _deadline_epoch(value: Any) -> float:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise Rejected("INVALID_ASSIGNMENT", 400) from None
    if parsed.tzinfo is None:
        raise Rejected("INVALID_ASSIGNMENT", 400)
    return parsed.timestamp()


@dataclass
class Grant:
    grant_id: str
    assignment: Mapping[str, Any]
    record: WorkerRecord
    expires_at: float
    message_key: bytes
    tokens: dict[str, str]
    run_id: str
    revoked: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    seen_nonces: set = field(default_factory=set)
    result: Any = None
    result_ready: threading.Event = field(default_factory=threading.Event)
    model_calls: int = 0
    model_tokens: int = 0
    collector_sequence: int = 0
    artifacts_written: int = 0
    revoke_reason: str = ""

    @property
    def assignment_id(self) -> str:
        return self.assignment["assignment_id"]

    @property
    def scan_id(self) -> str:
        return self.assignment["scan_id"]

    @property
    def attempt(self) -> int:
        return self.assignment["attempt"]

    def remaining(self) -> float:
        return self.expires_at - time.time()

    def check_active(self) -> None:
        if self.revoked.is_set():
            raise Rejected("CAPABILITY_REVOKED", 401)
        if self.remaining() <= 0:
            raise Rejected("CAPABILITY_EXPIRED", 401)


class GrantRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._grants: dict[str, Grant] = {}
        self._by_token: dict[str, tuple[Grant, str]] = {}

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def issue(self, assignment: Mapping[str, Any], record: WorkerRecord) -> Grant:
        if any(key not in assignment for key in _REQUIRED):
            raise Rejected("INVALID_ASSIGNMENT", 400)
        if not isinstance(assignment["attempt"], int) or isinstance(assignment["attempt"], bool):
            raise Rejected("INVALID_ASSIGNMENT", 400)
        now = time.time()
        expires_at = min(_deadline_epoch(assignment["deadline"]), now + MAX_GRANT_SECONDS)
        if expires_at <= now:
            raise Rejected("ASSIGNMENT_EXPIRED", 400)
        kinds = [KIND_RESOURCE]
        if record.uses_model:
            kinds.append(KIND_MODEL)
        if record.uses_simulated_tools:
            kinds.append(KIND_TOOLS)
        grant = Grant(
            grant_id=secrets.token_hex(8),
            assignment=dict(assignment),
            record=record,
            expires_at=expires_at,
            message_key=secrets.token_bytes(32),
            tokens={kind: secrets.token_urlsafe(32) for kind in kinds},
            # A may issue the behavior run id in the assignment; otherwise the runtime mints one.
            run_id=assignment["run_id"] if isinstance(assignment.get("run_id"), str) and assignment["run_id"] else "run_" + secrets.token_hex(12),
        )
        with self._lock:
            for other in self._grants.values():
                if other.assignment_id == grant.assignment_id and other.attempt == grant.attempt:
                    raise Rejected("DUPLICATE_ASSIGNMENT", 409)
            self._grants[grant.grant_id] = grant
            for kind, token in grant.tokens.items():
                self._by_token[self._digest(token)] = (grant, kind)
        return grant

    def authenticate(self, token: str | None, kind: str) -> Grant:
        """Resolve a bearer token to its active grant for exactly this capability kind."""
        entry = self._by_token.get(self._digest(token)) if token else None
        if entry is None:
            raise Rejected("CAPABILITY_UNKNOWN", 401)
        grant, granted_kind = entry
        if granted_kind != kind:
            raise Rejected("CAPABILITY_WRONG_SCOPE", 403)
        grant.check_active()
        return grant

    def revoke(self, grant: Grant, reason: str) -> None:
        with self._lock:
            if not grant.revoked.is_set():
                grant.revoke_reason = reason
                grant.revoked.set()
            for token in grant.tokens.values():
                self._by_token.pop(self._digest(token), None)
            self._grants.pop(grant.grant_id, None)

    def for_scan(self, scan_id: str) -> list[Grant]:
        with self._lock:
            return [grant for grant in self._grants.values() if grant.scan_id == scan_id]

    def all(self) -> list[Grant]:
        with self._lock:
            return list(self._grants.values())
