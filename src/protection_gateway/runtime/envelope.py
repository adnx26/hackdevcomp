"""Application-level message authentication.

SLIM admission only proves that a process may join the mesh. Every job and
result additionally carries an HMAC made with a key issued to exactly one
launched worker process for exactly one assignment attempt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from typing import Any, Mapping

from .. import CONTRACT_VERSION
from .errors import Rejected

MAX_ENVELOPE_BYTES = 1024 * 1024

KIND_ASSIGNMENT = "assignment"
KIND_WORKER_RESULT = "worker_result"
KIND_EXTRACTION_RESULT = "extraction_result"
KIND_WORKER_FAILURE = "worker_failure"

_FIELDS = {"contract_version", "kind", "sender", "assignment_id", "scan_id", "attempt", "nonce", "issued_at", "body", "mac"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _mac(key: bytes, envelope: Mapping[str, Any]) -> str:
    unsigned = {k: v for k, v in envelope.items() if k != "mac"}
    return hmac.new(key, canonical_json(unsigned), hashlib.sha256).hexdigest()


def seal(key: bytes, *, kind: str, sender: Mapping[str, str], assignment_id: str, scan_id: str, attempt: int, body: Any) -> bytes:
    envelope = {
        "contract_version": CONTRACT_VERSION,
        "kind": kind,
        "sender": dict(sender),
        "assignment_id": assignment_id,
        "scan_id": scan_id,
        "attempt": attempt,
        "nonce": secrets.token_hex(16),
        "issued_at": utc_now(),
        "body": body,
    }
    envelope["mac"] = _mac(key, envelope)
    return canonical_json(envelope)


def open_sealed(key: bytes, raw: bytes) -> dict:
    """Parse and authenticate an envelope. Binding checks are the caller's job."""
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise Rejected("MESSAGE_TOO_LARGE")
    try:
        envelope = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise Rejected("MALFORMED_MESSAGE") from None
    if not isinstance(envelope, dict) or set(envelope) != _FIELDS:
        raise Rejected("MALFORMED_MESSAGE")
    if envelope["contract_version"] != CONTRACT_VERSION:
        raise Rejected("CONTRACT_VERSION_MISMATCH")
    mac = envelope["mac"]
    if not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(key, envelope)):
        raise Rejected("SENDER_NOT_AUTHENTICATED")
    return envelope
