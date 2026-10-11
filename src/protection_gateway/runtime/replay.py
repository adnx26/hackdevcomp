"""Development-only record/replay of model responses for offline, deterministic demos.

Replay supplies cached *evidence* only: replayed responses still pass through
C's worker validation and A's result checks, and the core still makes every
decision. A replay run uses its own model configuration (``inference:
"replay"``), so its hash differs from the live configuration and a replayed
decision can never be presented as a live one.

Cache keys hash the rendered system prompt, the model identity and the request
payload after per-run volatile values (resource IDs, view IDs, collector event
IDs, scan/run IDs, timestamps, argument digests) are replaced with ordered
placeholders. Recorded responses are stored with the same placeholders and are
mapped back to the current run's values on replay. A missing entry, or a
placeholder the current request cannot resolve, raises REPLAY_CACHE_MISS, so
the inspection is incomplete and the gateway holds the content for REVIEW.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .envelope import canonical_json
from .errors import RuntimeUnavailable

MODE_RECORD = "record"
MODE_REPLAY = "replay"
MODES = (MODE_RECORD, MODE_REPLAY)
KEY_VERSION = 1

# Collector receipt fields that differ between otherwise identical runs.
_VOLATILE_EVENT_FIELDS = (("event_id", "E"), ("scan_id", "S"), ("run_id", "U"), ("timestamp", "T"), ("dummy_argument_digest", "D"))


def _token(prefix: str, index: int) -> str:
    return f"⟦{prefix}{index}⟧"


def volatile_mapping(payload: dict) -> dict[str, str]:
    """Real value -> placeholder, assigned in a deterministic first-seen order."""
    mapping: dict[str, str] = {}
    counters: dict[str, int] = {}

    def add(value: Any, prefix: str) -> None:
        if isinstance(value, str) and value and value not in mapping:
            counters[prefix] = counters.get(prefix, 0) + 1
            mapping[value] = _token(prefix, counters[prefix])

    for document in payload.get("documents") or []:
        if isinstance(document, dict):
            add(document.get("resource_id"), "R")
            add(document.get("view_id"), "V")
    for entry in payload.get("history") or []:
        receipt = entry.get("collector_result") if isinstance(entry, dict) else None
        if isinstance(receipt, dict):
            for field, prefix in _VOLATILE_EVENT_FIELDS:
                add(receipt.get(field), prefix)
    return mapping


def substitute(value: Any, mapping: dict[str, str]) -> Any:
    """Replace whole string values (never substrings, never keys) found in mapping."""
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        return [substitute(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, mapping) for key, item in value.items()}
    return value


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return "⟦" in value
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    return False


def model_identity(config) -> dict:
    """The model fields a cached response depends on; excludes the replay flag itself."""
    return {key: value for key, value in config.binding().items() if key != "inference"}


def cache_key(config, system: str, user: str) -> tuple[str, dict[str, str]]:
    try:
        payload = json.loads(user)
    except ValueError:
        raise RuntimeUnavailable("REPLAY_REQUEST_INVALID") from None
    if not isinstance(payload, dict):
        raise RuntimeUnavailable("REPLAY_REQUEST_INVALID")
    mapping = volatile_mapping(payload)
    material = {"key_version": KEY_VERSION, "model": model_identity(config), "system": system,
                "payload": substitute(payload, mapping)}
    return hashlib.sha256(canonical_json(material)).hexdigest(), mapping


class ReplayCache:
    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def _path(self, key: str) -> Path:
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise RuntimeUnavailable("REPLAY_KEY_INVALID")
        return self.directory / f"{key}.json"

    def get(self, key: str) -> dict | None:
        try:
            entry = json.loads(self._path(key).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(entry, dict) or entry.get("key_version") != KEY_VERSION or not isinstance(entry.get("response"), dict):
            return None
        return entry

    def put(self, key: str, entry: dict) -> None:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self._path(key)
        fd, temporary = tempfile.mkstemp(dir=self.directory, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(entry, handle, ensure_ascii=False, sort_keys=True, indent=1)
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def __len__(self) -> int:
        return len(list(self.directory.glob("*.json"))) if self.directory.is_dir() else 0


class RecordingTransport:
    """Wraps the live transport and stores each complete JSON-object reply."""

    def __init__(self, inner, cache: ReplayCache):
        self._inner = inner
        self.cache = cache

    def generate(self, config, *, system: str, user: str, max_output_tokens: int, timeout: float) -> dict:
        response = self._inner.generate(config, system=system, user=user, max_output_tokens=max_output_tokens, timeout=timeout)
        if response.get("stop_reason") == "end_turn":
            try:
                parsed = json.loads(response.get("text") or "")
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                key, mapping = cache_key(config, system, user)
                self.cache.put(key, {"key_version": KEY_VERSION, "model": model_identity(config),
                                     "response": substitute(parsed, mapping)})
        return response


class ReplayTransport:
    """Serves recorded replies. Contacts no provider and holds no credential."""

    def __init__(self, cache: ReplayCache):
        self.cache = cache

    def generate(self, config, *, system: str, user: str, max_output_tokens: int, timeout: float) -> dict:
        key, mapping = cache_key(config, system, user)
        entry = self.cache.get(key)
        if entry is None:
            raise RuntimeUnavailable("REPLAY_CACHE_MISS")
        restored = substitute(entry["response"], {placeholder: real for real, placeholder in mapping.items()})
        if _contains_placeholder(restored):
            raise RuntimeUnavailable("REPLAY_CACHE_MISS")
        return {"stop_reason": "end_turn", "text": json.dumps(restored, ensure_ascii=False),
                "usage": {"input_tokens": 0, "output_tokens": 0}}


def select_transport(mode: str | None, *, dev_mode: bool, directory: Path, live_factory):
    """Return the transport for a replay mode; live_factory() builds the provider transport."""
    if mode in (None, ""):
        return live_factory()
    if mode not in MODES:
        raise RuntimeUnavailable("REPLAY_MODE_INVALID")
    if not dev_mode:
        raise RuntimeUnavailable("REPLAY_REQUIRES_DEV_MODE")
    cache = ReplayCache(directory)
    if mode == MODE_REPLAY:
        return ReplayTransport(cache)
    return RecordingTransport(live_factory(), cache)
