"""Clock and ID sources, injectable for deterministic tests."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class IdFactory(Protocol):
    def new(self, prefix: str) -> str: ...

    def secret(self) -> str: ...


class RandomIds:
    def new(self, prefix: str) -> str:
        return f"{prefix}_{secrets.token_urlsafe(18).replace('-', 'A').replace('_', 'B')}"

    def secret(self) -> str:
        return secrets.token_urlsafe(32)


def iso(moment: datetime) -> str:
    """Second-precision UTC; fixed width so stored values sort lexicographically."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.rstrip("Z")).replace(tzinfo=timezone.utc)


def after(moment: datetime, seconds: float) -> datetime:
    return moment + timedelta(seconds=seconds)
