"""Authentication: server-derived principals.

User and tenant always come from a verified credential: a server-configured
demo bearer token, or a server-side browser session created from one. A
request field, header or assistant assertion never sets tenant, role or
approval authority.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, replace

from ..contracts.enums import Channel, ErrorCode
from ..contracts.errors import GatewayError
from .clock import Clock, IdFactory, after, iso, parse_iso
from .config import GatewayConfig
from .db import Database


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    channel: Channel

    def as_assistant(self) -> "Principal":
        """Principal for D's in-process chat adapter acting for this user."""
        return replace(self, channel=Channel.ASSISTANT)


@dataclass(frozen=True)
class BrowserSession:
    cookie_value: str
    csrf_token: str
    principal: Principal
    expires_at: str


class Authenticator:
    def __init__(self, config: GatewayConfig, db: Database, clock: Clock, ids: IdFactory):
        self._config = config
        self._db = db
        self._clock = clock
        self._ids = ids

    def authenticate_bearer(self, token: str | None, channel: Channel = Channel.API) -> Principal:
        if channel not in (Channel.API, Channel.MCP):
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "bearer tokens authenticate API or MCP only")
        if not token:
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "missing credential")
        presented = GatewayConfig.hash_token(token)
        match = None
        for identity in self._config.identities:
            if hmac.compare_digest(identity.token_sha256, presented):
                match = identity
        if match is None:
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "unknown credential")
        return Principal(match.user_id, match.tenant_id, channel)

    def issue_browser_session(self, bearer_token: str | None) -> BrowserSession:
        principal = self.authenticate_bearer(bearer_token, Channel.API)
        cookie = self._ids.secret()
        csrf = self._ids.secret()
        now = self._clock.now()
        expires = iso(after(now, self._config.retention.browser_session_seconds))
        self._db.execute(
            "INSERT INTO browser_sessions VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (
                GatewayConfig.hash_token(cookie),
                GatewayConfig.hash_token(csrf),
                principal.user_id,
                principal.tenant_id,
                iso(now),
                expires,
            ),
        )
        return BrowserSession(cookie, csrf, replace(principal, channel=Channel.USER_INTERFACE), expires)

    def authenticate_cookie(self, cookie_value: str | None, *, csrf_token: str | None, mutation: bool) -> Principal:
        if not cookie_value:
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "missing session")
        row = self._db.query_one(
            "SELECT * FROM browser_sessions WHERE session_hash = ?", (GatewayConfig.hash_token(cookie_value),)
        )
        if row is None or row["revoked_at"] or parse_iso(row["expires_at"]) <= self._clock.now():
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "invalid session")
        if mutation:
            if not csrf_token or not hmac.compare_digest(row["csrf_hash"], GatewayConfig.hash_token(csrf_token)):
                raise GatewayError(ErrorCode.FORBIDDEN, "csrf check failed")
        return Principal(row["user_id"], row["tenant_id"], Channel.USER_INTERFACE)

    def revoke_browser_session(self, cookie_value: str) -> None:
        self._db.execute(
            "UPDATE browser_sessions SET revoked_at = ? WHERE session_hash = ?",
            (iso(self._clock.now()), GatewayConfig.hash_token(cookie_value)),
        )
