"""WSGI mapping of the public v1 API onto GatewayService.

B's bootstrap mounts this app (and D's routers). Successful responses use a
``data`` envelope; errors use ``error: {code, retryable, request_id}`` with
no raw model or source text.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from typing import Callable, Iterable

from ..contracts.enums import CONTRACT_VERSION, Channel, ErrorCode
from ..contracts.errors import GatewayError
from .auth import Authenticator, Principal
from .service import GatewayService

log = logging.getLogger("protection_gateway.core.http")

SESSION_COOKIE = "pg_session"
CSRF_HEADER = "HTTP_X_CSRF_TOKEN"
IDEMPOTENCY_HEADER = "HTTP_IDEMPOTENCY_KEY"

_ID = r"([A-Za-z0-9_\-:.]{1,128})"


def _reject_constant(value: str):
    raise ValueError("non-finite number")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class GatewayApp:
    def __init__(self, service: GatewayService, authenticator: Authenticator):
        self.service = service
        self.auth = authenticator
        s = service
        # (method, pattern, handler, status, auth mode)
        self.routes: list[tuple[str, re.Pattern, Callable, int]] = [
            ("POST", re.compile(r"^/v1/session$"), self._login, 201),
            ("GET", re.compile(r"^/v1/session$"), self._recover_session, 200),
            ("DELETE", re.compile(r"^/v1/session$"), self._logout, 200),
            ("POST", re.compile(r"^/v1/resources$"), lambda p, b, m, e: s.upload_resource(p, b), 201),
            ("DELETE", re.compile(rf"^/v1/resources/{_ID}$"), lambda p, b, m, e: s.delete_resource(p, m[0]), 200),
            ("POST", re.compile(r"^/v1/task-sessions$"), lambda p, b, m, e: s.create_task_session(p, b), 201),
            ("GET", re.compile(rf"^/v1/task-sessions/{_ID}$"), lambda p, b, m, e: s.get_task_session(p, m[0]), 200),
            ("PUT", re.compile(rf"^/v1/task-sessions/{_ID}/resources$"),
             lambda p, b, m, e: s.update_task_session(p, m[0], b), 200),
            ("POST", re.compile(rf"^/v1/task-sessions/{_ID}/cancel$"),
             lambda p, b, m, e: self._empty(b) or s.cancel_task_session(p, m[0]), 200),
            ("POST", re.compile(r"^/v1/scans$"),
             lambda p, b, m, e: s.start_scan(p, b, e.get(IDEMPOTENCY_HEADER)), 202),
            ("GET", re.compile(rf"^/v1/scans/{_ID}$"), lambda p, b, m, e: s.get_scan_status(p, m[0]), 200),
            ("GET", re.compile(rf"^/v1/scans/{_ID}/result$"), lambda p, b, m, e: s.get_inspected_result(p, m[0]), 200),
            ("POST", re.compile(rf"^/v1/scans/{_ID}/cancel$"),
             lambda p, b, m, e: self._empty(b) or s.cancel_scan(p, m[0]), 200),
            ("POST", re.compile(rf"^/v1/scans/{_ID}/review$"), lambda p, b, m, e: s.review_scan(p, m[0], b), 200),
            ("POST", re.compile(r"^/v1/actions$"), lambda p, b, m, e: s.propose_simulated_action(p, b), 201),
            ("GET", re.compile(rf"^/v1/actions/{_ID}$"), lambda p, b, m, e: s.get_action(p, m[0]), 200),
            ("POST", re.compile(rf"^/v1/actions/{_ID}/confirm$"),
             lambda p, b, m, e: s.confirm_simulated_action(p, m[0], b), 200),
            ("POST", re.compile(rf"^/v1/actions/{_ID}/execute$"),
             lambda p, b, m, e: s.execute_simulated_action(p, m[0], b, e.get(IDEMPOTENCY_HEADER)), 200),
            ("GET", re.compile(rf"^/v1/evidence/{_ID}$"), lambda p, b, m, e: s.get_evidence(p, m[0]), 200),
            ("GET", re.compile(r"^/v1/baselines/([a-z_]{1,32})/([0-9a-f]{64})$"), lambda p, b, m, e: s.get_baseline(p, m[0], m[1]), 200),
        ]

    @staticmethod
    def _empty(body) -> None:
        from ..contracts import schemas

        schemas.validate(schemas.empty_request, body)
        return None

    # ----------------------------------------------------------- auth helpers

    @staticmethod
    def _cookie(environ) -> str | None:
        raw = environ.get("HTTP_COOKIE")
        if not raw:
            return None
        try:
            jar = SimpleCookie(raw)
        except CookieError:
            return None
        morsel = jar.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    @staticmethod
    def _bearer(environ) -> str | None:
        header = environ.get("HTTP_AUTHORIZATION", "")
        if header.startswith("Bearer "):
            return header[7:].strip() or None
        return None

    def _principal(self, environ, method: str) -> Principal:
        bearer = self._bearer(environ)
        if bearer is not None:
            return self.auth.authenticate_bearer(bearer, Channel.API)
        return self.auth.authenticate_cookie(
            self._cookie(environ), csrf_token=environ.get(CSRF_HEADER), mutation=method != "GET"
        )

    def _login(self, principal, body, match, environ):
        raise AssertionError("handled specially")

    def _logout(self, principal, body, match, environ):
        raise AssertionError("handled specially")

    def _recover_session(self, principal, body, match, environ):
        raise AssertionError("handled specially")

    # ---------------------------------------------------------------- WSGI

    def __call__(self, environ, start_response) -> Iterable[bytes]:
        request_id = "req_" + secrets.token_hex(8)
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        headers: list[tuple[str, str]] = []
        try:
            for route_method, pattern, handler, status in self.routes:
                match = pattern.match(path)
                if match and route_method == method:
                    break
            else:
                raise GatewayError(ErrorCode.NOT_FOUND, "no route")
            body = self._read_body(environ, method)
            if handler == self._login:
                session = self.auth.issue_browser_session(self._bearer(environ))
                headers.append(("Set-Cookie", self._session_cookie(session.cookie_value)))
                data = {
                    "user_id": session.principal.user_id,
                    "csrf_token": session.csrf_token,
                    "expires_at": session.expires_at,
                }
            elif handler == self._recover_session:
                if "HTTP_AUTHORIZATION" in environ or environ.get("HTTP_X_PG_SESSION_RESUME") != "1":
                    raise GatewayError(ErrorCode.FORBIDDEN, "session resume requires cookie and resume header")
                origin = environ.get("HTTP_ORIGIN")
                if (origin is not None and origin != self.service.config.public_origin) or environ.get(
                    "HTTP_SEC_FETCH_SITE"
                ) in ("cross-site", "same-site"):
                    raise GatewayError(ErrorCode.FORBIDDEN, "off-origin session resume")
                session = self.auth.recover_browser_session(self._cookie(environ))
                data = {
                    "user_id": session.principal.user_id,
                    "csrf_token": session.csrf_token,
                    "expires_at": session.expires_at,
                }
            elif handler == self._logout:
                cookie = self._cookie(environ)
                self.auth.authenticate_cookie(cookie, csrf_token=environ.get(CSRF_HEADER), mutation=True)
                self.auth.revoke_browser_session(cookie)
                headers.append(("Set-Cookie", self._session_cookie("", expire=True)))
                data = {"signed_out": True}
            else:
                principal = self._principal(environ, method)
                data = handler(principal, body, match.groups(), environ)
            payload = {"contract_version": CONTRACT_VERSION, "data": data}
            return self._respond(start_response, status, payload, headers)
        except GatewayError as exc:
            log.info("request_rejected request_id=%s code=%s", request_id, exc.code.value)
            return self._respond(start_response, exc.http_status, exc.envelope(request_id), headers)
        except Exception as exc:  # never leak internals
            log.error("request_failed request_id=%s error=%s", request_id, type(exc).__name__)
            error = GatewayError(ErrorCode.SERVICE_UNAVAILABLE, retryable=False)
            return self._respond(start_response, error.http_status, error.envelope(request_id), headers)

    def _session_cookie(self, value: str, expire: bool = False) -> str:
        parts = [f"{SESSION_COOKIE}={value}", "Path=/", "HttpOnly", "SameSite=Strict"]
        if self.service.config.cookie_secure:
            parts.append("Secure")
        if expire:
            parts.append("Max-Age=0")
        return "; ".join(parts)

    def _read_body(self, environ, method: str):
        if method in ("GET", "DELETE"):
            return None
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError as exc:
            raise GatewayError(ErrorCode.INVALID_REQUEST, "bad content length") from exc
        if length < 0:
            raise GatewayError(ErrorCode.INVALID_REQUEST, "bad content length")
        if length > self.service.config.limits.max_request_bytes:
            raise GatewayError(ErrorCode.LIMIT_EXCEEDED, "request too large", retryable=False)
        if length == 0:
            return None
        content_type = environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise GatewayError(ErrorCode.INVALID_REQUEST, "expected application/json")
        raw = environ["wsgi.input"].read(length)
        try:
            return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError) as exc:
            raise GatewayError(ErrorCode.INVALID_REQUEST, "malformed json") from exc

    @staticmethod
    def _respond(start_response, status: int, payload: dict, headers: list) -> list[bytes]:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        phrase = HTTPStatus(status).phrase
        start_response(
            f"{status} {phrase}",
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
                *headers,
            ],
        )
        return [body]


def make_wsgi_app(service: GatewayService, authenticator: Authenticator) -> GatewayApp:
    return GatewayApp(service, authenticator)
