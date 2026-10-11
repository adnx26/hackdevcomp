"""Explicit local development composition of the canonical core and runtime."""
from __future__ import annotations

import asyncio
import io
import ipaddress
import os
import secrets
import threading
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..core.auth import Authenticator
from ..core.config import DemoIdentity, GatewayConfig, Limits, RosterEntry
from ..core.http import GatewayApp
from ..core.service import GatewayService
from ..contracts.enums import Channel, ErrorCode
from ..contracts.errors import GatewayError
from .core_bridge import CoreRuntimeBridge, ROLE_KEYS


@dataclass(frozen=True)
class AdapterContext:
    principal: object
    cookie: str | None = None


class CoreFacade:
    def __init__(self, service, auth, bridge):
        self.service, self.auth, self.bridge = service, auth, bridge
        self._stop = threading.Event()
        self._maintenance = threading.Thread(target=self._maintain, name="gateway-maintenance", daemon=True)
        service.recover(startup=True)
        self._maintenance.start()

    def _maintain(self):
        while not self._stop.wait(2):
            try:
                self.service.recover()
                self.service.run_retention()
            except Exception:
                # Fail closed through normal assignment deadlines; no source text in logs.
                import logging
                logging.getLogger(__name__).error("maintenance unavailable")

    def close(self):
        if not self._stop.is_set():
            self._stop.set()
            self._maintenance.join()
            self.service.db.close()

    def authenticate(self, scope, surface):
        headers = {k.decode().upper().replace("-", "_"): v.decode("latin-1") for k, v in scope["headers"]}
        environ = {"HTTP_" + k: v for k, v in headers.items()}
        try:
            if surface == "mcp":
                principal = self.auth.authenticate_bearer(GatewayApp._bearer(environ), Channel.MCP)
                return AdapterContext(principal)
            cookie = GatewayApp._cookie(environ)
            principal = self.auth.authenticate_cookie(cookie, csrf_token=None, mutation=False)
            return AdapterContext(principal, cookie)
        except GatewayError:
            return None

    def verify_csrf(self, scope, context):
        headers = dict(scope["headers"])
        try:
            self.auth.authenticate_cookie(context.cookie, csrf_token=headers.get(b"x-csrf-token", b"").decode(), mutation=True)
            return True
        except GatewayError:
            return False

    def session_info(self, context):
        session = self.auth.recover_browser_session(context.cookie)
        return {"display_name": session.principal.user_id, "csrf_token": session.csrf_token}

    @staticmethod
    def error_status(code):
        return GatewayError(ErrorCode(code)).http_status

    async def _call(self, context, method, *args):
        try:
            return {"contract_version": "v1", "data": await asyncio.to_thread(method, context.principal, *args)}
        except GatewayError as error:
            return error.envelope("req_" + secrets.token_hex(8))

    async def inspect_resource(self, context, request):
        return await self._call(context, self.service.inspect_resource, request["resource_id"], request["task_session_id"])

    async def inspect_folder(self, context, request):
        return await self._call(context, self.service.inspect_folder, request["folder_id"])

    async def get_folder_status(self, context, request):
        return await self._call(context, self.service.get_folder_status, request["folder_id"])

    async def get_scan_status(self, context, request):
        return await self._call(context, self.service.get_scan_status, request["scan_id"])

    async def get_inspected_result(self, context, request):
        return await self._call(context, self.service.get_inspected_result, request["scan_id"])


class CoreASGI:
    """Bounded ASGI-to-WSGI bridge; extraction never blocks the ASGI event loop."""
    def __init__(self, app, origins):
        self.app = app
        self.origins = frozenset(origins)
        self.hosts = {urlsplit(o).netloc for o in origins}

    async def __call__(self, scope, receive, send):
        from ..bootstrap import _error
        headers = {}
        for key, value in scope["headers"]:
            key = key.lower()
            if key in headers:
                return await _error(send, 400, "INVALID_REQUEST")
            headers[key] = value.decode("latin-1")
        if headers.get(b"host") not in self.hosts or (b"origin" in headers and headers[b"origin"] not in self.origins):
            return await _error(send, 403, "FORBIDDEN")
        if headers.get(b"sec-fetch-site") in {"cross-site", "same-site"}:
            return await _error(send, 403, "FORBIDDEN")

        async def read_body():
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    raise ValueError("disconnected")
                body.extend(message.get("body", b""))
                if len(body) > self.app.service.config.limits.max_request_bytes:
                    raise OverflowError("request too large")
                if not message.get("more_body", False):
                    return bytes(body)
        try:
            body = await asyncio.wait_for(read_body(), 15)
        except OverflowError:
            return await _error(send, 413, "LIMIT_EXCEEDED")
        except (ValueError, asyncio.TimeoutError):
            return await _error(send, 400, "INVALID_REQUEST")
        environ = {"REQUEST_METHOD": scope["method"], "PATH_INFO": scope["path"],
                   "CONTENT_LENGTH": str(len(body)), "CONTENT_TYPE": headers.get(b"content-type", ""),
                   "wsgi.input": io.BytesIO(body)}
        environ.update({"HTTP_" + k.decode().upper().replace("-", "_"): v for k, v in headers.items()})
        def execute():
            result = []
            def start_response(status, response_headers):
                result.extend([int(status.split()[0]), [(k.lower().encode(), v.encode("latin-1")) for k, v in response_headers]])
            response = b"".join(self.app(environ, start_response))
            return *result, response
        status, response_headers, response = await asyncio.to_thread(execute)
        await send({"type": "http.response.start", "status": status, "headers": response_headers})
        await send({"type": "http.response.body", "body": response})


def prepare_development(config):
    if config.host != "localhost" and not ipaddress.ip_address(config.host).is_loopback:
        raise ValueError("Development mode requires a loopback interface")
    config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config.login_token_file = config.login_token_file or config.state_dir / "login-token"
    if not config.login_token_file.exists():
        fd = os.open(config.login_token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_urlsafe(32))
    if not config.allowed_origins:
        config.allowed_origins = (f"http{'s' if config.tls_cert else ''}://{config.host}:{config.port}",)


def attach_core(gateway, config):
    runtime = gateway.runtime
    bridge = CoreRuntimeBridge(runtime)
    roster = tuple(RosterEntry(r.worker_identity, next(k for k, v in ROLE_KEYS.items() if v == r.role), r.build, r.prompt_version)
                   for r in runtime.roster.records())
    token = config.login_token_file.read_text().strip()
    core_config = GatewayConfig(database_path=str(config.state_dir / "gateway.sqlite3"),
                               evidence_root=str(config.state_dir / "evidence"),
                               identities=(DemoIdentity(GatewayConfig.hash_token(token), "local-user", "local-tenant"),),
                               worker_roster=roster, collector_ids=frozenset({runtime.collector.identity.collector_id}),
                               model_configuration=config.model.binding() if config.model else {},
                               allow_unencrypted_dev_storage=True, cookie_secure=bool(config.tls_cert),
                               public_origin=config.allowed_origins[0],
                               baseline_dir=str(config.baseline_dir),
                               vendor_registry_path=str(config.vendor_registry) if config.vendor_registry else None,
                               limits=Limits(scan_deadline_seconds=300, worker_lease_seconds=150))
    service = GatewayService(core_config, runtime=bridge)
    bridge.service = service
    auth = Authenticator(core_config, service.db, service.clock, service.ids)
    runtime.bind_core(bridge)
    gateway.core = CoreFacade(service, auth, bridge)
    gateway.mount("/v1/", CoreASGI(GatewayApp(service, auth), config.allowed_origins), requires=("core",))
