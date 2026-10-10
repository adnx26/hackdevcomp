"""Composition root: wires A's core, B's runtime, C's workers and D's adapters.

Nothing is assumed to exist. Each component is attached only if it is really
present, every route declares the capabilities it needs, and a route whose
requirements are not met answers SERVICE_UNAVAILABLE. There are no no-op
workers and no fallback implementations.

    python -m protection_gateway.bootstrap --check   # print capabilities, exit 1 unless complete
    python -m protection_gateway.bootstrap           # serve
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import ipaddress
import json
import logging
import secrets
import sys
from typing import Callable, Iterable

from . import CONTRACT_VERSION
from .runtime.config import RuntimeConfig
from .runtime.runtime import Runtime

log = logging.getLogger("protection_gateway.bootstrap")

# Everything a complete scan-to-decision workflow needs.
COMPLETE_WORKFLOW = ("core", "isolation", "slim", "model_broker", "collector", "extraction", "inspection", "adapters")
# Contract v1 public surface: known paths answer 503 (not 404) while their owner is absent.
CONTRACT_PREFIXES = ("/v1/", "/mcp", "/ui")
# D's AdapterApp owns exactly these (adapters/http.py on their branch); A owns the rest of /v1.
ADAPTER_PREFIXES = ("/ui", "/mcp", "/v1/chat")
# What D's AdapterApp needs from A, looked up by these names on the core object.
ADAPTER_CORE_HOOKS = ("authenticate", "verify_csrf", "session_info", "error_status")
_HEADERS = [
    (b"content-type", b"application/json"),
    (b"x-content-type-options", b"nosniff"),
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
]


async def _error(send, status: int, code: str) -> None:
    body = json.dumps({"contract_version": CONTRACT_VERSION, "error": {"code": code, "retryable": False, "request_id": "req_" + secrets.token_hex(8)}}).encode()
    await send({"type": "http.response.start", "status": status, "headers": _HEADERS})
    await send({"type": "http.response.body", "body": body})


class Gateway:
    """ASGI application assembled from whatever components are really present."""

    def __init__(self, runtime: Runtime):
        self.runtime = runtime
        self.core = None
        self._routes: list[tuple[str, Callable, tuple[str, ...]]] = []
        self._extra: dict[str, dict] = {"adapters": {"available": False, "reason": "ADAPTERS_NOT_INSTALLED"}}

    # ---- registration (composition time only) -------------------------

    def mount(self, prefix: str, asgi_app: Callable, *, requires: Iterable[str]) -> None:
        """Route `prefix` to `asgi_app` (path left intact) only while every capability in `requires` is available."""
        requires = tuple(requires)
        if not requires:
            raise ValueError("every route must declare the capabilities it depends on")
        if not prefix.startswith(CONTRACT_PREFIXES):
            raise ValueError("routes outside the contract surface are not mounted")
        if any(prefix == existing for existing, _, _ in self._routes):
            raise ValueError("route already mounted")
        self._routes.append((prefix, asgi_app, requires))
        self._routes.sort(key=lambda route: len(route[0]), reverse=True)

    def provide(self, capability: str, available: bool, reason: str = "") -> None:
        self._extra[capability] = {"available": bool(available), "reason": reason}

    # ---- capability view ---------------------------------------------

    def capabilities(self) -> dict[str, dict]:
        capabilities = {**self._extra, **self.runtime.capabilities()}
        missing = [name for name in COMPLETE_WORKFLOW if not capabilities.get(name, {}).get("available")]
        capabilities["complete_workflow"] = {"available": not missing, "reason": "MISSING:" + ",".join(missing) if missing else ""}
        return capabilities

    # ---- ASGI ----------------------------------------------------------

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    self.close()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return  # no websocket or other protocol is offered
        path = scope.get("path", "") or "/"
        for prefix, app, requires in self._routes:
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                capabilities = self.capabilities()
                if not all(capabilities.get(name, {}).get("available") for name in requires):
                    return await _error(send, 503, "SERVICE_UNAVAILABLE")
                return await app(scope, receive, send)
        if path.startswith(CONTRACT_PREFIXES):
            return await _error(send, 503, "SERVICE_UNAVAILABLE")
        return await _error(send, 404, "NOT_FOUND")

    def close(self) -> None:
        self.runtime.shutdown()


def _optional_module(name: str):
    """Import a teammate's package if it exists; a missing package is a disabled capability."""
    try:
        if importlib.util.find_spec(name) is None:
            return None
    except ModuleNotFoundError:
        return None
    return importlib.import_module(name)


def _attach_adapters(gateway: Gateway, config: RuntimeConfig) -> None:
    """Mount D's AdapterApp. D fails closed on its own for anything A has not supplied."""
    adapters = _optional_module("protection_gateway.adapters")
    adapter_class = getattr(adapters, "AdapterApp", None)
    if adapter_class is None:
        return
    core = gateway.core
    if not gateway.capabilities()["core"]["available"]:
        return gateway.provide("adapters", False, "CORE_UNAVAILABLE")
    if not callable(getattr(core, "authenticate", None)):  # without it every adapter route is 503 anyway
        return gateway.provide("adapters", False, "CORE_HOOK_MISSING:authenticate")
    if not config.allowed_origins:
        return gateway.provide("adapters", False, "ALLOWED_ORIGINS_NOT_CONFIGURED")
    if not all((config.web_root / name).is_file() for name in ("index.html", "app.js", "style.css")):
        return gateway.provide("adapters", False, "WEB_ASSETS_MISSING")
    # No model_client_factory is injected: what the assistant model may be shown for a scan is
    # not agreed with D yet, so D's controlled chat stays in its deterministic mode.
    app = adapter_class(core=core, allowed_origins=config.allowed_origins, web_root=config.web_root,
                        **{name: getattr(core, name, None) for name in ADAPTER_CORE_HOOKS})
    for prefix in ADAPTER_PREFIXES:
        gateway.mount(prefix, app, requires=("core", "adapters"))
    gateway.provide("adapters", True)


def build_gateway(config: RuntimeConfig | None = None, *, runtime: Runtime | None = None) -> Gateway:
    """Activate the runtime, then attach whichever of A's core and D's adapters are installed.

    Hooks expected from A (provisional until A's package exists):
      protection_gateway.core.build_core(runtime=...) -> core   # gets B's extract/dispatch/cancel
      protection_gateway.core.register(gateway)                  # mounts A's ASGI routes under /v1/
    """
    config = config or RuntimeConfig.from_env()
    runtime = runtime or Runtime(config)
    gateway = Gateway(runtime)
    runtime.activate()
    core_module = _optional_module("protection_gateway.core")
    if core_module is not None and hasattr(core_module, "build_core"):
        gateway.core = core_module.build_core(runtime=runtime)
        runtime.bind_core(gateway.core)
        if hasattr(core_module, "register"):
            core_module.register(gateway)
    _attach_adapters(gateway, config)
    for name, state in gateway.capabilities().items():
        log.info("capability %s available=%s reason=%s", name, state["available"], state["reason"])
    return gateway


def server_options(config: RuntimeConfig) -> dict:
    """uvicorn options. Loopback may be served without TLS; any other interface requires a certificate and key."""
    try:
        loopback = config.host == "localhost" or ipaddress.ip_address(config.host).is_loopback
    except ValueError:
        loopback = False
    tls = bool(config.tls_cert and config.tls_key)
    if not loopback and not tls:
        raise SystemExit("refusing to listen on a non-loopback interface without PG_TLS_CERT and PG_TLS_KEY")
    options = {"host": config.host, "port": config.port, "log_level": "warning", "access_log": False,
               "server_header": False, "proxy_headers": False, "lifespan": "on"}
    if tls:
        options.update(ssl_certfile=str(config.tls_cert), ssl_keyfile=str(config.tls_key))
    return options


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="print capability status and exit non-zero unless the complete workflow is available")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    config = RuntimeConfig.from_env()
    options = None if args.check else server_options(config)
    gateway = build_gateway(config)
    if args.check:
        try:
            capabilities = gateway.capabilities()
            print(json.dumps({"capabilities": capabilities, "isolation_report": gateway.runtime.sandbox.report}, indent=2))
            return 0 if capabilities["complete_workflow"]["available"] else 1
        finally:
            gateway.close()
    import uvicorn

    log.info("gateway listening on %s:%d (complete_workflow=%s)", config.host, config.port, gateway.capabilities()["complete_workflow"]["available"])
    try:
        uvicorn.run(gateway, **options)  # the lifespan shutdown closes the runtime
    finally:
        gateway.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
