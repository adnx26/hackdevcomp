"""Composition root: wires A's core, B's runtime, C's workers and D's adapters.

Nothing is assumed to exist. Each component registers only what it can
actually provide, every route declares the capabilities it needs, and a route
whose requirements are not met answers SERVICE_UNAVAILABLE. There are no
no-op workers and no fallback implementations.

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
import mimetypes
import secrets
import ssl
import sys
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Callable, Iterable
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from . import CONTRACT_VERSION
from .runtime.config import RuntimeConfig
from .runtime.runtime import Runtime

log = logging.getLogger("protection_gateway.bootstrap")

# Everything a complete scan-to-decision workflow needs.
COMPLETE_WORKFLOW = ("core", "isolation", "slim", "model_broker", "collector", "extraction", "inspection", "adapters")
# Contract v1 public surface: known paths answer 503 (not 404) while their owner is absent.
CONTRACT_PREFIXES = ("/v1/", "/mcp", "/ui")
_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
]


def _error(start_response, status: str, code: str, retryable: bool = False):
    body = json.dumps({"contract_version": CONTRACT_VERSION, "error": {"code": code, "retryable": retryable, "request_id": "req_" + secrets.token_hex(8)}}).encode()
    start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body))), *_SECURITY_HEADERS])
    return [body]


class Gateway:
    """WSGI application assembled from whatever components are really present."""

    def __init__(self, runtime: Runtime, web_root: Path):
        self.runtime = runtime
        self.core = None
        self._web_root = Path(web_root)
        self._routes: list[tuple[str, Callable, tuple[str, ...]]] = []
        self._extra: dict[str, dict] = {"adapters": {"available": False, "reason": "ADAPTERS_NOT_INSTALLED"}}

    # ---- registration (composition time only) -------------------------

    def mount(self, prefix: str, wsgi_app: Callable, *, requires: Iterable[str]) -> None:
        """Serve `wsgi_app` under `prefix` only while every capability in `requires` is available."""
        requires = tuple(requires)
        if not requires:
            raise ValueError("every route must declare the capabilities it depends on")
        if not prefix.startswith(CONTRACT_PREFIXES):
            raise ValueError("routes outside the contract surface are not mounted")
        if any(prefix == existing for existing, _, _ in self._routes):
            raise ValueError("route already mounted")
        self._routes.append((prefix, wsgi_app, requires))
        self._routes.sort(key=lambda route: len(route[0]), reverse=True)

    def provide(self, capability: str, available: bool, reason: str = "") -> None:
        self._extra[capability] = {"available": bool(available), "reason": reason}

    # ---- capability view ---------------------------------------------

    def capabilities(self) -> dict[str, dict]:
        capabilities = {**self._extra, **self.runtime.capabilities()}
        ui_ready = (self._web_root / "index.html").is_file()
        capabilities["static_ui"] = {"available": ui_ready, "reason": "" if ui_ready else "WEB_ASSETS_MISSING"}
        missing = [name for name in COMPLETE_WORKFLOW if not capabilities.get(name, {}).get("available")]
        capabilities["complete_workflow"] = {"available": not missing, "reason": "MISSING:" + ",".join(missing) if missing else ""}
        return capabilities

    # ---- WSGI ----------------------------------------------------------

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "") or "/"
        for prefix, app, requires in self._routes:
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                capabilities = self.capabilities()
                if not all(capabilities.get(name, {}).get("available") for name in requires):
                    return _error(start_response, "503 Service Unavailable", "SERVICE_UNAVAILABLE")
                return app(environ, start_response)
        if path == "/ui" or path.startswith("/ui/"):
            return self._static(environ, start_response, path[len("/ui"):].lstrip("/"))
        if path.startswith(CONTRACT_PREFIXES):
            return _error(start_response, "503 Service Unavailable", "SERVICE_UNAVAILABLE")
        return _error(start_response, "404 Not Found", "NOT_FOUND")

    def _static(self, environ, start_response, relative: str):
        """D's static assets. Without a working core behind them the UI is not offered."""
        capabilities = self.capabilities()
        if not (capabilities["static_ui"]["available"] and capabilities["core"]["available"]):
            return _error(start_response, "503 Service Unavailable", "SERVICE_UNAVAILABLE")
        if environ.get("REQUEST_METHOD") not in ("GET", "HEAD"):
            return _error(start_response, "405 Method Not Allowed", "INVALID_REQUEST")
        root = self._web_root.resolve()
        target = (root / (relative or "index.html")).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            return _error(start_response, "404 Not Found", "NOT_FOUND")
        body = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        start_response("200 OK", [("Content-Type", content_type), ("Content-Length", str(len(body))), *_SECURITY_HEADERS])
        return [] if environ["REQUEST_METHOD"] == "HEAD" else [body]

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


def build_gateway(config: RuntimeConfig | None = None, *, runtime: Runtime | None = None) -> Gateway:
    """Activate the runtime, then attach whichever of A's core and D's adapters are installed.

    Expected (optional) hooks:
      protection_gateway.core.build_core(runtime=...) -> core   # A; gets B's extract/dispatch/cancel
      protection_gateway.core.register(gateway)                  # A's HTTP routes
      protection_gateway.adapters.register(gateway)              # D's /v1/chat, /mcp and UI routes
    """
    config = config or RuntimeConfig.from_env()
    runtime = runtime or Runtime(config)
    gateway = Gateway(runtime, config.web_root)
    runtime.activate()
    core_module = _optional_module("protection_gateway.core")
    if core_module is not None and hasattr(core_module, "build_core"):
        gateway.core = core_module.build_core(runtime=runtime)
        runtime.bind_core(gateway.core)
        if hasattr(core_module, "register"):
            core_module.register(gateway)
    adapters = _optional_module("protection_gateway.adapters")
    if adapters is not None and hasattr(adapters, "register"):
        if gateway.capabilities()["core"]["available"]:
            adapters.register(gateway)
            gateway.provide("adapters", True)
        else:
            gateway.provide("adapters", False, "CORE_UNAVAILABLE")
    for name, state in gateway.capabilities().items():
        log.info("capability %s available=%s reason=%s", name, state["available"], state["reason"])
    return gateway


class _Server(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):  # request lines may carry identifiers; A owns request logging
        pass


def make_gateway_server(gateway: Gateway, config: RuntimeConfig):
    """Loopback is served without TLS; any other interface requires a certificate and key."""
    loopback = config.host == "localhost" or _is_loopback(config.host)
    if not loopback and not (config.tls_cert and config.tls_key):
        raise SystemExit("refusing to listen on a non-loopback interface without PG_TLS_CERT and PG_TLS_KEY")
    server = make_server(config.host, config.port, gateway, server_class=_Server, handler_class=_QuietHandler)
    if config.tls_cert and config.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(config.tls_cert, config.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="print capability status and exit non-zero unless the complete workflow is available")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    config = RuntimeConfig.from_env()
    gateway = build_gateway(config)
    try:
        if args.check:
            capabilities = gateway.capabilities()
            print(json.dumps({"capabilities": capabilities, "isolation_report": gateway.runtime.sandbox.report}, indent=2))
            return 0 if capabilities["complete_workflow"]["available"] else 1
        server = make_gateway_server(gateway, config)
        log.info("gateway listening on %s:%d (complete_workflow=%s)", config.host, config.port, gateway.capabilities()["complete_workflow"]["available"])
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    finally:
        gateway.close()


if __name__ == "__main__":
    sys.exit(main())
