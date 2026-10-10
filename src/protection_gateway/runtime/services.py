"""Loopback-only HTTP services reached by sandboxed workers.

Two listeners on ephemeral 127.0.0.1 ports: the resource service and the
broker (model + simulated tools). A worker's sandbox allows only the ports
its role needs, and every call also needs that worker's bearer token.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Mapping

from .errors import Rejected, RuntimeUnavailable

log = logging.getLogger("protection_gateway.runtime.services")

MAX_BODY_BYTES = 4 * 1024 * 1024
Route = Callable[[str | None, dict], dict]


class LocalService:
    def __init__(self, name: str, routes: Mapping[str, Route]):
        service_name, table = name, dict(routes)

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # request lines never reach ordinary logs
                pass

            def _reply(self, status: int, payload: dict) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def do_POST(self):
                route = table.get(self.path)
                reason, status = "OK", 200
                try:
                    if route is None:
                        raise Rejected("NOT_FOUND", 404)
                    try:
                        length = int(self.headers.get("Content-Length", ""))
                    except ValueError:
                        raise Rejected("INVALID_REQUEST", 400) from None
                    if length < 0 or length > MAX_BODY_BYTES:
                        raise Rejected("LIMIT_EXCEEDED", 413)
                    try:
                        payload = json.loads(self.rfile.read(length))
                    except ValueError:
                        raise Rejected("INVALID_REQUEST", 400) from None
                    if not isinstance(payload, dict):
                        raise Rejected("INVALID_REQUEST", 400)
                    scheme, _, token = self.headers.get("Authorization", "").partition(" ")
                    result = route(token if scheme == "Bearer" else None, payload)
                    self._reply(200, {"data": result})
                except Rejected as error:
                    reason, status = error.reason_code, error.status
                    self._reply(status, {"error": {"code": reason}})
                except RuntimeUnavailable as error:
                    reason, status = error.reason_code, 503
                    self._reply(503, {"error": {"code": "SERVICE_UNAVAILABLE"}})
                except Exception as error:  # never leak details or content to a worker
                    reason, status = "INTERNAL:" + type(error).__name__, 500
                    self._reply(500, {"error": {"code": "SERVICE_UNAVAILABLE"}})
                log.info("local_service=%s path=%s status=%d reason=%s", service_name, self.path if route else "-", status, reason)

            do_GET = do_PUT = do_DELETE = do_PATCH = lambda self: self._reply(405, {"error": {"code": "INVALID_REQUEST"}})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, name=f"pg-{name}", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
