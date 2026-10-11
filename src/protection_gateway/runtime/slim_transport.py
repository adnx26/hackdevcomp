"""Gateway side of AGNTCY SLIM: one in-process SLIM node on loopback.

API usage here was exercised against slim-bindings 2.2.0 (runtime 3.0.1);
see deploy/README.md. Mesh admission uses a shared secret generated per
gateway process. Admission is not authorization: application messages are
authenticated separately (see envelope.py).
"""

from __future__ import annotations

import datetime
import secrets
import socket
import threading

from .errors import RuntimeUnavailable

ORGANIZATION = "protection-gateway"


def initialize(slim) -> None:
    """Initialize the bindings once, with its own stdout logging off (the default writes info lines to stdout)."""
    if slim.is_initialized():
        return
    defaults = slim.new_tracing_config()
    tracing = slim.TracingConfig(log_level="off", display_thread_names=False, display_thread_ids=False, filters=defaults.filters)
    slim.initialize_with_configs(slim.new_runtime_config(), tracing, [slim.new_service_config()])


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class SlimNode:
    def __init__(self):
        try:
            import slim_bindings
        except ImportError:
            raise RuntimeUnavailable("SLIM_BINDINGS_MISSING") from None
        self._slim = slim_bindings
        self.mesh_secret = secrets.token_urlsafe(48)
        self.port = _free_port()
        self.gateway_name = (ORGANIZATION, "gateway", secrets.token_hex(4))
        self._lock = threading.Lock()
        try:
            initialize(slim_bindings)
            self._service = slim_bindings.create_service("pg-gateway-" + secrets.token_hex(4))
            self._endpoint = f"127.0.0.1:{self.port}"
            self._service.run_server(slim_bindings.new_insecure_server_config(self._endpoint))
            self._connection = self._service.connect(slim_bindings.new_insecure_client_config("http://" + self._endpoint))
            self._app = self._service.create_app_with_secret(slim_bindings.Name(*self.gateway_name), self.mesh_secret)
            self._app.subscribe(self._app.name(), self._connection)
        except Exception as error:
            raise RuntimeUnavailable("SLIM_NODE_FAILED:" + type(error).__name__) from None

    def deliver(self, worker_name: tuple[str, str, str], payload: bytes, timeout: float):
        """Open a point-to-point session to one worker and publish its job. Returns the session."""
        slim = self._slim
        destination = slim.Name(*worker_name)
        config = slim.SessionConfig(
            session_type=slim.SessionType.POINT_TO_POINT, max_retries=3,
            interval=datetime.timedelta(seconds=max(0.2, min(1.0, timeout / 4))), metadata={}, mls_settings=None,
        )
        with self._lock:
            self._app.set_route(destination, self._connection)
            session = self._app.create_session_and_wait(config, destination)
        session.publish_and_wait(payload, None, None)
        return session

    def receive(self, session, timeout: float) -> bytes | None:
        """One message from the session, or None on timeout/closed session."""
        try:
            return session.get_message(datetime.timedelta(seconds=timeout)).payload
        except self._slim.SlimError:
            return None

    def close_session(self, session) -> None:
        try:
            self._app.delete_session(session)
        except Exception:
            pass

    def close(self) -> None:
        for step in (lambda: self._service.stop_server(self._endpoint), self._service.shutdown):
            try:
                step()
            except Exception:
                pass
