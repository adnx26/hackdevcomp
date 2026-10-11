"""Composition fails closed: missing components disable routes, they never fake success."""

import asyncio
import json
import sys
import types

import pytest

from protection_gateway import bootstrap
from protection_gateway.bootstrap import COMPLETE_WORKFLOW, build_gateway, server_options
from protection_gateway.runtime.config import RuntimeConfig
from protection_gateway.runtime.errors import RuntimeUnavailable
from protection_gateway.runtime.runtime import Runtime

from .conftest import MODEL, SANDBOX_WORKERS, TEST_ROSTER, FakeCore, FakeTransport, make_assignment


def call(app, path, method="GET"):
    """Drive the ASGI app once; returns (status, headers, body)."""
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "path": path, "method": method, "headers": [(b"host", b"gateway.example")]}
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), body


async def ok_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": scope["path"].encode()})


@pytest.fixture
def bare(tmp_path):
    """No sandbox launcher, no model, no core, no workers, no adapters."""
    config = RuntimeConfig(state_dir=tmp_path / "state", sandbox_backend="shadi", shadictl=str(tmp_path / "missing-shadictl"), web_root=tmp_path / "web")
    gateway = build_gateway(config)
    yield gateway, config
    gateway.close()


def test_nothing_is_available_until_it_is_really_present(bare):
    gateway, _ = bare
    capabilities = gateway.capabilities()
    assert all(not capabilities[name]["available"] for name in COMPLETE_WORKFLOW if name != "slim")
    assert capabilities["isolation"]["reason"] == "SANDBOX_LAUNCHER_MISSING"
    assert capabilities["model_broker"]["reason"] == "MODEL_CONFIGURATION_MISSING"
    assert capabilities["adapters"]["reason"] == "ADAPTERS_NOT_INSTALLED"
    assert capabilities["complete_workflow"]["available"] is False and "isolation" in capabilities["complete_workflow"]["reason"]


def test_runtime_calls_raise_service_unavailable_without_launching_anything(bare):
    gateway, config = bare
    for call_ in (lambda: gateway.runtime.extract({}), lambda: gateway.runtime.dispatch([{}]), gateway.runtime.model_configuration):
        with pytest.raises(RuntimeUnavailable) as error:
            call_()
        assert error.value.code == "SERVICE_UNAVAILABLE"
    assert not (config.state_dir / "scratch").exists()


def test_contract_routes_answer_503_and_unknown_paths_404(bare):
    gateway, _ = bare
    for path in ("/v1/scans", "/v1/chat", "/mcp", "/ui", "/ui/app.js"):
        status, headers, body = call(gateway, path)
        error = json.loads(body)
        assert status == 503 and error["error"]["code"] == "SERVICE_UNAVAILABLE" and error["contract_version"] == "v1", path
        assert set(error["error"]) == {"code", "retryable", "request_id"} and headers[b"x-content-type-options"] == b"nosniff"
    assert call(gateway, "/healthz")[0] == 404 and call(gateway, "/")[0] == 404


def test_mounted_route_stays_disabled_until_its_capabilities_exist(bare):
    gateway, _ = bare
    gateway.mount("/v1/scans", ok_app, requires=("core", "inspection"))
    assert call(gateway, "/v1/scans/abc")[0] == 503
    gateway.runtime.bind_core(FakeCore())  # a core alone is still not enough
    assert call(gateway, "/v1/scans/abc")[0] == 503
    gateway.mount("/v1/resources", ok_app, requires=("core",))
    status, _, body = call(gateway, "/v1/resources/r1")
    assert (status, body) == (200, b"/v1/resources/r1")  # the path reaches the mounted app intact
    assert call(gateway, "/v1/resourcesX")[0] == 503  # prefix match is on path segments
    for bad in (dict(prefix="/v1/x", requires=()), dict(prefix="/admin", requires=("core",)), dict(prefix="/v1/resources", requires=("core",))):
        with pytest.raises(ValueError):
            gateway.mount(bad["prefix"], ok_app, requires=bad["requires"])


def test_lifespan_shutdown_closes_the_runtime(bare):
    gateway, _ = bare
    messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
    sent = []

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message["type"])

    asyncio.run(gateway({"type": "lifespan"}, receive, send))
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
    assert gateway.capabilities()["slim"] == {"available": False, "reason": "SHUT_DOWN"}


def test_non_loopback_listener_requires_tls(bare, tmp_path):
    _, config = bare
    config.host = "0.0.0.0"
    with pytest.raises(SystemExit, match="refusing to listen"):
        server_options(config)
    config.tls_cert, config.tls_key = tmp_path / "tls.crt", tmp_path / "tls.key"
    assert server_options(config)["ssl_certfile"] == str(config.tls_cert)
    config.host, config.tls_cert, config.tls_key = "127.0.0.1", None, None
    options = server_options(config)
    assert options["host"] == "127.0.0.1" and "ssl_certfile" not in options and options["proxy_headers"] is False


class _AdapterDouble:
    """Stands in for D's AdapterApp (same keyword-only constructor). Test-only."""

    created = []

    def __init__(self, *, core=None, authenticate=None, verify_csrf=None, session_info=None, model_client_factory=None,
                 error_status=None, allowed_origins=(), web_root=None, sign_in_path=None):
        self.kwargs = dict(core=core, authenticate=authenticate, verify_csrf=verify_csrf, session_info=session_info,
                           model_client_factory=model_client_factory, error_status=error_status, allowed_origins=allowed_origins, web_root=web_root)
        _AdapterDouble.created.append(self)

    async def __call__(self, scope, receive, send):
        await ok_app(scope, receive, send)


@pytest.fixture
def adapters_installed(monkeypatch):
    module = types.ModuleType("protection_gateway.adapters")
    module.AdapterApp = _AdapterDouble
    _AdapterDouble.created.clear()
    real = bootstrap._optional_module
    monkeypatch.setattr(bootstrap, "_optional_module", lambda name: module if name == "protection_gateway.adapters" else real(name))


def _config(tmp_path, **overrides):
    web = tmp_path / "web"
    web.mkdir(exist_ok=True)
    for name in ("index.html", "app.js", "style.css"):
        (web / name).write_text("x")
    return RuntimeConfig(state_dir=tmp_path / "state", sandbox_backend="shadi", shadictl=None, web_root=web, **overrides)


def test_adapters_are_mounted_only_with_core_origins_assets_and_authentication(tmp_path, adapters_installed):
    class CoreWithAuth(FakeCore):
        def authenticate(self, scope, surface): ...
        def verify_csrf(self, scope, context): ...

    def attach(core, **overrides):
        config = _config(tmp_path, **overrides)
        runtime = Runtime(config, core=core)
        gateway = bootstrap.Gateway(runtime)
        gateway.core = core
        bootstrap._attach_adapters(gateway, config)
        return gateway

    origins = ("https://gateway.example",)
    assert attach(None, allowed_origins=origins).capabilities()["adapters"]["reason"] == "CORE_UNAVAILABLE"
    assert attach(FakeCore(), allowed_origins=origins).capabilities()["adapters"]["reason"] == "CORE_HOOK_MISSING:authenticate"
    assert attach(CoreWithAuth()).capabilities()["adapters"]["reason"] == "ALLOWED_ORIGINS_NOT_CONFIGURED"
    assert _AdapterDouble.created == []
    (tmp_path / "web" / "app.js").unlink()
    config = _config(tmp_path, allowed_origins=origins)
    (config.web_root / "app.js").unlink()
    gateway = bootstrap.Gateway(Runtime(config, core=CoreWithAuth()))
    gateway.core = gateway.runtime._core.core
    bootstrap._attach_adapters(gateway, config)
    assert gateway.capabilities()["adapters"]["reason"] == "WEB_ASSETS_MISSING" and _AdapterDouble.created == []

    core = CoreWithAuth()
    gateway = attach(core, allowed_origins=origins)
    assert gateway.capabilities()["adapters"]["available"] is True
    [adapter] = _AdapterDouble.created
    assert adapter.kwargs["core"] is core and adapter.kwargs["allowed_origins"] == origins
    assert adapter.kwargs["authenticate"] == core.authenticate and adapter.kwargs["verify_csrf"] == core.verify_csrf
    assert adapter.kwargs["session_info"] is None and adapter.kwargs["error_status"] is None  # absent hooks: D fails closed itself
    assert adapter.kwargs["model_client_factory"] is None  # D's chat stays deterministic until the model input is agreed
    for path in ("/ui", "/ui/app.js", "/ui/session", "/mcp", "/v1/chat"):
        assert call(gateway, path) == (200, {b"content-type": b"text/plain"}, path.encode()), path
    assert call(gateway, "/v1/scans")[0] == 503  # A's routes are not D's
    gateway.runtime.bind_core(None)  # the core goes away: D's routes go with it
    assert call(gateway, "/ui")[0] == 503


def test_unverified_sandbox_blocks_dispatch_even_with_every_other_component(tmp_path):
    """Core, model broker, roster and SLIM all present; isolation is not — so nothing runs."""
    config = RuntimeConfig(state_dir=tmp_path / "state", sandbox_backend="shadi", shadictl=None, model=MODEL,
                           extra_read_paths=(SANDBOX_WORKERS,), extra_python_path=(SANDBOX_WORKERS,))
    runtime = Runtime(config, roster=TEST_ROSTER, model_transport=FakeTransport(), core=FakeCore())
    try:
        capabilities = runtime.activate()
        assert capabilities["core"]["available"] and capabilities["model_broker"]["available"] and capabilities["slim"]["available"]
        assert capabilities["inspection"] == {"available": False, "reason": "isolation:SANDBOX_LAUNCHER_MISSING"}
        with pytest.raises(RuntimeUnavailable, match="SANDBOX_LAUNCHER_MISSING"):
            runtime.dispatch([make_assignment(runtime, "test.inspector.ok")])
        with pytest.raises(RuntimeUnavailable):
            runtime.extract(make_assignment(runtime, "test.extractor"))
        assert runtime._core.core.results == [] and runtime._grants.all() == []
    finally:
        runtime.shutdown()


def test_incomplete_core_port_disables_dependent_capabilities(bare):
    gateway, _ = bare

    class PartialCore:
        def accept_worker_result(self, identity, result): ...

    gateway.runtime.bind_core(PartialCore())
    core = gateway.capabilities()["core"]
    assert core["available"] is False and "record_collector_event" in core["reason"] and "accept_worker_result" not in core["reason"]
    assert gateway.capabilities()["collector"]["available"] is False


def test_uvicorn_is_the_pinned_root_server():
    import uvicorn
    assert uvicorn.__version__ == "0.53.0" and "uvicorn" in sys.modules
