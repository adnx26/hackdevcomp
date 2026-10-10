"""Composition fails closed: missing components disable routes, they never fake success."""

import io
import json

import pytest

from protection_gateway.bootstrap import COMPLETE_WORKFLOW, build_gateway, make_gateway_server
from protection_gateway.runtime.config import RuntimeConfig
from protection_gateway.runtime.errors import RuntimeUnavailable
from protection_gateway.runtime.runtime import Runtime

from .conftest import MODEL, TEST_ROSTER, FakeCore, FakeTransport, make_assignment


def call(app, path, method="GET"):
    captured = {}
    environ = {"PATH_INFO": path, "REQUEST_METHOD": method, "wsgi.input": io.BytesIO()}
    body = b"".join(app(environ, lambda status, headers: captured.update(status=status, headers=dict(headers))))
    return captured["status"], captured["headers"], body


def ok_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


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
    assert capabilities["complete_workflow"]["available"] is False and "isolation" in capabilities["complete_workflow"]["reason"]


def test_runtime_calls_raise_service_unavailable_without_launching_anything(bare):
    gateway, config = bare
    for call_ in (lambda: gateway.runtime.extract({}), lambda: gateway.runtime.dispatch([{}]), gateway.runtime.model_configuration,
                  lambda: gateway.runtime.assistant_model_client("ts", binding={})):
        with pytest.raises(RuntimeUnavailable) as error:
            call_()
        assert error.value.code == "SERVICE_UNAVAILABLE"
    assert not (config.state_dir / "scratch").exists()


def test_contract_routes_answer_503_and_unknown_paths_404(bare):
    gateway, _ = bare
    for path in ("/v1/scans", "/v1/chat", "/mcp", "/ui", "/ui/index.html"):
        status, headers, body = call(gateway, path)
        error = json.loads(body)
        assert status.startswith("503") and error["error"]["code"] == "SERVICE_UNAVAILABLE" and error["contract_version"] == "v1", path
        assert set(error["error"]) == {"code", "retryable", "request_id"}
    assert call(gateway, "/healthz")[0].startswith("404") and call(gateway, "/")[0].startswith("404")


def test_mounted_route_stays_disabled_until_its_capabilities_exist(bare):
    gateway, _ = bare
    gateway.mount("/v1/scans", ok_app, requires=("core", "inspection"))
    assert call(gateway, "/v1/scans/abc")[0].startswith("503")
    gateway.runtime.bind_core(FakeCore())  # a core alone is still not enough
    assert call(gateway, "/v1/scans/abc")[0].startswith("503")
    gateway.mount("/v1/resources", ok_app, requires=("core",))
    assert call(gateway, "/v1/resources") == ("200 OK", {"Content-Type": "text/plain"}, b"ok")
    assert call(gateway, "/v1/resourcesX")[0].startswith("503")  # prefix match is on path segments
    for bad in (dict(prefix="/v1/x", requires=()), dict(prefix="/admin", requires=("core",)), dict(prefix="/v1/resources", requires=("core",))):
        with pytest.raises(ValueError):
            gateway.mount(bad["prefix"], ok_app, requires=bad["requires"])


def test_static_ui_needs_assets_and_core_and_cannot_escape_its_root(bare, tmp_path):
    gateway, config = bare
    config.web_root.mkdir()
    (config.web_root / "index.html").write_text("<h1>ui</h1>")
    (tmp_path / "secret.txt").write_text("outside web root")
    assert call(gateway, "/ui")[0].startswith("503")  # assets exist but there is no core behind them
    gateway.runtime.bind_core(FakeCore())
    status, headers, body = call(gateway, "/ui")
    assert status == "200 OK" and body == b"<h1>ui</h1>" and headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    for escape in ("/ui/../secret.txt", "/ui/%2e%2e/secret.txt", "/ui//etc/passwd", "/ui/missing.js"):
        assert call(gateway, escape)[0].startswith("404"), escape
    assert call(gateway, "/ui/index.html", method="POST")[0].startswith("405")


def test_non_loopback_listener_requires_tls(bare):
    gateway, config = bare
    config.host, config.port = "0.0.0.0", 0
    with pytest.raises(SystemExit, match="refusing to listen"):
        make_gateway_server(gateway, config)
    config.host = "127.0.0.1"
    make_gateway_server(gateway, config).server_close()


def test_unverified_sandbox_blocks_dispatch_even_with_every_other_component(tmp_path):
    """Core, model broker, roster and SLIM all present; isolation is not — so nothing runs."""
    from .conftest import SANDBOX_WORKERS
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
