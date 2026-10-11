"""Demo preflight: one PASS/FAIL line per check, non-zero exit if any check fails.

    make doctor                # all checks, including one tiny live provider call
    make doctor ARGS=--offline # skip the provider call (no network, no API spend)

Secrets are never printed: the API key is reported only as set or missing.
"""

from __future__ import annotations

import argparse
import datetime
import json
import socket
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

KEY_NAME = "KIMI_API_KEY"
PLACEHOLDER = "replace-with-your-key"


@dataclass
class Result:
    name: str
    ok: bool
    detail: str
    skipped: bool = False

    def line(self) -> str:
        label = "SKIP" if self.skipped else ("PASS" if self.ok else "FAIL")
        return f"{label:<5} {self.name:<22} {self.detail}"


def check_python() -> Result:
    version = sys.version_info
    ok = version >= (3, 11)
    detail = f"{version.major}.{version.minor}.{version.micro}" + ("" if ok else " (3.11 or later required; run make setup)")
    return Result("python", ok, detail)


def check_api_key(env: Mapping[str, str]) -> Result:
    value = env.get(KEY_NAME, "")
    if not value:
        return Result("kimi api key", False, f"{KEY_NAME} is not set (add it to .env; see deploy/local.env.example)")
    if value.strip() == PLACEHOLDER:
        return Result("kimi api key", False, f"{KEY_NAME} still has the example placeholder value")
    if value != value.strip() or any(c in value for c in "\r\n \t"):
        return Result("kimi api key", False, f"{KEY_NAME} contains whitespace")
    return Result("kimi api key", True, f"{KEY_NAME} is set (value hidden)")


def check_port(port: int, host: str = "127.0.0.1") -> Result:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, port))
        except OSError:
            return Result(f"port {port}", False, f"{host}:{port} is in use (stop the other gateway or use PORT=...)")
    return Result(f"port {port}", True, f"{host}:{port} is free")


def check_slim(timeout: float = 10.0) -> Result:
    """Start a throwaway loopback SLIM node and do a real point-to-point round trip."""
    try:
        import slim_bindings as slim
        from protection_gateway.runtime.errors import RuntimeUnavailable
        from protection_gateway.runtime.slim_transport import SlimNode, initialize
    except ImportError as error:
        return Result("slim", False, f"cannot import SLIM bindings ({type(error).__name__}); run make setup")
    try:
        node = SlimNode()
    except RuntimeUnavailable as error:
        return Result("slim", False, f"node failed to start ({error.reason_code})")
    echoed: dict = {}
    peer_name = ("protection-gateway", "doctor", "peer")
    ready = threading.Event()

    def peer() -> None:
        try:
            initialize(slim)
            service = slim.get_global_service()
            connection = service.connect(slim.new_insecure_client_config(f"http://127.0.0.1:{node.port}"))
            app = service.create_app_with_secret(slim.Name(*peer_name), node.mesh_secret)
            app.subscribe(app.name(), connection)
            ready.set()
            session = app.listen_for_session(datetime.timedelta(seconds=timeout))
            message = session.get_message(datetime.timedelta(seconds=timeout))
            session.publish_to_and_wait(message.context, b"pong:" + message.payload, None, None)
        except Exception as error:  # reported below; never contains secrets
            echoed["error"] = type(error).__name__
            ready.set()

    thread = threading.Thread(target=peer, daemon=True)
    thread.start()
    try:
        if not ready.wait(timeout) or "error" in echoed:
            return Result("slim", False, f"peer could not join the node ({echoed.get('error', 'timeout')})")
        session = node.deliver(peer_name, b"ping", timeout)
        reply = node.receive(session, timeout)
        node.close_session(session)
    except Exception as error:
        return Result("slim", False, f"round trip failed ({type(error).__name__})")
    finally:
        node.close()
    if reply != b"pong:ping":
        return Result("slim", False, "round trip returned no reply")
    return Result("slim", True, f"loopback node on port {node.port}: point-to-point round trip OK")


def check_tls(host: str = "api.moonshot.ai", timeout: float = 10.0) -> Result:
    """Can this Python verify HTTPS certificates? python.org macOS builds ship
    without a CA bundle until 'Install Certificates.command' is run."""
    import ssl

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw, context.wrap_socket(raw, server_hostname=host):
            pass
    except ssl.SSLCertVerificationError:
        fix = f"run '/Applications/Python {sys.version_info.major}.{sys.version_info.minor}/Install Certificates.command'"
        if sys.platform == "darwin" and Path("/etc/ssl/cert.pem").exists():
            fix += " or prefix commands with SSL_CERT_FILE=/etc/ssl/cert.pem"
        return Result("tls trust", False, f"Python cannot verify HTTPS certificates ({fix})")
    except OSError as error:
        return Result("tls trust", False, f"cannot reach {host}:443 ({type(error).__name__})")
    return Result("tls trust", True, f"verified HTTPS certificate for {host}")


def check_sandbox() -> Result:
    from protection_gateway.runtime.config import find_shadictl
    from protection_gateway.runtime.isolation import BACKEND_SEATBELT, default_backend

    backend = default_backend()
    if backend == BACKEND_SEATBELT:
        ok = Path("/usr/bin/sandbox-exec").exists()
        return Result("sandbox", ok, "macOS Seatbelt available" if ok else "sandbox-exec not found")
    shadictl = find_shadictl()
    return Result("sandbox", bool(shadictl), f"shadictl at {shadictl}" if shadictl else "shadictl not found (see deploy/README.md)")


def check_model_broker(env: Mapping[str, str], transport_factory: Callable | None = None) -> Result:
    """Validate the approved model configuration, then make one tiny call through the
    broker's pinned provider transport. The prompt contains no document content."""
    from protection_gateway.runtime.config import RuntimeConfig
    from protection_gateway.runtime.errors import RuntimeUnavailable

    try:
        config = RuntimeConfig.from_env(env).model
    except (RuntimeUnavailable, ValueError) as error:
        return Result("model broker", False, f"model configuration rejected ({getattr(error, 'reason_code', type(error).__name__)})")
    if config is None:
        return Result("model broker", False, f"no model configured (set {KEY_NAME} or PG_MODEL_PROVIDER)")
    try:
        if transport_factory is None:
            from protection_gateway.runtime.providers import KimiTransport

            if config.provider != "kimi":
                return Result("model broker", False, f"doctor only probes the kimi provider (configured: {config.provider})", skipped=True)
            transport = KimiTransport(config, api_key=env.get(KEY_NAME))
        else:
            transport = transport_factory(config)
        response = transport.generate(
            config, system='Health check. Reply with exactly {"ok": true}.', user="{}",
            max_output_tokens=1024, timeout=min(30.0, config.timeout_seconds),
        )
    except RuntimeUnavailable as error:
        return Result("model broker", False, f"{config.provider}/{config.model}: {error.reason_code}")
    except Exception as error:
        return Result("model broker", False, f"{config.provider}/{config.model}: {type(error).__name__}")
    if response.get("stop_reason") != "end_turn":
        return Result("model broker", False, f"{config.provider}/{config.model}: incomplete reply ({response.get('stop_reason')})")
    try:
        parsed = json.loads(response.get("text") or "")
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        return Result("model broker", False, f"{config.provider}/{config.model}: reply was not a JSON object")
    return Result("model broker", True, f"{config.provider}/{config.model} at pinned endpoint responded")


def check_replay_cache(env: Mapping[str, str]) -> Result:
    from protection_gateway.runtime.config import RuntimeConfig
    from protection_gateway.runtime.replay import ReplayCache

    directory = RuntimeConfig.from_env(env).replay_dir
    entries = len(ReplayCache(directory))
    if not entries:
        return Result("replay cache", False, f"no recorded responses in {directory} (record first with make run REPLAY=record)")
    return Result("replay cache", True, f"{entries} recorded responses in {directory}; cache misses hold content for REVIEW")


def run(env: Mapping[str, str], *, port: int, offline: bool, transport_factory: Callable | None = None) -> list[Result]:
    if env.get("PG_MODEL_REPLAY") == "replay":
        # Offline demo: no provider key or call is needed; the recorded cache is.
        return [check_python(), Result("kimi api key", True, "not needed in replay mode", skipped=True), check_port(port),
                check_sandbox(), check_slim(), check_replay_cache(env)]
    results = [check_python(), check_api_key(env), check_port(port), check_sandbox(), check_slim()]
    if offline:
        results.append(Result("model broker", True, "skipped (--offline)", skipped=True))
    elif not results[1].ok and transport_factory is None:
        results.append(Result("model broker", False, "skipped: API key check failed"))
    else:
        if transport_factory is None:
            results.append(check_tls())
            if not results[-1].ok:
                results.append(Result("model broker", False, "skipped: fix TLS trust first"))
                return results
        results.append(check_model_broker(env, transport_factory))
    return results


def main(argv: list[str] | None = None) -> int:
    from protection_gateway.runtime.config import local_environment

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=None, help="gateway port to check (default: PG_PORT or 8766)")
    parser.add_argument("--offline", action="store_true", help="skip the live provider call")
    args = parser.parse_args(argv)
    try:
        env = local_environment()
    except ValueError:
        print("FAIL  .env                   could not be parsed (use simple KEY=value lines)")
        return 1
    port = args.port or int(env.get("PG_PORT", "8766"))
    results = run(env, port=port, offline=args.offline)
    for result in results:
        print(result.line())
    failed = [r for r in results if not r.ok and not r.skipped]
    skipped = [r for r in results if r.skipped]
    passed = len(results) - len(failed) - len(skipped)
    summary = f"\n{passed} passed, {len(failed)} failed, {len(skipped)} skipped"
    print(summary + (" — fix the FAIL lines before the demo" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
