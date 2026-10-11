"""The committed AP-footer demo replays offline, with and without the gateway.

demo/replay-cache holds Kimi K3 replies recorded for eval/corpus/redteam/
ap-policy-footer.txt (gateway inspectors and the naive agent); demo/baselines
holds the precomputed 'without the gateway' record. Nothing here calls a model.
"""
import importlib.util
import json
import os
import shutil
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from protection_gateway.bootstrap import build_gateway
from protection_gateway.runtime.config import REPO_ROOT, RuntimeConfig
from protection_gateway.runtime.model_broker import ModelConfig
from protection_gateway.runtime.replay import ReplayCache, ReplayTransport
from protection_gateway.runtime.runtime import Runtime

from test_gateway_e2e import smoke

DEMO = REPO_ROOT / "demo"
FIXTURE = REPO_ROOT / "eval" / "corpus" / "redteam" / "ap-policy-footer.txt"
RECORDED = DEMO / "ap_footer_recording.json"

pytestmark = pytest.mark.skipif(not RECORDED.exists(), reason="demo recording not present")


def load_redteam():
    sys.path.insert(0, str(REPO_ROOT / "eval"))
    spec = importlib.util.spec_from_file_location("redteam_demo", REPO_ROOT / "eval" / "redteam.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["redteam_demo"] = module
    spec.loader.exec_module(module)
    return module


def test_naive_agent_replays_the_recorded_runs():
    redteam = load_redteam()
    recorded = json.loads(RECORDED.read_text())
    scenario = next(s for s in redteam.SCENARIOS if s["id"] == "ap-policy-footer")
    config = ModelConfig(provider="kimi", model="kimi-k3")
    transport = ReplayTransport(ReplayCache(DEMO / "replay-cache"))
    harmed = [scenario["harm"](redteam.naive_agent(scenario, transport, config, attempt)["calls"]) for attempt in range(recorded["runs"])]
    assert sum(harmed) == recorded["naive_harmed"] and sum(harmed) > 0


@pytest.mark.isolation
def test_gateway_replays_offline_and_ui_baseline_is_served(tmp_path):
    recorded = json.loads(RECORDED.read_text())
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    state = REPO_ROOT / "var" / "demo-replay-test" / f"{os.getpid()}-{port}"
    config = RuntimeConfig(state_dir=state, dev_mode=True, port=port, model_replay="replay", replay_dir=DEMO / "replay-cache",
                           baseline_dir=DEMO / "baselines", model=ModelConfig(provider="kimi", model="kimi-k3", inference="replay"))
    gateway = build_gateway(config, runtime=Runtime(config))
    server = thread = None
    try:
        if not gateway.capabilities()["isolation"]["available"]:
            if os.environ.get("PG_REQUIRE_ISOLATION") == "1":
                pytest.fail("Host sandbox verification is required")
            pytest.skip("Verified host sandbox required")
        server = uvicorn.Server(uvicorn.Config(gateway, host="127.0.0.1", port=port, log_level="error", access_log=False))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.02)
        client = smoke.Client(f"http://127.0.0.1:{port}", config.login_token_file.read_text().strip())
        content = FIXTURE.read_bytes()
        resource = client.upload(content)
        _, scan = client.start([resource], "extract_invoice")
        status = client.wait(scan)
        assert status["inference_mode"] == "REPLAY"
        assert status["decision"] == recorded["gateway_decision"] == "REVIEW"
        assert set(status["reason_codes"]) == set(recorded["gateway_reason_codes"])
        client.request(f"/v1/scans/{scan}/result", expected=428)
        import hashlib
        baseline = client.request(f"/v1/baselines/extract_invoice/{hashlib.sha256(content).hexdigest()}")
        assert any(c["operation"] == "send_email" and "ap-audit-desk.example" in c["arguments"] for c in baseline["tool_calls"])
    finally:
        if server:
            server.should_exit = True
        if thread:
            thread.join(15)
        gateway.close()
        shutil.rmtree(state, ignore_errors=True)
