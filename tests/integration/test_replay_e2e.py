"""Replay mode through the real local stack (HTTP, core, sandboxed C workers, SLIM).

A run is recorded with deterministic inference, then replayed by a fresh gateway
with no provider transport at all: every resource/scan/run ID differs, the
decision and released values match, and status is labeled REPLAY. An empty cache
fails closed to REVIEW.
"""
import os
import shutil
import socket
import threading
import time
from contextlib import contextmanager

import pytest
import uvicorn

from protection_gateway.bootstrap import build_gateway
from protection_gateway.runtime.config import REPO_ROOT, RuntimeConfig
from protection_gateway.runtime.model_broker import ModelConfig
from protection_gateway.runtime.runtime import Runtime

from test_gateway_e2e import DeterministicInference, smoke


@contextmanager
def gateway(replay_mode, replay_dir, transport=None, baseline_dir=None):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    state = REPO_ROOT / "var" / "replay-e2e" / f"{os.getpid()}-{port}"
    inference = "replay" if replay_mode == "replay" else "live"
    config = RuntimeConfig(state_dir=state, dev_mode=True, port=port, model_replay=replay_mode, replay_dir=replay_dir,
                           baseline_dir=baseline_dir or replay_dir / "baselines",
                           model=ModelConfig(provider="kimi", model="kimi-k3", inference=inference))
    built = build_gateway(config, runtime=Runtime(config, model_transport=transport))
    server = thread = None
    try:
        if not built.capabilities()["isolation"]["available"]:
            if os.environ.get("PG_REQUIRE_ISOLATION") == "1":
                pytest.fail("Host sandbox verification is required")
            pytest.skip("Verified host sandbox required")
        assert built.capabilities()["complete_workflow"]["available"], built.capabilities()
        server = uvicorn.Server(uvicorn.Config(built, host="127.0.0.1", port=port, log_level="error", access_log=False))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(.02)
        assert server.started
        yield smoke.Client(f"http://127.0.0.1:{port}", config.login_token_file.read_text().strip())
    finally:
        if server:
            server.should_exit = True
        if thread:
            thread.join(15)
        built.close()
        shutil.rmtree(state, ignore_errors=True)


def run_invoice(client, content=smoke.INVOICE):
    resource = client.upload(content)
    _, scan = client.start([resource])
    status = client.wait(scan)
    result = client.request(f"/v1/scans/{scan}/result", expected=(200, 403, 428))
    return resource, scan, status, result


@pytest.mark.isolation
def test_record_then_replay_offline(tmp_path):
    recorder = DeterministicInference()
    with gateway("record", tmp_path, recorder) as client:
        live_resource, live_scan, live_status, live_result = run_invoice(client)
        _, _, attack_status, _ = run_invoice(client, smoke.ATTACK)
    assert live_status["decision"] == "ALLOW_UNDER_POLICY" and live_status["inference_mode"] == "LIVE"
    assert attack_status["decision"] == "REVIEW"
    assert len(list(tmp_path.glob("*.json"))) == len(recorder.calls)

    with gateway("replay", tmp_path) as client:
        resource, scan, status, result = run_invoice(client)
        _, _, replayed_attack, _ = run_invoice(client, smoke.ATTACK)
    assert resource != live_resource and scan != live_scan
    assert status["decision"] == "ALLOW_UNDER_POLICY" and status["inference_mode"] == "REPLAY"
    assert result["inference_mode"] == "REPLAY"
    values = lambda r: {k: v["value"] for k, v in r["result"]["output"]["fields"].items()}
    assert values(result) == values(live_result)
    assert all(ref["resource_id"] == resource for v in result["result"]["output"]["fields"].values() for ref in v["source_refs"])
    assert replayed_attack["decision"] == attack_status["decision"]
    assert {f["category"] for f in replayed_attack["findings"]} == {f["category"] for f in attack_status["findings"]}


@pytest.mark.isolation
def test_replay_cache_miss_fails_closed(tmp_path):
    with gateway("replay", tmp_path) as client:
        _, _, status, result = run_invoice(client)
    assert status["decision"] == "REVIEW" and status["inference_mode"] == "REPLAY"
    assert not status["review"]["eligible"]
    assert set(status["reason_codes"]) & {"INSPECTION_INCOMPLETE", "INSPECTION_ERROR", "WORKER_MISSING", "TIMEOUT"}
    assert result["code"] == "APPROVAL_REQUIRED"


@pytest.mark.isolation
def test_precomputed_baseline_served_over_http(tmp_path):
    import hashlib
    import json

    digest = hashlib.sha256(smoke.INVOICE).hexdigest()
    (tmp_path / "baselines" / "extract_invoice").mkdir(parents=True)
    (tmp_path / "baselines" / "extract_invoice" / f"{digest}.json").write_text(json.dumps({
        "original_hash": digest, "policy_id": "extract_invoice", "model": "kimi/kimi-k3", "inference": "live",
        "recorded_at": "t", "failed": False, "tool_calls": [{"operation": "make_payment", "arguments": {"payee": "x"}}], "answer": {"amount": "25.00"}}))
    with gateway("replay", tmp_path, baseline_dir=tmp_path / "baselines") as client:
        client.request(f"/v1/baselines/extract_invoice/{digest}", expected=404)  # not uploaded by this user yet
        client.upload(smoke.INVOICE)
        data = client.request(f"/v1/baselines/extract_invoice/{digest}")
    assert data["precomputed"] is True and data["tool_calls"][0]["operation"] == "make_payment"
