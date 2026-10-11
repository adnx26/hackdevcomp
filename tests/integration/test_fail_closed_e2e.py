"""Fail-closed audit through the real local stack.

One inspector's model call is broken at a time (timeout, provider error,
non-JSON, truncated, refusal, wrong schema) while the other two answer
normally. Every case must end in REVIEW: never ALLOW, no read-only review
exception, no released result, and a visible reason code plus the failed
inspector's non-COMPLETE status in the public scan status the UI renders.
"""
import json
import os
import shutil
import socket
import threading
import time

import pytest
import uvicorn

from protection_gateway.bootstrap import build_gateway
from protection_gateway.runtime.config import REPO_ROOT, RuntimeConfig
from protection_gateway.runtime.model_broker import ModelConfig
from protection_gateway.runtime.runtime import Runtime

from test_gateway_e2e import DeterministicInference, smoke

FAILURE_REASONS = {"INSPECTION_ERROR", "INSPECTION_INCOMPLETE", "WORKER_MISSING", "TIMEOUT"}
ROLE_NAMES = {"instruction": "INSTRUCTION_INSPECTOR", "data": "DATA_TOOL_INSPECTOR", "behavior": "BEHAVIOR_TESTER"}


class FaultyInference(DeterministicInference):
    """Deterministic replies, except `fault` for every call made by `role`."""

    def __init__(self, role, fault):
        super().__init__()
        self.role, self.fault = role, fault

    def generate(self, config, *, system, user, max_output_tokens, timeout):
        request = json.loads(user)
        role = "behavior" if request["tools"] else ("instruction" if "instruction overrides" in system else "data")
        if role != self.role:
            return super().generate(config, system=system, user=user, max_output_tokens=max_output_tokens, timeout=timeout)
        self.calls.append(role)
        if self.fault == "timeout":
            time.sleep(timeout + 1.5)
            return {"stop_reason": "end_turn", "text": "{}", "usage": {}}
        if self.fault == "provider_error":
            raise ConnectionError("provider unreachable")
        reply = {
            "non_json": ("I found nothing suspicious.", "end_turn"),
            "truncated": ('{"checked_views": [', "max_tokens"),
            "refusal": ('{"checked_views": [], "findings": []}', "refusal"),
            "wrong_schema": (json.dumps({"verdict": "safe", "approved": True}), "end_turn"),
        }[self.fault]
        return {"stop_reason": reply[1], "text": reply[0], "usage": {"input_tokens": 1, "output_tokens": 1}}


@pytest.fixture
def gateway_with(request):
    started = []

    def start(inference, timeout_seconds=60.0):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        state = REPO_ROOT / "var" / "fail-closed-e2e" / f"{os.getpid()}-{port}"
        config = RuntimeConfig(state_dir=state, dev_mode=True, port=port,
                               model=ModelConfig(provider="kimi", model="kimi-k3", timeout_seconds=timeout_seconds))
        gateway = build_gateway(config, runtime=Runtime(config, model_transport=inference))
        if not gateway.capabilities()["isolation"]["available"]:
            gateway.close()
            if os.environ.get("PG_REQUIRE_ISOLATION") == "1":
                pytest.fail("Host sandbox verification is required")
            pytest.skip("Verified host sandbox required")
        server = uvicorn.Server(uvicorn.Config(gateway, host="127.0.0.1", port=port, log_level="error", access_log=False))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(.02)
        started.append((server, thread, gateway, state))
        return smoke.Client(f"http://127.0.0.1:{port}", config.login_token_file.read_text().strip())

    yield start
    for server, thread, gateway, state in started:
        server.should_exit = True
        thread.join(15)
        gateway.close()
        shutil.rmtree(state, ignore_errors=True)


@pytest.mark.isolation
@pytest.mark.parametrize("fault", ["timeout", "provider_error", "non_json", "truncated", "refusal", "wrong_schema"])
@pytest.mark.parametrize("role", ["instruction", "data", "behavior"])
def test_inspector_failure_is_review_never_allow(gateway_with, role, fault):
    if fault == "timeout" and role != "instruction":
        pytest.skip("one timeout case keeps the suite fast; the broker path is role-independent")
    client = gateway_with(FaultyInference(role, fault), timeout_seconds=1.0 if fault == "timeout" else 60.0)
    _, scan = client.start([client.upload(smoke.INVOICE)])
    status = client.wait(scan)

    assert status["state"] == "DECIDED" and status["decision"] == "REVIEW", status
    assert set(status["reason_codes"]) & FAILURE_REASONS, status["reason_codes"]
    assert status["review"]["eligible"] is False
    assert status["coverage"]["inspections"].get(ROLE_NAMES[role]) != "COMPLETE"
    assert ROLE_NAMES[role] not in status["completed_checks"]
    error = client.request(f"/v1/scans/{scan}/result", expected=428)
    assert error["code"] == "APPROVAL_REQUIRED"
    # An exception cannot be recorded for a failed inspection either.
    client.request(f"/v1/scans/{scan}/review", {"action": "ALLOW_READ_ONLY", "reason": "test", "result_digest": "a" * 64}, expected=403)


@pytest.mark.isolation
def test_control_without_faults_is_allowed(gateway_with):
    """Guards the audit itself: the same harness with no fault reaches ALLOW."""
    client = gateway_with(DeterministicInference())
    _, scan = client.start([client.upload(smoke.INVOICE)])
    status = client.wait(scan)
    assert status["decision"] == "ALLOW_UNDER_POLICY", status
    assert all(status["coverage"]["inspections"][name] == "COMPLETE" for name in ROLE_NAMES.values())
