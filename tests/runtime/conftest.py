import hashlib
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from protection_gateway.runtime.config import REPO_ROOT, RuntimeConfig, find_shadictl
from protection_gateway.runtime.model_broker import ModelConfig
from protection_gateway.runtime.roster import (
    ROLE_BEHAVIOR_TESTER, ROLE_DATA_TOOL_INSPECTOR, ROLE_EXTRACTOR, ROLE_INSTRUCTION_INSPECTOR, WorkerRecord,
)
from protection_gateway.runtime.runtime import Runtime

SANDBOX_WORKERS = REPO_ROOT / "tests" / "runtime" / "sandbox_workers"
FAKE = "pg_fake_workers:"
TEST_ROSTER = (
    WorkerRecord("test.extractor", ROLE_EXTRACTOR, FAKE + "extract", "none", "b1"),
    WorkerRecord("test.inspector.ok", ROLE_INSTRUCTION_INSPECTOR, FAKE + "inspect_ok", "p1", "b1"),
    WorkerRecord("test.inspector.rogue", ROLE_DATA_TOOL_INSPECTOR, FAKE + "inspect_rogue", "p1", "b1"),
    WorkerRecord("test.inspector.crash", ROLE_DATA_TOOL_INSPECTOR, FAKE + "inspect_crash", "p1", "b1"),
    WorkerRecord("test.inspector.die", ROLE_DATA_TOOL_INSPECTOR, FAKE + "inspect_die", "p1", "b1"),
    WorkerRecord("test.inspector.hang", ROLE_INSTRUCTION_INSPECTOR, FAKE + "inspect_hang", "p1", "b1"),
    WorkerRecord("test.behavior", ROLE_BEHAVIOR_TESTER, FAKE + "behave_badly_then_look_clean", "p1", "b1"),
)
INPUT = b"Subject: invoice\n\nplease pay 10 EUR"
VIEW = "please pay 10 EUR"
MODEL_REPLY = {"checked_views": [{"resource_id": "res-1", "view_id": "res-1:0"}], "findings": []}


class FakeCore:
    """Test double for A's core port. Lives in tests only."""

    def __init__(self):
        self.results, self.events, self.artifacts, self.failures = [], [], [], []
        self.inputs = {("res-1", None): INPUT, ("res-1", "res-1:0"): VIEW.encode(), ("res-other", None): b"another tenant"}
        self.permitted_operations = {"read_email"}
        self.processor_permitted = True
        self.active = True
        self.accepted = threading.Event()

    def accept_worker_result(self, verified_identity, worker_result):
        self.results.append((verified_identity, worker_result))
        self.accepted.set()

    def record_collector_event(self, verified_collector_identity, event):
        self.events.append((verified_collector_identity, event))

    def read_assigned_input(self, verified_identity, assignment_id, resource_id, view_id):
        return self.inputs[(resource_id, view_id)]

    def store_worker_artifact(self, verified_identity, assignment_id, artifact):
        self.artifacts.append(artifact)
        return f"art_{len(self.artifacts)}"

    def check_simulated_operation(self, policy_binding, operation, arguments):
        return operation in self.permitted_operations

    def model_processing_permitted(self, binding, provider):
        return self.processor_permitted

    def assignment_active(self, assignment_id, attempt):
        return self.active

    def report_runtime_failure(self, assignment_id, attempt, reason_code):
        self.failures.append((assignment_id, attempt, reason_code))


class FakeTransport:
    """Deterministic model double: no network, no provider."""

    def __init__(self):
        self.calls, self.delay, self.usage = [], 0.0, {"input_tokens": 10, "output_tokens": 5}
        self.text, self.stop_reason = json.dumps(MODEL_REPLY), "end_turn"

    def generate(self, config, *, system, user, max_output_tokens, timeout):
        import time
        self.calls.append({"model": config.model, "system": system, "user": user, "max_output_tokens": max_output_tokens})
        time.sleep(self.delay)
        return {"stop_reason": self.stop_reason, "text": self.text, "usage": dict(self.usage)}


MODEL = ModelConfig(provider="anthropic", model="claude-opus-5-5", job_token_budget=1000, job_call_budget=3, timeout_seconds=5)


def deadline(seconds=30):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


_counter = iter(range(1, 10**6))


def make_assignment(runtime, identity, **overrides):
    record = next(r for r in runtime.roster.records() if r.worker_identity == identity)
    n = next(_counter)
    assignment = {
        "contract_version": "v1", "assignment_id": f"asg-{n}", "scan_id": f"scan-{n}", "attempt": 1,
        "worker_identity": record.worker_identity, "worker_role": record.role, "worker_build": record.build, "prompt_version": record.prompt_version,
        "task_session_id": "ts-1", "task_scope_version": 1, "policy_id": "summarize_email", "policy_version": "1", "policy_hash": "0" * 64,
        "resource_set_hash": "1" * 64, "context_hash": "2" * 64, "model_configuration_hash": MODEL.hash(),
        "resources": [{"resource_id": "res-1", "original_hash": hashlib.sha256(INPUT).hexdigest(), "media_type": "message/rfc822"}],
        "views": [{"resource_id": "res-1", "view_id": "res-1:0", "view_hash": hashlib.sha256(VIEW.encode()).hexdigest()}],
        "task_policy": {"policy_id": "summarize_email"}, "extraction_status": "COMPLETE", "run_id": f"run-{n}",
        "limits": {}, "deadline": deadline(),
    }
    assignment.update(overrides)
    return assignment


def _config(state_dir: Path) -> RuntimeConfig:
    return RuntimeConfig(state_dir=state_dir, shadictl=find_shadictl(), extra_read_paths=(SANDBOX_WORKERS,), extra_python_path=(SANDBOX_WORKERS,), model=MODEL)


@pytest.fixture(scope="session")
def state_root():
    # Under the repository, not the system temp directory (which the sandbox denies to workers).
    root = REPO_ROOT / "var" / "test-runtime" / str(os.getpid())
    root.mkdir(parents=True, exist_ok=True)
    yield root
    import shutil
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture(scope="session")
def live_runtime(state_root):
    """A really activated runtime: verified sandbox, SLIM node, loopback services."""
    transport = FakeTransport()
    runtime = Runtime(_config(state_root / "live"), roster=TEST_ROSTER, model_transport=transport, core=FakeCore())
    capabilities = runtime.activate()
    runtime.test_transport = transport
    if not capabilities["isolation"]["available"]:
        runtime.shutdown()
        message = "sandbox not verified on this host: " + capabilities["isolation"]["reason"]
        if os.environ.get("PG_REQUIRE_ISOLATION") == "1":
            pytest.fail(message)
        pytest.skip(message)
    yield runtime
    runtime.shutdown()


@pytest.fixture
def runtime(live_runtime):
    core = FakeCore()
    live_runtime.bind_core(core)
    live_runtime.test_transport.calls.clear()
    live_runtime.core = core
    return live_runtime
