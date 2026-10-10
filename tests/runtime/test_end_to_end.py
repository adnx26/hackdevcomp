"""Real sandbox + real SLIM node + fixed-roster workers. Host-specific: see deploy/README.md."""

import os
import time

import pytest

from protection_gateway.runtime import capabilities as caps
from protection_gateway.runtime.envelope import KIND_WORKER_RESULT, seal
from protection_gateway.runtime.errors import Rejected

from .conftest import deadline, make_assignment

pytestmark = pytest.mark.isolation


def wait_for(predicate, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def finished(runtime, assignment):
    return lambda: any(op.get("event") == "WORKER_FINISHED" and op["assignment_id"] == assignment["assignment_id"] for op in runtime.operations)


def outcome(runtime, assignment):
    return next(op["outcome"] for op in runtime.operations if op.get("event") == "WORKER_FINISHED" and op["assignment_id"] == assignment["assignment_id"])


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def test_fixed_roster_slim_round_trip(runtime):
    assignment = make_assignment(runtime, "test.inspector.ok")
    [receipt] = runtime.dispatch([assignment])
    assert receipt["status"] == "DELIVERED"  # delivery, not completion
    assert wait_for(finished(runtime, assignment))
    [(identity, result)] = runtime.core.results
    assert (identity.worker_identity, identity.role, identity.assignment_id, identity.attempt) == ("test.inspector.ok", "instruction_inspector", assignment["assignment_id"], 1)
    assert result["inspection_status"] == "COMPLETE" and result["bytes_read"] > 0 and result["model_stop_reason"] == "end_turn"
    # An inspector without the simulated-tool capability cannot attempt tools, and nothing was recorded.
    assert result["tools"].startswith("DENIED") and runtime.core.events == []
    assert runtime.test_transport.calls == [{"model": "claude-opus-5-5", "tools": [], "max_output_tokens": 1000}]  # capped to the job token budget
    assert outcome(runtime, assignment) == "ACCEPTED"
    assert not (runtime.config.state_dir / "scratch").exists() or not any((runtime.config.state_dir / "scratch").iterdir())
    assert runtime._grants.all() == []


def test_worker_cannot_reach_credentials_other_jobs_or_network(runtime, state_root, monkeypatch):
    secret = state_root / "provider.key"
    secret.write_text("sk-test-not-a-real-key")
    other = state_root / "other-job.txt"
    other.write_text("other job")
    outside = state_root / "escape.txt"
    import socket
    listener = socket.create_server(("127.0.0.1", 0))  # a local service this worker was not granted
    assignment = make_assignment(runtime, "test.inspector.rogue", limits={
        "credential_file": str(secret), "other_job_file": str(other), "outside_file": str(outside), "closed_to_worker_port": listener.getsockname()[1]})
    monkeypatch.setenv("PG_TEST_SECRET", "gateway-only")
    try:
        assert runtime.dispatch([assignment])[0]["status"] == "DELIVERED"
        assert wait_for(finished(runtime, assignment))
    finally:
        listener.close()
    [(_, result)] = runtime.core.results
    for scope in ("self", "child"):
        assert result[scope], scope
        assert all(value.startswith("DENIED") for value in result[scope].values()), (scope, result[scope])
    assert result["curl"].startswith("DENIED") and result["bad_endpoint"] == "DENIED CallbackError"
    assert not outside.exists() and runtime.test_transport.calls == []


def test_behavior_evidence_survives_a_harmless_final_answer(runtime):
    assignment = make_assignment(runtime, "test.behavior")
    assert runtime.dispatch([assignment])[0]["status"] == "DELIVERED"
    assert wait_for(finished(runtime, assignment))
    [(_, result)] = runtime.core.results
    assert result["final_text"] == "Here is a harmless summary."
    assert result["outcomes"] == ["DENIED", "EXECUTED_DUMMY", "DENIED"]
    events = [event for _, event in runtime.core.events]
    assert [(e["sequence"], e["operation"], e["attempted_outcome"], e["policy_check"]) for e in events] == [
        (1, "send_email", "DENIED", "FORBIDDEN"),
        (2, "read_email", "PROPOSED", "PERMITTED"),
        (3, "read_email", "EXECUTED_DUMMY", "PERMITTED"),
        (4, "UNKNOWN_OPERATION", "DENIED", "FORBIDDEN"),
    ]
    assert all(e["scan_id"] == assignment["scan_id"] and runtime.collector.verify(e) for e in events)
    assert all(identity == runtime.collector.identity for identity, _ in runtime.core.events)
    assert "secret" not in str(events) and "attacker@example.com" not in str(events)  # digests only


def test_extractor_gets_no_model_tools_or_slim(runtime):
    ports = [runtime._broker_service.port, runtime.slim.port]
    assignment = make_assignment(runtime, "test.extractor", limits={"probe_ports": ports})
    result = runtime.extract(assignment)
    assert result["status"] == "COMPLETE" and result["views"] == ["art_view-0.txt"]
    assert runtime.core.artifacts["view-0.txt"].startswith(b"SUBJECT")
    assert result["unassigned_read"] == "DENIED CallbackError"
    assert all(probe.startswith("DENIED") for probe in result["port_probes"]) and len(result["port_probes"]) == 2
    assert runtime.core.results == []  # extraction results return to A directly, not as findings


def test_crash_and_exit_never_produce_a_result(runtime):
    crash = make_assignment(runtime, "test.inspector.crash")
    die = make_assignment(runtime, "test.inspector.die")
    assert [r["status"] for r in runtime.dispatch([crash, die])] == ["DELIVERED", "DELIVERED"]
    assert wait_for(lambda: finished(runtime, crash)() and finished(runtime, die)())
    assert runtime.core.results == []
    assert outcome(runtime, crash) == "WORKER_FAILURE" and outcome(runtime, die) == "WORKER_EXITED"
    assert sorted(code for _, _, code in runtime.core.failures) == ["WORKER_EXITED", "WORKER_FAILURE"]
    assert runtime._grants.all() == []


def test_cancel_kills_the_process_group_and_revokes_capabilities(runtime):
    assignment = make_assignment(runtime, "test.inspector.hang")
    assert runtime.dispatch([assignment])[0]["status"] == "DELIVERED"
    [grant] = runtime._grants.for_scan(assignment["scan_id"])
    pid_file = runtime.config.state_dir / "scratch" / grant.grant_id / "pids"
    assert wait_for(pid_file.exists) and wait_for(lambda: len(pid_file.read_text().split()) == 2)
    worker_pid, child_pid = map(int, pid_file.read_text().split())
    assert alive(worker_pid) and alive(child_pid)
    token = grant.tokens[caps.KIND_RESOURCE]
    late = seal(grant.message_key, kind=KIND_WORKER_RESULT, sender={"worker_identity": "test.inspector.hang", "role": "instruction_inspector"},
                assignment_id=grant.assignment_id, scan_id=grant.scan_id, attempt=1, body={"inspection_status": "COMPLETE"})
    runtime.cancel(assignment["scan_id"])
    assert wait_for(lambda: not alive(worker_pid) and not alive(child_pid), timeout=5)
    assert not pid_file.parent.exists()
    with pytest.raises(Rejected):
        runtime._grants.authenticate(token, caps.KIND_RESOURCE)
    # A correctly signed result arriving after cancellation is refused and never reaches A.
    assert runtime._on_worker_message(grant, late) == "CAPABILITY_REVOKED"
    assert runtime.core.results == []
    # The canceled scan cannot be dispatched again by this runtime.
    assert runtime.dispatch([make_assignment(runtime, "test.inspector.ok", scan_id=assignment["scan_id"])])[0]["reason_code"] == "SCAN_CANCELED"


def test_deadline_expiry_cleans_up_without_a_result(runtime):
    assignment = make_assignment(runtime, "test.inspector.hang", deadline=deadline(4))
    assert runtime.dispatch([assignment])[0]["status"] == "DELIVERED"
    assert wait_for(finished(runtime, assignment), timeout=15)
    assert outcome(runtime, assignment) == "TIMEOUT" and runtime.core.results == [] and runtime._grants.all() == []


def test_dispatch_rejects_anything_outside_the_roster(runtime):
    good = make_assignment(runtime, "test.inspector.ok")
    cases = {
        "WORKER_NOT_IN_ROSTER": dict(worker_identity="downloaded.plugin"),
        "WORKER_ROLE_MISMATCH": dict(worker_role="behavior_tester"),
        "WORKER_BUILD_MISMATCH": dict(worker_build="f" * 64),
        "PROMPT_VERSION_MISMATCH": dict(prompt_version="p2"),
        "MODEL_CONFIGURATION_MISMATCH": dict(model_configuration_hash="0" * 64),
        "ASSIGNMENT_EXPIRED": dict(deadline=deadline(-5)),
    }
    receipts = runtime.dispatch([{**good, **change} for change in cases.values()])
    assert [(r["status"], r["reason_code"]) for r in receipts] == [("REJECTED", code) for code in cases]
    # The extractor is not an inspector, and an inspector is not an extractor.
    assert runtime.dispatch([make_assignment(runtime, "test.extractor")])[0]["reason_code"] == "WORKER_ROLE_MISMATCH"
    with pytest.raises(Rejected):
        runtime.extract(good)
    runtime.core.active = False
    assert runtime.dispatch([make_assignment(runtime, "test.inspector.ok")])[0]["reason_code"] == "LEASE_NOT_ACTIVE"
    assert runtime.core.results == [] and runtime._grants.all() == []


def test_mesh_membership_alone_cannot_submit_a_result(runtime):
    """A process holding the mesh secret, but no assignment key, gets nothing accepted."""
    import datetime
    import slim_bindings as slim

    victim = make_assignment(runtime, "test.inspector.hang")
    assert runtime.dispatch([victim])[0]["status"] == "DELIVERED"
    [grant] = runtime._grants.for_scan(victim["scan_id"])
    service = slim.create_service("intruder")
    connection = service.connect(slim.new_insecure_client_config(f"http://127.0.0.1:{runtime.slim.port}"))
    intruder = service.create_app_with_secret(slim.Name("protection-gateway", "behavior_tester", "intruder"), runtime.slim.mesh_secret)
    intruder.subscribe(intruder.name(), connection)
    forged = seal(b"k" * 32, kind=KIND_WORKER_RESULT, sender={"worker_identity": "test.inspector.hang", "role": "instruction_inspector"},
                  assignment_id=grant.assignment_id, scan_id=grant.scan_id, attempt=1, body={"inspection_status": "COMPLETE", "findings": []})
    try:
        gateway = slim.Name(*runtime.slim.gateway_name)
        intruder.set_route(gateway, connection)
        config = slim.SessionConfig(session_type=slim.SessionType.POINT_TO_POINT, max_retries=1, interval=datetime.timedelta(milliseconds=300), metadata={}, mls_settings=None)
        session = intruder.create_session_and_wait(config, gateway)
        session.publish_and_wait(forged, None, None)
    except slim.SlimError:
        pass  # not even deliverable: equally not accepted
    time.sleep(1.0)
    # The same forgery pushed straight into the victim's own session handler fails authentication.
    assert runtime._on_worker_message(grant, forged) == "SENDER_NOT_AUTHENTICATED"
    assert runtime.core.results == [] and not grant.result_ready.is_set()
    runtime.cancel(victim["scan_id"])
    service.shutdown()
