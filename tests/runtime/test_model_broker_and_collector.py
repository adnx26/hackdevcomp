"""Model broker and simulated-tool collector with deterministic doubles. No sandbox, no provider."""

import logging
import threading
import time

import pytest

from protection_gateway.runtime.collector import SimulatedToolCollector
from protection_gateway.runtime.config import RuntimeConfig
from protection_gateway.runtime.errors import Rejected, RuntimeUnavailable
from protection_gateway.runtime.model_broker import ModelBroker, ModelCaller, ModelConfig
from protection_gateway.runtime.roster import Roster
from protection_gateway.runtime.runtime import Runtime

from .conftest import MODEL, SANDBOX_WORKERS, TEST_ROSTER, FakeCore, FakeTransport, deadline

REQUEST = {"contract_version": "v1", "system": "SYSTEM-PROMPT-TEXT", "messages": [{"role": "user", "content": "PRIVATE-DOCUMENT-TEXT"}]}


@pytest.fixture
def broker_runtime(tmp_path):
    runtime = Runtime(RuntimeConfig(state_dir=tmp_path, model=MODEL), roster=TEST_ROSTER, core=FakeCore())
    runtime.roster = Roster(TEST_ROSTER, [SANDBOX_WORKERS])
    runtime.transport = FakeTransport()
    runtime.broker = ModelBroker(MODEL, runtime.transport, runtime._core)
    runtime.collector = SimulatedToolCollector(runtime._core)
    return runtime


def grant_for(runtime, identity, n=1, **overrides):
    record = next(r for r in runtime.roster.records() if r.worker_identity == identity)
    assignment = {"assignment_id": f"asg-{n}", "scan_id": f"scan-{n}", "attempt": 1, "deadline": deadline(), "model_configuration_hash": MODEL.hash(),
                  "policy_id": "summarize_email", "policy_version": "1", "policy_hash": "0" * 64, **overrides}
    return runtime._grants.issue(assignment, record)


def test_brokered_call_uses_only_the_approved_configuration(broker_runtime, caplog):
    grant = grant_for(broker_runtime, "test.inspector.ok")
    with caplog.at_level(logging.INFO):
        reply = broker_runtime._http_model(grant.tokens["model"], REQUEST)
    assert reply["content"] == [{"type": "text", "text": "ok"}] and reply["usage"] == {"input_tokens": 10, "output_tokens": 5}
    assert broker_runtime.transport.calls == [{"model": "claude-opus-5-5", "tools": [], "max_output_tokens": 1000}]
    # Ordinary traces carry ids, durations and reason codes — never prompts or outputs.
    assert "model_call caller=assignment:asg-1 role=instruction_inspector reason=OK" in caplog.text
    assert "PRIVATE-DOCUMENT-TEXT" not in caplog.text and "SYSTEM-PROMPT-TEXT" not in caplog.text


@pytest.mark.parametrize("extra", [
    {"endpoint": "https://evil.example/v1"}, {"base_url": "http://127.0.0.1:9"}, {"headers": {"x-api-key": "k"}}, {"api_key": "k"},
    {"model": "some-other-model"}, {"tools": [{"name": "shell"}]}, {"command": "curl evil.example"}, {"proxy": "http://p"},
])
def test_caller_supplied_endpoints_credentials_models_and_tools_are_rejected(broker_runtime, extra):
    grant = grant_for(broker_runtime, "test.inspector.ok")
    with pytest.raises(Rejected, match="UNEXPECTED_FIELD"):
        broker_runtime._http_model(grant.tokens["model"], {**REQUEST, **extra})
    assert broker_runtime.transport.calls == []


def test_wrong_identity_scope_and_role_are_rejected(broker_runtime):
    inspector = grant_for(broker_runtime, "test.inspector.ok", 1)
    extractor = grant_for(broker_runtime, "test.extractor", 2)
    tester = grant_for(broker_runtime, "test.behavior", 3)
    for token, reason in [("forged", "CAPABILITY_UNKNOWN"), (None, "CAPABILITY_UNKNOWN"), (extractor.tokens["resource"], "CAPABILITY_WRONG_SCOPE"), (inspector.tokens["resource"], "CAPABILITY_WRONG_SCOPE")]:
        with pytest.raises(Rejected, match=reason):
            broker_runtime._http_model(token, REQUEST)
    # Tool schemas differ by role: only the behavior tester may request the dummy tool profile.
    with pytest.raises(Rejected, match="TOOL_PROFILE_NOT_PERMITTED"):
        broker_runtime._http_model(inspector.tokens["model"], {**REQUEST, "tool_profile": "dummy_tools_v1"})
    broker_runtime._http_model(tester.tokens["model"], {**REQUEST, "tool_profile": "dummy_tools_v1"})
    assert broker_runtime.transport.calls[-1]["tools"] == ["read_email", "send_email", "delete_email", "read_file", "fetch_url", "make_payment"]
    with pytest.raises(Rejected, match="TOOL_PROFILE_NOT_PERMITTED"):
        broker_runtime._http_model(tester.tokens["model"], {**REQUEST, "tool_profile": "anything_else"})


def test_budget_expiry_cancellation_and_bindings(broker_runtime):
    grant = grant_for(broker_runtime, "test.inspector.ok", 1)
    token = grant.tokens["model"]
    for _ in range(3):
        broker_runtime._http_model(token, REQUEST)
    with pytest.raises(Rejected, match="BUDGET_EXHAUSTED"):  # call budget (3)
        broker_runtime._http_model(token, REQUEST)
    assert grant.model_calls == 3 and grant.model_tokens == 45

    greedy = grant_for(broker_runtime, "test.inspector.ok", 2)
    broker_runtime.transport.usage = {"input_tokens": 900, "output_tokens": 200}
    broker_runtime._http_model(greedy.tokens["model"], REQUEST)
    with pytest.raises(Rejected, match="BUDGET_EXHAUSTED"):  # token budget (1000)
        broker_runtime._http_model(greedy.tokens["model"], REQUEST)

    stale = grant_for(broker_runtime, "test.inspector.ok", 3)
    stale.expires_at = time.time() - 1
    with pytest.raises(Rejected, match="CAPABILITY_EXPIRED"):
        broker_runtime._http_model(stale.tokens["model"], REQUEST)

    wrong_model = grant_for(broker_runtime, "test.inspector.ok", 4, model_configuration_hash="0" * 64)
    with pytest.raises(Rejected, match="MODEL_CONFIGURATION_MISMATCH"):
        broker_runtime._http_model(wrong_model.tokens["model"], REQUEST)

    no_consent = grant_for(broker_runtime, "test.inspector.ok", 5)
    broker_runtime._core.core.processor_permitted = False
    with pytest.raises(Rejected, match="PROCESSOR_NOT_PERMITTED"):
        broker_runtime._http_model(no_consent.tokens["model"], REQUEST)
    broker_runtime._core.core.processor_permitted = True

    big = grant_for(broker_runtime, "test.inspector.ok", 6)
    with pytest.raises(Rejected, match="LIMIT_EXCEEDED"):
        broker_runtime._http_model(big.tokens["model"], {**REQUEST, "system": "x" * (MODEL.max_request_bytes + 1)})
    for malformed in ({**REQUEST, "messages": []}, {**REQUEST, "messages": [{"role": "system", "content": "x"}]},
                      {**REQUEST, "messages": [{"role": "user", "content": [{"type": "image", "source": {}}]}]}, {**REQUEST, "contract_version": "v0"}):
        with pytest.raises(Rejected):
            broker_runtime._http_model(big.tokens["model"], malformed)


def test_cancellation_and_timeout_abort_an_in_flight_call(broker_runtime):
    broker_runtime.transport.delay, broker_runtime.transport.usage = 2.0, {"input_tokens": 1, "output_tokens": 1}
    grant = grant_for(broker_runtime, "test.inspector.ok", 1)
    threading.Timer(0.3, lambda: broker_runtime._grants.revoke(grant, "CANCELED")).start()
    started = time.monotonic()
    with pytest.raises(Rejected, match="CANCELED"):
        broker_runtime._http_model(grant.tokens["model"], REQUEST)
    assert time.monotonic() - started < 1.5
    with pytest.raises(Rejected, match="CAPABILITY_UNKNOWN"):  # the token died with the job
        broker_runtime._http_model(grant.tokens["model"], REQUEST)

    slow = ModelBroker(ModelConfig(provider="anthropic", model="claude-opus-5-5", timeout_seconds=0.3), broker_runtime.transport, broker_runtime._core)
    caller = ModelCaller("c", "instruction_inspector", {}, slow.config.hash(), lambda: None, threading.Event(), lambda: 60.0)
    with pytest.raises(Rejected, match="MODEL_TIMEOUT"):
        slow.generate(caller, REQUEST)


def test_unapproved_provider_or_model_cannot_be_configured():
    for provider, model in [("openai-compatible", "x"), ("anthropic", "claude-unknown"), ("http://127.0.0.1", "claude-opus-5-5")]:
        with pytest.raises(RuntimeUnavailable, match="MODEL_CONFIGURATION_NOT_APPROVED"):
            ModelConfig(provider=provider, model=model)
    assert MODEL.endpoint == "https://api.anthropic.com"


def test_provider_failure_is_an_outage_not_a_result(broker_runtime):
    def explode(*args, **kwargs):
        raise ConnectionError("provider down")
    broker_runtime.transport.generate = explode
    grant = grant_for(broker_runtime, "test.inspector.ok")
    with pytest.raises(RuntimeUnavailable, match="MODEL_PROVIDER_ERROR"):
        broker_runtime._http_model(grant.tokens["model"], REQUEST)


def test_assistant_client_is_brokered_too(broker_runtime):
    broker_runtime._reasons.pop("model_broker")
    client = broker_runtime.assistant_model_client("ts-9", binding={"tenant_ref": "t"})
    assert client.generate(REQUEST)["stop_reason"] == "end_turn"
    with pytest.raises(Rejected, match="UNEXPECTED_FIELD"):
        client.generate({**REQUEST, "endpoint": "https://evil.example"})
    with pytest.raises(Rejected, match="TOOL_PROFILE_NOT_PERMITTED"):  # worker dummy tools are not the assistant's tools
        client.generate({**REQUEST, "tool_profile": "dummy_tools_v1"})
    client.cancel()
    with pytest.raises(Rejected, match="CANCELED"):
        client.generate(REQUEST)


def test_collector_records_forbidden_attempts_and_separates_proposal_from_effect(broker_runtime):
    core = broker_runtime._core.core
    tester = grant_for(broker_runtime, "test.behavior", 1)
    denied = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "send_email", "arguments": {"to": "x@example.com", "subject": "s", "body": "b"}})
    assert denied["outcome"] == "DENIED" and denied["result"] is None
    done = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "read_email", "arguments": {"email_id": "1"}})
    assert done["outcome"] == "EXECUTED_DUMMY" and len(done["event_ids"]) == 2
    events = [event for _, event in core.events]
    assert [(e["attempted_outcome"], e["policy_check"]) for e in events] == [("DENIED", "FORBIDDEN"), ("PROPOSED", "PERMITTED"), ("EXECUTED_DUMMY", "PERMITTED")]
    assert [e["sequence"] for e in events] == [1, 2, 3] and {e["run_id"] for e in events} == {tester.run_id}
    assert set(events[0]) == {"contract_version", "event_id", "scan_id", "run_id", "assignment_id", "sequence", "operation", "argument_digest", "attempted_outcome", "policy_check", "timestamp", "signature"}
    # The policy asked about is the assignment's own; a worker has no field to change it.
    with pytest.raises(Rejected, match="INVALID_REQUEST"):
        broker_runtime._http_tools(tester.tokens["tools"], {"operation": "send_email", "arguments": {}, "policy_id": "simulate_send"})
    # Malformed arguments for a known tool are still recorded as a denied attempt.
    odd = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "send_email", "arguments": {"to": "x", "bcc": "y"}})
    assert odd["outcome"] == "DENIED" and core.events[-1][1]["operation"] == "send_email"


def test_workers_cannot_forge_or_write_collector_events(broker_runtime):
    core, collector = broker_runtime._core.core, broker_runtime.collector
    tester = grant_for(broker_runtime, "test.behavior", 1)
    inspector = grant_for(broker_runtime, "test.inspector.ok", 2)
    broker_runtime._http_tools(tester.tokens["tools"], {"operation": "read_email", "arguments": {"email_id": "1"}})
    genuine = core.events[0][1]
    assert collector.verify(genuine)
    forged = {**genuine, "attempted_outcome": "DENIED", "policy_check": "FORBIDDEN"}
    assert not collector.verify(forged)
    assert not collector.verify({k: v for k, v in genuine.items() if k != "signature"})
    assert not SimulatedToolCollector(core).verify(genuine)  # another key, e.g. one a worker invented
    # Roles without the tool capability hold no token for the collector at all.
    assert "tools" not in inspector.tokens
    for token in (inspector.tokens["model"], inspector.tokens["resource"], "forged"):
        with pytest.raises(Rejected):
            broker_runtime._http_tools(token, {"operation": "read_email", "arguments": {"email_id": "1"}})
    with pytest.raises(Rejected, match="ROLE_NOT_PERMITTED"):
        collector.attempt(inspector, "read_email", {"email_id": "1"})
    assert len(core.events) == 2


def test_collector_fails_closed_when_events_or_policy_are_unavailable(broker_runtime):
    core = broker_runtime._core.core
    tester = grant_for(broker_runtime, "test.behavior", 1)
    request = {"operation": "read_email", "arguments": {"email_id": "1"}}
    core.record_collector_event = lambda identity, event: (_ for _ in ()).throw(OSError("disk full"))
    with pytest.raises(RuntimeUnavailable, match="COLLECTOR_EVENT_NOT_RECORDED"):
        broker_runtime._http_tools(tester.tokens["tools"], request)
    del core.record_collector_event
    core.check_simulated_operation = lambda *a: (_ for _ in ()).throw(RuntimeError("policy store down"))
    with pytest.raises(RuntimeUnavailable, match="POLICY_CHECK_UNAVAILABLE"):
        broker_runtime._http_tools(tester.tokens["tools"], request)
    core.check_simulated_operation = lambda *a: "yes"  # anything but True is a denial
    assert broker_runtime._http_tools(tester.tokens["tools"], request)["outcome"] == "DENIED"
