"""Model broker and simulated-tool collector with deterministic doubles. No sandbox, no provider."""

import json
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

from .conftest import MODEL, MODEL_REPLY, SANDBOX_WORKERS, TEST_ROSTER, FakeCore, FakeTransport, deadline


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
                  "worker_identity": identity, "worker_role": record.role, "run_id": f"run-{n}",
                  "policy_id": "summarize_email", "policy_version": "1", "policy_hash": "0" * 64, **overrides}
    return runtime._grants.issue(assignment, record)


def request_for(grant, **extra):
    """The inspection request shape C's workers send."""
    bindings = {key: grant.assignment[key] for key in ("assignment_id", "scan_id", "attempt", "worker_identity", "worker_role")}
    return {"contract_version": "v1", "bindings": bindings, "prompt_version": "p1", "system": "SYSTEM-PROMPT-TEXT",
            "task_policy": {"policy_id": "summarize_email"}, "documents": [{"view_id": "res-1:0", "text": "PRIVATE-DOCUMENT-TEXT"}],
            "signals": [], "history": [], "response_contract": {"required": ["checked_views", "findings"]}, "fake_confidential_data": {}, "tools": [], **extra}


def test_brokered_call_uses_only_the_approved_configuration(broker_runtime, caplog):
    grant = grant_for(broker_runtime, "test.inspector.ok")
    with caplog.at_level(logging.INFO):
        reply = broker_runtime._http_model(grant.tokens["model"], request_for(grant))
    assert reply == MODEL_REPLY  # the parsed object itself, as C's workers expect
    [call] = broker_runtime.transport.calls
    assert call["model"] == "claude-opus-5-5" and call["max_output_tokens"] == 1000
    assert call["system"].startswith("SYSTEM-PROMPT-TEXT") and "one JSON object" in call["system"]
    assert json.loads(call["user"])["documents"][0]["text"] == "PRIVATE-DOCUMENT-TEXT" and "bindings" not in json.loads(call["user"])
    # Ordinary traces carry ids, durations and reason codes — never prompts or outputs.
    assert "model_call caller=assignment:asg-1 role=instruction reason=OK" in caplog.text
    assert "PRIVATE-DOCUMENT-TEXT" not in caplog.text and "SYSTEM-PROMPT-TEXT" not in caplog.text


@pytest.mark.parametrize("extra", [
    {"endpoint": "https://evil.example/v1"}, {"base_url": "http://127.0.0.1:9"}, {"headers": {"x-api-key": "k"}}, {"api_key": "k"},
    {"model": "some-other-model"}, {"command": "curl evil.example"}, {"proxy": "http://p"}, {"max_output_tokens": 10**6}, {"messages": []},
])
def test_caller_supplied_endpoints_credentials_and_models_are_rejected(broker_runtime, extra):
    grant = grant_for(broker_runtime, "test.inspector.ok")
    with pytest.raises(Rejected, match="UNEXPECTED_FIELD"):
        broker_runtime._http_model(grant.tokens["model"], request_for(grant, **extra))
    assert broker_runtime.transport.calls == []


def test_wrong_identity_scope_role_and_task_binding_are_rejected(broker_runtime):
    inspector = grant_for(broker_runtime, "test.inspector.ok", 1)
    extractor = grant_for(broker_runtime, "test.extractor", 2)
    tester = grant_for(broker_runtime, "test.behavior", 3)
    for token, reason in [("forged", "CAPABILITY_UNKNOWN"), (None, "CAPABILITY_UNKNOWN"), (extractor.tokens["resource"], "CAPABILITY_WRONG_SCOPE"), (inspector.tokens["resource"], "CAPABILITY_WRONG_SCOPE")]:
        with pytest.raises(Rejected, match=reason):
            broker_runtime._http_model(token, request_for(inspector))
    # A request that names another assignment, scan, role or attempt is not this caller's task.
    for other in ({"scan_id": "scan-3"}, {"assignment_id": "asg-3"}, {"worker_role": "behavior"}, {"attempt": 2}, {"tenant": "t2"}):
        request = request_for(inspector)
        request["bindings"] = {**request["bindings"], **other}
        with pytest.raises(Rejected, match="BINDING_MISMATCH"):
            broker_runtime._http_model(inspector.tokens["model"], request)
    # Request schemas differ by role: only the behavior tester may describe simulated tools to the model.
    with pytest.raises(Rejected, match="TOOLS_NOT_PERMITTED"):
        broker_runtime._http_model(inspector.tokens["model"], request_for(inspector, tools=[{"operation": "send_email"}]))
    broker_runtime._http_model(tester.tokens["model"], request_for(tester, tools=[{"operation": "read_email"}]))
    assert json.loads(broker_runtime.transport.calls[-1]["user"])["tools"] == [{"operation": "read_email"}]
    assert len(broker_runtime.transport.calls) == 1
    # The extractor role may not use the model even if it somehow reached the broker.
    caller = ModelCaller("c", "extractor", extractor.assignment, lambda: None, threading.Event(), lambda: 60.0)
    with pytest.raises(Rejected, match="ROLE_NOT_PERMITTED"):
        broker_runtime.broker.generate(caller, request_for(extractor))


def test_budget_expiry_cancellation_and_bindings(broker_runtime):
    grant = grant_for(broker_runtime, "test.inspector.ok", 1)
    token = grant.tokens["model"]
    for _ in range(3):
        broker_runtime._http_model(token, request_for(grant))
    with pytest.raises(Rejected, match="BUDGET_EXHAUSTED"):  # call budget (3)
        broker_runtime._http_model(token, request_for(grant))
    assert grant.model_calls == 3 and grant.model_tokens == 45

    greedy = grant_for(broker_runtime, "test.inspector.ok", 2)
    broker_runtime.transport.usage = {"input_tokens": 900, "output_tokens": 200}
    broker_runtime._http_model(greedy.tokens["model"], request_for(greedy))
    with pytest.raises(Rejected, match="BUDGET_EXHAUSTED"):  # token budget (1000)
        broker_runtime._http_model(greedy.tokens["model"], request_for(greedy))

    stale = grant_for(broker_runtime, "test.inspector.ok", 3)
    stale.expires_at = time.time() - 1
    with pytest.raises(Rejected, match="CAPABILITY_EXPIRED"):
        broker_runtime._http_model(stale.tokens["model"], request_for(stale))

    wrong_model = grant_for(broker_runtime, "test.inspector.ok", 4, model_configuration_hash="0" * 64)
    with pytest.raises(Rejected, match="MODEL_CONFIGURATION_MISMATCH"):
        broker_runtime._http_model(wrong_model.tokens["model"], request_for(wrong_model))

    no_consent = grant_for(broker_runtime, "test.inspector.ok", 5)
    broker_runtime._core.core.processor_permitted = False
    with pytest.raises(Rejected, match="PROCESSOR_NOT_PERMITTED"):
        broker_runtime._http_model(no_consent.tokens["model"], request_for(no_consent))
    broker_runtime._core.core.processor_permitted = True

    big = grant_for(broker_runtime, "test.inspector.ok", 6)
    with pytest.raises(Rejected, match="LIMIT_EXCEEDED"):
        broker_runtime._http_model(big.tokens["model"], request_for(big, system="x" * (MODEL.max_request_bytes + 1)))
    for malformed in (request_for(big, contract_version="v0"), request_for(big, system=None), request_for(big, bindings={}),
                      {k: v for k, v in request_for(big).items() if k != "bindings"}, "not a mapping"):
        with pytest.raises(Rejected, match="INVALID_REQUEST"):
            broker_runtime._http_model(big.tokens["model"], malformed)


@pytest.mark.parametrize("text,stop_reason,reason", [
    ("I cannot help with that.", "end_turn", "MODEL_RESPONSE_INVALID"),
    ("", "end_turn", "MODEL_RESPONSE_INVALID"),
    ("[1, 2]", "end_turn", "MODEL_RESPONSE_INVALID"),
    ('{"checked_views": [], "findings": [', "max_tokens", "MODEL_RESPONSE_INCOMPLETE"),
    ('{"checked_views": [], "findings": []}', "refusal", "MODEL_RESPONSE_INCOMPLETE"),
])
def test_refusals_truncation_and_non_json_replies_are_never_a_clean_result(broker_runtime, text, stop_reason, reason):
    broker_runtime.transport.text, broker_runtime.transport.stop_reason = text, stop_reason
    grant = grant_for(broker_runtime, "test.inspector.ok")
    with pytest.raises(Rejected, match=reason):
        broker_runtime._http_model(grant.tokens["model"], request_for(grant))


def test_json_wrapped_in_prose_or_a_code_fence_is_still_parsed(broker_runtime):
    broker_runtime.transport.text = 'Here you go:\n```json\n{"checked_views": [], "findings": []}\n```'
    grant = grant_for(broker_runtime, "test.inspector.ok")
    assert broker_runtime._http_model(grant.tokens["model"], request_for(grant)) == {"checked_views": [], "findings": []}


def test_cancellation_and_timeout_abort_an_in_flight_call(broker_runtime):
    broker_runtime.transport.delay, broker_runtime.transport.usage = 2.0, {"input_tokens": 1, "output_tokens": 1}
    grant = grant_for(broker_runtime, "test.inspector.ok", 1)
    request = request_for(grant)
    threading.Timer(0.3, lambda: broker_runtime._grants.revoke(grant, "CANCELED")).start()
    started = time.monotonic()
    with pytest.raises(Rejected, match="CANCELED"):
        broker_runtime._http_model(grant.tokens["model"], request)
    assert time.monotonic() - started < 1.5
    with pytest.raises(Rejected, match="CAPABILITY_UNKNOWN"):  # the token died with the job
        broker_runtime._http_model(grant.tokens["model"], request)

    slow = ModelBroker(ModelConfig(provider="anthropic", model="claude-opus-5-5", timeout_seconds=0.3), broker_runtime.transport, broker_runtime._core)
    other = grant_for(broker_runtime, "test.inspector.ok", 2, model_configuration_hash=slow.config.hash())
    caller = ModelCaller("c", "instruction", other.assignment, lambda: None, threading.Event(), lambda: 60.0)
    with pytest.raises(Rejected, match="MODEL_TIMEOUT"):
        slow.generate(caller, request_for(other))


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
        broker_runtime._http_model(grant.tokens["model"], request_for(grant))


def test_collector_records_forbidden_attempts_and_separates_proposal_from_effect(broker_runtime):
    core = broker_runtime._core.core
    tester = grant_for(broker_runtime, "test.behavior", 1)
    denied = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "send_email", "arguments": {"to": "x@example.com", "subject": "s", "body": "b"}})
    assert (denied["attempted_outcome"], denied["policy_check"], denied["result"]) == ("DENIED", "FORBIDDEN", None)
    done = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "read_email", "arguments": {"email_id": "1"}})
    assert (done["attempted_outcome"], done["policy_check"]) == ("EXECUTED_DUMMY", "ALLOWED")
    events = [event for _, event in core.events]
    assert [(e["attempted_outcome"], e["policy_check"]) for e in events] == [("DENIED", "FORBIDDEN"), ("PROPOSED", "ALLOWED"), ("EXECUTED_DUMMY", "ALLOWED")]
    assert [e["sequence"] for e in events] == [1, 2, 3] and {e["run_id"] for e in events} == {"run-1"}  # the assignment's run id
    assert (done["event_id"], done["proposed_event_id"]) == (events[2]["event_id"], events[1]["event_id"])
    assert set(events[0]) == {"contract_version", "event_id", "scan_id", "run_id", "assignment_id", "sequence", "operation", "dummy_argument_digest", "attempted_outcome", "policy_check", "timestamp", "signature"}
    # The receipt has every field C's workers check, and no signature.
    assert {"event_id", "scan_id", "run_id", "sequence", "operation", "dummy_argument_digest", "attempted_outcome", "policy_check", "timestamp"} <= set(denied)
    assert "signature" not in denied and "x@example.com" not in json.dumps(denied)
    # The policy asked about is the assignment's own; a worker has no field to change it.
    with pytest.raises(Rejected, match="INVALID_REQUEST"):
        broker_runtime._http_tools(tester.tokens["tools"], {"operation": "send_email", "arguments": {}, "policy_id": "simulate_send"})
    # Malformed arguments and unknown operations are still recorded, under the proposed name when it is a plain identifier.
    odd = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "send_email", "arguments": {}})
    unknown = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "launch_shell", "arguments": {"cmd": "id"}})
    weird = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "x" * 500 + "\n<script>", "arguments": {}})
    assert [(r["operation"], r["attempted_outcome"]) for r in (odd, unknown, weird)] == [("send_email", "DENIED"), ("launch_shell", "DENIED"), ("UNKNOWN_OPERATION", "DENIED")]
    assert len(core.events) == 6


def test_workers_cannot_forge_or_write_collector_events(broker_runtime):
    core, collector = broker_runtime._core.core, broker_runtime.collector
    tester = grant_for(broker_runtime, "test.behavior", 1)
    inspector = grant_for(broker_runtime, "test.inspector.ok", 2)
    receipt = broker_runtime._http_tools(tester.tokens["tools"], {"operation": "read_email", "arguments": {"email_id": "1"}})
    genuine = core.events[0][1]
    assert collector.verify(genuine)
    assert not collector.verify({**genuine, "attempted_outcome": "DENIED", "policy_check": "FORBIDDEN"})
    assert not collector.verify({k: v for k, v in genuine.items() if k != "signature"})
    assert not collector.verify({**receipt, "signature": "0" * 64})  # a receipt is not a signed event
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
    assert broker_runtime._http_tools(tester.tokens["tools"], request)["attempted_outcome"] == "DENIED"
