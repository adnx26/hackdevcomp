"""Application-message authentication and grant scoping. No sandbox needed."""

import time

import pytest

from protection_gateway.runtime import capabilities as caps
from protection_gateway.runtime.capabilities import GrantRegistry
from protection_gateway.runtime.config import REPO_ROOT, RuntimeConfig
from protection_gateway.runtime.envelope import KIND_ASSIGNMENT, KIND_WORKER_RESULT, open_sealed, seal
from protection_gateway.runtime.errors import Rejected
from protection_gateway.runtime.roster import DEFAULT_ROSTER, Roster
from protection_gateway.runtime.runtime import Runtime

from .conftest import SANDBOX_WORKERS, TEST_ROSTER, FakeCore, deadline

BODY = {"inspection_status": "COMPLETE", "findings": []}


@pytest.fixture
def offline(tmp_path):
    """A runtime that was never activated: enough to exercise message checks."""
    runtime = Runtime(RuntimeConfig(state_dir=tmp_path), roster=TEST_ROSTER, core=FakeCore())
    runtime.roster = Roster(TEST_ROSTER, [SANDBOX_WORKERS])
    return runtime


def grant_for(runtime, identity, n=1, **overrides):
    record = next(r for r in runtime.roster.records() if r.worker_identity == identity)
    assignment = {"assignment_id": f"asg-{identity}-{n}", "scan_id": f"scan-{n}", "attempt": 1, "deadline": deadline(), **overrides}
    return runtime._grants.issue(assignment, record)


def sealed(grant, key=None, **overrides):
    fields = dict(kind=KIND_WORKER_RESULT, sender={"worker_identity": grant.record.worker_identity, "role": grant.record.role},
                  assignment_id=grant.assignment_id, scan_id=grant.scan_id, attempt=grant.attempt, body=BODY)
    fields.update(overrides)
    return seal(key or grant.message_key, **fields)


def test_valid_result_reaches_core_once_and_duplicates_are_refused(offline):
    grant = grant_for(offline, "test.inspector.ok")
    message = sealed(grant)
    assert offline._on_worker_message(grant, message) == "ACCEPTED"
    assert offline._on_worker_message(grant, message) == "DUPLICATE_MESSAGE"      # exact replay
    assert offline._on_worker_message(grant, sealed(grant)) == "DUPLICATE_MESSAGE"  # second result, fresh nonce
    [(identity, result)] = offline._core.core.results
    assert result == BODY and identity.assignment_id == grant.assignment_id and identity.build == grant.record.build


def test_impersonated_cross_role_and_unassigned_messages_are_rejected(offline):
    victim = grant_for(offline, "test.inspector.ok", 1)
    other = grant_for(offline, "test.inspector.rogue", 2)
    cases = {
        # Another mesh member signs with its own key and claims the victim's assignment.
        "SENDER_NOT_AUTHENTICATED": sealed(victim, key=other.message_key),
        # Right key, but the sender claims a different roster identity or role.
        "SENDER_ROLE_MISMATCH": sealed(victim, sender={"worker_identity": "test.behavior", "role": "behavior_tester"}),
        # Right key and sender, wrong assignment / scan / attempt.
        "NOT_ASSIGNED": sealed(victim, assignment_id=other.assignment_id),
        "UNEXPECTED_MESSAGE_KIND": sealed(victim, kind=KIND_ASSIGNMENT),
    }
    for expected, message in cases.items():
        assert offline._on_worker_message(victim, message) == expected
    assert offline._on_worker_message(victim, sealed(victim, scan_id="scan-2")) == "NOT_ASSIGNED"
    assert offline._on_worker_message(victim, sealed(victim, attempt=2)) == "NOT_ASSIGNED"
    assert offline._on_worker_message(victim, b"{not json") == "MALFORMED_MESSAGE"
    assert offline._on_worker_message(victim, sealed(victim)[:-2] + b'x"}'[-2:]) in ("SENDER_NOT_AUTHENTICATED", "MALFORMED_MESSAGE")
    assert offline._core.core.results == [] and not victim.result_ready.is_set()


def test_tampered_body_fails_authentication(offline):
    grant = grant_for(offline, "test.inspector.ok")
    tampered = sealed(grant).replace(b'"findings":[]', b'"findings":[1]')
    assert offline._on_worker_message(grant, tampered) == "SENDER_NOT_AUTHENTICATED"


def test_stale_messages_are_rejected(offline):
    revoked = grant_for(offline, "test.inspector.ok", 1)
    message = sealed(revoked)
    offline._grants.revoke(revoked, "CANCELED")
    assert offline._on_worker_message(revoked, message) == "CAPABILITY_REVOKED"
    expired = grant_for(offline, "test.inspector.ok", 2)
    expired.expires_at = time.time() - 1
    assert offline._on_worker_message(expired, sealed(expired)) == "CAPABILITY_EXPIRED"
    lapsed = grant_for(offline, "test.inspector.ok", 3)
    offline._core.core.active = False  # A no longer holds a lease for this attempt
    assert offline._on_worker_message(lapsed, sealed(lapsed)) == "LEASE_NOT_ACTIVE"
    assert offline._core.core.results == []


def test_core_refusal_is_not_acceptance(offline):
    grant = grant_for(offline, "test.inspector.ok")
    offline._core.core.accept_worker_result = lambda identity, result: (_ for _ in ()).throw(ValueError("bad binding"))
    assert offline._on_worker_message(grant, sealed(grant)) == "CORE_REJECTED"
    assert grant.result is None


def test_grant_expires_at_the_earlier_of_deadline_and_five_minutes(offline):
    long_job = grant_for(offline, "test.inspector.ok", 1, deadline=deadline(3600))
    short_job = grant_for(offline, "test.inspector.ok", 2, deadline=deadline(20))
    assert 295 < long_job.remaining() <= caps.MAX_GRANT_SECONDS
    assert 15 < short_job.remaining() <= 20
    with pytest.raises(Rejected, match="ASSIGNMENT_EXPIRED"):
        grant_for(offline, "test.inspector.ok", 3, deadline=deadline(-1))
    with pytest.raises(Rejected, match="DUPLICATE_ASSIGNMENT"):
        grant_for(offline, "test.inspector.ok", 1)
    with pytest.raises(Rejected, match="INVALID_ASSIGNMENT"):
        grant_for(offline, "test.inspector.ok", 4, deadline="2026-10-10T00:00:00")  # no timezone


def test_tokens_are_scoped_by_kind_role_and_lifetime(offline):
    registry: GrantRegistry = offline._grants
    inspector = grant_for(offline, "test.inspector.ok", 1)
    extractor = grant_for(offline, "test.extractor", 2)
    tester = grant_for(offline, "test.behavior", 3)
    assert set(extractor.tokens) == {"resource"}             # no model, no tools
    assert set(inspector.tokens) == {"resource", "model"}    # no tools
    assert set(tester.tokens) == {"resource", "model", "tools"}
    assert registry.authenticate(inspector.tokens["model"], caps.KIND_MODEL) is inspector
    for token, kind, reason in [
        (inspector.tokens["resource"], caps.KIND_MODEL, "CAPABILITY_WRONG_SCOPE"),
        (inspector.tokens["model"], caps.KIND_TOOLS, "CAPABILITY_WRONG_SCOPE"),
        ("guessed-token", caps.KIND_RESOURCE, "CAPABILITY_UNKNOWN"),
        (None, caps.KIND_RESOURCE, "CAPABILITY_UNKNOWN"),
    ]:
        with pytest.raises(Rejected, match=reason):
            registry.authenticate(token, kind)
    inspector.expires_at = time.time() - 1
    with pytest.raises(Rejected, match="CAPABILITY_EXPIRED"):
        registry.authenticate(inspector.tokens["model"], caps.KIND_MODEL)
    registry.revoke(tester, "CANCELED")
    with pytest.raises(Rejected, match="CAPABILITY_UNKNOWN"):
        registry.authenticate(tester.tokens["tools"], caps.KIND_TOOLS)


def test_resource_service_serves_only_assigned_hash_bound_inputs(offline):
    import hashlib
    from .conftest import INPUT
    resources = [{"resource_id": "res-1", "view_id": None, "hash": hashlib.sha256(INPUT).hexdigest()}]
    grant = grant_for(offline, "test.inspector.ok", 1, resources=resources)
    token = grant.tokens["resource"]
    assert offline._http_read(token, {"resource_id": "res-1", "view_id": None})["hash"] == resources[0]["hash"]
    with pytest.raises(Rejected, match="RESOURCE_NOT_ASSIGNED"):
        offline._http_read(token, {"resource_id": "res-other", "view_id": None})
    offline._core.core.inputs[("res-1", None)] = b"changed after assignment"
    with pytest.raises(Rejected, match="RESOURCE_HASH_MISMATCH"):
        offline._http_read(token, {"resource_id": "res-1", "view_id": None})
    for bad in ({"name": "../../etc/passwd", "content_b64": ""}, {"name": "ok.txt", "content_b64": "!!"}, {"name": "ok.txt", "content_b64": "", "path": "/x"}):
        with pytest.raises(Rejected, match="INVALID_REQUEST"):
            offline._http_write_artifact(token, bad)
    with pytest.raises(Rejected, match="CAPABILITY_WRONG_SCOPE"):
        offline._http_read(grant.tokens["model"], {"resource_id": "res-1", "view_id": None})
    with pytest.raises(Rejected, match="INVALID_REQUEST"):  # only the extractor may post an extraction result
        offline._http_extraction_result(token, {"envelope": sealed(grant).decode()})


def test_envelope_round_trip_and_size_limit():
    key = b"k" * 32
    raw = seal(key, kind=KIND_WORKER_RESULT, sender={"worker_identity": "w", "role": "r"}, assignment_id="a", scan_id="s", attempt=1, body={"x": "é"})
    assert open_sealed(key, raw)["body"] == {"x": "é"}
    with pytest.raises(Rejected, match="MESSAGE_TOO_LARGE"):
        open_sealed(key, b" " * (1024 * 1024 + 1))


def test_default_roster_is_fixed_and_unavailable_until_workers_exist():
    roster = Roster(DEFAULT_ROSTER, [REPO_ROOT / "src"])
    present = (REPO_ROOT / "src" / "protection_gateway" / "workers").is_dir()
    assert present or (roster.records() == [] and set(roster.unavailable().values()) == {"WORKER_ENTRYPOINT_MISSING"})
    assert [record.role for record in DEFAULT_ROSTER] == ["extractor", "instruction_inspector", "data_tool_inspector", "behavior_tester"]
    described = DEFAULT_ROSTER[3].to_oasf()
    assert described["name"] == "pg.worker.behavior-tester.v1" and described["modules"][0]["data"]["simulated_tools"] is True
