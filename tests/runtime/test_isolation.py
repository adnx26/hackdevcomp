"""Isolation proof on the deployment host. Skipped tests here are not a production pass."""

import sys

import pytest

from protection_gateway.runtime.config import REPO_ROOT, find_shadictl
from protection_gateway.runtime.errors import RuntimeUnavailable
from protection_gateway.runtime.isolation import Sandbox, seatbelt_profile


def test_missing_launcher_makes_the_runtime_unavailable(tmp_path):
    sandbox = Sandbox("shadi", str(tmp_path / "nope"), tmp_path, [REPO_ROOT / "src"])
    with pytest.raises(RuntimeUnavailable, match="SANDBOX_LAUNCHER_MISSING"):
        sandbox.verify()
    with pytest.raises(RuntimeUnavailable):
        sandbox.command(tmp_path, [], ["true"])
    assert sandbox.verified is False


def test_seatbelt_profile_is_deny_by_default_and_exact_about_ports(tmp_path):
    profile = seatbelt_profile(tmp_path / "job", [REPO_ROOT / "src"], [REPO_ROOT / "src"], [41001, 41002])
    assert "(deny default)" in profile and "(allow default)" not in profile
    assert profile.count("network-outbound") == 2 and 'localhost:41001' in profile and "network*" not in profile
    assert "file-write*" in profile and profile.count("file-write*") == 1


@pytest.mark.isolation
def test_probes_prove_the_sandbox(live_runtime):
    report = live_runtime.sandbox.report
    assert report["failures"] == []
    for scope in (report["probes"], report["probes"]["child"]):
        allowed = {name: value for name, value in scope.items() if name.startswith("allowed_")}
        forbidden = {name: value for name, value in scope.items() if name.startswith("forbidden_")}
        assert len(allowed) == 3 and set(allowed.values()) == {"OK"}
        assert len(forbidden) >= 10 and all(value.startswith("DENIED") for value in forbidden.values())


@pytest.mark.isolation
def test_a_too_broad_read_set_is_detected_and_refused(live_runtime, state_root):
    """Misconfiguration (state directory readable by workers) must fail verification, not weaken isolation."""
    state = state_root / "broad"
    state.mkdir(exist_ok=True)
    sandbox = Sandbox(live_runtime.sandbox.backend, find_shadictl(), state, [REPO_ROOT / "src"], extra_read_paths=[state])
    with pytest.raises(RuntimeUnavailable, match="SANDBOX_NOT_ENFORCED") as error:
        sandbox.verify()
    assert "forbidden_credential_read" in str(error.value) and sandbox.verified is False


@pytest.mark.isolation
@pytest.mark.skipif(sys.platform != "darwin" or not find_shadictl(), reason="documents shadictl 0.2.0 behaviour on macOS")
def test_shadictl_strict_profile_alone_is_not_sufficient_on_macos(state_root):
    """Recorded finding: shadictl 0.2.0 leaves the per-user temp directory open, so the probes reject it."""
    state = state_root / "shadi"
    state.mkdir(exist_ok=True)
    sandbox = Sandbox("shadi", find_shadictl(), state, [REPO_ROOT / "src"])
    with pytest.raises(RuntimeUnavailable, match="forbidden_temp_write"):
        sandbox.verify()
