"""make doctor preflight: one line per check, secrets never printed."""

import importlib.util
import socket
import sys
from pathlib import Path

import pytest

from protection_gateway.runtime.errors import RuntimeUnavailable

_spec = importlib.util.spec_from_file_location("doctor", Path(__file__).resolve().parents[2] / "scripts" / "doctor.py")
doctor = importlib.util.module_from_spec(_spec)
sys.modules["doctor"] = doctor  # dataclasses resolve the defining module by name
_spec.loader.exec_module(doctor)

SECRET = "sk-test-DO-NOT-PRINT-0123456789"


class FakeTransport:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def generate(self, config, *, system, user, max_output_tokens, timeout):
        self.calls.append({"system": system, "user": user})
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_api_key_states_never_print_the_value():
    assert not doctor.check_api_key({}).ok
    assert not doctor.check_api_key({"KIMI_API_KEY": "replace-with-your-key"}).ok
    assert not doctor.check_api_key({"KIMI_API_KEY": "abc def"}).ok
    result = doctor.check_api_key({"KIMI_API_KEY": SECRET})
    assert result.ok and SECRET not in result.line()


def test_busy_port_fails_and_free_port_passes():
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        busy = holder.getsockname()[1]
        assert not doctor.check_port(busy).ok
    assert doctor.check_port(busy).ok


def test_slim_round_trip():
    result = doctor.check_slim(timeout=10)
    assert result.ok, result.detail


def test_model_broker_probe_uses_no_content_and_validates_reply():
    env = {"KIMI_API_KEY": SECRET}
    ok = FakeTransport({"stop_reason": "end_turn", "text": '{"ok": true}', "usage": {}})
    result = doctor.check_model_broker(env, lambda config: ok)
    assert result.ok and SECRET not in result.line()
    assert ok.calls == [{"system": 'Health check. Reply with exactly {"ok": true}.', "user": "{}"}]
    for reply, expected in (
        ({"stop_reason": "max_tokens", "text": "", "usage": {}}, "incomplete"),
        ({"stop_reason": "end_turn", "text": "not json", "usage": {}}, "not a JSON object"),
        (RuntimeUnavailable("MODEL_PROVIDER_UNAUTHENTICATED"), "MODEL_PROVIDER_UNAUTHENTICATED"),
    ):
        result = doctor.check_model_broker(env, lambda config, reply=reply: FakeTransport(reply))
        assert not result.ok and expected in result.detail and SECRET not in result.line()


def test_unapproved_model_configuration_fails():
    result = doctor.check_model_broker({"KIMI_API_KEY": SECRET, "PG_MODEL": "gpt-9"}, lambda c: None)
    assert not result.ok and "MODEL_CONFIGURATION_NOT_APPROVED" in result.detail


def test_run_reports_every_check_and_skips_offline(capsys):
    results = doctor.run({"KIMI_API_KEY": SECRET}, port=0, offline=True)
    names = [r.name for r in results]
    assert names[:2] == ["python", "kimi api key"] and names[-1] == "model broker"
    assert results[-1].skipped
    assert all(r.line().split()[0] in {"PASS", "FAIL", "SKIP"} for r in results)
    assert SECRET not in "\n".join(r.line() for r in results)


def test_replay_mode_needs_a_cache_not_a_key(tmp_path):
    env = {"PG_MODEL_REPLAY": "replay", "PG_REPLAY_DIR": str(tmp_path)}
    results = doctor.run(env, port=0, offline=False)
    assert results[1].skipped and results[-1].name == "replay cache" and not results[-1].ok
    (tmp_path / ("a" * 64 + ".json")).write_text("{}")
    assert doctor.run(env, port=0, offline=False)[-1].ok


def test_missing_key_fails_broker_without_a_call():
    results = doctor.run({}, port=0, offline=False)
    assert not results[1].ok and not results[-1].ok and "API key" in results[-1].detail


@pytest.mark.parametrize("argv", [["--offline", "--port", "0"]])
def test_main_exit_code_and_no_secret(monkeypatch, capsys, argv):
    import protection_gateway.runtime.config as config

    monkeypatch.setattr(config, "local_environment", lambda: {"KIMI_API_KEY": SECRET})
    code = doctor.main(argv)
    out = capsys.readouterr().out
    assert SECRET not in out
    assert code == (0 if "FAIL" not in out else 1)
