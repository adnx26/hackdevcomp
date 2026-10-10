"""Runs inside the sandbox during activation and reports what it could do.

Standard library only. Every "forbidden_*" probe must fail and every
"allowed_*" probe must succeed, both here and from a child process.
"""

import json
import os
import socket
import subprocess
import sys


def _connect(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        return "OK"
    except OSError as error:
        return "DENIED " + type(error).__name__


def _read(path):
    try:
        with open(path, "rb") as handle:
            handle.read(1)
        return "OK"
    except OSError as error:
        return "DENIED " + type(error).__name__


def _write(path):
    try:
        with open(path, "w") as handle:
            handle.write("probe")
        return "OK"
    except OSError as error:
        return "DENIED " + type(error).__name__


def _list(path):
    try:
        os.listdir(path)
        return "OK"
    except OSError as error:
        return "DENIED " + type(error).__name__


def _imports():
    try:
        import hashlib, hmac, ssl, urllib.request  # noqa: F401,E401
        return "OK"
    except Exception as error:  # an unusable interpreter is a failed probe, not a crash
        return "DENIED " + type(error).__name__


def probe(spec):
    secrets = {"forbidden_secret_read_%d" % i: _read(path) for i, path in enumerate(spec["secret_files"])}
    return {
        **secrets,
        "allowed_runtime_imports": _imports(),
        "allowed_local_port": _connect("127.0.0.1", spec["allowed_port"]),
        "allowed_scratch_write": _write(os.path.join(spec["scratch"], "probe.txt")),
        "forbidden_local_port": _connect("127.0.0.1", spec["forbidden_port"]),
        "forbidden_external_ip": _connect("1.1.1.1", 443),
        "forbidden_external_name": _connect("example.com", 443),
        "forbidden_other_job_read": _read(spec["other_job_file"]),
        "forbidden_other_job_write": _write(os.path.join(os.path.dirname(spec["other_job_file"]), "planted.txt")),
        "forbidden_credential_read": _read(spec["credential_file"]),
        "forbidden_home_list": _list(spec["home_dir"]),
        "forbidden_outside_write": _write(spec["outside_file"]),
        "forbidden_temp_list": _list(spec["temp_dir"]),
        "forbidden_temp_write": _write(os.path.join(spec["temp_dir"], "pg-probe-%d.txt" % spec["gateway_pid"])),
    }


if __name__ == "__main__":
    spec = json.loads(sys.argv[1])
    report = probe(spec)
    if len(sys.argv) == 2:
        try:
            child = subprocess.run([sys.executable, __file__, sys.argv[1], "child"], capture_output=True, text=True, timeout=60)
            report["child"] = json.loads(child.stdout.strip().splitlines()[-1][len("PG-PROBE "):])
        except Exception as error:
            report["child"] = {"allowed_runtime_imports": "DENIED " + type(error).__name__}
    print("PG-PROBE " + json.dumps(report), flush=True)
