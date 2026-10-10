"""Entrypoint of every sandboxed worker process.

Runs untrusted (C's) code. Nothing here is a security control: the gateway
enforces identity, scope, budgets and isolation from the outside. This shim
only turns the grant received on stdin into the `restricted_io`,
`model_client` and `simulated_tools` callbacks of contract v1.
"""

from __future__ import annotations

import base64
import datetime
import importlib
import json
import sys
import urllib.error
import urllib.request

from .envelope import KIND_ASSIGNMENT, KIND_EXTRACTION_RESULT, KIND_WORKER_FAILURE, KIND_WORKER_RESULT, open_sealed, seal
from .launcher import READY_LINE

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class CallbackError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _call(base_url: str, path: str, token: str, payload: dict):
    request = urllib.request.Request(
        base_url + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token}, method="POST",
    )
    try:
        with _OPENER.open(request, timeout=330) as response:
            return json.loads(response.read())["data"]
    except urllib.error.HTTPError as error:
        try:
            code = json.loads(error.read())["error"]["code"]
        except Exception:
            code = "SERVICE_UNAVAILABLE"
        raise CallbackError(code) from None
    except OSError:
        raise CallbackError("SERVICE_UNAVAILABLE") from None


class RestrictedIO:
    """C's restricted I/O: assigned originals, assigned views, scoped private artifacts."""

    def __init__(self, boot: dict):
        self._url, self._token = boot["resource_url"], boot["tokens"]["resource"]
        self.scratch_dir = boot["scratch"]

    def read_resource(self, resource_id: str) -> bytes:
        data = _call(self._url, "/v1/resource/read", self._token, {"resource_id": resource_id})
        return base64.b64decode(data["content_b64"])

    def read_view(self, resource_id: str, view_id: str) -> dict:
        return _call(self._url, "/v1/view/read", self._token, {"resource_id": resource_id, "view_id": view_id})

    def write_artifact(self, artifact: dict) -> str:
        return _call(self._url, "/v1/artifact/write", self._token, {"artifact": artifact})["artifact_id"]


class ModelClient:
    def __init__(self, boot: dict):
        self._url, self._token = boot["broker_url"], boot["tokens"]["model"]

    def generate(self, model_request: dict) -> dict:
        return _call(self._url, "/v1/model/generate", self._token, model_request)


class SimulatedTools:
    def __init__(self, boot: dict):
        self._url, self._token = boot["broker_url"], boot["tokens"]["tools"]

    def attempt(self, operation: str, arguments: dict) -> dict:
        return _call(self._url, "/v1/tools/attempt", self._token, {"operation": operation, "arguments": arguments})


class _Unavailable:
    """Stands in for a callback this role was not granted."""

    def __getattr__(self, name):
        def refuse(*args, **kwargs):
            raise CallbackError("ROLE_NOT_PERMITTED")
        return refuse


def _entrypoint(spec: str):
    module, _, function = spec.partition(":")
    return getattr(importlib.import_module(module), function)


def main() -> None:
    boot = json.loads(sys.stdin.readline())
    key = bytes.fromhex(boot["message_key"])
    assignment = boot["assignment"]
    sender = {"worker_identity": boot["worker_identity"], "role": boot["role"]}

    def sealed(kind: str, body) -> bytes:
        return seal(key, kind=kind, sender=sender, assignment_id=assignment["assignment_id"], scan_id=assignment["scan_id"], attempt=assignment["attempt"], body=body)

    restricted_io = RestrictedIO(boot)
    if "slim" not in boot:  # extractor: no SLIM, no model, no simulated tools
        print(READY_LINE, flush=True)
        try:
            message = sealed(KIND_EXTRACTION_RESULT, _entrypoint(boot["entrypoint"])(assignment, restricted_io))
        except Exception as error:
            message = sealed(KIND_WORKER_FAILURE, {"reason_code": "WORKER_EXCEPTION:" + type(error).__name__})
        _call(boot["resource_url"], "/v1/extraction-result", boot["tokens"]["resource"], {"envelope": message.decode()})
        return

    import slim_bindings as slim

    from .slim_transport import initialize

    initialize(slim)
    service = slim.get_global_service()
    connection = service.connect(slim.new_insecure_client_config("http://127.0.0.1:%d" % boot["slim"]["port"]))
    app = service.create_app_with_secret(slim.Name(*boot["slim"]["name"]), boot["slim"]["mesh_secret"])
    app.subscribe(app.name(), connection)
    print(READY_LINE, flush=True)
    session = app.listen_for_session(datetime.timedelta(seconds=boot["lifetime_seconds"]))
    received = session.get_message(datetime.timedelta(seconds=boot["lifetime_seconds"]))
    # The job itself arrives over SLIM and must be the gateway's, for this assignment.
    job = open_sealed(key, received.payload)
    if job["kind"] != KIND_ASSIGNMENT or job["assignment_id"] != assignment["assignment_id"]:
        raise SystemExit(2)
    model_client = ModelClient(boot) if "model" in boot["tokens"] else _Unavailable()
    simulated_tools = SimulatedTools(boot) if "tools" in boot["tokens"] else _Unavailable()
    try:
        message = sealed(KIND_WORKER_RESULT, _entrypoint(boot["entrypoint"])(job["body"], restricted_io, model_client, simulated_tools))
    except Exception as error:
        message = sealed(KIND_WORKER_FAILURE, {"reason_code": "WORKER_EXCEPTION:" + type(error).__name__})
    session.publish_to_and_wait(received.context, message, None, None)


if __name__ == "__main__":
    main()
