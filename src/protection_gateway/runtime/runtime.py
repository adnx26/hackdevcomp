"""The verified execution environment between A's core and C's workers."""

from __future__ import annotations

import base64
import collections
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .. import CONTRACT_VERSION
from . import capabilities as caps
from .capabilities import Grant, GrantRegistry
from .collector import SimulatedToolCollector
from .config import RuntimeConfig
from .envelope import KIND_ASSIGNMENT, KIND_EXTRACTION_RESULT, KIND_WORKER_FAILURE, KIND_WORKER_RESULT, canonical_json, open_sealed, seal, sha256_hex, utc_now
from .errors import Rejected, RuntimeUnavailable
from .isolation import Sandbox
from .launcher import WorkerProcess, reap_leftovers
from .model_broker import ModelBroker, ModelCaller, ModelTransport
from .roster import DEFAULT_ROSTER, INSPECTOR_ROLES, ROLE_EXTRACTOR, Roster, WorkerRecord
from .services import LocalService
from .slim_transport import ORGANIZATION, SlimNode

log = logging.getLogger("protection_gateway.runtime")

# What B needs from A's core. A missing method keeps the dependent capability disabled.
CORE_PORT = (
    "accept_worker_result",        # (verified_identity, worker_result)
    "record_collector_event",      # (verified_collector_identity, event)
    "read_assigned_input",         # (verified_identity, assignment_id, resource_id, view_id | None) -> bytes
    "store_worker_artifact",       # (verified_identity, assignment_id, artifact: dict) -> artifact_id
    "check_simulated_operation",   # (policy_binding, operation, arguments) -> bool
    "model_processing_permitted",  # (binding, provider) -> bool
)
# Optional: assignment_active(assignment_id, attempt) -> bool; report_runtime_failure(assignment_id, attempt, reason_code)

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ARTIFACTS = 256
ACCEPTED = "ACCEPTED"


@dataclass(frozen=True)
class VerifiedIdentity:
    """Established by the runtime from the launch it performed, not from message contents."""

    worker_identity: str
    role: str
    build: str
    source_hash: str
    prompt_version: str
    assignment_id: str
    scan_id: str
    attempt: int


class _CoreProxy:
    def __init__(self):
        self.core = None

    def __getattr__(self, name):
        target = getattr(self.core, name, None) if self.core is not None else None
        if target is None:
            raise RuntimeUnavailable("CORE_CALLBACK_MISSING:" + name)
        return target


class Runtime:
    def __init__(self, config: RuntimeConfig, *, roster: Iterable[WorkerRecord] = DEFAULT_ROSTER, model_transport: ModelTransport | None = None, core=None):
        self.config = config
        self._roster_records = tuple(roster)
        self._model_transport = model_transport
        self._core = _CoreProxy()
        self._core.core = core
        self._grants = GrantRegistry()
        self._lock = threading.Lock()
        self._running: dict[str, dict] = {}
        self._callers: dict[str, ModelCaller] = {}
        self._canceled_scans: set[str] = set()
        self._reasons: dict[str, str] = {name: "NOT_ACTIVATED" for name in ("isolation", "slim", "model_broker")}
        self.operations: collections.deque = collections.deque(maxlen=1000)  # bounded operational metadata
        self.roster: Roster | None = None
        self.sandbox: Sandbox | None = None
        self.collector: SimulatedToolCollector | None = None
        self.broker: ModelBroker | None = None
        self.slim: SlimNode | None = None
        self._services: list[LocalService] = []

    # ---- composition -------------------------------------------------

    def bind_core(self, core) -> None:
        self._core.core = core

    def activate(self) -> dict:
        """Verify and start everything that can be verified. Never raises for a missing capability."""
        config = self.config
        config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        reaped = reap_leftovers(config.state_dir)
        if reaped:
            log.warning("reaped %d worker(s) left by a previous gateway process", reaped)
        self.roster = Roster(self._roster_records, (*config.source_roots, *config.extra_python_path))
        secret_files = [path for path in (config.model_api_key_file, config.collector_key_file, config.login_token_file) if path]
        self.sandbox = Sandbox(config.sandbox_backend, config.shadictl, config.state_dir, config.source_roots, config.extra_read_paths, secret_files, config.extra_python_path)
        try:
            self.sandbox.verify()
            self._reasons.pop("isolation", None)
        except RuntimeUnavailable as error:
            self._reasons["isolation"] = error.reason_code
        collector_key = config.collector_key_file.read_bytes() if config.collector_key_file else None
        self.collector = SimulatedToolCollector(self._core, collector_key)
        try:
            if config.model is None:
                raise RuntimeUnavailable("MODEL_CONFIGURATION_MISSING")
            transport = self._model_transport
            if transport is None:
                if config.model_api_key_file is None and not config.model_api_key:
                    raise RuntimeUnavailable("MODEL_PROVIDER_CREDENTIAL_MISSING")
                from .providers import AnthropicTransport, KimiTransport

                transport = (KimiTransport(config.model, config.model_api_key, config.model_api_key_file)
                             if config.model.provider == "kimi" else AnthropicTransport(config.model, config.model_api_key_file))
            self.broker = ModelBroker(config.model, transport, self._core)
            self._reasons.pop("model_broker", None)
        except RuntimeUnavailable as error:
            self._reasons["model_broker"] = error.reason_code
        try:
            self.slim = SlimNode()
            self._reasons.pop("slim", None)
        except RuntimeUnavailable as error:
            self._reasons["slim"] = error.reason_code
        self._resource_service = LocalService("resource", {
            "/v1/resource/read": self._http_read,
            "/v1/view/read": self._http_read_view,
            "/v1/artifact/write": self._http_write_artifact,
            "/v1/extraction-result": self._http_extraction_result,
        })
        self._broker_service = LocalService("broker", {
            "/v1/model/generate": self._http_model,
            "/v1/tools/attempt": self._http_tools,
        })
        self._services = [self._resource_service, self._broker_service]
        return self.capabilities()

    def capabilities(self) -> dict[str, dict]:
        """Capability name -> {"available": bool, "reason": str}. Nothing is assumed available."""
        reasons = dict(self._reasons)
        missing = [name for name in CORE_PORT if not callable(getattr(self._core.core, name, None))]
        if missing:
            reasons["core"] = "CORE_CALLBACK_MISSING:" + ",".join(missing)
        roles = self.roster.available_roles() if self.roster else set()

        def needs(*names: str, roles_needed: Iterable[str] = ()) -> str | None:
            for name in names:
                if name in reasons:
                    return f"{name}:{reasons[name]}"
            absent = sorted(set(roles_needed) - roles)
            return "WORKER_ENTRYPOINT_MISSING:" + ",".join(absent) if absent else None

        derived = {
            "collector": needs("core"),
            "extraction": needs("isolation", "core", roles_needed=[ROLE_EXTRACTOR]),
            "inspection": needs("isolation", "core", "slim", "model_broker", roles_needed=INSPECTOR_ROLES),
        }
        result = {name: {"available": name not in reasons, "reason": reasons.get(name, "")} for name in ("isolation", "core", "slim", "model_broker")}
        result.update({name: {"available": reason is None, "reason": reason or ""} for name, reason in derived.items()})
        return result

    def _require(self, capability: str) -> None:
        state = self.capabilities()[capability]
        if not state["available"]:
            raise RuntimeUnavailable(state["reason"])

    def model_configuration(self) -> dict:
        """The approved model configuration and the hash A binds into assignments."""
        self._require("model_broker")
        return {"configuration": self.broker.config.binding(), "hash": self.broker.config.hash()}

    # ---- A -> B: extract / dispatch / cancel --------------------------

    def extract(self, extraction_assignment: Mapping[str, Any]) -> dict:
        """Run C's deterministic extractor: no model, no simulated tools, no SLIM, no credentials."""
        self._require("extraction")
        record = self.roster.match(extraction_assignment, roles=[ROLE_EXTRACTOR])
        grant = self._start(extraction_assignment, record, ports=[self._resource_service.port], slim_name=None)
        process = self._running[grant.grant_id]["process"]
        outcome = "TIMEOUT"
        while grant.remaining() > 0 and not grant.revoked.is_set():
            if grant.result_ready.wait(0.05):
                break
            if process.exited() and not grant.result_ready.wait(0.5):
                outcome = "WORKER_EXITED"
                break
        if grant.result_ready.is_set():
            outcome = grant.revoke_reason or ACCEPTED if grant.result is not None else "WORKER_FAILURE"
        elif grant.revoked.is_set():
            outcome = grant.revoke_reason
        result = grant.result
        self._finish(grant, outcome)
        if outcome == ACCEPTED and isinstance(result, dict):
            return result
        # A failed run is reported as ERROR; it is never turned into a COMPLETE extraction.
        return {"contract_version": CONTRACT_VERSION, "assignment_id": grant.assignment_id, "scan_id": grant.scan_id,
                "extraction_status": "ERROR", "resources": [], "reason_codes": ["RUNTIME_" + outcome]}

    def dispatch(self, inspection_assignments: Iterable[Mapping[str, Any]]) -> list[dict]:
        """Launch each assigned inspector and deliver its job over SLIM. Delivery is not completion."""
        self._require("inspection")
        receipts = []
        for assignment in inspection_assignments:
            receipt = {"contract_version": CONTRACT_VERSION, "assignment_id": assignment.get("assignment_id"), "attempt": assignment.get("attempt")}
            grant = None
            try:
                record = self.roster.match(assignment, roles=INSPECTOR_ROLES)
                if assignment.get("model_configuration_hash") != self.broker.config.hash():
                    raise Rejected("MODEL_CONFIGURATION_MISMATCH", 409)
                name = (ORGANIZATION, record.role, "")
                grant = self._start(assignment, record, ports=[self._resource_service.port, self._broker_service.port, self.slim.port], slim_name=name)
                job = seal(grant.message_key, kind=KIND_ASSIGNMENT, sender={"worker_identity": "pg.gateway", "role": "gateway"},
                           assignment_id=grant.assignment_id, scan_id=grant.scan_id, attempt=grant.attempt, body=dict(assignment))
                entry = self._running[grant.grant_id]
                entry["session"] = self.slim.deliver(entry["slim_name"], job, timeout=max(1.0, min(10.0, grant.remaining())))
                threading.Thread(target=self._watch, args=(grant,), name="pg-watch-" + grant.grant_id, daemon=True).start()
                receipt.update(status="DELIVERED", delivered_at=utc_now())
            except Rejected as error:
                if grant is not None:
                    self._finish(grant, error.reason_code)
                receipt.update(status="REJECTED", reason_code=error.reason_code)
            except Exception as error:
                reason = getattr(error, "reason_code", "DELIVERY_FAILED:" + type(error).__name__)
                if grant is not None:
                    self._finish(grant, reason)
                receipt.update(status="FAILED", reason_code=reason)
            receipts.append(receipt)
        return receipts

    def cancel(self, scan_id: str) -> None:
        """Revoke every capability of the scan and kill its process groups. Later results are refused."""
        with self._lock:
            self._canceled_scans.add(scan_id)
        for grant in self._grants.for_scan(scan_id):
            self._finish(grant, "CANCELED")

    def shutdown(self) -> None:
        for grant in self._grants.all():
            self._finish(grant, "SHUTDOWN")
        for service in self._services:
            service.close()
        self._services = []
        if self.broker:
            self.broker.close()
        if self.slim:
            self.slim.close()
            self.slim = None
            self._reasons["slim"] = "SHUT_DOWN"

    # ---- worker lifecycle --------------------------------------------

    def _identity(self, grant: Grant) -> VerifiedIdentity:
        record = grant.record
        return VerifiedIdentity(record.worker_identity, record.role, record.build, record.source_hash, record.prompt_version, grant.assignment_id, grant.scan_id, grant.attempt)

    def _start(self, assignment: Mapping[str, Any], record: WorkerRecord, *, ports: list[int], slim_name) -> Grant:
        if not self.sandbox.verified:
            raise RuntimeUnavailable("isolation:NOT_VERIFIED")
        with self._lock:
            if assignment.get("scan_id") in self._canceled_scans:
                raise Rejected("SCAN_CANCELED", 409)
        active = getattr(self._core.core, "assignment_active", None)
        if callable(active) and active(assignment.get("assignment_id"), assignment.get("attempt")) is not True:
            raise Rejected("LEASE_NOT_ACTIVE", 409)
        grant = self._grants.issue(assignment, record)
        boot = {
            "assignment": grant.assignment,
            "worker_identity": record.worker_identity,
            "role": record.role,
            "entrypoint": record.entrypoint,
            "message_key": grant.message_key.hex(),
            "tokens": grant.tokens,
            "resource_url": f"http://127.0.0.1:{self._resource_service.port}",
            "lifetime_seconds": max(1.0, grant.remaining()),
        }
        if slim_name is not None:
            slim_name = (slim_name[0], slim_name[1], grant.grant_id)
            boot["broker_url"] = f"http://127.0.0.1:{self._broker_service.port}"
            boot["slim"] = {"port": self.slim.port, "mesh_secret": self.slim.mesh_secret, "name": slim_name}
        started = time.monotonic()
        try:
            process = WorkerProcess(self.sandbox, self.config.state_dir, grant.grant_id, ports, {**boot, "scratch": str((self.config.state_dir / "scratch" / grant.grant_id).resolve())},
                                    debug_stderr=self.config.debug_worker_stderr)
        except Exception:
            self._grants.revoke(grant, "LAUNCH_FAILED")
            raise RuntimeUnavailable("WORKER_LAUNCH_FAILED") from None
        with self._lock:
            self._running[grant.grant_id] = {"process": process, "session": None, "slim_name": slim_name, "started": started}
        if not process.wait_ready(min(self.config.ready_timeout_seconds, max(0.1, grant.remaining()))):
            self._finish(grant, "WORKER_NOT_READY")
            raise RuntimeUnavailable("WORKER_NOT_READY")
        return grant

    def _watch(self, grant: Grant) -> None:
        entry = self._running.get(grant.grant_id)
        outcome = "TIMEOUT"
        while entry and grant.remaining() > 0 and not grant.revoked.is_set():
            began = time.monotonic()
            raw = self.slim.receive(entry["session"], min(0.5, max(0.05, grant.remaining()))) if self.slim else None
            if raw is None:
                if entry["process"].exited():
                    raw = self.slim.receive(entry["session"], 0.5) if self.slim else None
                    if raw is None:
                        outcome = "WORKER_EXITED"
                        break
                elif time.monotonic() - began < 0.05:
                    time.sleep(0.1)
                    continue
                else:
                    continue
            code = self._on_worker_message(grant, raw)
            if code in (ACCEPTED, "WORKER_FAILURE", "CORE_REJECTED"):
                outcome = code
                break
        if grant.revoked.is_set():
            outcome = grant.revoke_reason
        self._finish(grant, outcome)

    def _on_worker_message(self, grant: Grant, raw: bytes) -> str:
        """Authenticate one application message for this grant; hand an accepted result to A."""
        try:
            grant.check_active()
            envelope = open_sealed(grant.message_key, raw)
            record = grant.record
            if envelope["sender"] != {"worker_identity": record.worker_identity, "role": record.role}:
                raise Rejected("SENDER_ROLE_MISMATCH")
            if (envelope["assignment_id"], envelope["scan_id"], envelope["attempt"]) != (grant.assignment_id, grant.scan_id, grant.attempt):
                raise Rejected("NOT_ASSIGNED")
            expected = KIND_EXTRACTION_RESULT if record.role == ROLE_EXTRACTOR else KIND_WORKER_RESULT
            if envelope["kind"] not in (expected, KIND_WORKER_FAILURE):
                raise Rejected("UNEXPECTED_MESSAGE_KIND")
            with grant.lock:
                if envelope["nonce"] in grant.seen_nonces or grant.result_ready.is_set():
                    raise Rejected("DUPLICATE_MESSAGE", 409)
                grant.seen_nonces.add(envelope["nonce"])
            active = getattr(self._core.core, "assignment_active", None)
            if callable(active) and active(grant.assignment_id, grant.attempt) is not True:
                raise Rejected("LEASE_NOT_ACTIVE", 409)
        except Rejected as error:
            log.warning("worker_message_rejected assignment=%s reason=%s", grant.assignment_id, error.reason_code)
            self.operations.append({"assignment_id": grant.assignment_id, "attempt": grant.attempt, "event": "MESSAGE_REJECTED", "reason_code": error.reason_code})
            return error.reason_code
        if envelope["kind"] == KIND_WORKER_FAILURE or not isinstance(envelope["body"], dict):
            # The worker's own reason is untrusted: keep a bounded, sanitized code only.
            claimed = envelope["body"].get("reason_code", "") if isinstance(envelope["body"], dict) else ""
            self.operations.append({"assignment_id": grant.assignment_id, "attempt": grant.attempt, "event": "WORKER_REPORTED_FAILURE",
                                    "reason_code": re.sub(r"[^A-Za-z0-9_:]", "", str(claimed))[:80]})
            grant.result_ready.set()
            return "WORKER_FAILURE"
        if grant.record.role != ROLE_EXTRACTOR:
            try:
                self._core.accept_worker_result(self._identity(grant), envelope["body"])
            except Exception as error:
                log.warning("core_refused_result assignment=%s error=%s", grant.assignment_id, type(error).__name__)
                grant.result_ready.set()
                return "CORE_REJECTED"
        grant.result = envelope["body"]
        grant.result_ready.set()
        return ACCEPTED

    def _finish(self, grant: Grant, outcome: str) -> None:
        """Revoke capabilities, kill the process group, delete scratch, record bounded metadata. Idempotent."""
        self._grants.revoke(grant, outcome)
        with self._lock:
            entry = self._running.pop(grant.grant_id, None)
            self._callers.pop(grant.grant_id, None)
        if entry is None:
            return
        entry["process"].destroy()
        if entry["session"] is not None and self.slim:
            self.slim.close_session(entry["session"])
        if self.collector:
            self.collector.discard_run(grant.run_id)
        self.operations.append({
            "assignment_id": grant.assignment_id, "scan_id": grant.scan_id, "attempt": grant.attempt, "role": grant.record.role,
            "event": "WORKER_FINISHED", "outcome": outcome, "duration_ms": int((time.monotonic() - entry["started"]) * 1000),
            "model_calls": grant.model_calls, "collector_events": grant.collector_sequence,
        })
        if outcome != ACCEPTED:
            report = getattr(self._core.core, "report_runtime_failure", None)
            if callable(report):
                try:
                    report(grant.assignment_id, grant.attempt, outcome)
                except Exception:
                    pass

    # ---- loopback services (called by sandboxed workers) ---------------

    def _read(self, grant: Grant, assigned: Mapping | None, hash_key: str, view_id) -> bytes:
        if assigned is None:
            raise Rejected("RESOURCE_NOT_ASSIGNED")
        # A validates tenant and resource access; the runtime supplies the identity it launched.
        data = self._core.read_assigned_input(self._identity(grant), grant.assignment_id, assigned["resource_id"], view_id)
        if not isinstance(data, bytes) or sha256_hex(data) != assigned.get(hash_key):
            raise Rejected("RESOURCE_HASH_MISMATCH", 409)
        return data

    def _http_read(self, token: str | None, payload: dict) -> dict:
        """Original bytes of an assigned resource (extraction assignments)."""
        grant = self._grants.authenticate(token, caps.KIND_RESOURCE)
        if grant.record.role != ROLE_EXTRACTOR:  # inspectors work from extracted views only
            raise Rejected("ROLE_NOT_PERMITTED")
        if set(payload) != {"resource_id"}:
            raise Rejected("INVALID_REQUEST", 400)
        assigned = next((r for r in grant.assignment.get("resources", ()) if r.get("resource_id") == payload["resource_id"]), None)
        return {"content_b64": base64.b64encode(self._read(grant, assigned, "original_hash", None)).decode()}

    def _http_read_view(self, token: str | None, payload: dict) -> dict:
        """Text of an assigned extracted view (inspection assignments)."""
        grant = self._grants.authenticate(token, caps.KIND_RESOURCE)
        if grant.record.role == ROLE_EXTRACTOR:
            raise Rejected("ROLE_NOT_PERMITTED")
        if set(payload) != {"resource_id", "view_id"} or payload["view_id"] is None:
            raise Rejected("INVALID_REQUEST", 400)
        assigned = next((v for v in grant.assignment.get("views", ()) if v.get("resource_id") == payload["resource_id"] and v.get("view_id") == payload["view_id"]), None)
        try:
            return {"text": self._read(grant, assigned, "view_hash", payload["view_id"]).decode("utf-8")}
        except UnicodeDecodeError:
            raise Rejected("RESOURCE_HASH_MISMATCH", 409) from None

    def _http_write_artifact(self, token: str | None, payload: dict) -> dict:
        grant = self._grants.authenticate(token, caps.KIND_RESOURCE)
        if set(payload) != {"artifact"} or not isinstance(payload["artifact"], dict):
            raise Rejected("INVALID_REQUEST", 400)
        with grant.lock:
            if len(canonical_json(payload["artifact"])) > MAX_ARTIFACT_BYTES or grant.artifacts_written >= MAX_ARTIFACTS:
                raise Rejected("LIMIT_EXCEEDED", 413)
            grant.artifacts_written += 1
        artifact_id = self._core.store_worker_artifact(self._identity(grant), grant.assignment_id, payload["artifact"])
        if not isinstance(artifact_id, str) or not artifact_id:
            raise RuntimeUnavailable("ARTIFACT_NOT_STORED")
        return {"artifact_id": artifact_id}

    def _http_extraction_result(self, token: str | None, payload: dict) -> dict:
        grant = self._grants.authenticate(token, caps.KIND_RESOURCE)
        if grant.record.role != ROLE_EXTRACTOR or set(payload) != {"envelope"} or not isinstance(payload["envelope"], str):
            raise Rejected("INVALID_REQUEST", 400)
        code = self._on_worker_message(grant, payload["envelope"].encode())
        if code not in (ACCEPTED, "WORKER_FAILURE"):
            raise Rejected(code)
        return {"received": True}

    def _http_model(self, token: str | None, payload: dict) -> dict:
        grant = self._grants.authenticate(token, caps.KIND_MODEL)
        if self.broker is None:
            raise RuntimeUnavailable("model_broker:" + self._reasons.get("model_broker", "UNAVAILABLE"))
        with self._lock:
            caller = self._callers.get(grant.grant_id)
            if caller is None:
                caller = self._callers[grant.grant_id] = ModelCaller(
                    caller_id="assignment:" + grant.assignment_id, role=grant.record.role, assignment=grant.assignment,
                    is_active=grant.check_active, canceled=grant.revoked, remaining_seconds=grant.remaining,
                )
        try:
            return self.broker.generate(caller, payload)
        except (Rejected, RuntimeUnavailable) as error:
            allowed = {'MODEL_PROVIDER_TLS_ERROR', 'MODEL_PROVIDER_UNAUTHENTICATED',
                       'MODEL_PROVIDER_FORBIDDEN', 'MODEL_PROVIDER_RATE_LIMITED',
                       'MODEL_PROVIDER_REQUEST_REJECTED', 'MODEL_PROVIDER_UNAVAILABLE',
                       'MODEL_PROVIDER_ERROR', 'MODEL_TIMEOUT', 'MODEL_RESPONSE_INCOMPLETE',
                       'MODEL_RESPONSE_INVALID', 'BUDGET_EXHAUSTED'}
            self.operations.append({'scan_id':grant.scan_id, 'assignment_id':grant.assignment_id,
                'role':grant.record.role, 'event':'MODEL_FAILED',
                'reason_code':error.reason_code if error.reason_code in allowed else 'MODEL_PROVIDER_ERROR'})
            raise
        finally:
            grant.model_calls, grant.model_tokens = caller.calls, caller.tokens

    def inspection_errors(self, scan_id):
        # Bounded gateway-owned metadata; never provider response bodies or source content.
        return [{'role':entry['role'], 'code':entry['reason_code']} for entry in list(self.operations)
                if entry.get('scan_id') == scan_id and entry['event'] in {'MODEL_FAILED', 'INSPECTION_FAILED'}]

    def _http_tools(self, token: str | None, payload: dict) -> dict:
        grant = self._grants.authenticate(token, caps.KIND_TOOLS)
        if set(payload) != {"operation", "arguments"}:
            raise Rejected("INVALID_REQUEST", 400)
        return self.collector.attempt(grant, payload["operation"], payload["arguments"])
