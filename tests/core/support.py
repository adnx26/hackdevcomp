"""Deterministic test doubles for the gateway core. Test-only; never a
production fallback."""

from __future__ import annotations

import base64
import itertools
import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone

from protection_gateway.contracts.canonical import sha256_hex
from protection_gateway.contracts.enums import CONTRACT_VERSION, Channel, WorkerRole
from protection_gateway.core.auth import Authenticator, Principal
from protection_gateway.core.config import DemoIdentity, GatewayConfig, Limits, RosterEntry
from protection_gateway.core.service import GatewayService

V = CONTRACT_VERSION

ROSTER = (
    RosterEntry("w-extractor", WorkerRole.EXTRACTOR.value, "x-1.0", "none"),
    RosterEntry("w-instruction", WorkerRole.INSTRUCTION_INSPECTOR.value, "i-1.0", "ip-1"),
    RosterEntry("w-data", WorkerRole.DATA_TOOL_INSPECTOR.value, "d-1.0", "dp-1"),
    RosterEntry("w-behavior", WorkerRole.BEHAVIOR_TESTER.value, "b-1.0", "bp-1"),
)
IDENTITIES = {r.role: r.as_dict() for r in ROSTER}
COLLECTOR = {"collector_id": "collector-1"}

TOKENS = {"alice": "token-alice-0123456789", "bob": "token-bob-0123456789", "mallory": "token-mallory-0123456789"}

INVOICE_TEXT = "Invoice INV-1001\nAmount due: $1,250.00 USD\nDue date: 2026-11-01\nThanks, Acme"


class FixedClock:
    def __init__(self, start: datetime | None = None):
        self.current = start or datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class CounterIds:
    def __init__(self):
        self._counter = itertools.count(1)

    def new(self, prefix: str) -> str:
        return f"{prefix}_{next(self._counter):04d}"

    def secret(self) -> str:
        return f"secret{next(self._counter):04d}xxxxxxxxxxxxxxxx"


class RuntimeDouble:
    """Stands in for B's runtime. Extraction reads through the real job-token
    path; dispatch records assignments for tests to answer explicitly."""

    def __init__(self):
        self.service: GatewayService | None = None
        self.assignments: dict[str, dict] = {}
        self.capabilities: dict[str, str] = {}
        self.canceled: list[str] = []
        self.extract_overrides: dict[str, dict] = {}
        self.fail_extract = False
        self.fail_dispatch = False
        self.undeliver_roles: set[str] = set()

    def extract(self, assignment):
        if self.fail_extract:
            raise ConnectionError("runtime down")
        # B provisions the extractor's capability privately.
        capability = self.service.issue_job_capability(assignment["assignment_id"])
        data = self.service.read_assigned_original(capability, IDENTITIES["EXTRACTOR"], assignment["resource_id"])
        text = data.decode("utf-8")
        result = {
            "contract_version": V,
            "assignment_id": assignment["assignment_id"],
            "resource_id": assignment["resource_id"],
            "original_hash": assignment["original_hash"],
            "extractor_version": "x-1.0",
            "status": "COMPLETE",
            "views": [
                {
                    "view_id": "visible",
                    "kind": "plain_text",
                    "text": text,
                    "view_hash": sha256_hex(text),
                    "source_map": [[0, len(text), 0, len(data)]],
                }
            ],
            "unsupported_parts": [],
        }
        result.update(self.extract_overrides.get(assignment["resource_id"], {}))
        return result

    def dispatch(self, assignments):
        if self.fail_dispatch:
            raise ConnectionError("slim down")
        receipts = []
        for a in assignments:
            self.assignments[a["assignment_id"]] = a
            self.capabilities[a["assignment_id"]] = self.service.issue_job_capability(a["assignment_id"])
            receipts.append({"assignment_id": a["assignment_id"], "delivered": a["worker"]["role"] not in self.undeliver_roles})
        return receipts

    def cancel(self, scan_id):
        self.canceled.append(scan_id)

    def latest(self, scan_id: str, role: str) -> dict:
        matches = [a for a in self.assignments.values() if a["scan_id"] == scan_id and a["worker"]["role"] == role]
        return max(matches, key=lambda a: a["attempt"])


class Harness:
    def __init__(self, *, runtime: bool = True, limits: Limits | None = None, trusted=None, executor=None):
        self.tmp = tempfile.mkdtemp(prefix="pg-test-")
        self.clock = FixedClock()
        self.ids = CounterIds()
        self.runtime = RuntimeDouble() if runtime else None
        self.config = GatewayConfig(
            database_path=os.path.join(self.tmp, "gateway.sqlite3"),
            evidence_root=os.path.join(self.tmp, "evidence"),
            identities=(
                DemoIdentity(GatewayConfig.hash_token(TOKENS["alice"]), "alice", "tenant-a"),
                DemoIdentity(GatewayConfig.hash_token(TOKENS["bob"]), "bob", "tenant-a"),
                DemoIdentity(GatewayConfig.hash_token(TOKENS["mallory"]), "mallory", "tenant-m"),
            ),
            worker_roster=ROSTER,
            collector_ids=frozenset({COLLECTOR["collector_id"]}),
            model_configuration={"provider": "test-double", "model": "deterministic", "temperature": "0"},
            trusted_contacts=trusted if trusted is not None else {"tenant-a": {"alice": frozenset({"carol@example.com"})}},
            allow_unencrypted_dev_storage=True,
            cookie_secure=False,
            limits=limits or Limits(),
        )
        self.service = GatewayService(
            self.config, runtime=self.runtime, clock=self.clock, ids=self.ids, executor=executor
        )
        if self.runtime:
            self.runtime.service = self.service
        self.auth = Authenticator(self.config, self.service.db, self.clock, self.ids)

    def close(self):
        self.service.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # principals -------------------------------------------------------
    def api(self, user="alice") -> Principal:
        return self.auth.authenticate_bearer(TOKENS[user], Channel.API)

    def ui(self, user="alice") -> Principal:
        session = self.auth.issue_browser_session(TOKENS[user])
        return session.principal

    # workflow helpers --------------------------------------------------
    def upload(self, principal, text=INVOICE_TEXT, media_type="text/plain") -> dict:
        return self.service.upload_resource(
            principal,
            {"contract_version": V, "media_type": media_type, "content_base64": base64.b64encode(text.encode()).decode()},
        )

    def session(self, principal, resource_ids, policy="extract_invoice") -> dict:
        return self.service.create_task_session(
            principal, {"contract_version": V, "policy_id": policy, "resource_ids": list(resource_ids)}
        )

    def scan(self, principal, task_session_id, key="k1") -> dict:
        return self.service.start_scan(principal, {"contract_version": V, "task_session_id": task_session_id}, key)

    def worker_result(self, scan_id: str, role: str, *, status="COMPLETE", findings=(), **extra) -> dict:
        a = self.runtime.latest(scan_id, role)
        result = {
            "contract_version": V,
            **{k: a[k] for k in (
                "assignment_id", "scan_id", "attempt", "worker", "task_session_id", "task_scope_version",
                "policy", "resource_set_hash", "context_hash", "model_configuration_hash",
            )},
            "nonce": f"nonce-{a['assignment_id']}-{len(findings)}-{status}",
            "inspection_status": status,
            "checked_views": [
                {"resource_id": r["resource_id"], "view_id": v["view_id"], "view_hash": v["view_hash"]}
                for r in a["resources"] for v in r["views"]
            ],
            "findings": list(findings),
        }
        result.update(extra)
        return result

    def view(self, scan_id: str, role: str = "BEHAVIOR_TESTER", index: int = 0) -> dict:
        a = self.runtime.latest(scan_id, role)
        r = a["resources"][index]
        return {"resource_id": r["resource_id"], **r["views"][0]}

    def invoice_output(self, scan_id: str, text: str = INVOICE_TEXT, overrides=None) -> dict:
        v = self.view(scan_id)

        def ref(fragment):
            start = text.index(fragment)
            return {
                "value": None,
                "source_refs": [{"resource_id": v["resource_id"], "view_hash": v["view_hash"], "start": start, "end": start + len(fragment)}],
            }

        fields = {
            "invoice_id": dict(ref("INV-1001"), value="INV-1001"),
            "amount": dict(ref("$1,250.00"), value="1250.00"),
            "currency": dict(ref("USD"), value="USD"),
            "due_date": dict(ref("2026-11-01"), value="2026-11-01"),
        }
        fields.update(overrides or {})
        return {"kind": "invoice", "fields": fields}

    def summary_output(self, scan_id: str) -> dict:
        v = self.view(scan_id)
        return {
            "kind": "summary",
            "statements": [{"text": "A message.", "source_refs": [{"resource_id": v["resource_id"], "view_hash": v["view_hash"], "start": 0, "end": 5}]}],
        }

    def submit(self, result: dict, role: str | None = None) -> dict:
        role = role or result["worker"]["role"]
        return self.service.accept_worker_result(IDENTITIES[role], result)

    def complete_clean(self, scan_id: str, output=None) -> None:
        self.submit(self.worker_result(scan_id, "INSTRUCTION_INSPECTOR"))
        self.submit(self.worker_result(scan_id, "DATA_TOOL_INSPECTOR"))
        self.submit(self.worker_result(scan_id, "BEHAVIOR_TESTER", task_output=output or self.invoice_output(scan_id)))

    def collector_event(self, scan_id: str, operation="send_email", policy_check="FORBIDDEN", sequence=0, event_id=None) -> dict:
        run = self.runtime.latest(scan_id, "BEHAVIOR_TESTER")["assignment_id"]
        return {
            "contract_version": V,
            "event_id": event_id or f"ce-{scan_id}-{sequence}",
            "scan_id": scan_id,
            "run_id": run,
            "sequence": sequence,
            "operation": operation,
            "argument_digest": sha256_hex(json.dumps({"to": "attacker@example.net"})),
            "attempted_outcome": "DENIED" if policy_check == "FORBIDDEN" else "ALLOWED",
            "policy_check": policy_check,
            "timestamp": "2026-10-10T12:00:01Z",
        }

    def allowed_scan(self, principal=None, policy="extract_invoice", text=INVOICE_TEXT, key="k1"):
        principal = principal or self.api()
        res = self.upload(principal, text)
        ts = self.session(principal, [res["resource_id"]], policy)
        scan = self.scan(principal, ts["task_session_id"], key)
        output = self.invoice_output(scan["scan_id"]) if policy == "extract_invoice" else self.summary_output(scan["scan_id"])
        self.complete_clean(scan["scan_id"], output)
        return res, ts, scan
