"""Fixed worker roster.

Only the workers listed here can be launched. There is no discovery, no
plugin download, and nothing in an assignment or in inspected content can
name a different executable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .errors import Rejected

ROLE_EXTRACTOR = "extractor"
# Inspector role keys are the ones C's `inspect` entrypoint dispatches on.
ROLE_INSTRUCTION_INSPECTOR = "instruction"
ROLE_DATA_TOOL_INSPECTOR = "data"
ROLE_BEHAVIOR_TESTER = "behavior"
INSPECTOR_ROLES = (ROLE_INSTRUCTION_INSPECTOR, ROLE_DATA_TOOL_INSPECTOR, ROLE_BEHAVIOR_TESTER)
WORKER_ROLES = (ROLE_EXTRACTOR, *INSPECTOR_ROLES)

# Capabilities by role. The extractor gets neither a model nor simulated
# tools nor a SLIM path; only the behavior tester may attempt dummy tools.
_ROLE_MODEL = {ROLE_EXTRACTOR: False, ROLE_INSTRUCTION_INSPECTOR: True, ROLE_DATA_TOOL_INSPECTOR: True, ROLE_BEHAVIOR_TESTER: True}
_ROLE_TOOLS = {ROLE_BEHAVIOR_TESTER}


@dataclass(frozen=True)
class WorkerRecord:
    worker_identity: str
    role: str
    entrypoint: str  # "package.module:function"
    prompt_version: str
    build: str  # version the worker declares; assignments must name it
    source_hash: str = ""  # hash of the worker's source tree, computed at activation

    def __post_init__(self):
        if self.role not in WORKER_ROLES:
            raise ValueError(f"unknown worker role {self.role!r}")
        module, _, function = self.entrypoint.partition(":")
        if not module or not function.isidentifier():
            raise ValueError("entrypoint must look like 'package.module:function'")

    @property
    def uses_model(self) -> bool:
        return _ROLE_MODEL[self.role]

    @property
    def uses_simulated_tools(self) -> bool:
        return self.role in _ROLE_TOOLS

    @property
    def uses_slim(self) -> bool:
        return self.role != ROLE_EXTRACTOR

    def to_oasf(self) -> dict:
        """OASF-shaped description of this role (not validated against an OASF schema server)."""
        skills = ["deterministic_extraction"] if self.role == ROLE_EXTRACTOR else ["content_inspection"]
        return {
            "schema_version": "0.7.0",
            "name": self.worker_identity,
            "version": self.build,
            "annotations": {"source_hash": self.source_hash},
            "description": f"Fixed-roster protection gateway worker: {self.role}",
            "skills": [{"name": skill} for skill in skills],
            "locators": [{"type": "python_entrypoint", "url": self.entrypoint}],
            "modules": [
                {
                    "name": "protection_gateway/runtime",
                    "data": {
                        "role": self.role,
                        "prompt_version": self.prompt_version,
                        "model_access": self.uses_model,
                        "simulated_tools": self.uses_simulated_tools,
                        "transport": "slim" if self.uses_slim else "none",
                    },
                }
            ],
        }


# Entry points and versions as published in C's handoff (workers/HANDOFF.md on their branch):
# one `extract` and one `inspect` in the package, the latter dispatching on worker_role.
_WORKERS = "protection_gateway.workers:"
DEFAULT_ROSTER = (
    WorkerRecord("pg.worker.extractor", ROLE_EXTRACTOR, _WORKERS + "extract", "none", "c-extractor-1"),
    WorkerRecord("pg.worker.instruction", ROLE_INSTRUCTION_INSPECTOR, _WORKERS + "inspect", "c-prompts-2", "c-workers-2"),
    WorkerRecord("pg.worker.data", ROLE_DATA_TOOL_INSPECTOR, _WORKERS + "inspect", "c-prompts-2", "c-workers-2"),
    WorkerRecord("pg.worker.behavior", ROLE_BEHAVIOR_TESTER, _WORKERS + "inspect", "c-prompts-2", "c-workers-2"),
)


def tree_hash(root: Path) -> str:
    """SHA-256 over the relative paths and bytes of every .py file under root."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


class Roster:
    def __init__(self, records: Iterable[WorkerRecord], source_roots: Iterable[Path]):
        self._roots = [Path(root).resolve() for root in source_roots]
        self._records: dict[str, WorkerRecord] = {}
        self._unavailable: dict[str, str] = {}
        for record in records:
            if record.worker_identity in self._records or record.worker_identity in self._unavailable:
                raise ValueError("duplicate worker identity")
            package_dir = self._package_dir(record)
            if package_dir is None:
                self._unavailable[record.worker_identity] = "WORKER_ENTRYPOINT_MISSING"
                continue
            self._records[record.worker_identity] = WorkerRecord(
                record.worker_identity, record.role, record.entrypoint, record.prompt_version, record.build, tree_hash(package_dir)
            )

    def _package_dir(self, record: WorkerRecord) -> Path | None:
        # Located on disk without importing: worker code never runs in the gateway process.
        parts = record.entrypoint.partition(":")[0].split(".")
        for root in self._roots:
            base = root.joinpath(*parts)
            if base.with_suffix(".py").is_file() or (base / "__init__.py").is_file():
                return base.parent if base.with_suffix(".py").is_file() else base
        return None

    def records(self) -> list[WorkerRecord]:
        return list(self._records.values())

    def unavailable(self) -> dict[str, str]:
        return dict(self._unavailable)

    def available_roles(self) -> set[str]:
        return {record.role for record in self._records.values()}

    def match(self, assignment: Mapping, *, roles: Iterable[str]) -> WorkerRecord:
        """Return the roster record an assignment names, or reject it."""
        record = self._records.get(assignment.get("worker_identity"))
        if record is None:
            raise Rejected("WORKER_NOT_IN_ROSTER")
        if record.role not in roles or assignment.get("worker_role") != record.role:
            raise Rejected("WORKER_ROLE_MISMATCH")
        if assignment.get("worker_build") != record.build:
            raise Rejected("WORKER_BUILD_MISMATCH")
        if assignment.get("prompt_version") != record.prompt_version:
            raise Rejected("PROMPT_VERSION_MISMATCH")
        return record
