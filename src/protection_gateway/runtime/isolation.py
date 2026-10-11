"""OS-level worker sandbox, verified before any worker is launched.

Two backends, selected by configuration:

* ``seatbelt`` (macOS): a deny-by-default Seatbelt profile applied with
  ``sandbox-exec``. This is the same kernel mechanism SHADI uses on macOS.
* ``shadi``: SHADI's ``shadictl`` launcher with its ``strict`` profile.

Neither is trusted because of its name. Activation runs direct socket,
child-process, filesystem and cross-scratch probes inside the sandbox, and any
probe that does not behave exactly as required makes the runtime unavailable.
(With shadictl 0.2.0 on macOS the probes fail: its platform profile leaves the
per-user temp directory readable and writable and ``--deny`` does not close
it, which is why ``seatbelt`` is the macOS default.) There is no weaker
fallback.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import site
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

from .errors import RuntimeUnavailable

_PROBE = Path(__file__).with_name("_isolation_probe.py")


def worker_environment(scratch: Path, python_path: Sequence[Path]) -> dict[str, str]:
    """A fresh environment: nothing is inherited from the gateway process."""
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(scratch),
        "TMPDIR": str(scratch),
        "PYTHONPATH": os.pathsep.join(str(path) for path in python_path),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONNOUSERSITE": "1",
        "NO_PROXY": "*",
    }


BACKEND_SEATBELT = "seatbelt"
BACKEND_SHADI = "shadi"
SANDBOX_EXEC = "/usr/bin/sandbox-exec"


def default_backend() -> str:
    return BACKEND_SEATBELT if sys.platform == "darwin" else BACKEND_SHADI


def _quote(path) -> str:
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def seatbelt_profile(scratch: Path, read_paths: Sequence[Path], exec_paths: Sequence[Path], local_ports: Sequence[int]) -> str:
    """Deny by default; read the interpreter and source, write scratch, connect to the listed loopback ports."""
    ancestors = sorted({parent for path in (scratch, *read_paths) for parent in Path(path).parents})
    return "\n".join([
        "(version 1)",
        "(deny default)",
        '(import "system.sb")',
        "(allow process-fork)",
        "(allow process-exec " + " ".join(f"(subpath {_quote(path)})" for path in exec_paths) + ")",
        "(allow file-read-metadata " + " ".join(f"(literal {_quote(path)})" for path in ancestors) + ")",
        "(allow file-read* " + " ".join(f"(subpath {_quote(path)})" for path in read_paths) + ")",
        f"(allow file-read* file-write* (subpath {_quote(scratch)}))",
        *[f'(allow network-outbound (remote tcp "localhost:{int(port)}"))' for port in local_ports],
    ])


def _expand(roots: Iterable) -> list[Path]:
    """Each root as named and as resolved, plus its Homebrew keg and `opt` link when it lives in a Cellar."""
    paths: set[Path] = set()
    for root in roots:
        for form in (Path(root), Path(root).resolve()):
            paths.add(form)
            keg = re.match(r"(.*)/Cellar/([^/]+)/[^/]+", str(form))
            if keg:
                paths.update({Path(keg[0]), Path(keg[1]) / "opt" / keg[2]})
    return sorted(paths)


def _loaded_library_dirs() -> list[Path]:
    """Directories of non-system libraries the interpreter needs (e.g. Homebrew OpenSSL on macOS)."""
    if sys.platform != "darwin":
        return []
    import ctypes
    import hashlib  # noqa: F401  (loaded so their libraries show up below)
    import ssl  # noqa: F401

    libc = ctypes.CDLL(None)
    libc._dyld_get_image_name.restype = ctypes.c_char_p
    names = (libc._dyld_get_image_name(index) for index in range(libc._dyld_image_count()))
    paths = (Path(name.decode()) for name in names if name)
    return sorted({path.parent for path in paths if path.suffix == ".dylib" and not str(path).startswith(("/usr/lib/", "/System/"))})


class Sandbox:
    def __init__(self, backend: str, shadictl: str | None, state_dir: Path, source_roots: Iterable[Path], extra_read_paths: Iterable[Path] = (), secret_files: Iterable[Path] = (), extra_python_path: Iterable[Path] = ()):
        if backend not in (BACKEND_SEATBELT, BACKEND_SHADI):
            raise ValueError("unknown sandbox backend")
        self.backend = backend
        self.shadictl = shadictl
        self.state_dir = Path(state_dir).resolve()
        self.source_roots = [Path(root).resolve() for root in source_roots]
        interpreter = [sys.base_prefix, sys.prefix, Path(getattr(sys, "_base_executable", sys.executable)).parent.parent]
        self.exec_paths = _expand(interpreter)
        self.read_paths = _expand([*interpreter, *self.source_roots, *extra_read_paths, *_loaded_library_dirs()])
        # Gateway secret files (provider key, collector key) are probed by path at activation.
        self.secret_files = [Path(path).resolve() for path in secret_files]
        # The resolved interpreter is executed directly (no symlink hops outside the read set);
        # the environment's packages are supplied through PYTHONPATH instead.
        self.python = os.path.realpath(sys.executable)
        self.python_path = [*self.source_roots, *(Path(path).resolve() for path in extra_python_path), *(Path(path) for path in site.getsitepackages())]
        self.verified = False
        self.report: dict = {}

    def command(self, scratch: Path, local_ports: Sequence[int], argv: Sequence[str]) -> list[str]:
        """Wrap argv so it can write only scratch and connect only to the given loopback ports."""
        if not self._launcher_present():
            raise RuntimeUnavailable("SANDBOX_LAUNCHER_MISSING")
        if self.backend == BACKEND_SEATBELT:
            return [SANDBOX_EXEC, "-p", seatbelt_profile(Path(scratch), self.read_paths, self.exec_paths, local_ports), *argv]
        command = [self.shadictl, "--profile", "strict", "--allow", str(scratch), "--net-block"]
        for path in self.read_paths:
            command += ["--read", str(path)]
        for port in local_ports:
            command += ["--net-allow", f"127.0.0.1:{int(port)}"]
        return command + ["--", *argv]

    def _launcher_present(self) -> bool:
        launcher = SANDBOX_EXEC if self.backend == BACKEND_SEATBELT else self.shadictl
        return bool(launcher) and Path(launcher).is_file() and os.access(launcher, os.X_OK)

    def verify(self) -> dict:
        """Prove the restrictions on this host, or raise RuntimeUnavailable."""
        self.verified = False
        if not self._launcher_present():
            raise RuntimeUnavailable("SANDBOX_LAUNCHER_MISSING")
        work = Path(tempfile.mkdtemp(prefix="probe-", dir=self.state_dir)).resolve()
        allowed = socket.create_server(("127.0.0.1", 0))
        forbidden = socket.create_server(("127.0.0.1", 0))
        try:
            scratch, other = work / "job", work / "other-job"
            scratch.mkdir(mode=0o700)
            other.mkdir(mode=0o700)
            (other / "input.txt").write_text("other job data")
            (work / "credential").write_text("canary credential")
            spec = {
                "allowed_port": allowed.getsockname()[1],
                "forbidden_port": forbidden.getsockname()[1],
                "scratch": str(scratch),
                "other_job_file": str(other / "input.txt"),
                "credential_file": str(work / "credential"),
                "home_dir": str(Path.home()),
                "secret_files": [str(path) for path in self.secret_files if Path(path).is_file()],
                "outside_file": str(work / "escape.txt"),
                "temp_dir": tempfile.gettempdir(),
                "gateway_pid": os.getpid(),
            }
            try:
                completed = subprocess.run(
                    self.command(scratch, [spec["allowed_port"]], [self.python, str(_PROBE), json.dumps(spec)]),
                    capture_output=True, text=True, timeout=120, cwd=scratch,
                    env=worker_environment(scratch, self.python_path), start_new_session=True,
                )
            except (OSError, subprocess.TimeoutExpired):
                raise RuntimeUnavailable("SANDBOX_PROBE_DID_NOT_RUN") from None
            lines = [line for line in completed.stdout.splitlines() if line.startswith("PG-PROBE ")]
            if not lines:
                raise RuntimeUnavailable("SANDBOX_PROBE_DID_NOT_RUN")
            report = json.loads(lines[-1][len("PG-PROBE "):])
            failures = self._failures(report) + ["child." + name for name in self._failures(report.get("child") or {})]
            planted = Path(tempfile.gettempdir()) / f"pg-probe-{os.getpid()}.txt"
            if planted.exists():
                planted.unlink()
                failures.append("write_escaped")
            if (other / "planted.txt").exists() or (work / "escape.txt").exists():
                failures.append("write_escaped")
            self.report = {"platform": sys.platform, "backend": self.backend, "probes": report, "failures": failures}
            if failures:
                raise RuntimeUnavailable("SANDBOX_NOT_ENFORCED:" + ",".join(sorted(failures)))
            self.verified = True
            return self.report
        finally:
            allowed.close()
            forbidden.close()
            shutil.rmtree(work, ignore_errors=True)

    @staticmethod
    def _failures(report: dict) -> list[str]:
        expected = [name for name in _EXPECTED if name not in report]
        for name, outcome in report.items():
            if name == "child":
                continue
            ok = outcome == "OK"
            if name.startswith("allowed_") != ok:
                expected.append(name)
        return expected


_EXPECTED = (
    "allowed_runtime_imports", "allowed_local_port", "allowed_scratch_write", "forbidden_local_port",
    "forbidden_external_ip", "forbidden_external_name", "forbidden_other_job_read", "forbidden_other_job_write",
    "forbidden_credential_read", "forbidden_home_list", "forbidden_outside_write", "forbidden_temp_list", "forbidden_temp_write",
)
