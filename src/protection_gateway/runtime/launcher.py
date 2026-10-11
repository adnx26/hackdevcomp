"""Launch, track and destroy sandboxed worker processes."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Sequence

from .isolation import Sandbox, worker_environment

READY_LINE = "PG-READY"


class WorkerProcess:
    def __init__(self, sandbox: Sandbox, state_dir: Path, grant_id: str, local_ports: Sequence[int], boot: dict, debug_stderr: bool = False):
        self.scratch = (Path(state_dir) / "scratch" / grant_id).resolve()
        self._pid_file = Path(state_dir) / "pids" / grant_id
        self.scratch.mkdir(parents=True, mode=0o700)
        self._ready = threading.Event()
        stderr = subprocess.DEVNULL
        if debug_stderr:  # development only: worker stderr can contain inspected content
            (Path(state_dir) / "debug").mkdir(exist_ok=True)
            stderr = open(Path(state_dir) / "debug" / f"{grant_id}.stderr", "wb")
        argv = [sandbox.python, "-m", "protection_gateway.runtime.worker_main"]
        try:
            self._process = subprocess.Popen(
                sandbox.command(self.scratch, local_ports, argv),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                cwd=self.scratch, env=worker_environment(self.scratch, sandbox.python_path),
                start_new_session=True, close_fds=True,
            )
        except OSError:
            shutil.rmtree(self.scratch, ignore_errors=True)
            raise
        self.pgid = self._process.pid  # start_new_session makes the child its own group leader
        self._pid_file.parent.mkdir(parents=True, exist_ok=True)
        self._pid_file.write_text(str(self.pgid))
        threading.Thread(target=self._drain, daemon=True).start()
        try:
            # Private channel for the grant: this process's stdin pipe, nothing else.
            self._process.stdin.write(json.dumps(boot).encode() + b"\n")
            self._process.stdin.close()
        except OSError:
            pass

    def _drain(self) -> None:
        # Worker output is untrusted and never logged; only the readiness marker is used.
        for line in self._process.stdout:
            if line.strip() == READY_LINE.encode():
                self._ready.set()

    def wait_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._ready.wait(0.05):
                return True
            if self._process.poll() is not None:
                return self._ready.wait(0.2)
        return False

    def exited(self) -> bool:
        return self._process.poll() is not None

    def destroy(self) -> None:
        """Kill the whole process group and remove the scratch directory."""
        kill_group(self.pgid)
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        shutil.rmtree(self.scratch, ignore_errors=True)
        self._pid_file.unlink(missing_ok=True)


def kill_group(pgid: int) -> None:
    for sig, grace in ((signal.SIGTERM, 0.5), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError):
            return
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            try:
                os.killpg(pgid, 0)
            except (ProcessLookupError, PermissionError):
                return
            time.sleep(0.02)


def _is_worker_group(pgid: int) -> bool:
    listing = subprocess.run(["ps", "-A", "-o", "pgid=,command="], capture_output=True, text=True).stdout
    for line in listing.splitlines():
        group, _, command = line.strip().partition(" ")
        if group == str(pgid) and "protection_gateway.runtime.worker_main" in command:
            return True
    return False


def reap_leftovers(state_dir: Path) -> int:
    """After a restart: kill process groups and delete scratch left by a previous gateway process."""
    reaped = 0
    pids = Path(state_dir) / "pids"
    if pids.is_dir():
        for entry in pids.iterdir():
            try:
                pgid = int(entry.read_text())
                # Pids are reused: only kill a group that is still one of our workers.
                if _is_worker_group(pgid):
                    kill_group(pgid)
            except (ValueError, OSError):
                pass
            entry.unlink(missing_ok=True)
            reaped += 1
    shutil.rmtree(Path(state_dir) / "scratch", ignore_errors=True)
    return reaped
