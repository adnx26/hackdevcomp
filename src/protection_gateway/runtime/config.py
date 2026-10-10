"""Runtime configuration. Secrets are referenced by file path, never stored here."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .isolation import default_backend
from .model_broker import ModelConfig

SOURCE_ROOT = Path(__file__).resolve().parents[2]  # .../src
REPO_ROOT = SOURCE_ROOT.parent


def find_shadictl(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    local = REPO_ROOT / ".tools" / "bin" / "shadictl"
    return str(local) if local.is_file() else shutil.which("shadictl")


@dataclass
class RuntimeConfig:
    state_dir: Path
    sandbox_backend: str = field(default_factory=default_backend)
    shadictl: str | None = None
    source_roots: tuple[Path, ...] = (SOURCE_ROOT,)
    extra_read_paths: tuple[Path, ...] = ()
    # Import roots that are not themselves readable; pair with a narrower extra_read_paths entry.
    extra_python_path: tuple[Path, ...] = ()
    model: ModelConfig | None = None
    model_api_key_file: Path | None = None
    collector_key_file: Path | None = None
    ready_timeout_seconds: float = 20.0
    debug_worker_stderr: bool = False  # development only; never enable with real content
    host: str = "127.0.0.1"
    port: int = 8443
    tls_cert: Path | None = None
    tls_key: Path | None = None
    web_root: Path = field(default_factory=lambda: REPO_ROOT / "web")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "RuntimeConfig":
        env = os.environ if env is None else env

        def path(name: str) -> Path | None:
            return Path(env[name]) if env.get(name) else None

        model = None
        if env.get("PG_MODEL_PROVIDER"):
            model = ModelConfig(
                provider=env["PG_MODEL_PROVIDER"],
                model=env.get("PG_MODEL", "claude-opus-5-5"),
                max_output_tokens=int(env.get("PG_MODEL_MAX_OUTPUT_TOKENS", "4096")),
                job_token_budget=int(env.get("PG_JOB_TOKEN_BUDGET", "200000")),
                job_call_budget=int(env.get("PG_JOB_CALL_BUDGET", "16")),
            )
        return cls(
            # Not the system temp directory: the sandbox denies that tree to workers.
            state_dir=path("PG_STATE_DIR") or REPO_ROOT / "var" / "runtime",
            sandbox_backend=env.get("PG_SANDBOX_BACKEND") or default_backend(),
            shadictl=find_shadictl(env.get("PG_SHADICTL")),
            model=model,
            model_api_key_file=path("PG_MODEL_API_KEY_FILE"),
            collector_key_file=path("PG_COLLECTOR_KEY_FILE"),
            host=env.get("PG_HOST", "127.0.0.1"),
            port=int(env.get("PG_PORT", "8443")),
            tls_cert=path("PG_TLS_CERT"),
            tls_key=path("PG_TLS_KEY"),
        )
