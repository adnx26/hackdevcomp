"""Gateway-only runtime configuration; credentials never enter worker environments."""

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
    model_api_key: str | None = field(default=None, repr=False)
    # Development only: "record" caches live replies, "replay" serves them offline.
    model_replay: str | None = None
    replay_dir: Path = field(default_factory=lambda: REPO_ROOT / "var" / "replay-cache")
    # Precomputed no-gateway baselines written by make eval; served read-only by the core.
    baseline_dir: Path = field(default_factory=lambda: REPO_ROOT / "var" / "baselines")
    # Known-vendor registry for the core's deterministic bank-details rule (demo fixture by default).
    vendor_registry: Path | None = field(default_factory=lambda: REPO_ROOT / "demo" / "vendors.json")
    dev_mode: bool = False
    login_token_file: Path | None = None
    collector_key_file: Path | None = None
    ready_timeout_seconds: float = 20.0
    debug_worker_stderr: bool = False  # development only; never enable with real content
    host: str = "127.0.0.1"
    port: int = 8443
    tls_cert: Path | None = None
    tls_key: Path | None = None
    web_root: Path = field(default_factory=lambda: REPO_ROOT / "web")
    # Exact external origins D's adapters accept, e.g. ("https://gateway.example",). Empty = adapters unavailable.
    allowed_origins: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "RuntimeConfig":
        env = os.environ if env is None else env

        def path(name: str) -> Path | None:
            return Path(env[name]) if env.get(name) else None

        model = None
        replay = env.get("PG_MODEL_REPLAY") or None
        provider = env.get("PG_MODEL_PROVIDER") or ("kimi" if env.get("KIMI_API_KEY") or replay == "replay" else None)
        if provider:
            model = ModelConfig(
                provider=provider,
                model=env.get("PG_MODEL", "kimi-k3" if provider == "kimi" else "claude-opus-5-5"),
                max_output_tokens=int(env.get("PG_MODEL_MAX_OUTPUT_TOKENS", "4096")),
                timeout_seconds=float(env.get("PG_MODEL_TIMEOUT_SECONDS", "120")),
                reasoning_effort=env.get("PG_MODEL_REASONING_EFFORT", "low"),
                job_token_budget=int(env.get("PG_JOB_TOKEN_BUDGET", "200000")),
                job_call_budget=int(env.get("PG_JOB_CALL_BUDGET", "16")),
                inference="replay" if replay == "replay" else "live",
            )
        return cls(
            # Not the system temp directory: the sandbox denies that tree to workers.
            state_dir=path("PG_STATE_DIR") or REPO_ROOT / "var" / "runtime",
            sandbox_backend=env.get("PG_SANDBOX_BACKEND") or default_backend(),
            shadictl=find_shadictl(env.get("PG_SHADICTL")),
            model=model,
            model_api_key_file=path("PG_MODEL_API_KEY_FILE"),
            model_api_key=env.get("KIMI_API_KEY") if provider == "kimi" else None,
            model_replay=replay,
            replay_dir=path("PG_REPLAY_DIR") or REPO_ROOT / "var" / "replay-cache",
            baseline_dir=path("PG_BASELINE_DIR") or REPO_ROOT / "var" / "baselines",
            vendor_registry=path("PG_VENDOR_REGISTRY") or REPO_ROOT / "demo" / "vendors.json",
            dev_mode=env.get("PG_DEV_MODE") == "1",
            login_token_file=path("PG_LOGIN_TOKEN_FILE"),
            collector_key_file=path("PG_COLLECTOR_KEY_FILE"),
            host=env.get("PG_HOST", "127.0.0.1"),
            port=int(env.get("PG_PORT", "8443")),
            tls_cert=path("PG_TLS_CERT"),
            tls_key=path("PG_TLS_KEY"),
            allowed_origins=tuple(origin.strip() for origin in env.get("PG_ALLOWED_ORIGINS", "").split(",") if origin.strip()),
        )


def local_environment(path: Path = REPO_ROOT / ".env") -> dict[str, str]:
    """Read simple KEY=value entries without executing shell code; environment wins."""
    values = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            key = key.removeprefix("export ").strip()
            if not separator or not key.replace("_", "a").isalnum():
                raise ValueError("Invalid .env entry")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key] = value
    return {**values, **os.environ}
