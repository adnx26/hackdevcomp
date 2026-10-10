# Runtime deployment notes (teammate B)

Contract consumed: `v1`. This is the verified execution environment only. It is **not** a
completed scanner: A's core, C's workers and D's adapters are not in this branch, and the
gateway reports `complete_workflow: unavailable` until they are.

## Verified platform and versions

Everything below was run on one machine. Other platforms are unverified.

| Item | Value |
|---|---|
| Host | macOS 26.4.1 (25E253), Apple silicon (arm64) |
| Python | 3.14.5 (Homebrew); `requires-python >=3.11` |
| SLIM | `slim-bindings==2.2.0` (reports runtime 3.0.1), in-process node on loopback |
| Sandbox | Seatbelt via `/usr/bin/sandbox-exec`, deny-by-default profile generated per job |
| SHADI | `shadictl` 0.2.0 tested and **rejected on macOS** (see below) |
| Model SDK | `anthropic==1.8.0` (optional extra; deterministic tests use a double, no live call was made) |
| Tests | `pytest==8.4.2` |

`requirements.lock` is the hashed lock for all of the above (`make lock` regenerates it with `uv`).

## Commands

```sh
make setup            # venv + hashed install + editable package
make test             # deterministic gates: 38 tests, no sandbox host, no live model
make test-isolation   # 12 host-specific tests; a skip is a failure (PG_REQUIRE_ISOLATION=1)
make check            # capability status as JSON; exits 1 unless the complete workflow is available
make run              # serve (configuration: deploy/gateway.env.example)
```

Result on the host above: `50 passed` with `PG_REQUIRE_ISOLATION=1`. `make check` exits 1 and
reports `isolation` and `slim` available; `core`, `model_broker`, `collector`, `extraction`,
`inspection`, `adapters`, `static_ui` and `complete_workflow` unavailable, each with a reason.

CI (`.github/workflows/ci.yml`) has not run yet. It defines a deterministic job on Ubuntu and
an isolation job on a macOS arm64 runner. Neither runner has been confirmed to pass; the
isolation job fails rather than skips if the sandbox cannot be verified there.

## Compatibility proof

Gateway → SLIM → worker → result, with application-level identity, is exercised by
`tests/runtime/test_end_to_end.py::test_fixed_roster_slim_round_trip`:

1. The gateway matches the assignment against the fixed roster and issues a grant.
2. The worker is launched in the sandbox; its grant arrives on its stdin pipe.
3. The job is delivered over a SLIM point-to-point session; the receipt says `DELIVERED`.
4. The worker reads its assigned input, calls the model broker, and publishes a result.
5. The gateway authenticates the message (per-attempt HMAC, sender, assignment, attempt,
   replay, lease) and only then calls `core.accept_worker_result(verified_identity, result)`.
6. Capabilities are revoked, the process group is killed and scratch is removed.

## Isolation evidence

Activation (`Sandbox.verify`) runs these probes inside the sandbox, from the worker process
and again from a child process. All must behave exactly as listed or the runtime is unavailable.

| Probe | Required | Observed (Seatbelt backend) |
|---|---|---|
| Connect to the one granted loopback port | allowed | OK |
| Write in the job's scratch directory | allowed | OK |
| Import `hashlib`, `hmac`, `ssl`, `urllib` | allowed | OK |
| Connect to another listening loopback port | denied | PermissionError |
| Connect to `1.1.1.1:443` | denied | PermissionError |
| Resolve and connect to `example.com:443` | denied | gaierror |
| Read / write another job's files | denied | PermissionError |
| Read a credential file in gateway state | denied | PermissionError |
| Read configured secret files (`PG_*_KEY_FILE`) | denied | probed when configured |
| List the home directory | denied | PermissionError |
| Write outside scratch | denied | PermissionError |
| List / write the system temp directory | denied | PermissionError |

The end-to-end tests repeat this from real worker entrypoints: a "rogue" inspector and its
child process cannot reach the network, another local service, a key file, another job's file,
the gateway's environment, or `curl`; the extractor cannot connect to the broker or SLIM ports.

### SHADI finding

`shadictl --profile strict --net-block --net-allow 127.0.0.1:<port>` enforced the network and
most filesystem restrictions on this host, including for child processes. It left the per-user
temp directory (`/private/var/folders/.../T`) listable and writable, and `--deny` (as a path, a
parent, or the canonical path) did not close it. That fails the "write outside scratch" and
"other job" requirements whenever anything sensitive lives there, so the `shadi` backend is
rejected by the probes on macOS (`test_shadictl_strict_profile_alone_is_not_sufficient_on_macos`).
Seatbelt is the mechanism SHADI itself uses on macOS; the gateway applies it directly with a
stricter profile. Seatbelt and `shadictl` cannot be nested. The `shadi` backend remains
selectable (`PG_SANDBOX_BACKEND=shadi`) for hosts where its probes pass; Linux is untested.

## Configuration

See `deploy/gateway.env.example`. Secrets are file paths injected by the host. The provider key
is read only by the gateway process; workers get a fresh environment and no key. The SLIM node,
resource service and broker bind ephemeral loopback ports only; there are no public worker or
collector ports. The public listener refuses a non-loopback address without TLS files.
`PG_STATE_DIR` must not be under the system temp directory.

## Disabled or unavailable in this branch

- `core`, `collector`, `extraction`, `inspection`: need A's core port (below) and C's entrypoints.
- `model_broker`: needs `PG_MODEL_PROVIDER` and a key file. Only the Anthropic provider is implemented.
- `adapters`, `static_ui`: need D's package and `web/index.html`.
- Real sending, payment, shell execution, agent discovery: not implemented anywhere here.

## Operational limitations

- One verified host. Linux, containers and Intel macOS are unverified; activation decides.
- `sandbox-exec` is marked deprecated by Apple. It works on macOS 26.4.1; a VM boundary is the fallback.
- SLIM on loopback uses no TLS and a per-process shared secret for admission, with MLS off.
  AGNTCY Identity (DID/SPIRE) is not integrated; worker identity is the per-attempt key the
  gateway issues at launch. Another local user with root could observe loopback traffic.
- Cleanup kills the worker's process group. A process that calls `setsid()` leaves the group; it
  stays sandboxed, its capabilities are revoked and its scratch is deleted, but it is not killed.
- The Seatbelt profile imports Apple's `system.sb` baseline and reads the interpreter's install
  tree (on Homebrew: the Python keg and the OpenSSL/xz/zstd library directories).
- Grants and the canceled-scan list are in memory. After a restart, leftover worker groups are
  killed and scratch is deleted; A's persisted leases decide what is retried.
- OASF records (`WorkerRecord.to_oasf`) are OASF-shaped but not validated against a schema server.
- The token budget is checked before each call and charged after it, so one call can overshoot.
- Server-side model fallbacks are intentionally off: a fallback would run a model other than
  the one bound into the scan's model-configuration hash.

## Interfaces handed to teammates

**A (core).** `runtime.extract(assignment) -> extraction_result`, `runtime.dispatch(assignments)
-> receipts` (`DELIVERED` / `REJECTED` / `FAILED` + `reason_code`), `runtime.cancel(scan_id)`,
`runtime.model_configuration()` (the hash to bind into assignments). When unavailable they raise
`RuntimeUnavailable` (`code == "SERVICE_UNAVAILABLE"`). A failed extraction returns
`{"status": "ERROR", "reason_code": "RUNTIME_..."}`, never `COMPLETE`. The core object must provide:

```python
accept_worker_result(verified_identity, worker_result)
record_collector_event(verified_collector_identity, event)
read_assigned_input(verified_identity, assignment_id, resource_id, view_id) -> bytes
store_worker_artifact(verified_identity, assignment_id, name, data) -> artifact_id
check_simulated_operation(policy_binding, operation, arguments) -> bool
model_processing_permitted(binding, provider) -> bool
assignment_active(assignment_id, attempt) -> bool                 # optional (leases)
report_runtime_failure(assignment_id, attempt, reason_code)        # optional
```

Assignment keys the runtime reads (to be aligned with A's canonical schema on rebase):
`assignment_id`, `scan_id`, `attempt`, `deadline`, `worker_identity`, `worker_role`,
`worker_build`, `prompt_version`, `model_configuration_hash`, `policy_id`, `policy_version`,
`policy_hash`, `task_session_id`, `task_scope_version`, `resources: [{resource_id, view_id, hash}]`.

Collector event example (`signature` is checked with `runtime.collector.verify(event)`):

```json
{"contract_version": "v1", "event_id": "evt_3f1c…", "scan_id": "scan-3", "run_id": "run_9ab2…",
 "assignment_id": "asg-3", "sequence": 1, "operation": "send_email",
 "argument_digest": "<sha256 of canonical arguments>", "attempted_outcome": "DENIED",
 "policy_check": "FORBIDDEN", "timestamp": "2026-10-10T22:19:40.512Z", "signature": "<hmac>"}
```

Outcomes: `DENIED` (forbidden, malformed or unknown operation), `PROPOSED` then `EXECUTED_DUMMY`
(permitted; two events). Arguments are never stored, only their digest.

**C (workers).** Entry points are called as `extract(assignment, restricted_io)` and
`inspect(assignment, restricted_io, model_client, simulated_tools)`; the expected module paths
and prompt versions are in `runtime/roster.py` (`DEFAULT_ROSTER`) — tell B if they differ.
`restricted_io.read(resource_id, view_id=None) -> bytes`, `.write_artifact(name, data) -> id`
(name `[A-Za-z0-9._-]{1,64}`, 2 MiB, 32 per job), `.scratch_dir`. `model_client.generate(request)`
and `simulated_tools.attempt(operation, arguments)` raise `CallbackError(code)` on refusal.
Constraints: standard library plus the pinned packages only; no network except the callbacks;
only the interpreter can be executed; `HOME`/`TMPDIR` are the scratch directory; a job lives at
most five minutes. `tests/runtime/sandbox_workers/` shows working (test-only) entrypoints.

**D (adapters).** `protection_gateway.adapters.register(gateway)` mounts routes with
`gateway.mount(prefix, wsgi_app, requires=(...capabilities))`; static assets in `web/` are served
at `/ui`. Model calls go through `gateway.runtime.assistant_model_client(task_session_id,
binding=...)`. Model request (any other field is rejected):

```json
{"contract_version": "v1", "system": "…", "max_output_tokens": 1024, "tool_profile": "none",
 "messages": [{"role": "user", "content": "…"}]}
```

Response: `{contract_version, stop_reason, content: [blocks], usage: {input_tokens, output_tokens}}`.
Treat `stop_reason` of `refusal` or `max_tokens` as incomplete. Echo `thinking` blocks back
unchanged on the next turn. Assistant tool schemas are registered at composition time with
`broker.register_assistant_tool_profile(name, tools)`.
