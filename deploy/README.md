# Runtime deployment notes (teammate B)

Contract consumed: `v1`. This is the verified execution environment only. It is **not** a
completed scanner: A's core does not exist yet, and C's workers and D's adapters live on their
own branches (`codex/team-c-inspectors`, `codex/team-d-interfaces`). On this branch alone the
gateway reports `complete_workflow: unavailable`.

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
| Root server | `uvicorn==0.53.0` (ASGI, because D's adapters are an ASGI application) |
| Tests | `pytest==8.4.2` |

`requirements.lock` is the hashed lock for all of the above (`make lock` regenerates it with `uv`).

## Commands

```sh
make setup            # venv + hashed install + editable package
make test             # deterministic gates: 47 tests, no sandbox host, no live model
make test-isolation   # 13 host-specific tests; a skip is a failure (PG_REQUIRE_ISOLATION=1)
make check            # capability status as JSON; fails unless the complete workflow is available
make run              # serve (configuration: deploy/gateway.env.example)
```

Result on the host above: `60 passed` with `PG_REQUIRE_ISOLATION=1`. `make check` fails (the
Python command exits 1, so `make` exits 2) and reports `isolation` and `slim` available; `core`,
`model_broker`, `collector`, `extraction`, `inspection`, `adapters` and `complete_workflow`
unavailable, each with a reason. `make run` was started once on loopback: `/v1/scans` answered
503 `SERVICE_UNAVAILABLE`, an unknown path 404, and Ctrl-C shut it down cleanly.

Only Python 3.14.5 was exercised. The package declares 3.11+ and CI uses 3.12; neither was run.

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

### Check against C's and D's real code

Not part of the committed tests (their code is on other branches), but run once locally with
C's `workers/` and D's `adapters/` + `web/` overlaid on this branch, a core double and a model
double, in the real sandbox over the real SLIM node:

- C's extractor produced a `COMPLETE` extraction of a MIME email (two views).
- C's three inspectors (`instruction`, `data`, `behavior`) each returned `COMPLETE`.
- The scripted model proposed a forbidden `send_email` and then gave a harmless summary; the
  collector recorded the denied attempt and C's result carried `OBSERVED_FORBIDDEN_ACTION`
  referencing that event id.
- D's `AdapterApp` mounted at `/ui`, `/mcp` and `/v1/chat` and answered 401 (no session) and
  403 (wrong host); `/v1/scans` stayed 503 because A's routes do not exist.

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

Checked once by hand and not part of the startup probes: UDP, inbound listening, Unix-socket
connections and running `/bin/sh`, `security` or `osascript` are denied; `/etc/hosts`, `/usr/bin`,
the repository and keychain directories are unreadable. `/etc/passwd` **is** readable (Apple's
`system.sb` baseline allows it), and `setsid()` succeeds.

The end-to-end tests repeat the probes from real worker entrypoints: a "rogue" inspector and its
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

- `core`, `collector`, `extraction`, `inspection`: need A's core port (below) and C's package.
- `model_broker`: needs `PG_MODEL_PROVIDER` and a key file. Only the Anthropic provider is implemented.
- `adapters`: need D's package, the three `web/` assets, `PG_ALLOWED_ORIGINS`, and a core that
  provides `authenticate`.
- D's optional assistant model call: no `model_client_factory` is injected, so D's controlled
  chat runs in its deterministic mode. D's request carries only a scan id; what the model may be
  shown for that scan has to be agreed between A, B and D before the broker serves it.
- Tenant-level model quotas: budgets are per job only.
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
- OASF records (`WorkerRecord.to_oasf`) name schema version 0.7.0, which exists, but the field
  layout was written from memory and has not been validated against the OASF schema.
- `deploy/fetch_shadictl.sh` passes a shell syntax check but has never been executed.
- No service definition or volume configuration is provided beyond the env example; the state
  directory is created with mode 0700. The public listener relies on A and D for authentication.
- Leases are respected across restart only if A provides `assignment_active`.
- The token budget is checked before each call and charged after it, so one call can overshoot.
- Server-side model fallbacks are intentionally off: a fallback would run a model other than
  the one bound into the scan's model-configuration hash.

## Interfaces handed to teammates

Where C and D had already published provisional shapes on their branches, the runtime follows
them. What remains B-defined is marked "provisional" and needs A's review.

**A (core).** `runtime.extract(assignment) -> extraction_result`, `runtime.dispatch(assignments)
-> receipts` (`DELIVERED` / `REJECTED` / `FAILED` + `reason_code`; provisional),
`runtime.cancel(scan_id)`, `runtime.model_configuration()` (the hash to bind into assignments).
When unavailable they raise `RuntimeUnavailable` (`code == "SERVICE_UNAVAILABLE"`). A failed
extraction returns `{"extraction_status": "ERROR", "reason_codes": ["RUNTIME_..."]}`, never
`COMPLETE`. The core object must provide (the last four are B's additions to the contract table):

```python
accept_worker_result(verified_identity, worker_result)
record_collector_event(verified_collector_identity, event)
read_assigned_input(verified_identity, assignment_id, resource_id, view_id | None) -> bytes
store_worker_artifact(verified_identity, assignment_id, artifact: dict) -> artifact_id
check_simulated_operation(policy_binding, operation, arguments) -> bool
model_processing_permitted(binding, provider) -> bool
assignment_active(assignment_id, attempt) -> bool                 # optional (leases)
report_runtime_failure(assignment_id, attempt, reason_code)        # optional
```

For D's adapters the bootstrap also reads `authenticate`, `verify_csrf`, `session_info` and
`error_status` from the core object and passes them to `AdapterApp`. Composition hooks
`protection_gateway.core.build_core(runtime=...)` and `register(gateway)` are provisional.

Assignment keys the runtime itself reads: `assignment_id`, `scan_id`, `attempt`, `deadline`,
`worker_identity`, `worker_role`, `worker_build`, `prompt_version`, `model_configuration_hash`,
`policy_id`, `policy_version`, `policy_hash`, `task_session_id`, `task_scope_version`, `run_id`
(behavior), `resources: [{resource_id, original_hash}]` (extraction) and
`views: [{resource_id, view_id, view_hash}]` (inspection). `view_hash` is SHA-256 of the view's
UTF-8 text. Everything else in an assignment is passed to the worker untouched.

Collector event example (`signature` is checked with `runtime.collector.verify(event)`;
`assignment_id`, `contract_version` and `signature` are B's additions to the contract's list):

```json
{"contract_version": "v1", "event_id": "evt_3f1c…", "scan_id": "scan-3", "run_id": "run-A",
 "assignment_id": "asg-3", "sequence": 1, "operation": "send_email",
 "dummy_argument_digest": "<sha256 of canonical arguments>", "attempted_outcome": "DENIED",
 "policy_check": "FORBIDDEN", "timestamp": "2026-10-10T22:19:40.512Z", "signature": "<hmac>"}
```

Outcomes: `DENIED`/`FORBIDDEN` (forbidden, malformed or unknown operation), or `PROPOSED` then
`EXECUTED_DUMMY` with `ALLOWED` (two events). Arguments are never stored, only their digest.
`run_id` is the assignment's when A supplies one.

**C (workers).** The roster launches `protection_gateway.workers:extract` and `:inspect` with
roles `extractor`, `instruction`, `data`, `behavior`, builds `c-extractor-1` / `c-workers-1` and
prompts `c-prompts-1`, as in C's handoff. Callbacks:

- `restricted_io.read_resource(resource_id) -> bytes` (extractor only),
  `read_view(resource_id, view_id) -> {"text": str}` (inspectors only),
  `write_artifact(mapping) -> id` (2 MiB, 256 per job), `.scratch_dir`.
- `model_client.generate(request) -> dict`: accepts C's inspection request (`contract_version`,
  `bindings`, `prompt_version`, `system`, `task_policy`, `documents`, `signals`, `history`,
  `response_contract`, `fake_confidential_data`, `tools`) and nothing else. `bindings` must match
  the caller's own assignment; `tools` must be empty except for `behavior`. The broker sends
  `system` plus the JSON payload to the model and returns its reply parsed as one JSON object.
  Refusals, truncated output and non-JSON replies raise instead of returning.
- `simulated_tools.attempt(operation, arguments) -> receipt`: the recorded event without its
  signature (`event_id`, `scan_id`, `run_id`, `sequence`, `operation`, `dummy_argument_digest`,
  `attempted_outcome`, `policy_check`, `timestamp`), plus `result` and, when executed,
  `proposed_event_id`. The fixed dummy tool set is `read_email`, `send_email`, `delete_email`,
  `read_file`, `fetch_url`, `make_payment` (B's choice; anything else is recorded as denied).

Refusals raise `CallbackError(code)`. Constraints: standard library plus the pinned packages
only; no network except the callbacks; only the interpreter can be executed; `HOME`/`TMPDIR` are
the scratch directory; a job lives at most five minutes.

**D (adapters).** The root is an ASGI application served by uvicorn. `AdapterApp` is constructed
with `core`, `authenticate`, `verify_csrf`, `session_info`, `error_status` (from A's core),
`allowed_origins` (`PG_ALLOWED_ORIGINS`) and `web_root`, and receives `/ui*`, `/mcp` and
`/v1/chat` with the path intact. TLS, the lifespan and the listener are B's. `sign_in_path` and
`model_client_factory` are not supplied yet (see "Disabled or unavailable").
