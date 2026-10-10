# Teammate B: AGNTCY communication and isolated runtime

Your deliverable is the verified execution environment connecting the gateway and inspection workers. Agents exchange jobs and findings through AGNTCY SLIM, run under enforced restrictions, and use mediated model calls. You also own the authoritative simulated-tool collector.

Read the [system design](system-design.md), especially [the shared contracts](system-design.md#15-four-person-implementation-contracts). Use contract `v1`; do not define alternative result, decision, or permission formats. These are implementation requirements, not features already present in the repository.

## 1. Ownership and boundaries

Own `src/protection_gateway/runtime/`, `src/protection_gateway/bootstrap.py`, root Python package scaffolding, `pyproject.toml`, the dependency lockfile, `deploy/`, `.github/workflows/`, and `tests/runtime/`. You own dependency/version compatibility, application composition, runtime callbacks, fixed worker registration, SLIM delivery, identity validation, isolation, model brokerage, collector events, and cleanup.

A owns policy, schemas, durable decisions, and evidence persistence. C owns deterministic extraction and model-based worker behavior. D owns user interfaces, MCP/chat adapters, and complete-workflow evaluation. You launch their components; do not independently implement their authorization or detector conclusions.

## 2. Start with a compatibility proof

On the team's actual deployment platform, pin and test one gateway → SLIM → worker → result exchange with application-level identity validation. Verify a restricted worker can reach only its assigned resource service, permitted SLIM path, and local model broker.

Do not assume SDK calls or SHADI profiles based on their names. Record actual supported versions and configuration in your PR. Keep one gateway, one SLIM node, and one worker pool; model/collector brokerage remains gateway modules, not extra public services.

SHADI restrictions vary by OS and configuration. Verify them with direct socket, subprocess, filesystem, and scratch-isolation probes. If a desired restriction cannot be enforced, stop activation and report runtime unavailable. A tested stronger OS/VM boundary can be used, but weakening isolation is not an acceptable workaround. Model access stays brokered even in that case.

## 3. Worker lifecycle and SLIM

Maintain a fixed allowlist of worker identity, role, build, prompt version, and entrypoint. Describe it with OASF-compatible role records. No discovery of arbitrary agents, downloaded plugins, or commands from inspected content.

1. Receive an A-issued extraction or inspection assignment.
2. Verify its bindings and provision a short-lived worker-specific resource capability through a private channel.
3. Create fresh scratch space and launch the expected executable under enforced policy. The extractor receives no model or simulated-tool capability.
4. Deliver inspector jobs through SLIM; acknowledge delivery without claiming completion.
5. Authenticate application messages in addition to mesh admission. Check sender role, assignment, attempt, lease, and replay rules before calling A's result validator.
6. Revoke capabilities and terminate the complete process group on expiry, cancellation, or failure. Remove scratch state and record bounded operational metadata.

Treat workers as untrusted processes even with verified identity. They cannot choose another tenant, write storage outside assigned artifacts, receive mailbox/provider keys, modify launcher policy, or invoke production actions. Persisted leases and job decisions belong to A; your runtime respects them during restart and cancellation.

## 4. Model broker and resource access

Expose a local authenticated typed model callback. The broker owns provider credentials and enforces approved provider/model configuration, data-processor permission, caller role, task binding, request size, total token/call budget, timeout, and cancellation. Reject caller-supplied arbitrary endpoints, headers, credentials, or shell commands.

The controlled assistant adapter from D also uses this broker. Workers and adapters cannot contact model providers directly or acquire the provider credential. Different caller roles receive different permitted request/tool schemas. Ordinary traces contain IDs, durations, and reason codes, not prompts or secrets.

Enforce network isolation outside Python hooks and environment proxy settings. Account for local SLIM/resource/broker communication explicitly; direct external connections and arbitrary proxy destinations must fail. Approving an HTTPS port alone does not prove an exact remote-host restriction.

Resource capabilities authorize only the assigned immutable inputs and scoped artifact writes, expire at the earlier of job expiry or five minutes, and are invalid after cancellation. A validates tenant and resource access; you bind runtime identity to those checks. No raw bytes are broadcast to unrelated workers.

## 5. Authoritative simulated-tool collector

Provide C with a typed `simulated_tools.attempt` callback against fake data and dummy state. The callback records both denied and permitted attempts under the assignment's unchanged task policy. A summary task cannot silently become a send task inside the harness.

Record collector-issued `event_id`, scan/run bindings, sequence, operation, dummy argument digest, attempted outcome, policy check, and timestamp. Authenticate events to A through a separate collector identity/channel. C can reference events but cannot write or sign them. Model-generated logs are ordinary artifacts, never authoritative events.

The collector exposes only a fixed dummy tool set and no real network-delivery operation. Its state and keys are inaccessible to workers. Separate a proposed attempt from an executed dummy effect; a clean final model answer must not conceal an earlier forbidden attempt.

## 6. Composition, deployment, and failure behavior

Own the bootstrap wiring: A's core receives your callbacks, your runtime launches C's entrypoints, and D's routers/static interface register through explicit capability checks. Missing components, secrets, unsupported isolation, or required checks keep the relevant routes disabled or returning `SERVICE_UNAVAILABLE`; never substitute successful no-op workers.

Provide a repeatable developer launch and test command using the pinned Python environment. Serve D's static UI from the gateway. Configure restricted volumes, TLS/authentication for any exposed interface, secret injection outside the repository, and no public worker/collector ports. Document the chosen host/VM boundary if OS sandboxing cannot provide the verified requirements inside containers.

CI validates contract/core/runtime/worker/adapter suites as their components land. Label isolation tests that require a particular host and document how they run there; skipped isolation tests are not a production pass. Live model evaluation is separate from deterministic mandatory gates. A broken CI route is not fixed by disabling a security check.

## 7. Required tests and handoffs

- Cross-role, unassigned, stale, duplicate, and impersonated application messages are rejected.
- Membership in SLIM alone cannot submit another worker's finding or collector event.
- Workers cannot read credentials or another job's files, write outside scratch, or use arbitrary network connections, including from child processes.
- Model/resource broker calls reject wrong identity, scope, endpoint, budget, expired token, and canceled job.
- Collector evidence cannot be forged by C; forbidden attempts are visible even with harmless final model text.
- SLIM/broker failure, crash, retry, cancellation, and process-group cleanup cannot yield silent approval or orphaned privileged access.
- Bootstrap refuses to activate a complete workflow when any required capability is missing.

Give A verified callbacks and collector-event examples, C restricted callback implementations and launcher constraints, and D launch/configuration commands plus the broker interface. Root dependency changes requested by teammates go through you.

## 8. Your PR

Use a branch such as `codex/team-b-runtime`. Merge after A, update against A's actual contract implementation, and pass core/runtime contract tests. C/D can work against your callback specification and test doubles before your PR merges.

Include exact versions/platform, commands and results, isolation evidence, disabled capabilities, safe configuration examples, and operational limitations. Ask A to review authority boundaries and C to review its execution environment. Completion requires a verified fixed-roster SLIM round trip and isolation proof; transport success alone is not a completed scanner.
