# Teammate A: gateway, storage, and policy enforcement

Your deliverable is the gateway's trusted core. It accepts authorized resources, tracks inspections, decides whether content can be released, and gates simulated actions. Agents can supply evidence; only your code can change job state, release content, or authorize an effect.

Read the [system design](system-design.md), especially [the shared contracts](system-design.md#15-four-person-implementation-contracts). Contract version is `v1`. This assignment implements that design; it does not replace it. The existing repository contains documentation, not working interfaces.

## 1. Ownership and boundaries

Own `src/protection_gateway/contracts/`, `src/protection_gateway/core/`, `tests/contracts/`, and `tests/core/`. You own canonical schemas, fixtures, task-policy definitions, authenticated resource/task/scan/action APIs, durable metadata, restricted storage, and public status/error mapping.

Do not edit B's dependency locks, bootstrap, deployment, or CI; C's extractor/agent code; or D's UI, chat, and MCP adapters. The production simulated-tool collector belongs to B inside the gateway runtime. You accept its authenticated events and persist them separately from untrusted worker artifacts.

Expose core service functions used by both HTTP and D's MCP adapter. They must perform the same authorization checks, including when called in process. Accept runtime callbacks by dependency injection so the core works with B's implementation and test doubles without importing C or D.

## 2. Build the trusted workflow

1. Authenticate requests and derive user/tenant from verified session context. For the demo, use a configured server-side test identity mechanism; do not accept a user-controlled tenant header as authority. Coordinate browser-session authentication with D and configuration with B.
2. Accept bounded supported uploads. Store immutable original bytes and hashes privately. Have B run C's extractor in a restricted subprocess; do not import and run parsers in the privileged gateway process.
3. Create user-owned task sessions with `summarize_email`, `extract_invoice`, or `simulate_send` policies. Bind resources, context version, expiry, and disclosure constraints. Task classification may suggest a selection, never grant capabilities.
4. Persist scan jobs, required checks, worker assignments, budgets, leases, and cancellation. Dispatch through B after complete extraction. Delivery receipts are not inspection results.
5. Accept only authenticated, correctly assigned results. Validate contract version, resource/view hashes, worker build/prompt versions, policy/model/context bindings, limits, and duplicate/replay rules.
6. Compute decisions using the master's decision table. All required checks must complete before `ALLOW_UNDER_POLICY`. Suspicions produce review; a confirmed forbidden dummy action must reference B's authoritative collector evidence.
7. Release only an active task-bound result to its authorized user. Recheck bindings at retrieval and before every action. Changes, cancellation, expiry, or an incomplete inspection withhold content.

Implement the user-only review endpoint and record eligible exceptions with user identity, permitted result/digest, resources, context, reason, and expiry. Eligibility requires complete extraction and all required inspections with only uncorroborated suspicion remaining. Missing coverage, isolation failure, invalid bindings, verified quarantine, and expired context cannot be overridden. It cannot waive tenant checks, disclose unrelated data, or approve an action. Quarantine never deletes the original mailbox item.

## 3. Storage and evidence

Use SQLite for durable metadata and a separately permissioned encrypted evidence volume as specified in the master. Do not place raw content, model output, tokens, or evidence excerpts in ordinary logs. Every metadata and object lookup enforces tenant and resource access; opaque IDs are not authorization.

Store original and extracted hashes, source maps, inspected resource-set/context hashes, versions, and expiry. Source/disclosure labels are server-owned and survive derivation and formatting. Combining private fields must not produce a public result merely because an agent calls it a summary.

Separate worker artifacts from authoritative collector records. A worker-supplied `event_id` is a reference to validate, not proof. The authenticated user evidence endpoint returns bounded escaped text to D's viewer and is never exposed as an assistant tool.

Implement retention cleanup, token revocation, durable event history, and lease recovery. A crash or an exhausted retry must not turn incomplete coverage into approval. Cancellation prevents late findings from releasing content. Define backup/log expiry together with B; do not promise immediate deletion from immutable backups.

## 4. Simulated-action gate

Implement the propose → exact preview → user confirmation → execute sequence in the shared API. Only the user-owned interface/session can confirm; an LLM-generated approval string cannot. Protect cookie-authenticated mutation endpoints against CSRF and coordinate the authenticated session flow with D.

Verify exact recipient, body and attachment hashes, task permissions, current context, origin/disclosure rules, one-use approval, expiry, and cancellation. Changing an argument invalidates approval. Document-supplied addresses remain untrusted until approved by user selection or a trusted contact source.

The initial executor changes dummy state only. Use durable idempotency and atomic simulated updates. Include the future `UNKNOWN_OUTCOME` reconciliation path in the action contract; never add a real email provider as a convenient fallback. Reading a source, allowing a scan, and confirming an action are separate authorizations.

## 5. Handoffs

Publish canonical schema examples and contract fixtures early. B needs extraction/dispatch/result callbacks, job-token validation, resource access, cancellation, and collector-event storage. C needs exact assignment/result fields, source-span conventions, output schemas, and allowed evidence references. D needs endpoint/error examples, authentication/session behavior, result disclosure rules, and confirmation semantics.

Your fixtures cover allowed, suspicious review, collector-backed quarantine, incomplete, canceled, stale-context, cross-tenant, and action-replay outcomes. Put fixtures in your owned test paths; other owners consume them rather than inventing different enums or fake approval states.

## 6. Required tests and acceptance

- Unauthorized user/tenant lookups cannot read resources, scans, artifacts, or collector events.
- Upload/extraction limits and unsupported task-relevant parts withhold release.
- Duplicate, stale, forged, wrongly assigned, canceled, or malformed worker results cannot satisfy completeness.
- Worker/model claims cannot forge collector evidence, expand policies, or remove disclosure labels.
- Missing workers, timeouts, runtime outages, and restarts never create approval.
- Changed task/resource/model/policy/context bindings invalidate cached results and pending approvals.
- A real user must confirm the exact simulated action; edits, expiry, cancellation, and replay fail.
- Idempotent simulated execution records one effect; ambiguous future-provider outcomes require reconciliation.
- Private content stays out of status endpoints and ordinary logs; cleanup revokes related access.

Use deterministic test doubles for runtime/model behavior. A runtime double belongs in tests only. Keep schema/core-service tests runnable with the standard library and `PYTHONPATH=src` before B's root package setup arrives; do not import unavailable composition code in those tests. Without B, actual extraction/dispatch endpoints return `SERVICE_UNAVAILABLE` and release no content.

## 7. Your PR

Use a branch such as `codex/team-a-gateway`. Your PR merges first and supplies the canonical contracts plus the trusted core. Share API/fixture examples before the final PR so the others can work in parallel.

Include owned paths, `v1` compatibility, exact tests/results, disabled capabilities, and configuration requirements without secrets. Ask B to review runtime callbacks and D to review public/authentication contracts. After changes requested by their review, update the canonical examples rather than leaving teammates to infer behavior.

Completion means the core's authority and state-transition tests pass, missing runtime capability fails closed, and B/C/D can consume the published contracts. It does not mean the complete scanner or a production email integration is ready.

## 8. Reviewed v1 handoff clarification

Implement the exact [A v1 handoff additions](system-design.md#reviewed-a-v1-handoff-additions-october-10-2026), including cookie-only recovery with origin/header rules, current status eligibility, private diagnostic projection, pinned extraction version, commit-time worker authority, and the A/B retention policy. Canonical fixtures must match the final core. The merge audit records independent role-review provenance and separates proposal approval from deployment proof. No later PR is verified by this amendment.
