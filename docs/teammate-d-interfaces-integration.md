# Teammate D: user interfaces, MCP adapter, and end-to-end integration

Your deliverable is the usable system: users submit content, inspect progress and evidence, receive permitted results, and confirm exact simulated actions. You also prove that the four teammates' components form the intended workflow.

Read the [system design](system-design.md), especially [the shared contracts](system-design.md#15-four-person-implementation-contracts). Use contract `v1`; call A's authorization services and B's model broker rather than implementing alternate shortcuts. The backend described here is a contract, not already running code.

## 1. Ownership and boundaries

Own `src/protection_gateway/adapters/`, `web/`, `tests/adapters/`, `tests/integration/`, `tests/evaluation/`, and `tests/fixtures/workflow/`. Own the static user interface, read-only MCP adapter, controlled chat adapter, safe rendering, demo scenarios, integration tests, and evaluation reporting.

A owns authorization, sessions, decisions, durable state, and actions; B owns bootstrap, deployment, identity/runtime, broker/collector, dependencies, and CI; C owns extraction and inspection behavior. Do not duplicate their contracts or edit their paths without review. Ask B to add any shared testing dependency.

Serve simple static browser assets from the gateway; no separate frontend service or build tool is required for the first version. Use explicit HTML text rendering and bounded API results. B wires your routers into the composition entrypoint.

## 2. User journey

1. Sign in through the gateway's authenticated session flow. Coordinate cookie/token handling with A; the browser cannot grant tenant or role authority by request fields.
2. Upload a supported email/text resource through our interface, keeping raw content out of the assistant until A releases an inspected result.
3. Select a supported task and resources. Display which parts/formats are supported and hold relevant unsupported attachments.
4. Start inspection and show real job/check progress. Poll the authenticated status endpoint with bounded backoff, support cancellation, and never invent completed checks.
5. Display `ALLOW_UNDER_POLICY`, `QUARANTINE`, or `REVIEW`, coverage, reason codes, expiry, and source references. Label an allowed result as inspected under the task's policy, not universally safe.
6. Let the user view bounded evidence separately, narrow/reject a task, or request A's recorded read-only exception through the user-only review endpoint. Offer that exception only for fully completed checks with uncorroborated suspicion; incomplete scans, isolation failures, invalid context, and verified quarantine remain blocked. No general “disable protection” or blanket approval control.
7. For a simulated action, display exact recipient, body, attachments, and digest; require confirmation through the user interface. A stores approval and validates execution. Edits require a new proposal/confirmation.

Escape all evidence and model text. Do not execute HTML, automatically load images, activate unvetted links, or send evidence excerpts back into chat/model context. A blocked report returns metadata and references rather than the attack text. Keep private content out of console logs, analytics, browser persistent storage, and error messages.

## 3. Read-only MCP integration

Expose only `inspect_resource`, `get_scan_status`, and `get_inspected_result` at `/mcp`. Map these tools to A's core services so in-process access enforces the same session, resource, tenant, binding, and decision checks as HTTP.

Authenticate the connector and bind its requests to the correct gateway user. Tokens and task-session IDs are not permission to change scope. Tool schemas accept opaque IDs, not arbitrary filesystem paths, provider credentials, or URLs. Resource upload, task selection, raw evidence inspection, and sensitive confirmation happen through the gateway interface.

Test connection and tool metadata against the actual supported Claude/ChatGPT account/workspace configuration. Follow the official links in the master; availability must be verified at integration time. Do not invent a global interception hook.

Show this coverage plainly: our connector protects its own content and tools. Native uploads, pasted content, built-in browsing, other connectors, and the native app's final answer remain outside our enforcement. There are no MCP tools for sending, confirming actions, raw evidence, or unrestricted retrieval in the first release.

## 4. Controlled assistant integration

Expose `/v1/chat` using A's task/result services and B's broker. All submitted supported external content must become an authorized resource and pass ingestion; no raw upload/paste branch can route it directly to the model. Unknown input/tool types remain unavailable.

For the simple policies, keep task orchestration deterministic where possible: select an authorized task, await its decision, then consume permitted structured results. If an LLM proposes an operation, it can only call the registered gated tools. It cannot approve an action, modify policies, contact providers directly, or access storage independently.

Keep planning state limited to task policy and opaque references. Source-reading extraction runs under C/B restrictions. Treat extracted values and generated responses as untrusted data with A-owned disclosure labels. A typed tool argument is still subject to A's semantic authorization checks.

Route every new external tool result back through ingestion and context binding. Do not append a raw tool result to model history first and scan it afterward. No persistent memory, vector index, arbitrary shell, real sending, or remote-image rendering is enabled.

## 5. Integration harness and required scenarios

Use deterministic model doubles and C's reviewed fixtures to prove wiring and mandatory controls. Run the real combined A/B/C services for the full integration gate, including SLIM; an in-process transport double is useful for adapter tests but is not evidence that AGNTCY integration works.

The demo and end-to-end suite cover:

- A legitimate invoice reaches an allowed source-backed result with all required checks complete.
- A suspicious instruction becomes review, with no source text leaked through the public report.
- A forbidden dummy action recorded by B's collector leads to quarantine, even with harmless final model text.
- A deliberate detector miss still cannot expand permissions or execute an unauthorized action.
- Unsupported relevant attachments, timeouts, missing workers, malformed outputs, and runtime outages stay held.
- A resource/task/model/policy/context change invalidates previous results and pending approvals.
- Changed recipients, approval replay, cancellation, and duplicate execution cannot create extra effects.
- Cross-tenant access, malicious markup, report payloads, and evidence links cannot escape their intended boundaries.
- The native MCP adapter stays read-only; the controlled adapter has no ungated tool or raw-input route.

Do not simulate a successful allow result when the backend is unavailable. Show `SERVICE_UNAVAILABLE` or the actual pending state. No browser permission setting or prompt text may replace backend enforcement.

## 6. Evaluation and handoffs

Compare enforcement alone, enforcement plus one inspector, and enforcement plus the three-worker pool on the same tasks and attack budget. This comparison is an evaluation harness mode only; production endpoints cannot select a weaker configuration to bypass required checks.

Measure attack success by objective, legitimate task completion, false blocks, pending reviews, failures/inconclusive tests, latency, and cost. Record versions, model/configuration, cases, repeats, and coverage. Use held-out and adaptive attempts; do not call one successful demonstration proof of general safety. Live model evaluation is reported separately from deterministic mandatory CI.

Return contract problems to A, runtime/launch problems to B, and extraction/detection problems to C. Do not patch around them in the interface. Supply B with commands/test markers for CI, including which full-stack and host-isolation tests must run outside a basic CI container. Ask A and C to review fixture expectations and decision mappings.

## 7. Your PR and final merge

Use a branch such as `codex/team-d-interfaces`. Merge after A, B, and C. Update your branch against their merged implementations, then rerun the complete integration suite and native connector smoke tests against actual configuration.

Your PR includes interface screenshots, exact adapter/integration/evaluation results, coverage limitations, safe launch instructions, and disabled capabilities. A reviews all authority/confirmation flows, B reviews broker/transport integration, and C reviews source/evidence consumption.

Completion means the authenticated user journey works through the actual gateway and AGNTCY runtime, required release gates have evidence, error states stay honest, and the four-owner demo can be repeated. Do not enable real side effects because all four PRs merged; that requires the additional provider-specific gates in the master design.

## 8. Reviewed A public/session contract

Consume the exact [A v1 handoff additions](system-design.md#reviewed-a-v1-handoff-additions-october-10-2026), canonical schemas and generated fixtures. Recover reload sessions with cookie-only GET `/v1/session` plus `X-PG-Session-Resume: 1`, same-origin fetch and no Authorization header. Keep CSRF in memory; latest recovered token wins, no lifetime extension. A stale tab may recover and offer explicit retry; never automatically replay mutations after generic 403. B supplies configured public origin and same-origin transport.

Use A's current `review.eligible` and optional digest, metadata-only status projection, exact preview/digest and source-label union. Render bounded `text_escaped` inertly; do not pass evidence into models. Task scope/context changes call A's seam and invalidate decisions/approvals. Resource deletion is UI/API only and supplies no assistant/MCP deletion tool. All channel/error/response fields follow the master. Add later D integration tests for recovery, header/origin rules, multi-tab rotation, expiry/revocation and protected confirmation. This amendment is A contract review, not proof that D's PR meets its design.
