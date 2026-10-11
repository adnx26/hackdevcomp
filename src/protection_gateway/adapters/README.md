# D: interface implementation and integration handoff

Consumes the [v1 shared design](../../../../docs/system-design.md#15-four-person-implementation-contracts).
Owned changes are `src/protection_gateway/adapters/`, `web/`, and D's test/fixture directories.
No canonical contracts, core policy, worker code, dependencies, bootstrap, deployment, or CI files were changed.

## Current capability

`AdapterApp` is a standard-library ASGI HTTP application for B to compose with A's routes. It serves authenticated static assets at `/ui`, read-only MCP at `/mcp`, and the controlled result workflow at `POST /v1/chat`. There is no frontend build or new Python dependency. The package imports using `PYTHONPATH=src` even before B adds root package scaffolding.

**A/B/C have not been implemented in this checkout. This is D's integration surface, not a working scanner or a passed release gate.** Missing services fail with `SERVICE_UNAVAILABLE`. Successful core/model/transport doubles exist only under tests. There is no demo identity, simulated scan, or successful release fallback in production code.

The UI supports private upload, resource selection, task selection, bounded progress polling, cancellation, retained sources/labels, separate bounded text evidence, recorded read-only review exceptions, and exact simulated action previews/confirmations. Inputs and results never enter browser persistent storage or console logs. No source text goes to controlled chat: it receives only a scan ID and asks A for a currently permitted result. Every evidence/model/result string uses text rendering. CSP disables remote images, arbitrary markup, frames, and off-origin connections.

MCP exposes exactly `inspect_resource`, `get_scan_status`, and `get_inspected_result`. Tokens must authenticate through A's connector mechanism. Progress messages project bounded IDs/enums rather than forwarding rich findings. Released output is retained intact with nested disclosure labels and source spans. No tool exposes upload, policy selection, evidence text, review, approval, sending, credentials, paths, or URL retrieval.

Controlled orchestration is deterministic by default. If B injects a scoped model client, it receives opaque scan references with an empty tool list. Any tool proposal or unsupported response shape remains unavailable; no generated approval is accepted. A revalidates the result again after inference to prevent a canceled, expired, or changed context being released during a slow call. Async dependency calls and incoming-body reads have a 15-second transport timeout. Scan execution remains A/B's durable asynchronous workflow.

The MCP implementation uses stateless JSON Streamable HTTP; GET returns 405 because no SSE subscription is offered. It supports negotiated protocol versions `2025-03-26` and `2025-06-18`, following the [official transport specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports). Actual Claude/ChatGPT connector compatibility and authorization discovery still require account-specific smoke tests and A/B's authentication routes. No general interception hook is claimed.

## A/B composition seam

Construct and mount an `AdapterApp` without stripping `/ui` or `/mcp` from ASGI `scope.path`. B handles ASGI lifespan, TLS, limits/concurrency, secret injection, and the root server. Mount A's `/v1/resources`, `/v1/task-sessions`, `/v1/scans`, `/v1/actions`, and `/v1/evidence` HTTP routes alongside D, routing only `/v1/chat` to D. Route only the named static files; no arbitrary filesystem serving is needed.

| Injected argument | Required behavior |
| --- | --- |
| `core` | A-owned facade with `inspect_resource(context, request)`, `get_scan_status(context, request)`, and `get_inspected_result(context, request)`. Returns A-validated v1 data/error envelopes, including authorization for in-process calls. |
| `authenticate(scope, surface)` | A-owned session/bearer verifier. Returns a trusted A context or `None`; `surface` is `mcp` or `ui`. Never derive tenant/role from request JSON or an unverified header. |
| `verify_csrf(scope, context)` | A-owned verifier for the chat POST; returns exactly `True` after cookie CSRF or authenticated API-token checks. A applies the same protection to its own mutation routes. |
| `session_info(context)` | A's public browser session presentation: exactly `display_name`, `csrf_token`. Tokens stay in page memory. This is served at D's authenticated `GET /ui/session`. |
| `error_status(code)` | A's canonical HTTP error status mapping. Without it, a core error at chat is held with HTTP 503. D does not redefine A's status-code mapping. |
| `model_client_factory(context)` | Optional B-owned factory binding caller, tenant, task authorization, allowed processor, budget, model configuration, and timeout. Returns a broker client exposing `generate(model_request)`. Must not provide caller credentials. |
| `allowed_origins` | Exact external origins, e.g. `("https://gateway.example",)`. Host and any Origin are checked; no origins means unavailable. B must normalize trusted proxy headers before calling D. |
| `sign_in_path` | Optional same-origin A/B sign-in path. Unauthenticated UI shell requests redirect there; no login mechanism is invented by D. |
| `web_root` | Optional installed location of the three static assets; defaults to repository `web/`. |

Callbacks can be asynchronous or immediate synchronous functions; do not pass blocking synchronous I/O into an ASGI event loop. A's facade translates its typed exceptions into canonical public envelopes or bounded `AdapterError`s, never exception text. D passes the authenticated context object unchanged. The broker factory must perform task authorization against current server state when resolving an opaque scan ID. No client-selectable mode, provider, endpoint, model, or tool override is offered.

These are adapter seams, **not duplicate canonical schema definitions**. A has not yet published field-level implementations. A/B must review the following presentation fields against their canonical examples before mounting the interface. If their schemas differ, adapt D to A's canonical validators rather than patching authority checks in D:

| Surface | Fields consumed/sent by D |
| --- | --- |
| Upload | Sends `contract_version`, `media_type` (`text/plain` or `message/rfc822`), `content_base64`. Consumes `resource_id`, `storage_state: STORED`. Raw bytes are retained by A; no extraction runs in D. |
| Task and scan creation | Sends `policy_id`, `resource_ids`; then `task_session_id` and an `Idempotency-Key` header. Consumes opaque `task_session_id`, `scan_id`. |
| Scan status | `scan_id`, `state`, `required_checks`, `completed_checks`, `decision`, `reason_codes`, `expires_at`, `evidence_ids`. Browser coverage uses `coverage.complete`; richer public coverage is displayed as escaped text. IDs use `[A-Za-z0-9_-]{1,128}` in D. |
| Review | Browser consumes A's `review: {eligible, digest}` and recorded `review_exception: {active}`. Sends `outcome: REJECT` or `ALLOW_READ_ONLY`, and the unchanged gateway digest. A must bind it to scan/context/result/expiry and verify eligibility. The UI offers exceptions only with complete checks/coverage and current expiry; the decision remains REVIEW. |
| Evidence | Authenticated, user-only `GET /v1/evidence/{id}` returns bounded `text` (up to 32,000 characters, within the 256 KiB response ceiling). Evidence is never fed to the broker or chat. Copy is an explicit user action. |
| Action proposal | Sends `task_session_id`, `typed_action: {operation: simulate_send, recipient, body, attachment_ids}`. The recipient is explicit user input; A owns origin/disclosure checks. Consumes `action_id`, exact `preview`, unchanged canonical SHA-256 `digest`, and `expires_at`. |
| Confirm/execute | Sends only `digest` to the user-only confirmation endpoint, then an empty v1 request with a fresh execution `Idempotency-Key`. Edits discard the preview; in-flight changed proposals and confirmations cannot execute from the UI. A owns one-use approval, expiry, atomic idempotency, and effects. |
| Controlled chat | Accepts exactly `{contract_version: v1, scan_id}`. Returns the complete A-released result under `data.result`, plus an explicit untrusted marker. Optional broker request is `{operation: describe_inspected_result, input: {scan_id}, tools: []}`; response must be exactly `{text}`. It receives no raw source or released private values. |

Browser requests use same-origin credentials and A's CSRF token for every mutation. The UI retries only explicitly retryable progress reads, with 1–8 second backoff; mutations are never automatically retried. Switching resources/policy suppresses stale responses. Expiry clears released displays and pending previews. Cancellation is available after decision as well, so A can revoke pending capabilities; it cannot undo a completed effect. Relevant MIME attachments stay subject to C's extraction coverage and A's hold decision.

No memory, vector index, arbitrary tool, new external-result path, shell, real delivery, payment, remote-image rendering, or provider credentials are enabled. Future tools need an A-gated executor and must ingest any external result before context use; currently all model tool proposals are rejected.

## Checks and repeatable demo

From the repository root:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests/adapters -v
PYTHONPATH=src python3 -B -m unittest discover -s tests/evaluation -v
PYTHONPATH=src python3 -B -m unittest discover -s tests/integration -v
node --input-type=module --check < web/app.js
```

The first two suites use deterministic doubles. The integration suite is skipped with explicit unavailable messages unless the actual stack/account drivers are configured. B should run the mandatory release command below; it **fails** when missing prerequisites rather than counting skips as a release pass:

```sh
GATEWAY_REQUIRE_FULL_STACK=1 \
GATEWAY_FULL_STACK_FACTORY=your_test_driver:create_real_stack \
GATEWAY_NATIVE_SMOKE_FACTORY=your_account_driver:create_smoke \
PYTHONPATH=src python3 -B -m unittest discover -s tests/integration -v
```

The full-stack driver exposes `transport: SLIM`, `uses_test_transport: False`, `run_scenario(id)`, and `close()`. Each observation returns runtime event IDs, actual component versions, decision where relevant, and a boolean for every listed scenario check. B's driver must actually launch A/B/C, connect the real SLIM node, and obtain those events from authenticated runtime instrumentation. Driver declarations alone do not independently prove transport/isolation. Host-specific isolation checks remain B's mandatory suite, outside a basic container where needed.

The native driver exposes `run()` and `close()`; its observations include an account configuration reference, authenticated connection, exact three-tool inventory, visible coverage, and denied unauthorized access. It must exercise the actual supported account/workspace, not a transport double.

`tests/fixtures/workflow/scenarios.json` inventories 22 proposed cases, including changed bindings, dummy collector telemetry, detector misses, replay, outage, and unsupported attachments. **Expected decisions await A/C review**; the actual-stack gate requires recorded A/C review before treating them as acceptance evidence. No attack/benign inspector fixture or policy decision implementation is duplicated in D.

For a static **test-only** browser demo:

```sh
PYTHONPATH=src python3 -B tests/adapters/preview.py
```

Open `http://127.0.0.1:8765/ui` using gstack `/browse`. This test server supplies a clearly labeled test session and static assets only; backend operations are unavailable. Run `browse eval tests/adapters/ui-browser.js` after page load to exercise 17 browser scenarios with in-page API doubles. The browser harness returns its scenario names and test-double limitation. It is never loaded by production assets. Screenshots under `tests/adapters/screenshots/` show the test-only session, not a live inspection deployment.

## Comparative evaluation

`tests/evaluation/harness.py` compares enforcement alone, one inspector, and the three-worker pool for identical cases, repeat indices/seeds, model/configuration, versions, and attack budgets. Only an offline runner can select comparison modes. No production API exposes them.

Provide a manifest containing `contract_version: v1`, `versions`, `model_configuration`, `attack_budget`, `coverage`, `evaluation_kind: deterministic` or `live`, and `dataset_id`. Record held-out/adaptive coverage accurately. The runner factory returns a callable `(case, mode, repeat, attack_budget)` producing instrumented `decision`, `attack_succeeded`, `task_completed`, `latency_ms`, `cost_usd` (decimal string), and optional `failed`. Objective success comes from instrumentation, not the detector verdict. Unknown measurements remain inconclusive; exceptions are failures without private exception text.

```sh
PYTHONPATH=src python3 -B tests/evaluation/run.py \
  --factory your_offline_driver:create_runner \
  --manifest /tmp/evaluation-manifest.json \
  --cases tests/fixtures/workflow/scenarios.json \
  --repeats 3 --output /tmp/evaluation-report.json
```

Reports separate attack success, legitimate completion, benign quarantines (false blocks), pending reviews, failures/inconclusive objectives, p50/p95 latency and decimal cost. Measurement counts accompany rates/costs so missing data is not silently counted as success or zero spend. Live evaluation uses a separate manifest/report and cannot redefine deterministic contract expectations. No live quality or cost baseline has been measured in this checkout.

## Observed validation (October 10, 2026)

- 34 adapter tests and 7 evaluation tests passed with deterministic doubles.
- 17 gstack browser workflow checks passed. Fresh console/network checks showed no console errors or unexpected requests: only the four same-origin UI/session assets loaded; workflow APIs were mocked in the page. At 375px, the page had no horizontal overflow.
- JavaScript module syntax passed. [Desktop](../../../../tests/adapters/screenshots/ui-desktop.png) and [mobile](../../../../tests/adapters/screenshots/ui-mobile.png) screenshots show the test-only session.
- 2 actual-stack/native-account tests were explicitly skipped because their dependencies are missing. Enabling `GATEWAY_REQUIRE_FULL_STACK=1` correctly failed both gates for those missing dependencies. There is no actual SLIM, host-isolation, native-account, or live-model release evidence yet.

## Final review against D's design

Reviewed the complete change against [D's deliverable](../../../../docs/teammate-d-interfaces-integration.md), with testing, maintainability, security, performance, API, design, and adversarial checks. Findings addressed before the PR:

- Failed result/chat rereads clear previously released content; obsolete request failures cannot invalidate a newer task.
- An unconfirmed cancellation clears local results and capabilities and reports the uncertain gateway outcome.
- Action proposals have independent expiry timers and current-expiry checks before confirmation and execution.
- Upload-library size does not consume a different task's selected-resource budget; count and byte limits apply at task creation.
- One transport deadline covers the whole incoming request body, preventing each chunk from extending the deadline. Static assets are loaded at app construction rather than blocking on disk per request.
- MCP protocol `_meta` is accepted as metadata on supported methods without becoming authority or tool arguments.
- The evidence dialog has an accessible name. Evidence, released values, and model strings remain inactive text.
- Each evaluation invocation receives isolated case/budget inputs, so adaptive runner mutations cannot alter subsequent comparisons or exported provenance.

| D requirement | Reviewed state |
| --- | --- |
| Static authenticated UI and safe content/result/action workflows | Implemented; deterministic browser coverage passes. A's actual session and policy services remain required. |
| Three read-only MCP tools and explicit native coverage limits | Implemented; adapter tests pass. Real account authentication/discovery and smoke test remain required. |
| Controlled reference-only assistant and broker seam | Implemented; deterministic and injected-broker tests pass. B's actual scoped broker remains required. |
| Workflow fixtures and full-stack release harness | 22 proposed scenarios and mandatory gates implemented. A/C expectation review and actual A/B/C + SLIM execution remain required. |
| Comparative objective/latency/cost reporting | Implemented and tested offline. Held-out/adaptive live evaluation and measured baselines remain required. |
| Screenshots, commands, limitations, review handoff | Included here and in the PR. Merge follows A, B, and C; authority/runtime/source-consumption review is still required. |

**D's local implementation is ready for a draft integration PR. The design's final completion condition is not met:** the authenticated four-owner journey, AGNTCY transport, native account, host isolation, and repeatable combined demo cannot run until A/B/C land. Do not merge or present deterministic doubles as release evidence.

## Remaining release handoff

- A: supply canonical facade/HTTP examples, authenticated session and CSRF flow, exact review/action bindings, disclosure-preserving outputs, and review the authority paths.
- B: compose routers/static assets; pin the actual compatible dependencies; bind the broker; supply real-SLIM/account launch drivers and host-isolation/CI commands. No deployment or CI change is included in D.
- C with A: review workflow expectations, connect actual extraction/inspector fixtures, and review source/evidence consumption.
- After A → B → C land: update D against their implementations, run the real-stack/native/host gates and live evaluation, and review recorded evidence together. Real effects remain disabled even after integration.
