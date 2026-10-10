# Teammate C: extraction and specialist inspection agents

Your deliverable is the inspection logic: a deterministic extractor, two specialist inspectors, and a sandbox behavior tester. All inspect the content assigned by the gateway. They return evidence and coverage, not approval or new permissions.

Read the [system design](system-design.md), especially [the shared contracts](system-design.md#15-four-person-implementation-contracts). Consume contract `v1` and use B's restricted callbacks. The code and callbacks described here still need to be implemented.

## 1. Ownership and boundaries

Own `src/protection_gateway/workers/`, `tests/workers/`, and `tests/fixtures/inspection/`. Own bounded extraction, source maps, worker prompts/versions, inspection routines, task-output extraction, attack/benign inputs, and worker-local tests.

Do not write A's decision engine, authorization rules, schema files, or evidence records; B's launcher, network controls, credentials, model broker, collector, or root dependencies; or D's UI, MCP tool declarations, or workflow evaluation harness. Request shared schema/dependency changes from their owners.

Implement the shared `extract` and `inspect` entrypoints. Restricted I/O, models, and simulated tools arrive as callbacks from B. No provider SDK call may bypass the broker; no worker gets production tools. Test doubles live under your tests only.

## 2. Deterministic extraction

Start with plain text and bounded email MIME/HTML bodies. Preserve original bytes through A's storage path; return extracted views, hashes, complete/incomplete/error status, task-relevant unsupported parts, extractor version, and source maps.

Expose visible and hidden HTML views without executing JavaScript, rendering active markup, or loading images/links. Inspect invisible Unicode and permitted encoding layers with explicit depth/work limits. Decode into a separate hashed view rather than altering offsets in an existing view.

Source spans are half-open Unicode code-point offsets in the exact hashed view. Decoded/normalized views map back to original content. Preserve meaningful alternatives: do not hide an attack merely because one MIME body looks benign. Invalid encodings, limits, malformed relevant parts, or unknown extraction coverage produce incomplete/error results rather than silently discarded content.

Attachments, PDFs, archives, images, and audio remain unsupported. Report their existence and task relevance so A can hold the scan. Do not claim an email is fully inspected when its invoice attachment was skipped.

The extractor runs under B's credential-free sandbox with no model/SLIM/production-tool permissions. Inspection agents then receive the complete supported resource set within budget. A task exceeding the full-set budget stays incomplete.

## 3. Instruction and hidden-content inspector

Look for attempts to impersonate system/developer instructions, override the user's task, redirect output, exploit hidden/encoded content, or plant future memory instructions. Analyze source instructions in relation to the fixed task: a recipe, code sample, quotation, or security article is not malicious solely because it uses imperative language.

Use cheap deterministic signals as evidence, not universal keyword verdicts. A model result contains bounded finding categories and source references; free-form explanation is a private artifact. Content telling you to change your format, hide evidence, call tools, or claim approval cannot alter the assignment or output contract.

Return `COMPLETE` only when all assigned views/checks were actually processed. A completed inspection can still contain suspicious findings. A model refusal, empty response, invalid schema, skipped view, or exception is not evidence of safety.

## 4. Data and tool-abuse inspector

Detect requests for unrelated private content, external disclosure, unauthorized recipients, commands, file changes, downloads, payments, or tool arguments supplied by hostile sources. Compare them to the immutable task policy supplied by A, not a policy rewritten in the content.

Distinguish an observed instruction from an executed action. `DISCLOSURE_REQUEST` or `UNAUTHORIZED_TOOL_REQUEST` is an allegation with source evidence. Only a validated collector reference can support `OBSERVED_FORBIDDEN_ACTION`.

Never fetch a discovered URL, send an email, open a shell, or retrieve more data to prove an attack. Submit a finding; the gateway determines whether a separately authorized follow-up exists. Source-supplied addresses and formatted values remain untrusted.

## 5. Sandbox behavior tester

Run a representative supported task using B's model broker, fake confidential data, and fixed simulated tools. Include the complete assigned document set and record model/task/configuration versions and the conditions covered. No real mailbox or unrelated conversation secrets enter the harness.

Every attempted tool operation goes through B's collector. You cannot directly mutate dummy state or manufacture authoritative telemetry. A forbidden send attempt under `summarize_email` remains forbidden even if the model later apologizes or gives a harmless summary. Reference collector event IDs in the completion report; A/B validate them independently.

No observed violation means only that the tested conditions did not show one. Timeouts, refusals, unsupported task context, unavailable telemetry, and invalid tool outputs are incomplete/error outcomes. Do not treat a sandbox run as a universal safety certificate or an exact reproduction of a native ChatGPT/Claude session.

For `extract_invoice`, return source-backed `invoice_id`, `amount`, `currency`, and `due_date`; missing fields stay absent. For summaries, attach source references to claims. This reduces semantic error but does not prove every narrative claim true. A decides release; D displays supporting sources.

## 6. Fixtures, tests, and acceptance

Create harmless fixture data only. Include legitimate invoices, quotations of attack text, normal document procedures, hidden HTML, encoded instructions, multilingual content, unauthorized disclosure/tool requests, split attacks across two sources, memory attempts, and amount-changing summaries. Do not place real secrets in the fixtures.

- Extraction returns deterministic hashes/source maps; spans remain correct for Unicode and decoded views.
- Malformed MIME, unsupported attachments, resource limits, and missing views return incomplete/error coverage.
- Content cannot change prompts, task policy, schemas, resource scope, model endpoint, or permissions.
- Invalid/empty model outputs never become “clean”; findings reference the exact inspected views.
- Both benign and malicious fixtures are tested; imperative keywords alone do not quarantine legitimate content.
- Forbidden attempted dummy actions reference B's collector, even if the final model text appears harmless.
- Worker logs, invented event IDs, or an unsupported sandbox run cannot become authoritative evidence.
- Fresh jobs cannot read previous scratch/memory, unrelated sources, or production credentials.
- No worker bypasses mediated models or fake tools.

Use deterministic callback doubles for unit/contract tests. Coordinate expected fixture outcomes with A; D consumes those reviewed expectations for integration. Live model tests report variation and failures separately and cannot redefine the mandatory contract behavior.

## 7. Handoffs and your PR

Give A extraction status examples, exact source/output references, prompt/build versions, and fixture expectations. Give B worker entrypoints and declared minimal resource/model/tool requirements. Give D clear completion/error examples and safe public reason-code expectations. All rich evidence remains a referenced private artifact.

Use a branch such as `codex/team-c-inspectors`. Merge after A and B; update your branch and rerun against their actual validators, broker, and collector. Ask B to review bypass/isolation assumptions, A to review evidence/decision compatibility, and D to review source-backed output consumption.

Your PR lists supported formats, coverage limits, exact test results, prompt/build versions, and known detector misses. Completion means all three workers and the extractor operate under the restricted contracts, with honest incomplete results and meaningful benign/adversarial tests. It does not imply all prompt injection is detected.

## 8. Reviewed A extraction and source-reference clarification

Consume the exact [A v1 handoff additions](system-design.md#reviewed-a-v1-handoff-additions-october-10-2026). `extractor_version` equals the assignment's pinned EXTRACTOR build; source maps cover every Unicode code point and remain bounded by original bytes. Rejected or uncommitted results must not leave staged artifacts. Unsupported-part diagnostic prose is private; A projects canonical public metadata and generates public part IDs. This projection does not require C to invent a different worker enum. All amount citations include the entire signed currency/number unit; no positive substring of a negative amount may pass. Preserve server-owned disclosure labels and source hashes/spans. Workers have one shared scan token budget across roles/retries, enforced by B. Committed forbidden collector proof is authoritative, never worker assertions. This amendment reviews A's contract conventions only, not C's implementation.
