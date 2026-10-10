# Canonical v1 contracts (owner: A)

This package is the single source of the shared contract in
[system-design.md §15](../../../docs/system-design.md#15-four-person-implementation-contracts).
Propose changes there first; don't redefine these in another subtree.

| Module | Contents |
|---|---|
| `enums.py` | Job states, decisions, action states, error codes, finding categories, reason codes, roles, channels |
| `errors.py` | `GatewayError`, error envelope, HTTP status mapping |
| `canonical.py` | Canonical JSON and SHA-256 digests used for policy, action, output and binding hashes |
| `schemas.py` | Strict validators for public requests, runtime messages and task outputs |
| `policies.py` | `summarize_email`, `extract_invoice`, `simulate_send` |

Generated examples and scenario outcomes live in `tests/contracts/fixtures/`.
They come from real runs of the core with deterministic doubles, and
`tests/contracts/test_fixtures.py` fails if they drift from the code. To
regenerate them, run `PYTHONPATH=src:. python3 -m tests.contracts.fixture_builder`.

## Conventions consumers depend on

- **Canonical serialization**: UTF-8 JSON, sorted keys, `(",", ":")`
  separators, no floats. Digests are lowercase SHA-256 hex. D shows the
  `digest` returned by `POST /v1/actions` unchanged.
- **Timestamps**: UTC, second precision, `YYYY-MM-DDTHH:MM:SSZ`.
- **Spans and source refs**: half-open Unicode code-point offsets
  `[start, end)` into the exact view whose `view_hash` is
  `sha256(view_text_utf8)`. A source ref is
  `{resource_id, view_hash, start, end}`.
- **Extraction `source_map`**: `[view_start, view_end, original_start,
  original_end]` segments, with view offsets in code points and original
  offsets in bytes.
- **Worker evidence references**: each entry in a finding's `evidence_ids`
  is either the `artifact_id` of an artifact in the same result or a
  collector `event_id` already recorded for the scan. The gateway rewrites
  both to server-issued `ev_…` IDs, which are the only IDs exposed publicly.
- **`OBSERVED_FORBIDDEN_ACTION`** is accepted only when it cites a recorded
  collector event whose effective policy check is `FORBIDDEN`. A forbidden
  collector event quarantines the scan on its own, even when every worker
  missed it.
- **Collector events**: `run_id` must be the behavior tester's
  `assignment_id` for that scan. `(run_id, sequence)` is unique. The
  effective policy check is the stricter of the collector's check and the
  gateway policy.
- **Task outputs**: only the behavior tester submits `task_output` or
  `telemetry_event_ids`. Invoice fields are `{value, source_refs}` or
  `{"absent": true}`. Amounts are decimal strings, currencies are uppercase
  ISO 4217 codes, and dates are `YYYY-MM-DD`. Workers can't supply labels:
  the gateway attaches server-owned `label_ids`, and a combined output
  carries the union of its sources' labels.
- **Duplicates**: resubmitting the same result with the same nonce returns
  `DUPLICATE` and doesn't advance completeness. Reusing a nonce with
  different content, or sending a second result for a completed assignment,
  is rejected.
- **Channels** are derived on the server: `USER_INTERFACE` is a cookie
  session with CSRF, `API` is a bearer token, `MCP` is the read-only
  connector, and `ASSISTANT` is `principal.as_assistant()` for D's in-process
  chat. Only `USER_INTERFACE` can confirm actions or record review
  exceptions. `MCP` can only inspect, read status and read results.
