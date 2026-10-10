# Gateway core (owner: A)

The trusted core. It authenticates, stores resources, keeps scan state,
applies the decision table, releases results and gates simulated actions.
It uses only the standard library and never imports B, C or D.

## Run the tests

```sh
PYTHONPATH=src:. python3 -m unittest discover -s tests/contracts -t .
PYTHONPATH=src:. python3 -m unittest discover -s tests/core -t .
```

Once B's root package setup lands, switch to B's agreed environment and test
command.

## Composition (for B)

```python
from protection_gateway.core import Authenticator, GatewayConfig, GatewayService
from protection_gateway.core.http import make_wsgi_app

service = GatewayService(config, runtime=runtime_callbacks)  # plus cipher=..., clock=..., ids=...
auth = Authenticator(config, service.db, service.clock, service.ids)
app = make_wsgi_app(service, auth)
service.recover(startup=True)   # interrupted extractions fail closed
# periodically: service.recover(); service.run_retention()
# operator controls: service.emergency_stop() / service.emergency_resume()
```

- `runtime_callbacks` implements `core.runtime_api.RuntimeCallbacks`, which
  has exactly the §15 signatures: `extract(extraction_assignment)`,
  `dispatch(inspection_assignments)` and `cancel(scan_id)`. If
  `runtime=None` or the roster is incomplete, `POST /v1/scans` returns
  `SERVICE_UNAVAILABLE`. If a callback raises, the scan moves to `FAILED`
  with `RUNTIME_UNAVAILABLE`. Neither case releases anything.
- Job capabilities are short-lived opaque tokens. B's launcher provisions
  one per assignment by calling `service.issue_job_capability(assignment_id)`
  and passes it to the worker privately; it never travels in an assignment
  message. Re-issuing revokes the previous token. Tokens expire at the
  earlier of 5 minutes or the scan deadline, are revoked on completion,
  cancel, decision, failure or emergency stop, and only their hashes are
  stored. Workers read inputs through
  `service.read_assigned_original(capability, identity, resource_id)` for
  extraction and `service.read_assigned_view(capability, identity,
  resource_id, view_id)` for inspection. `service.validate_job_token` checks
  a capability without reading anything.
- Results go to `service.accept_worker_result(verified_identity, result)`
  once B has verified the sender and replay rules. `verified_identity` is
  `{worker_id, role, build_version, prompt_version}`.
- Collector events go to `service.record_collector_event({"collector_id":
  ...}, event)`. The collector ID must be in `config.collector_ids`, and
  workers never get that identity.
- `GatewayConfig` holds demo identities (as token SHA-256 only), the fixed
  worker roster (including an `EXTRACTOR` entry), collector IDs, model
  configuration, trusted contacts and limits. The evidence root must be on a
  separately permissioned encrypted volume, declared by setting
  `evidence_volume_encrypted=True`. Otherwise storage stays unavailable
  unless `allow_unencrypted_dev_storage=True` is set explicitly for
  development. B can also inject application-level encryption through
  `storage.Cipher`.

## Sessions and channels (for D)

- `POST /v1/session` with `Authorization: Bearer <demo token>` returns an
  HttpOnly `SameSite=Strict` cookie plus a `csrf_token`. Every cookie-based
  mutation needs an `X-CSRF-Token` header. `DELETE /v1/session` signs out.
- Bearer requests use the `API` channel. D's MCP adapter calls
  `auth.authenticate_bearer(token, Channel.MCP)`, and D's chat adapter uses
  `principal.as_assistant()`. Service methods enforce channel rules
  themselves, so calling them in process doesn't bypass anything:

| Operation | USER_INTERFACE | API | ASSISTANT | MCP |
|---|---|---|---|---|
| upload, task sessions | ✓ | ✓ | read-only policies only | – |
| inspect / status / result | ✓ | ✓ | ✓ | ✓ |
| cancel scan | ✓ | ✓ | ✓ | – |
| review exception / reject | ✓ | – | – | – |
| evidence viewer | ✓ | ✓ | – | – |
| propose / execute simulated action | ✓ | ✓ | ✓ | – |
| confirm simulated action | ✓ | – | – | – |

- MCP tool mapping: `inspect_resource` → `service.inspect_resource`, which
  is idempotent for the current scope and context. `get_scan_status` →
  `service.get_scan_status`. `get_inspected_result` →
  `service.get_inspected_result`.
- Error status mapping: 400 `INVALID_REQUEST`, 401 `UNAUTHENTICATED`, 403
  `FORBIDDEN`, 404 `NOT_FOUND`, 409 `NOT_READY` / `CONTEXT_CHANGED`, 428
  `APPROVAL_REQUIRED`, 429 `LIMIT_EXCEEDED`, 503 `SERVICE_UNAVAILABLE`.

## Proposed contract additions (need B/D review)

These endpoints and fields are in addition to the §15 table:

- `POST/DELETE /v1/session`: the demo browser-session exchange.
- `GET /v1/task-sessions/{id}`, `PUT /v1/task-sessions/{id}/resources`
  (creates a new scope version), and `POST /v1/task-sessions/{id}/cancel`.
- `DELETE /v1/resources/{id}`: deletes the stored bytes and derived
  artifacts and revokes access that depends on them.
- `GET /v1/actions/{id}`: re-displays an exact preview.
- The scan status adds `findings`, `collector_evidence` and
  `review.{eligible, result_digest}`. All of these are IDs, enums and
  digests only.
- The task-session view adds `disclosure` (the server-owned label for each
  resource).
- `service.issue_job_capability(assignment_id)` lets B provision worker
  capabilities.
- New reason codes `CONTRADICTORY_EVIDENCE` (collector events for a run that
  the behavior tester's telemetry omitted) and `EMERGENCY_STOP`.
- `service.advance_task_context`: lets D record a relevant change in
  conversation context, which invalidates cached decisions and pending
  approvals.

## Emergency controls

`service.emergency_stop()` is an operator control, not an HTTP route. It:

- blocks uploads, new scans, capability issue and worker reads
- cancels queued and running scans with `EMERGENCY_STOP`
- revokes every job capability
- cancels pending actions

Effects that already happened aren't undone. `service.emergency_resume()`
lifts the stop.

## Disabled or not provided

- There is no real email provider. `UNKNOWN_OUTCOME` and
  `actions.reconcile_unknown_outcome` exist for a future provider, and the
  simulated executor never produces that state.
- There is no extraction or parsing in this process. That is C's code,
  launched by B.
- Backups and immutable logs are outside this module. B and A still need to
  agree on their expiry, and nothing here promises immediate deletion from
  them.
