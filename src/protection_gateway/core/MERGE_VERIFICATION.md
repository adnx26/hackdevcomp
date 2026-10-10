# A merge gate: not yet passed

Reviewed on October 10, 2026 against `docs/teammate-a-gateway.md` and the
shared requirements in `docs/system-design.md`, especially sections 6–11
and 15. Original PR head: `f43dcf8150a6aff018e4f8034cc74740ec75b428`.
Only A-owned implementation, test, and handoff paths were changed.

## Reproduced failures repaired

- Emergency stop previously allowed retrieval of an already allowed result.
  Retrieval now checks the stop control. Pending jobs and actions retain the
  existing cancellation/revocation behavior.
- Worker input capabilities previously remained readable after their lease
  expired until recovery happened. Expiry now includes the assignment lease;
  each read checks live assignment state, lease, build, and prompt version.
- Extracted view reads previously skipped an integrity check. Worker reads
  and output source validation now verify the stored view against its hash.
- Action arguments and full execution replay responses previously stored
  private text in SQLite. Arguments now live in the restricted encrypted
  evidence volume; metadata/replay records contain references and identifiers.
  Dummy effect subjects are hashed. Public previews and canonical digests
  remain unchanged, proven by the committed contract fixture tests.
- Retention previously left action arguments/approvals/effects indefinitely.
  Action bytes now expire with evidence; action metadata, approvals and dummy
  effects expire with metadata. Old task and label metadata is also cleaned.
  Deleting a labeled source purges derived action content and revokes approval.
- Complete extraction previously accepted missing or partial source maps.
  Every nonempty extracted view now requires mapping coverage over its full
  Unicode code-point range before it can satisfy extraction.
- Invoice validation previously accepted `250.00` from a subspan of
  `$1,250.00`. Amount references must contain a complete numeric token whose
  decimal value matches the reported amount; mismatches produce REVIEW.
- Action validation previously allowed an effect if approval expiry or a
  collector-backed quarantine happened between the initial checks and the
  write transaction. Execution now revalidates the active action, stop state,
  policy/context and source inspection under the transaction, then claims
  only a still-unexpired approval before recording the effect.

## Deterministic evidence

Commands in the isolated PR checkout, with the actual source and no B/C/D
composition or live provider substituted:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/contracts -t .
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/core -t .
git diff --check
```

Results: **13 contract tests and 116 core tests pass**, including 14 added
design regressions in `tests/core/test_design_merge_gates.py`. The original
13/102 suites passed despite the reproduced failures. These suites also pass
with Python 3.12. Cancellation and
task-context changes between validation and execution prevent effects via
the existing approval revocation; these regression checks also pass.

| A requirement | Implementation and test evidence | Gate |
|---|---|---|
| Server-derived identity; identical absent/cross-owner objects | `auth.py`, `_owned`; tenancy and HTTP suites | Deterministic pass |
| Bounded uploads, immutable original bytes, runtime extraction only | `upload_resource`, `_run_extraction`, restricted storage; scan workflow and privacy suites | Deterministic pass |
| Fixed user task policies, resources, scope, expiry, labels | task/session methods, `contracts/policies.py`; actions, tenancy, review/binding suites | Deterministic pass |
| Persisted states, assignments, leases, deadline, one retry, restart and cancellation | database schema, scan dispatch/recovery/termination; scan workflow suite and lease regression | Deterministic pass |
| Validate worker identity, assignment, bindings, coverage, nonce and evidence | result acceptance and capability paths; worker results, tenancy, fixture and new regression suites | Deterministic pass |
| Ordinary-code decisions; authoritative collector evidence; no receipt-as-result | `decisions.py`, collector and finalization paths; decision, collector and spec alignment suites | Deterministic pass |
| Active task-bound result; private server-owned labels; eligible read-only exception | result/review methods; review/binding, worker and fixture suites | Deterministic pass |
| Exact browser confirmation, CSRF, one-use approval, atomic simulated effect | `actions.py`, `http.py`; action/HTTP suites plus expiry/quarantine race regressions | Deterministic pass |
| Unknown-outcome reconciliation without resend | action executor protocol and reconciliation; action suite | Deterministic pass; no real provider |
| Evidence access, no raw public status/logs, encrypted-volume prerequisite, cleanup | evidence store/service and retention; privacy and new regression suites | Deterministic pass; deployment encryption verification remains B's responsibility |
| Emergency controls withhold retrieval and revoke pending work | emergency and result paths; spec alignment and new regression suites | Deterministic pass |
| Canonical fixture publication and actual B/D consumer review | committed fixture suite and handoff README | **Blocked: required reviews absent** |
| Shared-contract additions proposed in master/affected assignment docs and reviewed | additions listed in core README only | **Blocked: shared baseline has not been updated/reviewed** |
| Backup and immutable-log expiry defined together with B | core README explicitly says still to be agreed | **Blocked: agreement/evidence absent** |

## Required before merge

1. B reviews the canonical assignment/capability/result/collector handoff,
   including the stricter lease, source-map and private storage behavior.
2. D reviews authentication/session/CSRF, public statuses and errors,
   result/evidence disclosure, exact previews, confirmation and replay.
3. Affected owners review the proposed contract additions already listed in
   `core/README.md`; update the shared master and affected assignment documents
   as required by system design section 15. This audit does not silently amend
   that shared baseline or treat an implementation proposal as approval.
4. A/B define backup and immutable-log expiry and record whether backups/log
   exports exist in the chosen deployment. The core does not create backups;
   its retention job is not proof of expiry for external copies or providers.

No owner review, actual consumer compatibility, deployed encryption, live
model, SLIM/host isolation, full workflow, or provider-retention pass is claimed.
Those broader runtime/workflow gates belong to subsequent owners; A's required
contract handoff and retention agreement must still be resolved first.

**Do not merge A or advance to B until the blocked A requirements are resolved
and the final remote head is reverified.**
