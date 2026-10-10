# A merge gate: passed

Reviewed on October 10, 2026 against `docs/teammate-a-gateway.md` and the
shared requirements in `docs/system-design.md`, especially sections 6–11
and 15. Original PR head: `f43dcf8150a6aff018e4f8034cc74740ec75b428`.
A-owned implementation/tests and reviewed shared design appendices were changed.
No B/C/D implementation, root dependencies, deployment or CI paths changed.

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

Results: **13 contract tests and 154 core tests pass**, including 52 added
design and review regression tests. Five review regression modules cover
runtime/retention, HTTP sessions, action authority, result release and status. The original
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
| Canonical fixture publication and actual B/D consumer review | committed fixture suite and handoff README | Independent B-facing and D remote-head review passed |
| Shared-contract additions proposed in master/affected assignment docs and reviewed | master §15 and affected A/B/C/D appendices; generated canonical examples | Independent B/C-facing and D shared-document review passed |
| Backup and immutable-log expiry defined together with B | core README explicitly says still to be agreed | Independent B-facing policy approval passed; B must verify deployment inventory before activation |

## Additional independent review repairs

- Extraction version must match the pinned assignment build; every view is
  validated before allocation, and rejected/uncommitted objects are cleaned.
  Late extraction terminates at deadline; periodic recovery handles a hung
  extraction. Source/context changes cannot commit stale extraction objects.
- Worker results recheck current lease, deadline and bindings inside their
  persistence transaction; rejected staged artifacts and outputs are removed.
- Result authorization and storage reads serialize with stop/quarantine;
  committed forbidden collector evidence immediately blocks release/actions.
  Body-derived actions require allowed inspection of every source, including
  when attachment lists are empty. Signed currency values cannot be cited as
  positive substrings.
- Unsupported extraction status projects gateway IDs and fixed metadata
  rather than worker diagnostic prose. Review eligibility uses current
  bindings, expiry, evidence and stop; insertion rechecks these transactionally.
- Negative Content-Length is rejected before reading. Cookie-only recovery
  follows D's explicit header/origin/bearer rules; CSRF rotation and logout
  serialize, original session expiry is preserved, and stale tokens have no
  mutation effect.
- Source and derived-content access expires independently of cleanup. Resource,
  session and label metadata cleanup is anchored to creation, never deletion.

## Completed A reviews and later deployment requirements

The independent B-facing runtime reviewer approved the exact amended master,
A/B appendices, capability/result/collector handoff and retention proposal,
then verified all 11 focused runtime regression tests. This is role review,
not original B-author approval or deployed-host verification. The independent C-facing reviewer approved A's extraction/source contract
and C appendix, including Unicode signed amounts, without verifying or
advancing to C's implementation.

The existing **Implement design doc D** chat reviewed A's public/authentication
contract, reproduced four gaps and an exception-insertion race, and supplied
an explicit conditional session recovery contract. Those fixes, fixtures and
shared appendices are now concrete; D approved remote implementation head `4476b2d` and the exact shared contracts.
It independently ran all 167 tests on Python 3.9/3.12, the four original probes,
seven exception-insertion race cases and 20 Unicode-sign cases. No D-facing
blocker remained. Final review report is attached to the PR handoff. This
bookkeeping revision changes documentation only; implementation is unchanged.

A/B define evidence ≤24 hours, metadata/logs ≤seven days from creation, no
initial demo backups/snapshots/immutable exports, and original-expiry bounds
for any later reviewed copies/restores. B must inventory and verify the actual
host and copying/log settings before activation; local A tests do not prove
host encryption, external-copy expiry or provider retention. Those deployment
proofs belong to B's subsequent gate and cannot be waived.

No original-author approval, actual later-PR consumer compatibility, deployed
encryption, live model, SLIM/host isolation or full workflow pass is claimed.
A's completion uses standard-library runtime doubles and fails closed without
B; later PRs require independent verification after A lands.

**A's design, deterministic tests, canonical fixtures and required role-facing
handoff reviews pass. Merge only the verified remote head; then begin B's
separate design gate.**
