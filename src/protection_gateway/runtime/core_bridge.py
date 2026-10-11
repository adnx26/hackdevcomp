"""Connect canonical core contracts to the restricted runtime and C workers.

Only this gateway-owned boundary translates the provisional worker shapes.
Authority always comes from the persisted core assignment and its capability.
"""
from __future__ import annotations

import json
import secrets
import threading
import bisect
import functools
import re

from ..contracts import schemas
from ..contracts.enums import WorkerRole
from ..contracts.policies import get_policy
from ..core.clock import parse_iso
from ..core.service import LIVE_ASSIGNMENT_STATES

ROLE_KEYS = {
    WorkerRole.EXTRACTOR.value: 'extractor',
    WorkerRole.INSTRUCTION_INSPECTOR.value: 'instruction',
    WorkerRole.DATA_TOOL_INSPECTOR.value: 'data',
    WorkerRole.BEHAVIOR_TESTER.value: 'behavior',
}


class CoreRuntimeBridge:
    def __init__(self, runtime):
        self.runtime = runtime
        self.service = None
        self._tokens = {}
        self._assignments = {}
        self._artifacts = {}
        self._collector_events = {}
        self._lock = threading.RLock()

    def _row(self, assignment_id):
        row = self.service.db.query_one('SELECT * FROM assignments WHERE assignment_id = ?', (assignment_id,))
        if row is None:
            raise ValueError('unknown assignment')
        return row

    def _identity(self, identity):
        return {'worker_id': identity.worker_identity, 'role': next(k for k, v in ROLE_KEYS.items() if v == identity.role),
                'build_version': identity.build, 'prompt_version': identity.prompt_version}

    def _prepare(self, payload, worker):
        row = self._row(payload['assignment_id'])
        scan = self.service._scan(row['scan_id'])
        policy = get_policy(scan['policy_id'])
        a = {k: payload[k] for k in ('contract_version', 'assignment_id', 'scan_id', 'attempt', 'deadline')}
        a.update(worker_identity=worker['worker_id'], worker_role=ROLE_KEYS[worker['role']],
                 worker_build=worker['build_version'], prompt_version=worker['prompt_version'],
                 task_session_id=scan['task_session_id'], task_scope_version=scan['task_scope_version'],
                 policy_id=scan['policy_id'], policy_version=scan['policy_version'], policy_hash=scan['policy_hash'],
                 resource_set_hash=scan['resource_set_hash'], context_hash=scan['context_hash'],
                 model_configuration_hash=scan['model_configuration_hash'], task_policy=policy.as_canonical(),
                 run_id=payload['assignment_id'], extraction_status='COMPLETE')
        # A's persisted lease, rather than the longer scan deadline, bounds B's grant.
        a['deadline'] = min(payload['deadline'], row['lease_expires_at'])
        if row['kind'] == 'EXTRACTION':
            a['resources'] = [{k: payload[k] for k in ('resource_id', 'original_hash', 'media_type')}]
            a['limits'] = {'max_bytes': payload['limits']['max_source_bytes'],
                           'max_chars': payload['limits']['max_extracted_chars'], 'max_views': 32,
                           'max_parts': 128, 'max_decode_depth': 3}
        else:
            a['views'] = [dict(v, resource_id=r['resource_id']) for r in payload['resources'] for v in r['views']]
            a['views'] = [{k: v[k] for k in ('resource_id', 'view_id', 'view_hash')} for v in a['views']]
            a['limits'] = {'max_chars': self.service.config.limits.max_extracted_chars, 'max_views': 320,
                           'max_model_calls': self.runtime.config.model.job_call_budget,
                           'max_tool_calls': 8, 'max_output_chars': 100000}
            a['simulated_operations'] = ['read_email', 'send_email', 'delete_email', 'read_file', 'fetch_url', 'make_payment']
        with self._lock:
            self._tokens[a['assignment_id']] = self.service.issue_job_capability(a['assignment_id'])
            self._assignments[a['assignment_id']] = a
        return a

    def extract(self, assignment):
        payload = schemas.validate(schemas.extraction_assignment, assignment)
        entry = self.service.config.roster_entry(WorkerRole.EXTRACTOR.value)
        a = self._prepare(payload, entry.as_dict())
        try:
            raw = self.runtime.extract(a)
            resources = raw.get('resources', [])
            resource = resources[0] if len(resources) == 1 else None
            if resource is None or resource['resource_id'] != payload['resource_id'] or resource['original_hash'] != payload['original_hash']:
                raise ValueError('extraction bindings')
            original_views = {v['view_id']: v for v in resource['views']}
            indexes = {v['view_id']: ([s['span'][0] for s in v['source_map']], [s['span'][1] for s in v['source_map']]) for v in resource['views']}

            @functools.lru_cache(maxsize=200000)
            def origin(view_id, start, end, visited=()):
                if view_id in visited:
                    raise ValueError('cyclic provenance')
                view = original_views[view_id]
                mapped = []
                starts, ends = indexes[view_id]
                for segment in view['source_map'][bisect.bisect_right(ends, start):bisect.bisect_left(starts, end)]:
                    vs, ve = segment['span']
                    if vs < end and start < ve:
                        os_, oe = segment['source_span']
                        parent = view['parent_view_id']
                        if parent is None:
                            mapped.append((os_, oe))
                        else:
                            mapped.append(origin(parent, os_, oe, (*visited, view_id)))
                if not mapped:
                    raise ValueError('missing provenance')
                return min(s[0] for s in mapped), max(s[1] for s in mapped)

            views = []
            for view in resource['views']:
                segments = []
                for segment in view['source_map']:
                    start, end = segment['span']
                    if start == end:
                        continue
                    os_, oe = origin(view['view_id'], start, end)
                    segments.append([start, end, os_, oe])
                views.append({k: view[k] for k in ('view_id', 'kind', 'text', 'view_hash')} | {'source_map': segments})
            result = {'contract_version': 'v1', 'assignment_id': payload['assignment_id'],
                      'resource_id': payload['resource_id'], 'original_hash': payload['original_hash'],
                      'extractor_version': raw['extractor_version'], 'status': raw['extraction_status'], 'views': views,
                      'unsupported_parts': [{'part_id': 'part_' + str(i), 'media_type': p['media_type'],
                                             'task_relevant': True, 'reason': 'UNSUPPORTED_CONTENT'}
                                            for i, p in enumerate(resource['unsupported_parts'])]}
            return schemas.validate(schemas.extraction_result, result)
        except (KeyError, ValueError, TypeError):
            return {'contract_version': 'v1', 'assignment_id': payload['assignment_id'], 'resource_id': payload['resource_id'],
                    'original_hash': payload['original_hash'], 'extractor_version': entry.build_version,
                    'status': 'ERROR', 'views': [], 'unsupported_parts': []}
        finally:
            self._clear(payload['assignment_id'])

    def dispatch(self, assignments):
        prepared = []
        for assignment in assignments:
            p = schemas.validate(schemas.inspection_assignment, assignment)
            prepared.append(self._prepare(p, p['worker']))
        receipts = self.runtime.dispatch(prepared)
        return [{'assignment_id': r['assignment_id'], 'delivered': r.get('status') == 'DELIVERED'} for r in receipts]

    def cancel(self, scan_id):
        self.runtime.cancel(scan_id)
        for aid, a in list(self._assignments.items()):
            if a['scan_id'] == scan_id:
                self._clear(aid)

    def _clear(self, assignment_id):
        with self._lock:
            artifacts = self._artifacts.pop(assignment_id, {})
            self._tokens.pop(assignment_id, None)
            self._assignments.pop(assignment_id, None)
            self._collector_events.pop(assignment_id, None)
        for ref, tenant in artifacts.values():
            self.service.store.delete(ref, tenant)

    def assignment_active(self, assignment_id, attempt):
        try:
            row = self._row(assignment_id)
            scan = self.service._scan(row['scan_id'])
            return (row['attempt'] == attempt and row['state'] in LIVE_ASSIGNMENT_STATES
                    and parse_iso(row['lease_expires_at']) > self.service._now()
                    and scan['state'] in {'EXTRACTING', 'INSPECTING'})
        except (ValueError, TypeError):
            return False

    def read_assigned_input(self, identity, assignment_id, resource_id, view_id):
        if identity.assignment_id != assignment_id:
            raise ValueError('assignment mismatch')
        token = self._tokens[assignment_id]
        worker = self._identity(identity)
        if view_id is None:
            return self.service.read_assigned_original(token, worker, resource_id)
        return self.service.read_assigned_view(token, worker, resource_id, view_id).encode('utf-8')

    def store_worker_artifact(self, identity, assignment_id, artifact):
        self.service.validate_job_token(self._tokens[assignment_id], self._identity(identity))
        if identity.assignment_id != assignment_id:
            raise ValueError('assignment mismatch')
        row = self._row(assignment_id)
        artifact_id = 'art_' + secrets.token_hex(12)
        ref = self.service.store.put(row['tenant_id'], 'scratchartifact', json.dumps(artifact).encode('utf-8'))
        with self._lock:
            self._artifacts.setdefault(assignment_id, {})[artifact_id] = (ref, row['tenant_id'])
        return artifact_id

    def accept_worker_result(self, identity, result):
        aid = identity.assignment_id
        a = self._assignments[aid]
        for key in ('assignment_id', 'scan_id', 'attempt', 'worker_identity', 'worker_role', 'worker_build',
                    'prompt_version', 'task_session_id', 'task_scope_version', 'policy_id', 'policy_version',
                    'policy_hash', 'resource_set_hash', 'context_hash', 'model_configuration_hash', 'deadline'):
            if result.get(key) != a[key]:
                raise ValueError('worker binding mismatch')
        row = self._row(aid)
        payload = json.loads(row['assignment_json'])
        binding_keys = ('assignment_id', 'scan_id', 'attempt', 'worker', 'task_session_id', 'task_scope_version',
                        'policy', 'resource_set_hash', 'context_hash', 'model_configuration_hash')
        out = {'contract_version': 'v1', **{k: payload[k] for k in binding_keys},
               'nonce': secrets.token_hex(16), 'inspection_status': result['inspection_status'],
               'checked_views': result['checked_views'], 'findings': [], 'artifacts': []}
        used = set()
        for finding in result['findings']:
            for ref in finding['source_references']:
                out['findings'].append({'category': finding['category'], 'resource_id': ref['resource_id'],
                                        'view_hash': ref['view_hash'], 'span': dict(zip(('start', 'end'), ref['span'])),
                                        'evidence_ids': finding['evidence_ids']})
            used.update(finding['evidence_ids'])
        for artifact_id in used:
            item = self._artifacts.get(aid, {}).get(artifact_id)
            if item:
                ref, tenant = item
                out['artifacts'].append({'artifact_id': artifact_id, 'kind': 'EXPLANATION',
                                        'text': self.service.store.get(ref, tenant).decode('utf-8')})

        def refs(source):
            return [{'resource_id': r['resource_id'], 'view_hash': r['view_hash'],
                     'start': r['span'][0], 'end': r['span'][1]} for r in source]

        output = result.get('task_output')
        if output is not None:
            if a['policy_id'] == 'extract_invoice':
                out['task_output'] = {'kind': 'invoice', 'fields': {
                    name: {'value': output[name]['value'], 'source_refs': refs(output[name]['source_references'])}
                    if name in output else {'absent': True} for name in ('invoice_id', 'amount', 'currency', 'due_date')}}
            else:
                out['task_output'] = {'kind': 'summary', 'statements': [
                    {'text': s['text'], 'source_refs': refs(s['source_references'])} for s in output['statements']]}
        if identity.role == 'behavior':
            out['telemetry_event_ids'] = result.get('collector_event_ids', [])
            # Include the proposed event preceding an executed dummy receipt.
            events = self._collector_events.get(aid, [])
            for event in events:
                if event['attempted_outcome'] == 'EXECUTED_DUMMY' and event['event_id'] in out['telemetry_event_ids']:
                    proposed = next((e for e in events if e['sequence'] == event['sequence'] - 1 and e['attempted_outcome'] == 'PROPOSED'), None)
                    if proposed:
                        out['telemetry_event_ids'].append(proposed['event_id'])
            out['coverage_limits'] = result.get('completion_report', {}).get('coverage_limits', [])
        try:
            return self.service.accept_worker_result(self._identity(identity), schemas.validate(schemas.worker_result, out))
        finally:
            self._clear(aid)

    def record_collector_event(self, identity, event):
        collector = self.runtime.collector
        if identity != collector.identity or not collector.verify(event):
            raise ValueError('collector authentication')
        with self._lock:
            self._collector_events.setdefault(event['assignment_id'], []).append(dict(event))
        translated = {'contract_version': 'v1', **{k: event[k] for k in
                      ('event_id', 'scan_id', 'run_id', 'sequence', 'operation', 'timestamp')},
                      'argument_digest': event['dummy_argument_digest'],
                      'attempted_outcome': 'DENIED' if event['attempted_outcome'] == 'DENIED' else 'ALLOWED',
                      'policy_check': 'FORBIDDEN' if event['policy_check'] == 'FORBIDDEN' else 'PERMITTED'}
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', translated['operation']):
            translated['operation'] = 'unknown_operation'
            translated['policy_check'] = 'FORBIDDEN'
            translated['attempted_outcome'] = 'DENIED'
        return self.service.record_collector_event({'collector_id': identity.collector_id}, translated)

    def check_simulated_operation(self, binding, operation, arguments):
        scan = self.service._scan(binding['scan_id'])
        if scan is None or any(scan[k] != binding[k] for k in ('task_session_id', 'task_scope_version', 'policy_id', 'policy_version', 'policy_hash')):
            return False
        return get_policy(scan['policy_id']).operation_permitted(operation)

    def model_processing_permitted(self, binding, provider):
        # Only the configured processor receives the views of a live assignment.
        aid = binding['assignment_id']
        row = self._row(aid)
        if not self.assignment_active(aid, row['attempt']):
            return False
        scan = self.service._scan(row['scan_id'])
        return (provider == self.runtime.config.model.provider and binding['scan_id'] == scan['scan_id']
                and binding['task_session_id'] == scan['task_session_id']
                and scan['model_configuration_hash'] == self.runtime.config.model.hash())

    def report_runtime_failure(self, assignment_id, attempt, reason_code):
        row = self._row(assignment_id)
        if row['attempt'] != attempt or row['state'] not in LIVE_ASSIGNMENT_STATES:
            self._clear(assignment_id)
            return
        with self.service.db.transaction() as conn:
            conn.execute("UPDATE assignments SET state = 'UNDELIVERED' WHERE assignment_id = ?", (assignment_id,))
        self._clear(assignment_id)
