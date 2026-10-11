"""User-uploaded folder manifests, bound to an immutable read-only task scope.

No server filesystem paths are opened. File names are private, untrusted metadata.
"""
import json
from pathlib import PurePosixPath

from ..contracts import schemas
from ..contracts.canonical import canonical_digest
from ..contracts.enums import Channel, ErrorCode
from ..contracts.errors import GatewayError
from .clock import after, iso, parse_iso

FOLDER_SCHEMA = """
CREATE TABLE IF NOT EXISTS folders (
    folder_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_id TEXT NOT NULL,
    task_session_id TEXT, scope_version INTEGER, context_version INTEGER,
    manifest_ref TEXT NOT NULL, manifest_hash TEXT NOT NULL,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
"""
TEXT_EXTENSIONS = frozenset({'.txt', '.md', '.csv', '.json', '.log', '.py', '.js', '.ts', '.css', '.yaml', '.yml', '.xml', '.html', '.htm', '.eml'})


def media_for_path(path):
    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in TEXT_EXTENSIONS:
        return None
    return 'message/rfc822' if suffix == '.eml' else ('text/html' if suffix in {'.html', '.htm'} else 'text/plain')


def valid_relative_path(path):
    return (isinstance(path, str) and 0 < len(path) <= 512 and not path.startswith('/')
            and not any(c in path for c in '\\:') and not any(ord(c) < 32 or ord(c) == 127 for c in path)
            and all(part not in {'', '.', '..'} for part in path.split('/')))


class FolderMixin:
    def create_folder(self, principal, body):
        # Only a user's authenticated UI/API can select upload scope; MCP consumes IDs.
        self._require_channel(principal, {Channel.USER_INTERFACE, Channel.API})
        self._require_not_stopped()
        req = schemas.validate(schemas.folder_upload_request, body)
        entries = req['entries']
        paths, resources, total = set(), [], 0
        for entry in entries:
            path = entry['path']
            if not valid_relative_path(path) or path in paths:
                raise GatewayError(ErrorCode.INVALID_REQUEST, 'invalid folder path')
            paths.add(path)
            expected_media = media_for_path(path)
            if entry['status'] == 'STORED':
                if set(entry) != {'path', 'size_bytes', 'status', 'resource_id'} or expected_media is None:
                    raise GatewayError(ErrorCode.INVALID_REQUEST, 'invalid stored entry')
                row = self._owned('resources', 'resource_id', entry['resource_id'], principal)
                if row['deleted_at'] or parse_iso(row['evidence_expires_at']) <= self._now():
                    raise GatewayError(ErrorCode.NOT_FOUND, 'resource unavailable')
                if row['media_type'] != expected_media or row['size_bytes'] != entry['size_bytes'] or row['resource_id'] in resources:
                    raise GatewayError(ErrorCode.INVALID_REQUEST, 'resource mismatch')
                resources.append(row['resource_id'])
                total += row['size_bytes']
            elif 'resource_id' in entry or (entry['status'] == 'UNSUPPORTED_FORMAT' and expected_media is not None):
                raise GatewayError(ErrorCode.INVALID_REQUEST, 'invalid skipped entry')
        within_budget = len(resources) <= self.config.limits.max_task_sources and total <= self.config.limits.max_task_bytes
        task = None
        if resources and within_budget:
            task = self.create_task_session(principal, {'contract_version': 'v1', 'policy_id': 'summarize_email', 'resource_ids': resources})
        manifest = {'entries': entries, 'within_budget': within_budget}
        reference = self.store.put(principal.tenant_id, 'folder-manifest', json.dumps(manifest, ensure_ascii=False).encode())
        folder_id = self.ids.new('folder')
        session = self._owned('task_sessions', 'task_session_id', task['task_session_id'], principal) if task else None
        expiry = iso(after(self._now(), min(self.config.retention.evidence_seconds, self.config.retention.task_session_seconds)))
        self.db.execute('INSERT INTO folders VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (folder_id, principal.tenant_id, principal.user_id, task['task_session_id'] if task else None,
                         session['scope_version'] if session else None, session['context_version'] if session else None,
                         reference, canonical_digest(manifest), self._now_iso(), expiry))
        return self.get_folder_status(principal, folder_id)

    def _folder(self, principal, folder_id):
        self._require_channel(principal, set(Channel))
        folder = self._owned('folders', 'folder_id', folder_id, principal)
        if parse_iso(folder['expires_at']) <= self._now():
            raise GatewayError(ErrorCode.NOT_FOUND, 'folder expired')
        manifest = json.loads(self.store.get(folder['manifest_ref'], principal.tenant_id))
        if canonical_digest(manifest) != folder['manifest_hash']:
            raise GatewayError(ErrorCode.CONTEXT_CHANGED, 'manifest changed')
        if folder['task_session_id']:
            session = self._active_session(principal, folder['task_session_id'])
            resources = [e['resource_id'] for e in manifest['entries'] if e['status'] == 'STORED']
            if (session['scope_version'] != folder['scope_version'] or session['context_version'] != folder['context_version']
                    or json.loads(session['resource_ids_json']) != resources):
                raise GatewayError(ErrorCode.CONTEXT_CHANGED, 'folder scope changed')
            self._load_resources(principal, resources)
        return folder, manifest

    def inspect_folder(self, principal, folder_id):
        folder, manifest = self._folder(principal, folder_id)
        self._require_not_stopped()
        if folder['task_session_id']:
            first = next(e['resource_id'] for e in manifest['entries'] if e['status'] == 'STORED')
            self.inspect_resource(principal, first, folder['task_session_id'])
        return self.get_folder_status(principal, folder_id)

    def get_folder_status(self, principal, folder_id):
        folder, manifest = self._folder(principal, folder_id)
        scan = None
        if folder['task_session_id']:
            row = self.db.query_one('SELECT scan_id FROM scans WHERE task_session_id = ? ORDER BY created_at DESC LIMIT 1', (folder['task_session_id'],))
            if row:
                scan = self.get_scan_status(principal, row['scan_id'])
                scan_row = self._scan(row['scan_id'])
                session = self._active_session(principal, folder['task_session_id'])
                current = self._current_bindings(session)
                if current['context_hash'] != scan_row['context_hash'] or current['resource_set_hash'] != scan_row['resource_set_hash']:
                    raise GatewayError(ErrorCode.CONTEXT_CHANGED, 'scan context changed')
        extractions = {e['resource_id']: e['status'] for e in scan['coverage']['extraction']} if scan else {}
        all_inspected = bool(scan and scan['state'] == 'DECIDED' and set(scan['completed_checks']) == set(scan['required_checks']) and scan['required_checks'])
        unexpired = bool(scan and scan['decision_expires_at'] and parse_iso(scan['decision_expires_at']) > self._now())
        results = []
        for entry in manifest['entries']:
            item = dict(entry)
            categories = sorted({f['category'] for f in (scan['findings'] if scan else []) if f['resource_id'] == entry.get('resource_id')})
            evidence = sorted({eid for f in (scan['findings'] if scan else []) if f['resource_id'] == entry.get('resource_id') for eid in f['evidence_ids']})
            inspected = bool(all_inspected and unexpired and extractions.get(entry.get('resource_id')) == 'COMPLETE')
            item.update(finding_categories=categories, evidence_ids=evidence, inspection_complete=inspected)
            if entry['status'] == 'STORED':
                item['status'] = ('LIMIT_EXCEEDED' if not manifest['within_budget'] else 'FLAGGED' if categories else 'NO_FINDINGS' if inspected
                                  else 'INCOMPLETE' if scan and scan['state'] in {'DECIDED', 'FAILED', 'CANCELED'} else 'PENDING')
            results.append(item)
        complete = bool(all_inspected and unexpired and all(e['inspection_complete'] and e['status'] in {'FLAGGED', 'NO_FINDINGS'} for e in results))
        diagnostics = getattr(self.runtime, 'inspection_errors', None)
        return {'folder_id': folder_id, 'task_session_id': folder['task_session_id'],
                'scan_id': scan['scan_id'] if scan else None, 'state': scan['state'] if scan else 'NOT_STARTED',
                'decision': scan['decision'] if complete else None, 'coverage_complete': complete,
                'required_checks': scan['required_checks'] if scan else [],
                'completed_checks': scan['completed_checks'] if scan else [],
                'inspection_statuses': scan['coverage']['inspections'] if scan else {},
                'file_count': len(results), 'files': results,
                'reason_codes': sorted(set((scan['reason_codes'] if scan else []) +
                    (['LIMIT_EXCEEDED'] if not manifest['within_budget'] else []) +
                    (['UNSUPPORTED_CONTENT'] if any(e['status'] == 'UNSUPPORTED_FORMAT' for e in results) else []) +
                    (['UPLOAD_INCOMPLETE'] if any(e['status'] in {'UPLOAD_FAILED', 'LIMIT_EXCEEDED'} for e in results) else []))),
                'collector_evidence': scan['collector_evidence'] if scan else [],
                'inspection_errors': diagnostics(scan['scan_id']) if scan and callable(diagnostics) else [],
                'inference_mode': scan.get('inference_mode') if scan else None,
                'expires_at': folder['expires_at']}

    def purge_folders(self):
        for row in self.db.query_all('SELECT * FROM folders WHERE expires_at <= ?', (self._now_iso(),)):
            self.store.delete(row['manifest_ref'], row['tenant_id'])
            self.db.execute('DELETE FROM folders WHERE folder_id = ?', (row['folder_id'],))
