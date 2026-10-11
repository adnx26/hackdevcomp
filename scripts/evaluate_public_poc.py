"""Small live evaluation of pinned public PoCs; does not execute their code."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import subprocess
import time

from smoke_test import Client

ROOT = Path(__file__).resolve().parents[1]


def evaluate(client, cases, run_name):
    entries = []
    for case in cases:
        path = ROOT / 'tests/fixtures/public-poc/scan-folder' / case['file']
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != case['file_sha256']:
            raise ValueError('Fixture hash mismatch: ' + case['file'])
        entries.append({'path': case['file'], 'size_bytes': len(content),
                        'status': 'STORED', 'resource_id': client.upload(content)})
    folder = client.request('/v1/folders', {'entries': entries}, expected=201)
    folder_id = folder['folder_id']
    client.request(f'/v1/folders/{folder_id}/inspect', {}, expected=202)
    print(run_name + ': inspection started', flush=True)
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        folder = client.request(f'/v1/folders/{folder_id}')
        if folder['state'] in {'DECIDED', 'FAILED', 'CANCELED'}:
            break
        time.sleep(3)
    evidence = {}
    outcomes = []
    labels = {case['file']: case['label'] for case in cases}
    for file in folder['files']:
        complete = file['inspection_complete']
        flagged = bool(file['finding_categories'])
        label = labels[file['path']]
        outcome = ('incomplete' if not complete else
                   'detected' if label == 'attack' and flagged else
                   'missed' if label == 'attack' else
                   'false_alarm' if flagged else 'correct_benign')
        outcomes.append({'file': file['path'], 'label': label, 'outcome': outcome,
                         'early_flag': flagged and not complete,
                         'categories': file['finding_categories']})
        for evidence_id in file['evidence_ids']:
            evidence[evidence_id] = client.request('/v1/evidence/' + evidence_id)
    core = client.request('/v1/scans/' + folder['scan_id']) if folder['scan_id'] else None
    release = client.request('/v1/scans/' + folder['scan_id'] + '/result', expected=(200, 403, 428)) if folder['scan_id'] else None
    release_probe = {'released': bool(release and 'result' in release),
                     'error_code': release.get('code') if release else None}
    counts = {key: sum(row['outcome'] == key for row in outcomes)
              for key in ('detected', 'missed', 'false_alarm', 'correct_benign', 'incomplete')}
    print(run_name + ': ' + json.dumps(counts), flush=True)
    return {'run': run_name, 'counts': counts, 'outcomes': outcomes,
            'folder_status': folder, 'scan_status': core, 'evidence': evidence,
            'release_probe': release_probe}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8766')
    parser.add_argument('--token-file', type=Path, default=ROOT / 'var/runtime/login-token')
    parser.add_argument('--output', type=Path, default=ROOT / 'var/evaluations/public-poc.json')
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'tests/fixtures/public-poc/manifest.json').read_text())
    client = Client(args.url, args.token_file.read_text().strip())
    report = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'code_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'code_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()),
              'source_manifest': manifest, 'policy': 'summarize_email',
              'limitations': 'Small convenience sample of published research PoCs, not confirmed incident files. Adapted task and tools; no attack-success benchmark or real exfiltration test. Incomplete checks do not count as detections or misses.',
              'runs': []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for name, cases in [('mixed-1', manifest['cases']),
                        ('benign-only', [case for case in manifest['cases'] if case['label'] == 'benign']),
                        ('mixed-2', manifest['cases'])]:
        report['runs'].append(evaluate(client, cases, name))
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('Saved report: ' + str(args.output), flush=True)


if __name__ == '__main__':
    main()
