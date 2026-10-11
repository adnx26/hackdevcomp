// Run through gstack browse eval after opening the TEST-ONLY preview server.
// API doubles prove UI behavior only; this is not real-stack release evidence.
return await (async () => {
  const el = id => document.getElementById(id);
  const results = [];
  const calls = [];
  const originalFetch = window.fetch;
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const waitFor = async predicate => {
    const end = performance.now() + 4000;
    while (!predicate()) {
      if (performance.now() > end) throw new Error('UI test timed out');
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  };
  const settle = () => new Promise(resolve => setTimeout(resolve, 40));
  const submit = id => el(id).dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
  const input = (id, value) => { el(id).value = value; el(id).dispatchEvent(new Event('input', {bubbles: true})); };
  const malicious = '<img src="https://evil.invalid/pixel" onerror="window.uiAttack=true"><script>window.uiAttack=true</script>';
  const digest = 'a'.repeat(64);
  let scanNumber = 0, actionNumber = 0, uploadNumber = 0, decision = 'ALLOW_UNDER_POLICY';
  let complete = true, reviewException = false, pending = false, outage = false;
  let reviewExpiry = null;
  let delayedProposal = null, delayedConfirmation = null, delayedResult = null, delayedEvidence = null;
  let resultDenied = false, chatDenied = false, cancelDenied = false, actionLifetime = 60000;
  const sample = {amount: {value: '125.00', label_ids: ['private_1'], source_refs: [
    {resource_id: 'resource_1', view_hash: 'b'.repeat(64), span: {start: 3, end: 9}}]},
    invoice_id: null, currency: null, due_date: null, model_text: malicious};
  const status = () => ({scan_id: `scan_${scanNumber}`, state: pending ? 'INSPECTING' : 'DECIDED',
    decision: pending ? null : decision, required_checks: ['instruction','data','behavior'],
    completed_checks: complete ? ['instruction','data','behavior'] : ['instruction'],
    coverage: {complete}, reason_codes: decision === 'REVIEW' ? ['SUSPICIOUS_INSTRUCTIONS'] : [],
    expires_at: new Date(Date.now() + 60000).toISOString(), evidence_ids: ['evidence_1'],
    review: {eligible: true, digest}, review_exception: {active: reviewException, ...(reviewExpiry ? {expires_at: reviewExpiry} : {})}});
  const envelope = (data, httpStatus = 200) => new Response(JSON.stringify({contract_version: 'v1', data}),
    {status: httpStatus, headers: {'Content-Type': 'application/json'}});
  const error = (code, httpStatus = 409) => new Response(JSON.stringify({contract_version: 'v1',
    error: {code, retryable: false, request_id: 'test'}}), {status: httpStatus});
  await waitFor(() => !el('upload-button').disabled);
  window.fetch = async (path, options = {}) => {
    if (!String(path).startsWith('/v1/')) return originalFetch(path, options);
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push({path, body, headers: options.headers});
    if (path === '/v1/resources') return envelope({resource_id: `resource_${++uploadNumber}`, storage_state: 'STORED'});
    if (path === '/v1/task-sessions') return envelope({task_session_id: 'task_1'});
    if (path === '/v1/scans') { ++scanNumber; return envelope({scan_id: `scan_${scanNumber}`, state: 'QUEUED'}); }
    if (/\/cancel$/.test(path)) return cancelDenied ? error('SERVICE_UNAVAILABLE', 503) : envelope({...status(), state: 'CANCELED', decision: null});
    if (/\/review$/.test(path)) { reviewException = body.action === 'ALLOW_READ_ONLY'; return envelope({recorded: true}); }
    if (/\/result$/.test(path)) {
      if (delayedResult) await delayedResult.promise;
      return resultDenied ? error('NOT_READY') : envelope(sample);
    }
    if (/\/v1\/scans\//.test(path)) return outage ? error('SERVICE_UNAVAILABLE', 503) : envelope(status());
    if (path === '/v1/evidence/evidence_1') {
      if (delayedEvidence) { await delayedEvidence.promise; return error('CONTEXT_CHANGED'); }
      return envelope({text: malicious});
    }
    if (path === '/v1/chat') return chatDenied ? error('NOT_READY') : envelope({scan_id: `scan_${scanNumber}`, result: sample, untrusted: true});
    if (path === '/v1/actions') {
      assert(body.action?.operation === 'simulated_send_email' && typeof body.action.arguments.to === 'string'
        && Array.isArray(body.action.arguments.attachment_resource_ids), 'Canonical action request required');
      const preview = structuredClone(body.action);
      const action_id = `action_${++actionNumber}`;
      if (delayedProposal) await delayedProposal.promise;
      return envelope({action_id, preview, digest, expires_at: new Date(Date.now() + actionLifetime).toISOString()});
    }
    if (/\/confirm$/.test(path)) {
      assert(body.digest === digest && body.recipient_selected_by_user === true, 'Exact user-selected recipient confirmation required');
      if (delayedConfirmation) await delayedConfirmation.promise;
      return envelope({state: 'CONFIRMED'});
    }
    if (/\/execute$/.test(path)) return envelope({state: 'EXECUTED'});
    throw new Error('Unexpected test route');
  };
  const deferred = () => { let release; const promise = new Promise(resolve => { release = resolve; }); return {promise, release}; };
  const beginScan = async () => {
    submit('scan-form');
    await waitFor(() => !el('scan-button').disabled &&
      (el('scan-heading').textContent !== 'Awaiting a task' || el('notice').textContent.includes('SERVICE_UNAVAILABLE')));
  };
  try {
    const files = new DataTransfer();
    files.items.add(new File(['Invoice 125.00 USD'], 'invoice.txt', {type: 'text/plain'}));
    el('upload').files = files.files;
    submit('upload-form');
    await waitFor(() => !el('scan-button').disabled);
    assert(calls[0].body.content_base64 && !calls.some(c => c.path === '/v1/chat'), 'Upload must only enter ingestion');
    assert(el('upload').value === '', 'Upload field must be cleared');
    results.push('upload enters ingestion only');

    await beginScan();
    const scanRequest = calls.find(c => c.path === '/v1/scans');
    assert(scanRequest.headers['Idempotency-Key'], 'Scan requires idempotency key');
    assert(!el('result-button').disabled, 'Completed allowed scan enables result');
    el('result-button').click();
    await waitFor(() => !el('result-panel').hidden);
    assert(el('result').textContent.includes('private_1') && el('result').textContent.includes('source_refs'), 'Preserve labels and sources');
    assert(!el('result').querySelector('img,script,a'), 'No active result markup');
    el('chat-button').click();
    await waitFor(() => !el('chat-result').hidden);
    const chat = calls.find(c => c.path === '/v1/chat');
    assert(Object.keys(chat.body).sort().join(',') === 'contract_version,scan_id', 'Chat has only scan references');
    results.push('allowed source-backed result and reference-only chat');

    el('evidence-links').querySelector('button').click();
    await waitFor(() => el('evidence-dialog').open);
    assert(el('evidence-text').textContent === malicious, 'Evidence displayed literally');
    assert(el('evidence-dialog').getAttribute('aria-labelledby') === 'evidence-heading', 'Evidence dialog has an accessible name');
    assert(!el('evidence-text').querySelector('img,script,a') && !window.uiAttack, 'Evidence has no executable markup');
    el('close-evidence').click();
    assert(el('evidence-text').textContent === '', 'Closed evidence cleared');
    assert(!calls.some(c => c.path === '/v1/chat' && JSON.stringify(c.body).includes('evil.invalid')), 'No evidence in chat');
    results.push('separate text-only evidence with no model echo');

    resultDenied = true;
    el('result-button').click();
    await waitFor(() => !el('result-button').disabled && el('notice').textContent.includes('NOT_READY'));
    assert(el('result-panel').hidden && el('chat-result').hidden && !el('result').textContent, 'Denied reread clears prior releases');
    resultDenied = false;
    el('result-button').click();
    await waitFor(() => !el('result-panel').hidden);
    el('chat-button').click();
    await waitFor(() => !el('chat-result').hidden);
    chatDenied = true;
    el('chat-button').click();
    await waitFor(() => el('chat-result').hidden && !el('chat-button').disabled);
    assert(el('result-panel').hidden && !el('chat-result').textContent, 'Denied chat clears prior releases');
    chatDenied = false;
    results.push('denied repeat reads clear previously released content');

    delayedEvidence = deferred();
    const evidenceCalls = calls.filter(c => c.path === '/v1/evidence/evidence_1').length;
    el('evidence-links').querySelector('button').click();
    await waitFor(() => calls.filter(c => c.path === '/v1/evidence/evidence_1').length > evidenceCalls);
    await beginScan();
    const currentHeading = el('scan-heading').textContent;
    delayedEvidence.release();
    await settle(); delayedEvidence = null;
    assert(el('scan-heading').textContent === currentHeading && !el('result-button').disabled && !el('evidence-dialog').open,
      'Obsolete evidence failure cannot invalidate the new scan');
    results.push('stale evidence failures leave the current task intact');

    decision = 'REVIEW'; complete = false;
    await beginScan();
    assert(el('result-button').disabled && el('review-controls').hidden, 'Incomplete scan cannot be overridden');
    complete = true;
    await beginScan();
    assert(!el('review-controls').hidden, 'Completed eligible suspicion offers read-only exception');
    el('review-allow').click();
    await waitFor(() => !el('result-button').disabled);
    assert(el('scan-heading').textContent === 'REVIEW', 'Exception cannot fabricate clean decision');
    results.push('review exceptions require completion and keep REVIEW');

    reviewExpiry = new Date(Date.now() + 250).toISOString();
    await beginScan();
    el('result-button').click();
    await waitFor(() => !el('result-panel').hidden);
    await waitFor(() => el('result-panel').hidden && el('result-button').disabled);
    assert(el('scan-heading').textContent === 'REVIEW', 'Exception expiry retains REVIEW');
    results.push('review exception expiry clears released content before decision expiry');
    reviewExpiry = null;

    decision = 'QUARANTINE'; reviewException = true;
    await beginScan();
    assert(el('result-button').disabled && el('review-controls').hidden, 'Quarantine cannot use review exception');
    results.push('quarantine remains held');

    reviewException = false; decision = 'ALLOW_UNDER_POLICY';
    el('policy').value = 'simulate_send'; el('policy').dispatchEvent(new Event('change', {bubbles: true}));
    await beginScan();
    input('recipient', 'user-selected@example.test'); input('body', 'Exact dummy body');
    input('attachment-ids', 'resource_1');
    submit('action-form');
    await waitFor(() => !el('action-preview').hidden);
    assert(el('confirm-action').disabled && !calls.some(c => /\/confirm$|\/execute$/.test(c.path)), 'Proposal cannot execute');
    assert(el('preview').textContent.includes('user-selected@example.test'), 'Exact recipient preview');
    input('recipient', 'changed@example.test');
    assert(el('action-preview').hidden && el('confirm-action').disabled, 'Edits discard approval');
    results.push('exact preview and edits require new proposal');

    delayedProposal = deferred();
    submit('action-form');
    await waitFor(() => calls.filter(c => c.path === '/v1/actions').length === 2);
    input('body', 'Edited while proposal is pending');
    delayedProposal.release(); delayedProposal = null;
    await settle();
    assert(el('action-preview').hidden, 'Stale proposal response must not re-enable confirmation');
    results.push('editing during proposal rejects stale preview');

    submit('action-form');
    await waitFor(() => !el('action-preview').hidden);
    el('exact-approval').checked = true; el('exact-approval').dispatchEvent(new Event('change'));
    delayedConfirmation = deferred();
    el('confirm-action').click();
    await waitFor(() => calls.some(c => /\/confirm$/.test(c.path)));
    input('recipient', 'third@example.test');
    delayedConfirmation.release(); delayedConfirmation = null;
    await settle();
    assert(!calls.some(c => /\/execute$/.test(c.path)), 'Editing during confirmation must stop execution');
    results.push('editing during confirmation stops execution');

    submit('action-form');
    await waitFor(() => !el('action-preview').hidden);
    el('exact-approval').checked = true; el('exact-approval').dispatchEvent(new Event('change'));
    el('confirm-action').click();
    await waitFor(() => el('action-status').textContent.includes('EXECUTED'));
    assert(calls.filter(c => /\/execute$/.test(c.path)).length === 1, 'One execution per confirmed action');
    assert(calls.find(c => /\/execute$/.test(c.path)).headers['Idempotency-Key'], 'Execution idempotency key');
    assert(el('confirm-action').disabled, 'Consumed proposal stays disabled');
    results.push('confirmed simulation executes once with idempotency');

    actionLifetime = 200;
    const confirmationCount = calls.filter(c => /\/confirm$/.test(c.path)).length;
    submit('action-form');
    await waitFor(() => !el('action-preview').hidden);
    await waitFor(() => el('action-status').textContent.includes('expired'));
    assert(el('action-preview').hidden && el('confirm-action').disabled && !el('result-button').disabled,
      'Action expiry independently discards approval while scan remains current');
    el('exact-approval').checked = true; el('exact-approval').dispatchEvent(new Event('change'));
    el('confirm-action').click();
    assert(calls.filter(c => /\/confirm$/.test(c.path)).length === confirmationCount, 'Expired proposal sends no confirmation');
    actionLifetime = 60000;
    results.push('action proposal expiry prevents confirmation independently of scan expiry');

    delayedResult = deferred();
    const resultCount = calls.filter(c => /\/result$/.test(c.path)).length;
    el('result-button').click();
    await waitFor(() => calls.filter(c => /\/result$/.test(c.path)).length > resultCount);
    el('policy').value = 'extract_invoice'; el('policy').dispatchEvent(new Event('change', {bubbles: true}));
    delayedResult.release(); delayedResult = null;
    await settle();
    assert(el('result-panel').hidden && el('action-panel').hidden, 'Changed task cannot show stale result');
    results.push('scope changes suppress in-flight results');

    pending = true;
    await beginScan();
    assert(el('result-button').disabled && !el('cancel').disabled, 'Pending scan held and cancellable');
    el('cancel').click();
    await waitFor(() => el('scan-heading').textContent === 'CANCELED');
    assert(el('cancel').disabled && el('result-panel').hidden, 'Canceled scan stays held');
    results.push('pending progress and cancellation stay honest');

    pending = false;
    await beginScan();
    cancelDenied = true;
    el('cancel').click();
    await waitFor(() => el('notice').textContent.includes('Cancellation outcome is unconfirmed'));
    assert(el('scan-heading').textContent === 'Awaiting a task' && el('result-button').disabled && el('cancel').disabled,
      'Lost cancellation response clears local release authority');
    cancelDenied = false;
    results.push('unconfirmed cancellation invalidates local results and capabilities');

    const upload = async (bytes, name) => {
      const list = new DataTransfer(); list.items.add(new File([new Uint8Array(bytes)], name, {type: 'text/plain'}));
      el('upload').files = list.files; const before = uploadNumber; submit('upload-form');
      await waitFor(() => uploadNumber > before && !el('upload-button').disabled);
    };
    for (let n = 0; n < 3; n++) await upload(800 * 1024, `large-${n}.txt`);
    const taskCount = calls.filter(c => c.path === '/v1/task-sessions').length;
    submit('scan-form');
    await waitFor(() => !el('scan-button').disabled && el('notice').textContent.includes('LIMIT_EXCEEDED'));
    assert(calls.filter(c => c.path === '/v1/task-sessions').length === taskCount, 'Selected task byte limit enforced before request');
    for (const box of el('resources').querySelectorAll('input')) {
      box.checked = box.value === 'resource_1'; box.dispatchEvent(new Event('change'));
    }
    await beginScan();
    assert(!el('result-button').disabled, 'Unselected resources do not consume task byte budget');
    for (let n = 0; n < 10; n++) await upload(1, `small-${n}.txt`);
    for (const box of el('resources').querySelectorAll('input')) {
      box.checked = !['resource_2','resource_3','resource_4'].includes(box.value); box.dispatchEvent(new Event('change'));
    }
    const countBeforeLimit = calls.filter(c => c.path === '/v1/task-sessions').length;
    submit('scan-form'); await waitFor(() => !el('scan-button').disabled && el('notice').textContent.includes('LIMIT_EXCEEDED'));
    assert(calls.filter(c => c.path === '/v1/task-sessions').length === countBeforeLimit, 'Selected task resource count enforced');
    for (const box of el('resources').querySelectorAll('input')) { box.checked = box.value === 'resource_1'; box.dispatchEvent(new Event('change')); }
    await beginScan();
    assert(!el('result-button').disabled, 'Resource library can exceed the selected task count');
    results.push('byte and resource limits apply to selected task rather than upload library');

    pending = false; outage = true;
    await beginScan();
    assert(el('notice').textContent.includes('SERVICE_UNAVAILABLE') && el('result-button').disabled,
      'Backend outage must not fabricate success');
    assert(!localStorage.length && !sessionStorage.length, 'No private browser persistence');
    results.push('outage is held and browser persistence is empty');
    return {passed: results.length, tests: results, evidence: 'TEST DOUBLES ONLY; real-stack gate still required'};
  } finally { window.fetch = originalFetch; }
})()
