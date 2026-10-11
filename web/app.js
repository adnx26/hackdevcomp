// All sensitive state stays in this page's memory. Never render source HTML.
const $ = id => document.getElementById(id);
const state = {csrf: null, resources: [], task: null, scan: null, status: null,
  action: null, actionRevision: 0, timer: null, expiryTimer: null, actionExpiryTimer: null,
  generation: 0, delay: 1000, polling: false, busy: false};
const idPattern = /^[A-Za-z0-9_-]{1,128}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const knownErrors = new Set(['UNAUTHENTICATED','FORBIDDEN','NOT_FOUND','INVALID_REQUEST',
  'LIMIT_EXCEEDED','NOT_READY','CONTEXT_CHANGED','APPROVAL_REQUIRED','SERVICE_UNAVAILABLE']);
const findingInfo = {
  OVERRIDE_ATTEMPT: ['Instruction override attempt', 'The source appears to ask the system to ignore or replace the task instructions.'],
  HIDDEN_INSTRUCTIONS: ['Hidden instructions', 'The source appears to contain instructions concealed in its content or formatting.'],
  DISCLOSURE_REQUEST: ['Request to disclose private information', 'The source appears to ask for information outside the task’s permitted scope.'],
  UNAUTHORIZED_TOOL_REQUEST: ['Unapproved tool or action request', 'The source appears to request an action that the selected task does not authorize.'],
  OBSERVED_FORBIDDEN_ACTION: ['Blocked action attempt', 'The gateway recorded and blocked an action that the task policy forbids.'],
  ANSWER_MISMATCH: ['Source and answer did not match', 'An inspector could not verify an extracted answer against its cited source.'],
};
const reasonInfo = {
  EXTRACTION_INCOMPLETE: 'The gateway could not read all of the submitted content.',
  EXTRACTION_ERROR: 'The gateway hit an error while reading the submitted content.',
  UNSUPPORTED_CONTENT: 'The source includes content this workflow cannot inspect, so it stays held.',
  LIMIT_EXCEEDED: 'The source or task exceeded a processing limit.',
  INSPECTION_INCOMPLETE: 'At least one required inspection did not finish.',
  INSPECTION_ERROR: 'At least one required inspection encountered an error.',
  WORKER_MISSING: 'A required inspection did not return a result.',
  TIMEOUT: 'The inspection reached its time limit before all checks finished.',
  SUSPICIOUS_UNCORROBORATED: 'An inspector flagged suspicious content. Review the supporting records below.',
  ANSWER_MISMATCH: 'An extracted answer did not match its cited source.',
  TASK_OUTPUT_MISSING: 'The requested task result was not produced.',
  VERIFIED_FORBIDDEN_ACTION: 'The gateway recorded a forbidden action attempt and quarantined the source.',
  RUNTIME_UNAVAILABLE: 'A required local service was unavailable.',
  INTERRUPTED: 'The inspection was interrupted before it could finish.',
  CANCELED_BY_USER: 'The inspection was canceled.',
  REJECTED_BY_USER: 'The content was rejected during review.',
  RESOURCE_DELETED: 'A source was removed before the inspection completed.',
  CONTRADICTORY_EVIDENCE: 'The inspection produced conflicting records, so the content remains held.',
  EMERGENCY_STOP: 'The gateway emergency stop prevented this inspection from completing.',
};
const roleInfo = {
  INSTRUCTION_INSPECTOR: 'Instruction check',
  DATA_TOOL_INSPECTOR: 'Data and action check',
  BEHAVIOR_TESTER: 'Task result check',
};
function readableName(value) {
  return String(value || '').toLowerCase().split('_').map(part => part ? part[0].toUpperCase() + part.slice(1) : '').join(' ');
}
function decodeEscapedText(value) {
  return value.replace(/&(?:amp|lt|gt|quot|#x27);/g, entity => ({
    '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#x27;': "'",
  })[entity]);
}

function notice(text, error = false) {
  $('notice').textContent = text;
  $('notice').dataset.error = String(error);
}
function renderText(id, value) { $(id).textContent = JSON.stringify(value, null, 2); }
function validId(value) { if (typeof value !== 'string' || !idPattern.test(value)) throw new Error('SERVICE_UNAVAILABLE'); return value; }
function safeCode(value) { return /^[A-Z][A-Z0-9_]{0,63}$/.test(value || '') ? value : 'SERVICE_UNAVAILABLE'; }
function fail(error) {
  if (Number.isInteger(error.generation) && error.generation !== state.generation) return;
  const code = knownErrors.has(error.message) ? error.message : 'SERVICE_UNAVAILABLE';
  notice(code + '. Content remains held unless the gateway grants a current permitted result.', true);
  clearReleased();
  if (['CONTEXT_CHANGED','UNAUTHENTICATED','FORBIDDEN'].includes(code)) invalidate();
}

async function api(path, body, key) {
  const generation = state.generation;
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('INVALID_REQUEST');
  const headers = {Accept: 'application/json'};
  if (body !== undefined) {
    if (!state.csrf) throw new Error('UNAUTHENTICATED');
    headers['Content-Type'] = 'application/json';
    headers['X-CSRF-Token'] = state.csrf;
    if (key) headers['Idempotency-Key'] = key;
  }
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST',
      headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      signal: controller.signal, body: body === undefined ? undefined : JSON.stringify({contract_version: 'v1', ...body})});
    const reader = response.body.getReader();
    let size = 0;
    const chunks = [];
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 256 * 1024) { await reader.cancel(); throw new Error('LIMIT_EXCEEDED'); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const envelope = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
    if (envelope.contract_version !== 'v1') throw new Error('SERVICE_UNAVAILABLE');
    if (!response.ok || envelope.error) {
      const error = new Error(knownErrors.has(envelope.error?.code) ? envelope.error.code : 'SERVICE_UNAVAILABLE');
      error.retryable = envelope.error?.retryable === true;
      throw error;
    }
    if (!envelope.data || typeof envelope.data !== 'object' || Array.isArray(envelope.data)) throw new Error('SERVICE_UNAVAILABLE');
    return envelope.data;
  } catch (error) { error.generation = generation; throw error; }
  finally { clearTimeout(deadline); }
}

function discardAction() {
  ++state.actionRevision;
  state.action = null;
  clearTimeout(state.actionExpiryTimer);
  $('action-preview').hidden = true;
  $('preview').textContent = '';
  $('action-digest').textContent = '';
  $('action-status').textContent = '';
  $('exact-approval').checked = false;
  $('confirm-action').disabled = true;
}
function actionCurrent(action) {
  return action && action === state.action && Number.isFinite(Date.parse(action.expires_at))
    && Date.parse(action.expires_at) > Date.now();
}
function resultExpiry(data) {
  const expiry = Date.parse(data?.expires_at);
  const exceptionExpiry = Date.parse(data?.review_exception?.expires_at);
  return data?.decision === 'REVIEW' && data.review_exception?.active === true && Number.isFinite(exceptionExpiry)
    ? Math.min(expiry, exceptionExpiry) : expiry;
}
function canReadResult(data = state.status) {
  return data?.state === 'DECIDED' && data.coverage?.complete === true
    && data.required_checks?.length > 0 && data.required_checks.every(c => data.completed_checks.includes(c))
    && Number.isFinite(resultExpiry(data)) && resultExpiry(data) > Date.now()
    && (data.decision === 'ALLOW_UNDER_POLICY' || (data.decision === 'REVIEW' && data.review_exception?.active === true));
}
function clearReleased() {
  $('result-panel').hidden = true;
  $('result-replay-banner').hidden = true;
  $('result').textContent = '';
  $('chat-result').hidden = true;
  $('chat-result').textContent = '';
  discardAction();
}
function invalidate() {
  ++state.generation;
  clearTimeout(state.timer);
  clearTimeout(state.expiryTimer);
  state.task = state.scan = state.status = null;
  state.polling = false;
  clearReleased();
  $('action-panel').hidden = true;
  $('result-button').disabled = $('cancel').disabled = true;
  $('review-controls').hidden = $('review-reject').hidden = true;
  $('scan-heading').textContent = 'Awaiting a task';
  $('scan-meta').replaceChildren(); $('checks').replaceChildren(); $('evidence-links').replaceChildren();
  $('reasons').textContent = '';
  $('evidence-text').textContent = '';
  $('evidence-summary').replaceChildren();
  $('evidence-dialog').close();
}

function renderStatus(data) {
  const states = ['QUEUED','EXTRACTING','INSPECTING','DECIDED','FAILED','CANCELED'];
  if (!states.includes(data.state) || validId(data.scan_id) !== state.scan
    || !Array.isArray(data.required_checks) || !Array.isArray(data.completed_checks)) throw new Error('SERVICE_UNAVAILABLE');
  if (data.required_checks.length > 64 || data.completed_checks.length > 64) throw new Error('SERVICE_UNAVAILABLE');
  data.required_checks.forEach(validId); data.completed_checks.forEach(validId);
  if (data.completed_checks.some(check => !data.required_checks.includes(check))) throw new Error('SERVICE_UNAVAILABLE');
  if (data.decision && !['ALLOW_UNDER_POLICY','REVIEW','QUARANTINE'].includes(data.decision)) throw new Error('SERVICE_UNAVAILABLE');
  if (data.decision_expires_at !== undefined) {
    data.expires_at = data.decision_expires_at;
    data.coverage.complete = data.coverage.extraction.length > 0
      && data.coverage.extraction.every(e => e.status === 'COMPLETE' && !e.unsupported_parts.some(p => p.task_relevant))
      && ['INSTRUCTION_INSPECTOR', 'DATA_TOOL_INSPECTOR', 'BEHAVIOR_TESTER'].every(r => data.coverage.inspections[r] === 'COMPLETE');
    data.review = {...data.review, digest: data.review?.result_digest};
    data.evidence_ids = [...new Set([...(data.findings || []).flatMap(f => f.evidence_ids), ...(data.collector_evidence || []).map(e => e.evidence_id)])];
  }
  state.status = data;
  // Replayed runs are always labeled; anything other than LIVE is shown as such.
  const inference = ['LIVE', 'REPLAY'].includes(data.inference_mode) ? data.inference_mode : 'UNKNOWN';
  $('replay-banner').hidden = inference !== 'REPLAY';
  const decisionCopy = {
    ALLOW_UNDER_POLICY: ['Checks complete · permitted result', 'The required checks completed. You can view the result under the selected task policy.'],
    REVIEW: ['Held for review', 'The gateway found an unresolved issue or could not complete coverage. The source is not available to the assistant.'],
    QUARANTINE: ['Quarantined', 'The gateway recorded a forbidden action. The source and its result remain unavailable.'],
  };
  const [heading, description] = decisionCopy[data.decision] || [readableName(data.state), 'The gateway is processing the selected source.'];
  $('scan-heading').textContent = heading;
  $('scan-description').textContent = description;
  $('scan-meta').replaceChildren();
  const metadata = {'Scan': data.scan_id,
    'Completed checks': `${new Set(data.completed_checks).size} / ${new Set(data.required_checks).size}`,
    'Coverage': data.coverage?.complete === true ? 'Complete' : data.coverage?.complete === false ? 'Incomplete' : 'Not reported',
    'Inference': inference === 'REPLAY' ? 'REPLAY (recorded responses)' : inference === 'LIVE' ? 'Live model' : 'Not reported',
    'Result expires': Number.isFinite(resultExpiry(data)) ? new Date(resultExpiry(data)).toLocaleString() : 'Not issued'};
  for (const [key, value] of Object.entries(metadata)) {
    const dt = document.createElement('dt'), dd = document.createElement('dd');
    dt.textContent = key; dd.textContent = typeof value === 'object' ? JSON.stringify(value) : String(value);
    $('scan-meta').append(dt, dd);
  }
  $('checks').replaceChildren();
  for (const check of new Set(data.required_checks)) {
    const li = document.createElement('li');
    const complete = data.completed_checks.includes(check);
    li.textContent = `${complete ? 'Complete' : 'Waiting'} · ${roleInfo[check] || readableName(check)}`;
    li.dataset.complete = String(complete); $('checks').append(li);
  }
  $('reasons').replaceChildren();
  const reasonCodes = (data.reason_codes || []).slice(0, 64).map(safeCode);
  if (reasonCodes.length) {
    const heading = document.createElement('h3'); heading.textContent = 'Why it was held'; $('reasons').append(heading);
    const list = document.createElement('ul'); list.className = 'reason-list';
    for (const code of reasonCodes) {
      const item = document.createElement('li');
      item.textContent = reasonInfo[code] || readableName(code);
      list.append(item);
    }
    $('reasons').append(list);
  }
  $('cancel').disabled = ['FAILED','CANCELED'].includes(data.state);
  const allComplete = data.required_checks.length > 0 && data.required_checks.every(c => data.completed_checks.includes(c));
  const expiry = resultExpiry(data);
  const current = Number.isFinite(expiry) && expiry > Date.now();
  const reviewEligible = data.state === 'DECIDED' && data.decision === 'REVIEW' && allComplete
    && current && data.coverage?.complete === true && data.review?.eligible === true && digestPattern.test(data.review.digest);
  $('review-controls').hidden = !reviewEligible;
  $('review-reject').hidden = data.decision !== 'REVIEW';
  $('result-button').disabled = !canReadResult(data);
  clearTimeout(state.expiryTimer);
  if (current) {
    const generation = state.generation;
    const checkExpiry = () => {
      if (generation !== state.generation) return;
      if (expiry > Date.now()) {
        state.expiryTimer = setTimeout(checkExpiry, Math.min(expiry - Date.now(), 2147483647));
      } else {
        clearReleased(); $('result-button').disabled = true; $('review-controls').hidden = true;
        notice('The scan expired. Start a new inspection before using its result.', true);
      }
    };
    state.expiryTimer = setTimeout(checkExpiry, Math.min(expiry - Date.now(), 2147483647));
  }
  if ($('result-button').disabled) clearReleased();
  $('evidence-links').replaceChildren();
  $('evidence-summary').replaceChildren();
  const evidenceTitles = new Map();
  for (const finding of (data.findings || []).slice(0, 64)) {
    const [title, meaning] = findingInfo[finding.category] || [readableName(finding.category), 'An inspector recorded this finding.'];
    const role = roleInfo[finding.role] || readableName(finding.role);
    for (const evidenceId of (finding.evidence_ids || []).slice(0, 20)) {
      if (!evidenceTitles.has(evidenceId)) evidenceTitles.set(evidenceId, {title, meaning, role});
    }
  }
  for (const event of (data.collector_evidence || []).slice(0, 64)) {
    evidenceTitles.set(event.evidence_id, {
      title: 'Blocked action attempt',
      meaning: `The gateway recorded a ${readableName(event.operation)} attempt and marked it ${readableName(event.policy_check).toLowerCase()}.`,
      role: 'Gateway action record',
    });
  }
  if (data.evidence_ids?.length) {
    const heading = document.createElement('h3'); heading.textContent = 'Supporting evidence'; $('evidence-links').append(heading);
    const intro = document.createElement('p'); intro.className = 'hint'; intro.textContent = 'Each record shows what was flagged and a short excerpt from the source. Review it as untrusted content.'; $('evidence-links').append(intro);
  }
  for (const evidenceId of (data.evidence_ids || []).slice(0, 64)) {
    validId(evidenceId);
    const detail = evidenceTitles.get(evidenceId) || {title: 'Inspection record', meaning: 'Open the record to see the supporting details.', role: 'Gateway evidence'};
    const card = document.createElement('article'); card.className = 'finding-card';
    const title = document.createElement('h4'); title.textContent = detail.title;
    const explanation = document.createElement('p'); explanation.textContent = detail.meaning;
    const source = document.createElement('p'); source.className = 'finding-source'; source.textContent = `Recorded by ${detail.role}`;
    const button = document.createElement('button'); button.className = 'secondary'; button.textContent = 'Review source excerpt';
    button.addEventListener('click', () => viewEvidence(evidenceId, detail));
    card.append(title, explanation, source, button); $('evidence-links').append(card);
  }
}

async function poll(generation) {
  if (generation !== state.generation || !state.scan || state.polling) return;
  state.polling = true;
  const scan = state.scan;
  try {
    const data = await api(`/v1/scans/${scan}`);
    if (generation !== state.generation) return;
    renderStatus(data);
    if (!['QUEUED','EXTRACTING','INSPECTING'].includes(data.state)) return;
    state.delay = Math.min(Math.round(state.delay * 1.5), 8000);
  } catch (error) {
    if (generation !== state.generation) return;
    fail(error);
    $('result-button').disabled = true;
    clearReleased();
    if (!error.retryable) return;
    state.delay = Math.min(state.delay * 2, 8000);
  } finally { if (generation === state.generation) state.polling = false; }
  if (generation === state.generation) state.timer = setTimeout(() => poll(generation), state.delay);
}

async function viewEvidence(evidenceId, detail) {
  const generation = state.generation;
  try {
    const data = await api(`/v1/evidence/${validId(evidenceId)}`);
    if (generation !== state.generation) return;
    const escaped = data.text ?? data.text_escaped;
    if (typeof escaped !== 'string' || escaped.length > 32000) throw new Error('SERVICE_UNAVAILABLE');
    const text = decodeEscapedText(escaped);
    $('evidence-heading').textContent = detail?.title || 'Supporting evidence';
    $('evidence-explainer').textContent = `${detail?.meaning || 'This record supports the inspection result.'} Evidence is shown as text only and is not sent to the assistant.`;
    $('evidence-summary').replaceChildren();
    let parsed;
    try { parsed = JSON.parse(text); } catch {}
    const sourceExcerpts = Array.isArray(data.source_excerpts) ? data.source_excerpts : parsed?.source_excerpts;
    if (Array.isArray(sourceExcerpts)) {
      sourceExcerpts.slice(0, 64).forEach(excerpt => {
        if (!excerpt || typeof excerpt.text !== 'string') return;
        const finding = Number.isInteger(excerpt.finding_index) ? parsed.model_findings?.[excerpt.finding_index] : null;
        const findingTitle = findingInfo[finding?.category]?.[0];
        if (findingTitle) {
          const label = document.createElement('h3'); label.textContent = findingTitle; $('evidence-summary').append(label);
        }
        const block = document.createElement('blockquote');
        block.textContent = `${excerpt.truncated ? '…' : ''}${excerpt.text}${excerpt.truncated ? '…' : ''}`;
        $('evidence-summary').append(block);
      });
      if (!$('evidence-summary').childElementCount) $('evidence-summary').textContent = 'The record has no source excerpt.';
    } else {
      const textLine = text.match(/(?:^|\s)operation=([^\s]+)/);
      if (textLine) {
        const summary = document.createElement('p');
        summary.textContent = `Attempted action: ${readableName(textLine[1])}. ${detail?.meaning || ''}`;
        $('evidence-summary').append(summary);
      } else $('evidence-summary').textContent = 'This technical record does not include a source excerpt.';
    }
    $('evidence-text').textContent = parsed === undefined ? text : JSON.stringify(parsed, null, 2);
    $('evidence-dialog').showModal();
  } catch (error) { if (generation === state.generation) fail(error); }
}

async function exclusive(button, operation) {
  if (state.busy) return;
  state.busy = true; button.disabled = true;
  try { await operation(); } catch (error) { fail(error); }
  finally {
    state.busy = false; button.disabled = false;
    $('confirm-action').disabled = !actionCurrent(state.action) || !$('exact-approval').checked;
    if (button.id === 'result-button') {
      button.disabled = !canReadResult();
    }
    if (button.id === 'cancel') button.disabled = !state.scan || ['FAILED','CANCELED'].includes(state.status?.state);
  }
}

$('upload-form').addEventListener('submit', event => {
  event.preventDefault();
  exclusive($('upload-button'), async () => {
    const file = $('upload').files[0];
    if (!file || file.size > 1024 * 1024) throw new Error('LIMIT_EXCEEDED');
    if (!/\.(txt|eml)$/i.test(file.name)) throw new Error('INVALID_REQUEST');
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = '';
    for (let start = 0; start < bytes.length; start += 16384) binary += String.fromCharCode(...bytes.subarray(start, start + 16384));
    const data = await api('/v1/resources', {media_type: /\.eml$/i.test(file.name) ? 'message/rfc822' : 'text/plain', content_base64: btoa(binary)});
    if (data.storage_state !== 'STORED') throw new Error('SERVICE_UNAVAILABLE');
    const resourceId = validId(data.resource_id);
    state.resources.push({id: resourceId, size: file.size});
    $('empty-resources').hidden = true;
    const label = document.createElement('label'), checkbox = document.createElement('input');
    checkbox.type = 'checkbox'; checkbox.value = resourceId; checkbox.checked = true;
    checkbox.addEventListener('change', invalidate);
    label.append(checkbox, document.createTextNode(resourceId)); $('resources').append(label);
    invalidate(); $('upload').value = ''; $('scan-button').disabled = false;
    notice('Resource stored privately. Select a task to inspect it.');
  });
});
$('policy').addEventListener('change', invalidate);
$('scan-form').addEventListener('submit', event => {
  event.preventDefault();
  exclusive($('scan-button'), async () => {
    const resourceIds = [...$('resources').querySelectorAll('input:checked')].map(input => validId(input.value));
    if (!resourceIds.length) throw new Error('INVALID_REQUEST');
    const selectedSize = state.resources.filter(resource => resourceIds.includes(resource.id)).reduce((n, resource) => n + resource.size, 0);
    if (resourceIds.length > 10 || selectedSize > 2 * 1024 * 1024) throw new Error('LIMIT_EXCEEDED');
    invalidate(); const generation = state.generation;
    const task = await api('/v1/task-sessions', {policy_id: $('policy').value, resource_ids: resourceIds});
    if (generation !== state.generation) return;
    state.task = validId(task.task_session_id);
    const scan = await api('/v1/scans', {task_session_id: state.task}, crypto.randomUUID());
    if (generation !== state.generation) return;
    state.scan = validId(scan.scan_id); state.delay = 1000;
    $('action-panel').hidden = $('policy').value !== 'simulate_send';
    notice('Inspection requested. Waiting for gateway progress.');
    await poll(generation);
  });
});
$('cancel').addEventListener('click', () => exclusive($('cancel'), async () => {
  const scan = state.scan;
  if (!scan) return;
  const generation = ++state.generation;
  clearTimeout(state.timer); clearTimeout(state.expiryTimer);
  state.polling = false;
  clearReleased();
  let data;
  try { data = await api(`/v1/scans/${scan}/cancel`, {}); }
  catch (error) {
    // A lost response does not establish cancellation or a current release.
    if (generation === state.generation) {
      invalidate();
      notice('Cancellation outcome is unconfirmed. Start a new task before using a result; the gateway may still be processing the previous scan.', true);
    }
    throw error;
  }
  if (generation !== state.generation) return;
  clearTimeout(state.timer); clearReleased(); renderStatus(data);
  notice('Gateway cancellation recorded. Pending content and capabilities remain subject to its state.');
}));
$('result-button').addEventListener('click', () => exclusive($('result-button'), async () => {
  const scan = state.scan, generation = state.generation;
  const data = await api(`/v1/scans/${scan}/result`);
  if (generation !== state.generation || !canReadResult()) return;
  $('result-replay-banner').hidden = data.inference_mode !== 'REPLAY';
  renderText('result', data); $('result-panel').hidden = false;
}));
$('chat-button').addEventListener('click', () => exclusive($('chat-button'), async () => {
  const generation = state.generation;
  const data = await api('/v1/chat', {scan_id: state.scan});
  if (generation !== state.generation || !canReadResult()) return;
  renderText('chat-result', data); $('chat-result').hidden = false;
}));
async function review(outcome) {
  if (!state.scan) return;
  const generation = state.generation;
  const digest = state.status?.review?.digest;
  if (outcome === 'ALLOW_READ_ONLY' && !digestPattern.test(digest || '')) throw new Error('NOT_READY');
  await api(`/v1/scans/${state.scan}/review`, {action: outcome, reason: 'User reviewed the inspection in the gateway UI',
    ...(digestPattern.test(digest || '') ? {result_digest: digest} : {})});
  if (generation === state.generation) await poll(generation);
}
$('review-allow').addEventListener('click', () => exclusive($('review-allow'), () => review('ALLOW_READ_ONLY')));
$('review-reject').addEventListener('click', () => exclusive($('review-reject'), () => review('REJECT')));
$('action-form').addEventListener('input', discardAction);
$('action-form').addEventListener('submit', event => {
  event.preventDefault();
  exclusive($('action-form').querySelector('button'), async () => {
    discardAction();
    if (!state.task) throw new Error('NOT_READY');
    const generation = state.generation;
    const actionRevision = state.actionRevision;
    const attachmentIds = $('attachment-ids').value.split(',').map(s => s.trim()).filter(Boolean).map(validId);
    if (attachmentIds.length > 10) throw new Error('LIMIT_EXCEEDED');
    const data = await api('/v1/actions', {task_session_id: state.task,
      action: {operation: 'simulated_send_email', arguments: {to: $('recipient').value, subject: $('subject')?.value || '', body: $('body').value, attachment_resource_ids: attachmentIds}}});
    if (generation !== state.generation || actionRevision !== state.actionRevision) return;
    validId(data.action_id);
    if (typeof data.digest !== 'string' || !digestPattern.test(data.digest) || !data.preview || typeof data.preview !== 'object'
      || !Number.isFinite(Date.parse(data.expires_at)) || Date.parse(data.expires_at) <= Date.now()) throw new Error('SERVICE_UNAVAILABLE');
    state.action = {...data, key: crypto.randomUUID()};
    renderText('preview', data.preview);
    $('action-digest').textContent = `Digest: ${data.digest} · Expiry: ${data.expires_at || 'Not reported'}`;
    $('action-preview').hidden = false;
    const action = state.action;
    const checkActionExpiry = () => {
      if (action !== state.action || generation !== state.generation) return;
      if (actionCurrent(action)) {
        state.actionExpiryTimer = setTimeout(checkActionExpiry, Math.min(Date.parse(action.expires_at) - Date.now(), 2147483647));
      } else {
        discardAction();
        $('action-status').textContent = 'The action proposal expired. Create a new proposal before confirming.';
      }
    };
    state.actionExpiryTimer = setTimeout(checkActionExpiry, Math.min(Date.parse(action.expires_at) - Date.now(), 2147483647));
  });
});
$('exact-approval').addEventListener('change', () => { $('confirm-action').disabled = !actionCurrent(state.action) || !$('exact-approval').checked; });
$('confirm-action').addEventListener('click', () => exclusive($('confirm-action'), async () => {
  const action = state.action, generation = state.generation;
  if (!actionCurrent(action) || !$('exact-approval').checked) throw new Error('APPROVAL_REQUIRED');
  await api(`/v1/actions/${action.action_id}/confirm`, {digest: action.digest, recipient_selected_by_user: true});
  if (generation !== state.generation || !actionCurrent(action)) return;
  const data = await api(`/v1/actions/${action.action_id}/execute`, {}, action.key);
  if (generation !== state.generation || state.action !== action) return;
  discardAction();
  $('action-status').textContent = `Gateway action state: ${safeCode(data.state)}. Simulation only.`;
}));
$('close-evidence').addEventListener('click', () => { $('evidence-dialog').close(); $('evidence-text').textContent = ''; $('evidence-summary').replaceChildren(); });
$('evidence-dialog').addEventListener('close', () => { $('evidence-text').textContent = ''; $('evidence-summary').replaceChildren(); });
$('copy-evidence').addEventListener('click', () => { navigator.clipboard.writeText($('evidence-text').textContent).catch(() => notice('Copy is unavailable in this browser.', true)); });
window.addEventListener('pagehide', () => { invalidate(); state.csrf = null; state.resources = []; $('body').value = ''; });

async function connectSession() {
  const session = await api('/ui/session');
  if (typeof session.csrf_token !== 'string' || !session.csrf_token) throw new Error('UNAUTHENTICATED');
  state.csrf = session.csrf_token;
  $('identity').textContent = session.display_name || 'Authenticated session';
  $('upload-button').disabled = false;
  if ($('login-form')) $('login-form').hidden = true;
  notice('Session connected. Upload content to begin.');
}
$('login-form')?.addEventListener('submit', event => {
  event.preventDefault();
  exclusive($('login-button'), async () => {
    const token = $('login-token').value;
    $('login-token').value = '';
    const response = await fetch('/v1/session', {method: 'POST', credentials: 'same-origin', redirect: 'error',
      headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, body: '{}'});
    if (!response.ok) throw new Error('UNAUTHENTICATED');
    await connectSession();
  });
});
try { await connectSession(); }
catch (error) {
  $('identity').textContent = 'Sign in to begin';
  if ($('login-form')) $('login-form').hidden = false;
  if (error.message === 'UNAUTHENTICATED') notice('Sign in with your local gateway login token.');
  else fail(error);
}
