const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
// Small DOM double: exercise selection and progress logic without model calls.
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = {}; this.dataset = {}; this.hidden = false; this.value = ''; this.textContent = ''; this.classList = {add(){}, remove(){}}; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  setAttribute(name, value) { this[name] = value; }
  querySelectorAll() { return []; }
  close() {}
}
function setup() {
  const elements = new Map();
  const document = {getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); }, createElement(tag) { return new Element(tag); }};
  const context = vm.createContext({document, window:{addEventListener(){}}, clearTimeout, setTimeout, console, Uint8Array, TextDecoder, AbortController});
  let source = fs.readFileSync(path.join(__dirname, '../../web/app.js'), 'utf8');
  source = source.slice(0, source.lastIndexOf('try { await connectSession(); }'));
  vm.runInContext(source + '\nstate.csrf="test"; this.ui={state,renderFolder,selectScanFiles,readDroppedFiles};', context);
  return {ui:context.ui, el:id=>document.getElementById(id)};
}
function status(extra = {}) {
  return {folder_id:'folder_test', task_session_id:'task_test', scan_id:'scan_test', state:'INSPECTING', coverage_complete:false,
    required_checks:['EXTRACTION','INSTRUCTION_INSPECTOR','DATA_TOOL_INSPECTOR','BEHAVIOR_TESTER'], completed_checks:['EXTRACTION'],
    file_count:2, files:[{path:'notes.txt', resource_id:'res_notes', status:'PENDING', inspection_complete:false, finding_categories:[], evidence_ids:[]},
    {path:'nested/attack.txt', resource_id:'res_attack', status:'FLAGGED', inspection_complete:false, finding_categories:['OVERRIDE_ATTEMPT'], evidence_ids:[]}], ...extra};
}
test('progress reflects completed checks and lists the whole active batch', () => {
  const {ui,el}=setup(); ui.state.folder='folder_test'; ui.renderFolder(status());
  assert.equal(el('scan-progress-bar').value,38.75);
  assert.deepEqual(el('progress-files').children.map(x=>x.textContent),['notes.txt','nested/attack.txt']);
  assert.equal(el('folder-report').hidden,true);
  assert.equal(el('folder-button').disabled,true);
});
test('finished report puts suspicious files first and only full coverage reaches 100%', () => {
  const {ui,el}=setup(); ui.state.folder='folder_test';
  const data=status({state:'DECIDED',coverage_complete:true,inspection_errors:[{code:'MODEL_RESPONSE_INVALID'}]});
  data.files[0].status='NO_FINDINGS'; data.files.forEach(file=>file.inspection_complete=true);
  data.completed_checks=data.required_checks;
  ui.renderFolder(data);
  assert.equal(el('scan-progress-bar').value,100);
  assert.equal(el('folder-report').hidden,false);
  assert.doesNotMatch(el('folder-summary').textContent,/failed|invalid/i);
  assert.equal(el('folder-heading').textContent,'1 suspicious file found');
  assert.equal(el('folder-files').children[0].children[1].children[0].textContent,'nested/attack.txt');
});
test('incomplete and unsupported scans never imply successful completion', () => {
  const {ui,el}=setup(); ui.state.folder='folder_test';
  ui.renderFolder(status({state:'DECIDED',completed_checks:['EXTRACTION','INSTRUCTION_INSPECTOR','DATA_TOOL_INSPECTOR']}));
  assert.ok(el('scan-progress-bar').value<100);
  assert.equal(el('progress-heading').textContent,'Scan incomplete');
  assert.match(el('folder-files').children[0].children[1].children[1].textContent,/checks incomplete/);
  ui.renderFolder(status({state:'NOT_STARTED',task_session_id:null,scan_id:null,required_checks:[],completed_checks:[]}));
  assert.equal(el('folder-report').hidden,false);
});
test('filenames render as text and duplicate selections clear old files', () => {
  const {ui,el}=setup();
  ui.selectScanFiles([{file:{},path:'<img onerror=attack>.txt'}]);
  assert.equal(el('selection-files').children[0].textContent,'<img onerror=attack>.txt');
  ui.selectScanFiles([{file:{},path:'a.txt'},{file:{},path:'a.txt'}]);
  assert.equal(ui.state.selectedFiles.length,0);
  assert.equal(el('folder-button').disabled,true);
});
function file(name) { return {name,isFile:true,file(resolve){resolve({name});}}; }
function directory(name,batches) { return {name,isDirectory:true,createReader(){let n=0;return {readEntries(resolve){resolve(batches[n++]||[]);}};}}; }
test('folder drop walks nested entries and all directory-reader batches', async () => {
  const {ui}=setup();
  const entries=[directory('project',[[file('a.txt')],[directory('nested',[[file('b.txt')]])]])];
  const result=await ui.readDroppedFiles(entries,[]);
  assert.deepEqual(Array.from(result,x=>x.path),['project/a.txt','project/nested/b.txt']);
});
test('oversized folder drops are rejected rather than silently truncated', async () => {
  const {ui}=setup();
  await assert.rejects(ui.readDroppedFiles([directory('large',[Array.from({length:101},(_,i)=>file(i+'.txt'))])],[]),/LIMIT_EXCEEDED/);
});
