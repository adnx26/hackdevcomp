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
  showModal() {}
  get childElementCount() { return this.children.length; }
}
function setup() {
  const elements = new Map();
  const document = {getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); }, createElement(tag) { return new Element(tag); }};
  const context = vm.createContext({document, window:{addEventListener(){}}, clearTimeout, setTimeout, console, Uint8Array, TextDecoder, AbortController});
  let source = fs.readFileSync(path.join(__dirname, '../../web/app.js'), 'utf8');
  source = source.slice(0, source.lastIndexOf('try { await connectSession(); }'));
  vm.runInContext(source + '\nstate.csrf="test"; this.ui={state,renderFolder,selectScanFiles,readDroppedFiles,viewEvidence,fail};', context);
  return {context,ui:context.ui, el:id=>document.getElementById(id)};
}
function status(extra = {}) {
  return {folder_id:'folder_test', task_session_id:'task_test', scan_id:'scan_test', state:'INSPECTING', coverage_complete:false,
    required_checks:['EXTRACTION','INSTRUCTION_INSPECTOR','DATA_TOOL_INSPECTOR','BEHAVIOR_TESTER'], completed_checks:['EXTRACTION'],
    file_count:2, files:[{path:'notes.txt', resource_id:'res_notes', status:'PENDING', inspection_complete:false, finding_categories:[], evidence_ids:[]},
    {path:'nested/attack.txt', resource_id:'res_attack', status:'FLAGGED', inspection_complete:false, finding_categories:['OVERRIDE_ATTEMPT'], evidence_ids:[]}], ...extra};
}
test('rejected sessions restore sign-in and disable scanning without releasing content', () => {
  const {ui,el}=setup();
  ui.selectScanFiles([{file:{},path:'a.txt'}]);
  ui.state.resources=['res_old']; ui.state.folder='folder_test';
  ui.state.folderScanning=true;
  el('login-form').hidden=true;
  ui.fail(new Error('UNAUTHENTICATED'));
  assert.equal(ui.state.csrf,null);
  assert.equal(ui.state.resources.length,0);
  assert.equal(ui.state.folder,null);
  assert.equal(el('login-form').hidden,false);
  assert.equal(el('identity').textContent,'Sign in to begin');
  assert.equal(el('folder-button').disabled,true);
  assert.equal(el('upload-button').disabled,true);
  assert.equal(el('result-panel').hidden,true);
  assert.match(el('notice').textContent,/Sign in again.*Content remains held/);
});
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

test('file evidence shows only excerpts bound to the selected resource', async () => {
  const {context,ui,el}=setup();
  context.evidenceFixture={text_escaped:JSON.stringify({model_findings:[
    {category:'OVERRIDE_ATTEMPT',source_references:[{resource_id:'res_other'},{resource_id:'res_attack'}]}]}),
    source_excerpts:[{finding_index:0,reference_index:0,text:'Other file'},
      {finding_index:0,reference_index:1,text:'Selected attack file'},
      {finding_index:0,reference_index:9,text:'Unbound excerpt'}]};
  vm.runInContext('api = async () => evidenceFixture;',context);
  await ui.viewEvidence('evidence_test',{title:'attack.txt',resourceId:'res_attack'});
  assert.equal(el('evidence-heading').textContent,'attack.txt');
  assert.deepEqual(el('evidence-summary').children.map(x=>x.textContent),['Instruction override attempt','Selected attack file']);
  assert.match(el('evidence-text').textContent,/res_other/);
});

test('macOS metadata is excluded explicitly while other hidden and unsupported files remain selected', () => {
  const {ui,el}=setup();
  ui.selectScanFiles(['repo/.DS_Store','repo/nested/.DS_Store','repo/.env','repo/.DS_Store.txt','repo/document.pdf','repo/notes.txt'].map(path=>({file:{},path})));
  assert.deepEqual(Array.from(ui.state.selectedFiles,x=>x.path),['repo/.DS_Store.txt','repo/.env','repo/document.pdf','repo/notes.txt']);
  assert.match(el('selection-summary').textContent,/4 files ready.*2 .DS_Store metadata files excluded/);
  assert.match(el('selection-files').children.at(-1).textContent,/not inspected/);
  ui.state.folder='folder_test';
  const complete=status({state:'DECIDED',coverage_complete:true});
  complete.completed_checks=complete.required_checks;
  complete.files.forEach(file=>file.inspection_complete=true);
  ui.renderFolder(complete);
  assert.match(el('folder-summary').textContent,/2 .DS_Store metadata files were excluded before upload; not inspected/);
});
test('folder selection uses the same path order regardless of browser enumeration', () => {
  const {ui}=setup();
  const paths=['demo/z.txt','demo/nested/b.txt','demo/a.txt'];
  const expected=['demo/a.txt','demo/nested/b.txt','demo/z.txt'];
  for (const order of [paths, [...paths].reverse()]) {
    ui.selectScanFiles(order.map(path=>({file:{},path})));
    assert.deepEqual(Array.from(ui.state.selectedFiles,x=>x.path),expected);
  }
});
test('recorded folder results visibly disclose replay mode', () => {
  const {ui,el}=setup(); ui.state.folder='folder_test';
  ui.renderFolder(status({inference_mode:'REPLAY'}));
  assert.equal(el('folder-replay').hidden,false);
  ui.renderFolder(status({inference_mode:'LIVE'}));
  assert.equal(el('folder-replay').hidden,true);
});
test('metadata-only selection cannot start a scan and new selection clears exclusions', () => {
  const {ui,el}=setup();
  ui.selectScanFiles([{file:{},path:'.DS_Store'}]);
  assert.equal(ui.state.selectedFiles.length,0);
  assert.equal(el('folder-button').disabled,true);
  assert.match(el('notice').textContent,/Only macOS metadata/);
  ui.selectScanFiles([{file:{},path:'notes.txt'}]);
  assert.equal(ui.state.excludedMetadata.length,0);
  assert.doesNotMatch(el('selection-summary').textContent,/excluded/);
});
