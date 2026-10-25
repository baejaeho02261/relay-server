'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Execute the production modal/upload/security/deployment handlers against a DOM
// and a fake server. This does not claim a real browser or Windows execution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { JSDOM, VirtualConsole } = require('jsdom');
const errors = [], calls = [], vc = new VirtualConsole();
let completed=false;
process.on('beforeExit',()=>{if(!completed){console.error('Overlay administrator UI test did not reach its completion marker');process.exitCode=1;}});
vc.on('jsdomError', error => errors.push(error.message));
const dom = new JSDOM('<main id="content"></main><div id="modal" class="hidden"><h1 id="modal-title"></h1><div id="modal-body"></div><button id="modal-confirm"></button><button id="modal-cancel"></button></div>', {
  url: 'https://fixture.invalid/', runScripts: 'outside-only', virtualConsole: vc
});
const w = dom.window, document = w.document;
const timeouts=new Map(),nativeSetTimeout=w.setTimeout.bind(w),nativeClearTimeout=w.clearTimeout.bind(w);
w.setTimeout=(fn,delay,...args)=>{const id=nativeSetTimeout(()=>{timeouts.delete(id);fn(...args);},delay);timeouts.set(id,{delay});return id;};
w.clearTimeout=id=>{timeouts.delete(id);nativeClearTimeout(id);};
vm.runInContext(`
const content=document.getElementById('content'),modalEl=document.getElementById('modal'),modalBody=document.getElementById('modal-body'),modalTitle=document.getElementById('modal-title'),modalConfirm=document.getElementById('modal-confirm'),modalCancel=document.getElementById('modal-cancel');
let session={csrf:'ADMIN_SESSION',role:'admin'},currentView='desktop-licenses';
function roleIsAdmin(){return session?.role==='admin';}
function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmtTime(x){return String(x);}
function toast(){}
async function renderCurrent(){}
`, dom.getInternalVMContext());
const byId = id => document.getElementById(id);
const candidates = ['A', 'B', 'O', 'O'].map((component, i) => ({ id: component + (i + 1), component, version: '3.2.1', sha512: String(i + 1).repeat(128) }));
let active = { A: 'A1', B: 'B2', O: 'O3' }, uploadError = true;
let policy = { revision: 8, mode: 'enforce', dynamicCode: 'observe', freshnessMs: 45000, challengeMs: 15000, minVersionA: '1', minVersionB: '2', minVersionO: '3.2.1', enforceLegacy: false, requireReadonlyApi: true, requireCfg: false, requireReleaseSignature: false, trustedReleaseKeys: [], revokedSha512: [] };
const operations = { revision: 12, requireBuildContract: false, requireTestEvidence: false, rollout: { enabled: false, artifactKeys: [], patch: {} }, activations: [], signerStates: {} };
const manifestId='a'.repeat(128),manifest={releaseName:'Verified operator baseline',securityVersion:3,artifacts:{A:candidates[0].sha512,B:candidates[1].sha512,O:candidates[2].sha512}};
operations.releaseGovernance={requireManifest:false,requireCiEvidence:false,minimumSecurityVersion:3,manifests:{[manifestId]:{registration:'REGISTERED',manifest}},ciKeys:{},ciEvidence:{}};
const releaseSafety={revision:4,baseline:null,revokedCohorts:{}};
const listing = () => ({ active: { ...active }, candidates: candidates.map(a => ({ ...a, active: active[a.component] === a.id })), operations: { ...operations }, releaseSafety:clone(releaseSafety), auditHealth: { status: 'HEALTHY', failedWrites: 0 } });
const clone = x => JSON.parse(JSON.stringify(x));
const base = '/api/desktop/bootstrap/security-operations';
let customConfigured=true,sourceTreeAvailable=false,packingConfigured=true,customRunning=false,packingEvidenceAvailable=true;
w.api = async (url, options = {}) => {
  const body = options.body && clone(options.body);
  calls.push({ url, body, rawBody: options.rawBody, method: options.method || 'GET' });
  if (url.startsWith('/api/desktop/bootstrap/artifacts?')) {
    assert.equal(new URL(url, 'https://fixture.invalid').searchParams.get('component'), 'O');
    if (uploadError) {
      uploadError = false;
      throw Object.assign(Error('요청을 완료하지 못했습니다. <img src=x onerror=bad()>'), { code: 'BOOTSTRAP_COMPONENT_INVALID' });
    }
    return { artifact: candidates[2] };
  }
  if (url === '/api/desktop/bootstrap/security-authority/preview') return { preview: { readOnly: true } };
  if (url === '/api/desktop/bootstrap/security-authority') {
    if (body) policy = { ...policy, ...body, revision: policy.revision + 1 };
    return { policy: clone(policy), operations: listing(), recentBuildObservations: [], events: [] };
  }
  if (url === base) return listing();
  if (url === base + '/activation') return { status: {} };
  if (url === base + '/preview-pair') return { preview: { ...body, eligible: true, reasons: [], policyRevision: policy.revision, operationsRevision: operations.revision } };
  if (url === base + '/activate') {
    active = { A: body.aId, B: body.bId, O: body.oId };
    operations.revision++;
    return { ok: true };
  }
  if(url===base+'/baseline-pin'){
    assert.equal(body.expectedRevision,releaseSafety.revision);assert.equal(body.expectedOperationsRevision,operations.revision);assert.equal(body.expectedPolicyRevision,policy.revision);assert.equal(body.manifestId,manifestId);
    releaseSafety.baseline={manifestId,note:body.note,pinnedAt:1700000000000};releaseSafety.revision++;return {ok:true};
  }
  if(url===base+'/retire-cohort'){
    assert.equal(body.expectedRevision,releaseSafety.revision);assert.equal(body.manifestId,manifestId);
    releaseSafety.revokedCohorts[body.manifestId]={reason:body.reason};releaseSafety.revision++;return {ok:true};
  }
  if(url==='/api/desktop/bootstrap/packing/status')return {custom:{configured:customConfigured,sourceTreeAvailable},packing:{configured:packingConfigured}};
  if(url==='/api/desktop/bootstrap/packing/custom/jobs')return {job:{id:'custom-fixture',status:customRunning?'RUNNING':'COMPLETE',fileCount:3,size:111,sha512:'e'.repeat(128)}};
  if(url==='/api/desktop/bootstrap/packing/jobs')return {job:{id:'packing-fixture',status:'COMPLETE',outputs:Object.fromEntries(['A','B','O'].map((c,i)=>[c,{sha512:String(i+5).repeat(128)}])),...(packingEvidenceAvailable?{evidence:{scope:'TRANSFORMED_TEMPLATES',receipts:Object.fromEntries(['A','B','O'].map((c,i)=>[c,String(i+6).repeat(128)])),windowsVerified:false,protectionVerified:false}}:{})}};
  if (url === base + '/test-evidence' || url === '/api/desktop/workspace/deployment-note') return { ok: true };
  throw Error('Unexpected endpoint: ' + url);
};
for (const name of ['peace.admin-modal.js', 'peace.admin-desktop-licenses.js', 'peace.admin-desktop-workflow.js', 'peace.admin-desktop-security.js']) {
  new vm.Script(fs.readFileSync(require('../fixtures/source/peace.project-layout').RelayFile(name), 'utf8'), { filename: name }).runInContext(dom.getInternalVMContext());
}
async function waitFor(check, label) {
  const end = Date.now() + 2500;
  while (Date.now() < end) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw Error('Timeout: ' + label + '; ' + errors.join('; '));
}
const count = url => calls.filter(c => c.url === url && c.method === 'POST').length;
const last = url => calls.filter(c => c.url === url).at(-1);
function file(id, value) { Object.defineProperty(byId(id), 'files', { configurable: true, value: [value] }); }
async function securityAction(action) {
  const button = document.querySelector('[data-security-action="' + action + '"]');
  button.click();
  await waitFor(() => !button.isConnected || byId('security-status')?.dataset.state !== 'busy', action);
}
async function close(pending) { byId('modal-cancel').click(); await pending; }

(async () => {
  try {
    const contentMarkup = w.desktopBootstrapMarkup({ artifacts: {}, sessions: [], launchers: [] });
    byId('content').innerHTML = contentMarkup;
    for(const component of ['A','B','O'])assert.equal(document.querySelectorAll(`[data-desktop-action="artifact-upload"][data-component="${component}"]`).length,1);
    assert.equal(document.querySelectorAll('#desktop-launcher-create').length,1);
    assert.doesNotMatch(byId('desktop-bootstrap-panel').textContent,/메인에 등록/);
    assert.match(byId('desktop-bootstrap-panel').textContent, /A \/ B \/ O 실행 파일 배포/);
    assert.equal(typeof w.showDesktopMainRegistration,'undefined');
    const upload = w.showDesktopArtifactUpload('O');
    const exe = new w.File(['MZ_OVERLAY'], 'cozy.Overlay.exe');
    file('desktop-artifact-file', exe);byId('desktop-artifact-manifest').value='a'.repeat(128);
    document.querySelector('[data-modal-field="version"]').value = '3.2.1';
    await byId('modal-confirm').onclick();
    assert.match(byId('desktop-artifact-status').textContent, /BOOTSTRAP_COMPONENT_INVALID/);
    assert.match(byId('desktop-artifact-status').textContent, /<img src=x/);
    assert.equal(byId('desktop-artifact-status').querySelector('img'), null);
    assert.equal(byId('desktop-artifact-file').files[0], exe);
    assert.equal(byId('modal-confirm').disabled, false);
    assert.equal(byId('modal').classList.contains('hidden'), false);
    await byId('modal-confirm').onclick();
    await upload;
    assert.equal(calls.filter(c => c.rawBody === exe).length, 2);for(const request of calls.filter(c=>c.rawBody===exe))assert.equal(new URL(request.url,'https://fixture.invalid').searchParams.get('releaseManifestId'),'a'.repeat(128));
    assert.equal(count(base + '/activate'), 0, 'Candidate upload must not publish');
    console.log('PASS Overlay upload preserves server error code, escapes text, and retries the selected file without publishing');

    const security = w.showDesktopSecurityOperations();
    await waitFor(() => byId('sec-min-o'), 'security modal');
    assert.equal(byId('sec-min-o').value, '3.2.1');
    assert.equal(byId('sec-o').value, 'O3');
    assert.deepEqual([...byId('sec-o').options].map(x => x.value), ['', 'O3', 'O4']);
    byId('sec-min-o').value = '4.0';
    await securityAction('preview-policy');
    assert.equal(last('/api/desktop/bootstrap/security-authority/preview').body.minVersionO, '4.0');
    byId('sec-min-o').value = '4.1';
    await securityAction('save-policy');
    assert.equal(count('/api/desktop/bootstrap/security-authority'), 0, 'Changed O policy requires a new preview');
    await securityAction('preview-policy');
    await securityAction('save-policy');
    assert.equal(last('/api/desktop/bootstrap/security-authority').method, 'GET');
    assert.equal(policy.minVersionO, '4.1');
    byId('sec-o').value = 'O4';
    await securityAction('preview-pair');
    assert.equal(last(base + '/preview-pair').body.oId, 'O4');
    byId('sec-o').value = 'O3';
    await securityAction('activate');
    assert.equal(count(base + '/activate'), 0, 'Changed O candidate requires a new preview');
    byId('sec-o').value = 'O4';
    await securityAction('preview-pair');
    await securityAction('activate');
    assert.equal(last(base + '/activate').body.oId, 'O4');
    file('sec-evidence-file', { size: 18, text: async () => '{"nativeBuild":"NOT_RUN"}' });
    await securityAction('record-evidence');
    assert.equal(last(base + '/test-evidence').body.oId, 'O4');
    await close(security);
    console.log('PASS O minimum version preview/save, O candidate preview/publication and evidence preserve revisions and selection guards');

    for (const selectedO of ['', 'O3']) {
      const publication = w.showDesktopSecurityOperations();
      await waitFor(() => byId('sec-o'), 'single publication surface');
      const select = byId('sec-o');
      select.value = selectedO;
      select.dispatchEvent(new w.Event('change', { bubbles: true }));
      byId('sec-release-notes').value = 'Overlay selection ' + (selectedO || 'disabled');
      await securityAction('preview-pair');
      assert.equal(last(base + '/preview-pair').body.oId, selectedO);
      const publish=document.querySelector('[data-security-action="activate"]');
      assert.equal(publish.disabled, false);
      byId('sec-release-notes').value+=' changed';
      byId('sec-release-notes').dispatchEvent(new w.Event('input', { bubbles: true }));
      assert.equal(publish.disabled, true,'Editing deployment notes invalidates the preview');
      await securityAction('preview-pair');
      await securityAction('activate');
      assert.equal(last('/api/desktop/workspace/deployment-note').body.oId, selectedO);
      assert.equal(last('/api/desktop/workspace/deployment-note').body.note,'Overlay selection ' + (selectedO || 'disabled')+' changed');
      assert.equal(last(base + '/activate').body.oId, selectedO);
      await close(publication);
    }
    console.log('PASS The single security publication surface binds O and deployment notes, including explicit no-Overlay selection');

    // The operations entry closes its existing modal before the focused safety
    // panel opens. Merely navigating must never pin or retire anything.
    const securityForSafety=w.showDesktopSecurityOperations();
    await waitFor(()=>byId('sec-o'),'operations entry before release safety');
    const oldSecurityRoot=byId('desktop-security-root'),beforeSafety=calls.filter(c=>c.method==='POST').length;
    document.querySelector('[data-security-action="release-safety"]').click();
    await waitFor(()=>byId('desktop-baseline-pin'),'focused release safety');
    assert.equal(oldSecurityRoot.isConnected,false);
    assert.equal(byId('modal-title').textContent,'정상본 보존 · 배포 묶음 관리');
    assert.equal(calls.filter(c=>c.method==='POST').length,beforeSafety);
    assert.equal(document.querySelectorAll('#desktop-release-safety input[type="file"],#desktop-release-safety [data-candidate],#desktop-custom-selected,#desktop-pack-selected').length,0);
    assert.equal(document.querySelector('[data-security-action="activate"]'),null);
    const beforePin=count(base+'/baseline-pin');
    await byId('desktop-baseline-pin').onclick();
    assert.equal(count(base+'/baseline-pin'),beforePin,'An operator note is required');
    byId('desktop-baseline-note').value='Operator verified baseline';
    await byId('desktop-baseline-pin').onclick();
    assert.equal(count(base+'/baseline-pin'),beforePin+1);
    assert.equal(last(base+'/baseline-pin').body.note,'Operator verified baseline');
    assert.equal(last(base+'/baseline-pin').body.expectedPolicyRevision,policy.revision);
    const beforeRetire=count(base+'/retire-cohort');
    byId('desktop-retire-cohort').value=manifestId;
    byId('desktop-retire-reason').value='A reviewed security retirement';
    await byId('desktop-retire-submit').onclick();
    assert.equal(count(base+'/retire-cohort'),beforeRetire,'RETIRE acknowledgement is required');
    byId('desktop-retire-confirm').value='RETIRE';
    await byId('desktop-retire-submit').onclick();
    assert.equal(count(base+'/retire-cohort'),beforeRetire+1);
    assert.equal(last(base+'/retire-cohort').body.expectedRevision,5);
    assert.equal(byId('desktop-retire-confirm').value,'');
    byId('modal-cancel').click();
    await securityForSafety;
    await waitFor(()=>!byId('desktop-baseline-pin'),'release safety close scrubs controls');
    console.log('PASS Release safety is separate, navigation is read-only, and explicit baseline/retirement writes retain policy and revision guards');

    candidates[0].packingEvidence={receiptId:'a'.repeat(128),jobId:'b'.repeat(32),scope:'TRANSFORMED_TEMPLATE',inputSha512:'c'.repeat(128),outputSha512:candidates[0].sha512,toolSha512:'d'.repeat(128),profileSha512:'e'.repeat(128),createdAt:1700000000000,windowsVerified:false,protectionVerified:false};
    candidates[1].packingEvidence={...candidates[0].packingEvidence,outputSha512:'f'.repeat(128)};
    const beforeProtection=calls.filter(c=>c.method==='POST').length,publishedBeforeProtection=count(base+'/activate'),protection=w.showDesktopExecutableProtection();
    await waitFor(()=>byId('desktop-protection-modal'),'separate executable protection');
    assert.equal(calls.filter(c=>c.method==='POST').length,beforeProtection);
    assert.equal(document.querySelectorAll('#desktop-protection-modal input[type="file"],#desktop-baseline-pin,[data-security-action="activate"]').length,0);
    assert.equal(document.querySelectorAll('[data-protection-candidate]').length,3);
    assert.equal(document.querySelectorAll('[data-active-packing]').length,3);
    assert.match(document.querySelector('[data-active-packing="A"]').textContent,/워커 변환 기록 연결됨/);
    assert.match(document.querySelector('[data-active-packing="A"]').textContent,new RegExp(candidates[0].sha512));
    assert.match(document.querySelector('[data-active-packing="B"]').textContent,/연결된 서버 패킹 기록 없음/,'A mismatched output hash cannot display a linked worker record');
    assert.match(byId('desktop-protection-issued-config').textContent,/평문 JSON/);
    assert.match(byId('desktop-protection-modal').textContent,/A 발급·B\/O 배포에는 적용되지 않습니다/);
    assert.equal(byId('desktop-custom-selected').textContent,'암호화 보관 파일 만들기');
    assert.equal(new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size,document.querySelectorAll('[id]').length,'No duplicate modal IDs');
    const protectionO=document.querySelector('[data-protection-candidate="O"]');
    protectionO.value='';
    const beforeCustom=count('/api/desktop/bootstrap/packing/custom/jobs');
    await byId('desktop-custom-selected').onclick();
    assert.equal(count('/api/desktop/bootstrap/packing/custom/jobs'),beforeCustom,'A/B/O selection is mandatory');
    protectionO.value='O4';
    await byId('desktop-custom-selected').onclick();
    assert.deepEqual(last('/api/desktop/bootstrap/packing/custom/jobs').body,{kind:'artifacts',A:'A1',B:'B2',O:'O4'});
    assert.match(byId('desktop-custom-result').querySelector('a').getAttribute('href'),/custom-fixture\/download$/);
    assert.match(byId('desktop-custom-result').textContent,/A 발급·B\/O 배포에는 적용되지 않습니다/);
    byId('desktop-custom-kind').value='sources';
    await byId('desktop-custom-selected').onclick();
    assert.equal(count('/api/desktop/bootstrap/packing/custom/jobs'),beforeCustom+1,'Missing server source tree cannot start source packaging');
    packingConfigured=false;
    const beforePack=count('/api/desktop/bootstrap/packing/jobs');
    await byId('desktop-pack-selected').onclick();
    assert.equal(count('/api/desktop/bootstrap/packing/jobs'),beforePack,'Unconfigured worker cannot start packing');
    packingConfigured=true;
    await byId('desktop-pack-selected').onclick();
    assert.deepEqual(last('/api/desktop/bootstrap/packing/jobs').body,{A:'A1',B:'B2',O:'O4'});
    assert.equal(byId('desktop-pack-result').querySelectorAll('a[download]').length,4);
    assert.match(byId('desktop-pack-result').textContent,/A\/B\/O 워커 변환 기록 저장됨/);
    assert.match(byId('desktop-pack-result').textContent,/A 출력 SHA-512: 5{128}/);
    assert.match(byId('desktop-pack-result').textContent,/발급된 A의 새 평문 JSON 보호는 완료되지 않았습니다/);
    packingEvidenceAvailable=false;
    await byId('desktop-pack-selected').onclick();
    assert.match(byId('desktop-pack-result').textContent,/서버 변환 기록을 확인하지 못했습니다/);
    assert.doesNotMatch(byId('desktop-pack-result').textContent,/워커 변환 기록 저장됨/,'A completed job without durable evidence cannot claim a linked record');
    packingEvidenceAvailable=true;
    assert.equal(count(base+'/activate'),publishedBeforeProtection,'Packing and encryption do not publish artifacts');
    await close(protection);
    delete candidates[0].packingEvidence;delete candidates[1].packingEvidence;
    assert.equal(document.querySelector('[data-protection-candidate]'),null);
    console.log('PASS Encryption/packing uses existing candidates in a separate category, requires server capability and never uploads or publishes');

    customRunning=true;
    const pollingProtection=w.showDesktopExecutableProtection();
    await waitFor(()=>byId('desktop-custom-selected'),'protection before polling cleanup');
    const pendingPackage=byId('desktop-custom-selected').onclick();
    await waitFor(()=>[...timeouts.values()].some(x=>x.delay>=1000),'owned packaging poll wait');
    const beforeClose=calls.length;
    await close(pollingProtection);await pendingPackage;
    assert.equal(calls.length,beforeClose,'Closing wakes and cancels the client polling wait');
    assert.equal([...timeouts.values()].some(x=>x.delay>=1000),false);
    customRunning=false;
    const snapshotProtection=w.showDesktopExecutableProtection();
    await waitFor(()=>byId('desktop-custom-selected'),'protection before selection snapshot');
    const initialO=document.querySelector('[data-protection-candidate="O"]').value;
    const snapshotApi=w.api;let finishSnapshot;
    w.api=(url,options)=>url==='/api/desktop/bootstrap/packing/status'?new Promise(resolve=>{finishSnapshot=resolve;}):snapshotApi(url,options);
    const pendingSnapshot=byId('desktop-custom-selected').onclick();
    await waitFor(()=>finishSnapshot,'in-flight selection snapshot capability read');
    document.querySelector('[data-protection-candidate="O"]').value='O4';
    finishSnapshot({custom:{configured:true,sourceTreeAvailable:true},packing:{configured:true}});await pendingSnapshot;
    assert.equal(last('/api/desktop/bootstrap/packing/custom/jobs').body.O,initialO,'The submitted job keeps the explicit click-time selection snapshot');
    w.api=snapshotApi;await close(snapshotProtection);
    const abandonedProtection=w.showDesktopExecutableProtection();
    await waitFor(()=>byId('desktop-custom-selected'),'protection before owner replacement');
    const regularApi=w.api;let finishStatus;
    w.api=(url,options)=>url==='/api/desktop/bootstrap/packing/status'?new Promise(resolve=>{finishStatus=resolve;}):regularApi(url,options);
    const pendingOwner=byId('desktop-custom-selected').onclick();
    await waitFor(()=>finishStatus,'in-flight server capability read');
    vm.runInContext("session={csrf:'REPLACED_SESSION',role:'admin'}",dom.getInternalVMContext());
    const beforeReplacement=calls.filter(c=>c.method==='POST').length;
    finishStatus({custom:{configured:true,sourceTreeAvailable:true},packing:{configured:true}});await pendingOwner;
    assert.equal(calls.filter(c=>c.method==='POST').length,beforeReplacement,'A stale modal cannot start a packaging job after session replacement');
    w.api=regularApi;await close(abandonedProtection);
    vm.runInContext("session={csrf:'ADMIN_SESSION',role:'admin'}",dom.getInternalVMContext());
    const abandonedSafety=w.showDesktopReleaseSafety();
    await waitFor(()=>byId('desktop-baseline-pin'),'safety before owner replacement');
    byId('desktop-baseline-note').value='No stale-owner write';
    const safetyApi=w.api;let finishPolicy;
    w.api=(url,options)=>url==='/api/desktop/bootstrap/security-authority'?new Promise(resolve=>{finishPolicy=resolve;}):safetyApi(url,options);
    const pendingSafety=byId('desktop-baseline-pin').onclick();
    await waitFor(()=>finishPolicy,'in-flight baseline policy read');
    vm.runInContext("session={csrf:'REPLACED_SESSION',role:'admin'}",dom.getInternalVMContext());
    const beforeSafetyReplacement=count(base+'/baseline-pin');
    finishPolicy({policy:clone(policy)});await pendingSafety;
    assert.equal(count(base+'/baseline-pin'),beforeSafetyReplacement,'An owner change during policy read cannot pin a baseline');
    w.api=safetyApi;await close(abandonedSafety);
    const beforeViewer=calls.length;
    vm.runInContext("session={csrf:'VIEWER',role:'viewer'}",dom.getInternalVMContext());
    await w.showDesktopReleaseSafety();
    await w.showDesktopExecutableProtection();
    assert.equal(calls.length,beforeViewer,'Viewer entry is refused before reading administrator state');
    vm.runInContext("session={csrf:'ADMIN_SESSION',role:'admin'}",dom.getInternalVMContext());
    console.log('PASS Closing protection clears polling timers and drafts; replaced or non-admin sessions cannot create jobs');
    w.desktopWorkflowError(byId('content'), { code: 'OVERLAY_ERROR', problem: { code: 'REQUEST_FAILED', title: '<script>bad()</script>', current: 'state', next: 'retry' } });
    assert.equal(byId('content').querySelector('code').textContent, 'OVERLAY_ERROR');
    assert.equal(byId('content').querySelector('script'), null);
    assert.deepEqual(errors, []);
    completed=true;
    console.log('PASS Workflow errors retain the specific server code and escape server text');
  } finally { w.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
