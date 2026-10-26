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
let customConfigured=true,sourceTreeAvailable=false,packingConfigured=true,customRunning=false,packingEvidenceAvailable=true,ownEngineConfigured=true,ownSlotMissing=false,ownWrongEngine=false,ownWrongScope=false,ownRunning=false;
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
  if(url==='/api/desktop/bootstrap/packing/status')return {custom:{configured:customConfigured,sourceTreeAvailable},packing:{configured:packingConfigured},ownEngine:{configured:ownEngineConfigured,engine:'COZY_SERVER_POLICY_V2',scope:'SERVER_POLICY_BINDING',requiresRebuiltTemplate:true,windowsVerified:false}};
  if(url==='/api/desktop/bootstrap/packing/custom/jobs')return {job:{id:'custom-fixture',status:customRunning?'RUNNING':'COMPLETE',fileCount:3,size:111,sha512:'e'.repeat(128)}};
  if(url==='/api/desktop/bootstrap/packing/jobs'){
    const own=body.mode==='COZY_SERVER_POLICY_V2';
    return {job:{id:'packing-fixture',engine:own&&!ownWrongEngine?'COZY_SERVER_POLICY_V2':'EXTERNAL',protectionScope:own&&!ownWrongScope?'SERVER_POLICY_BINDING':'TRANSFORMED_TEMPLATES_ONLY',status:own&&ownSlotMissing?'FAILED':own&&ownRunning?'RUNNING':'COMPLETE',...(own&&ownSlotMissing?{error:'COZY_PROTECTION_SLOT_MISSING'}:{}),outputs:Object.fromEntries(['A','B','O'].map((c,i)=>[c,{sha512:String(i+5).repeat(128)}])),...(packingEvidenceAvailable?{evidence:{scope:'TRANSFORMED_TEMPLATES',receipts:Object.fromEntries(['A','B','O'].map((c,i)=>[c,String(i+6).repeat(128)])),windowsVerified:false,protectionVerified:false}}:{})}};
  }
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
function ownProfileFile(text,overrides={}) { const value={name:'functions.json',size:Buffer.byteLength(text),text:async()=>text,...overrides};file('desktop-own-profile-file',value);byId('desktop-own-profile-file').dispatchEvent(new w.Event('change'));return value; }
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
    assert.equal(document.querySelectorAll('#desktop-release-safety input[type="file"],#desktop-release-safety [data-candidate],#desktop-custom-selected,#desktop-pack-selected,#desktop-own-pack-selected').length,0);
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
    assert.equal(document.querySelectorAll('#desktop-protection-modal input[type="file"]').length,1);
    assert.equal(byId('desktop-own-profile-file').getAttribute('accept'),'.json,application/json');
    assert.equal(document.querySelectorAll('#desktop-baseline-pin,[data-security-action="activate"]').length,0);
    assert.equal(document.querySelectorAll('[data-protection-candidate]').length,3);
    assert.equal(document.querySelectorAll('[data-active-packing]').length,3);
    assert.match(document.querySelector('[data-active-packing="A"]').textContent,/워커 변환 기록 연결됨/);
    assert.match(document.querySelector('[data-active-packing="A"]').textContent,new RegExp(candidates[0].sha512));
    assert.match(document.querySelector('[data-active-packing="B"]').textContent,/연결된 서버 패킹 기록 없음/,'A mismatched output hash cannot display a linked worker record');
    assert.match(byId('desktop-protection-issued-config').textContent,/A의 발급 설정 형식은 게시된 템플릿에 따라/);
    assert.match(byId('desktop-protection-issued-config').textContent,/공개 연결 정보와 최초 기기 승인/);
    assert.match(byId('desktop-protection-modal').textContent,/임의의 Delphi 소스 자동 변환이나 EXE 전체 암호화는 지원하지 않습니다/);
    assert.match(byId('desktop-protection-modal').textContent,/서버 정책 연결 전에는 실행되지 않습니다/);
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
    assert.match(byId('desktop-pack-result').textContent,/기존 형식 A의 새 평문 JSON 보호는 완료되지 않았습니다/);
    packingEvidenceAvailable=false;
    await byId('desktop-pack-selected').onclick();
    assert.match(byId('desktop-pack-result').textContent,/서버 변환 기록을 확인하지 못했습니다/);
    assert.doesNotMatch(byId('desktop-pack-result').textContent,/워커 변환 기록 저장됨/,'A completed job without durable evidence cannot claim a linked record');
    packingEvidenceAvailable=true;
    ownEngineConfigured=false;
    const beforeOwn=count('/api/desktop/bootstrap/packing/jobs');
    await byId('desktop-own-pack-selected').onclick();
    assert.equal(count('/api/desktop/bootstrap/packing/jobs'),beforeOwn,'An unavailable own engine cannot submit a job');
    ownEngineConfigured=true;packingConfigured=false;
    await byId('desktop-own-pack-selected').onclick();
    assert.deepEqual(last('/api/desktop/bootstrap/packing/jobs').body,{A:'A1',B:'B2',O:'O4',mode:'COZY_SERVER_POLICY_V2'});
    assert.equal(byId('desktop-own-pack-result').querySelectorAll('a[download]').length,4);
    assert.match(byId('desktop-own-pack-result').textContent,/정책 내용과 연산은 서버에 두고 EXE에는 공개 정책 식별자·해시만/);
    assert.match(byId('desktop-own-pack-result').textContent,/EXE 전체 암호화·함수 자동 변환이나 Windows 실행 성공을 뜻하지 않습니다/);
    assert.match(byId('desktop-own-pack-result').textContent,/현재 운영 파일을 게시하거나 A를 발급하지 않습니다/);
    assert.match(byId('desktop-own-pack-result').textContent,/A\/B\/O 서버 정책 연결 기록 저장됨/);
    const expressionProfile={version:1,functions:[{id:2,args:1,body:{op:'xor',left:{op:'arg',index:0},right:{op:'const',value:12345}}}]},profileText=JSON.stringify(expressionProfile);
    ownProfileFile(profileText);
    await byId('desktop-own-pack-selected').onclick();
    assert.deepEqual(last('/api/desktop/bootstrap/packing/jobs').body,{A:'A1',B:'B2',O:'O4',mode:'COZY_SERVER_POLICY_V2',profile:expressionProfile});
    assert(!byId('desktop-own-pack-result').textContent.includes('12345'),'Selected server policy IR is never echoed in job results');
    packingConfigured=true;
    await byId('desktop-pack-selected').onclick();
    assert.deepEqual(last('/api/desktop/bootstrap/packing/jobs').body,{A:'A1',B:'B2',O:'O4'},'External packing never receives a selected own-engine profile');
    packingConfigured=false;
    for(const invalid of [
      {text:'{',message:/JSON 형식이 올바르지 않습니다/},
      {text:JSON.stringify({...expressionProfile,script:'not executable'}),message:/정수식 IR만 지원합니다/},
      {text:JSON.stringify({version:1,functions:[{...expressionProfile.functions[0],script:'not executable'}]}),message:/정수식 IR만 지원합니다/},
      {text:JSON.stringify({version:1,functions:[{id:1,args:0,body:{op:'const',value:1}}]}),message:/정수식 IR만 지원합니다/},
      {text:profileText,overrides:{name:'functions.js'},message:/\.json 파일/}
    ]){
      ownProfileFile(invalid.text,invalid.overrides);const beforeInvalid=calls.length;
      await byId('desktop-own-pack-selected').onclick();
      assert.equal(calls.length,beforeInvalid,'Malformed or unsupported profile data must not make any API request');
      assert.match(byId('desktop-own-pack-result').textContent,invalid.message);
    }
    let oversizedReads=0;
    ownProfileFile(profileText,{size:65537,text:async()=>{oversizedReads++;return profileText;}});const beforeOversized=calls.length;
    await byId('desktop-own-pack-selected').onclick();
    assert.equal(calls.length,beforeOversized);assert.equal(oversizedReads,0,'Oversized profile is rejected before reading its content');
    assert.match(byId('desktop-own-pack-result').textContent,/64 KiB/);
    ownProfileFile(profileText,{size:32,text:async()=>profileText+' '.repeat(65537)});const beforeDecodedOversized=calls.length;
    await byId('desktop-own-pack-selected').onclick();
    assert.equal(calls.length,beforeDecodedOversized);assert.match(byId('desktop-own-pack-result').textContent,/UTF-8 기준 64 KiB/);
    const boundaryText=profileText+' '.repeat(65536-Buffer.byteLength(profileText));ownProfileFile(boundaryText);
    await byId('desktop-own-pack-selected').onclick();
    assert.deepEqual(last('/api/desktop/bootstrap/packing/jobs').body.profile,expressionProfile,'Exactly 64 KiB valid JSON is accepted');
    byId('desktop-own-profile-clear').onclick();
    assert.match(byId('desktop-own-profile-status').textContent,/기본 정책: 필수 서버 시작 함수 1만/);
    await byId('desktop-own-pack-selected').onclick();
    assert.deepEqual(last('/api/desktop/bootstrap/packing/jobs').body,{A:'A1',B:'B2',O:'O4',mode:'COZY_SERVER_POLICY_V2'},'Clearing the optional profile restores the default request');
    ownSlotMissing=true;
    await byId('desktop-own-pack-selected').onclick();
    assert.match(byId('desktop-own-pack-result').textContent,/COZY_PROTECTION_SLOT_MISSING/);
    assert.equal(byId('desktop-own-pack-result').querySelector('code').textContent,'COZY_PROTECTION_SLOT_MISSING');
    assert.equal(byId('desktop-own-pack-result').querySelectorAll('a[download]').length,0);
    ownSlotMissing=false;ownWrongEngine=true;
    await byId('desktop-own-pack-selected').onclick();
    assert.match(byId('desktop-own-pack-result').textContent,/요청한 서버 정책 연결 엔진으로 생성한 결과인지 확인하지 못했습니다/);
    assert.equal(byId('desktop-own-pack-result').querySelectorAll('a[download]').length,0,'An external result cannot be presented as own-engine output');
    ownWrongEngine=false;ownWrongScope=true;
    await byId('desktop-own-pack-selected').onclick();
    assert.match(byId('desktop-own-pack-result').textContent,/요청한 서버 정책 연결 엔진으로 생성한 결과인지 확인하지 못했습니다/);
    assert.equal(byId('desktop-own-pack-result').querySelectorAll('a[download]').length,0,'Wrong protection scope cannot claim a keyless policy binding');
    ownWrongScope=false;packingConfigured=true;
    assert.equal(count(base+'/activate'),publishedBeforeProtection,'Packing and encryption do not publish artifacts');
    let finishProfileRead;
    ownProfileFile(profileText,{text:()=>new Promise(resolve=>{finishProfileRead=resolve;})});
    const pendingProfileRead=byId('desktop-own-pack-selected').onclick();
    await waitFor(()=>finishProfileRead,'in-flight custom profile read');
    const beforeProfileClose=calls.length;
    await close(protection);finishProfileRead(profileText);await pendingProfileRead;
    assert.equal(calls.length,beforeProfileClose,'Closing during profile reading cannot submit a late job');
    delete candidates[0].packingEvidence;delete candidates[1].packingEvidence;
    assert.equal(document.querySelector('[data-protection-candidate]'),null);
    console.log('PASS Encryption/packing uses existing candidates in a separate category, requires server capability and never uploads or publishes');

    const previousActiveO=active.O;active.O='O3';
    for(const [i,candidate]of candidates.slice(0,3).entries()){
      candidate.ownProtection={engine:'COZY_SERVER_POLICY_V2',state:'BOUND',version:2,role:candidate.component,slotBytes:4096,functionCount:2,policyId:'a'.repeat(64),policySha512:'b'.repeat(128),execution:'SERVER_ONLY',authenticationRequired:true,slotContainsSecret:false,clientBytecode:false,windowsVerified:false,arbitraryDelphiTranslation:false};
      candidate.packingEvidence={receiptId:String(i+7).repeat(128),jobId:'b'.repeat(32),scope:'TRANSFORMED_TEMPLATE',inputSha512:'c'.repeat(128),outputSha512:candidate.sha512,toolSha512:'d'.repeat(128),profileSha512:'e'.repeat(128),createdAt:1700000000000,windowsVerified:false,protectionVerified:false};
    }
    const ownActiveProtection=w.showDesktopExecutableProtection();
    await waitFor(()=>byId('desktop-protection-active'),'own active template metadata');
    assert.match(document.querySelector('[data-active-packing="A"]').textContent,/서버 정책 연결 기록 확인/);
    assert.match(byId('desktop-protection-issued-config').textContent,/같은 작업의 서버 정책 연결 v2 묶음/);
    assert.match(byId('desktop-protection-issued-config').textContent,/공개 발급 설정은 암호화 비밀이 아니며 최초 기기 승인이 필요/);
    assert.match(byId('desktop-protection-issued-config').textContent,/Windows 실행 시험은 별도/);
    await close(ownActiveProtection);
    for(const patch of [{slotContainsSecret:true},{clientBytecode:true},{execution:'CLIENT'},{policyId:'malformed'}]){
      const original={...candidates[0].ownProtection};Object.assign(candidates[0].ownProtection,patch);const invalidBinding=w.showDesktopExecutableProtection();
      await waitFor(()=>byId('desktop-protection-active'),'invalid keyless metadata');
      assert.doesNotMatch(document.querySelector('[data-active-packing="A"]').textContent,/서버 정책 연결 기록 확인/);
      assert.doesNotMatch(byId('desktop-protection-issued-config').textContent,/슬롯에는 복호화 키·바이트코드가 없습니다/);
      await close(invalidBinding);candidates[0].ownProtection=original;
    }
    candidates[0].ownProtection.role='B';candidates[1].ownProtection={...candidates[1].ownProtection,state:'UNSEALED',role:null};
    const wrongOwnMetadata=w.showDesktopExecutableProtection();
    await waitFor(()=>byId('desktop-protection-active'),'wrong role and unsealed metadata');
    assert.doesNotMatch(document.querySelector('[data-active-packing="A"]').textContent,/서버 정책 연결 기록 확인/);
    assert.match(document.querySelector('[data-protection-candidate="B"] option[value="B2"]').textContent,/서버 정책 연결 전 템플릿/);
    assert.match(byId('desktop-protection-issued-config').textContent,/정책 연결 상태·역할·같은 작업의 기록을 확인하지 못했습니다/);
    await close(wrongOwnMetadata);
    candidates[0].ownProtection.role='A';candidates[1].ownProtection={...candidates[1].ownProtection,state:'BOUND',role:'B'};candidates[1].packingEvidence.jobId='c'.repeat(32);
    const mixedOwnJobs=w.showDesktopExecutableProtection();
    await waitFor(()=>byId('desktop-protection-active'),'different own-engine job bindings');
    assert.match(document.querySelector('[data-active-packing="B"]').textContent,/서버 정책 연결 기록 확인/);
    assert.doesNotMatch(byId('desktop-protection-issued-config').textContent,/같은 작업의 서버 정책 연결 v2 묶음/,'Individual valid receipts cannot imply a single protected cohort');
    assert.match(byId('desktop-protection-issued-config').textContent,/같은 작업의 기록을 확인하지 못했습니다/);
    await close(mixedOwnJobs);
    candidates[0].ownProtection={engine:'COZY_VM_V1',state:'SEALED',version:1,role:'A',slotBytes:4096,functionCount:1,configProtection:'COZY_A_CONFIG_V2',windowsVerified:false,arbitraryDelphiTranslation:false};
    const legacyOwn=w.showDesktopExecutableProtection();await waitFor(()=>byId('desktop-protection-active'),'legacy own engine warning');
    assert.match(document.querySelector('[data-active-packing="A"]').textContent,/기존 VM v1.*내장 키 남음/);
    assert.match(byId('desktop-protection-issued-config').textContent,/기존 VM v1 내장 키 남음/);
    assert.doesNotMatch(byId('desktop-protection-issued-config').textContent,/슬롯에는 복호화 키·바이트코드가 없습니다/);await close(legacyOwn);
    for(const candidate of candidates.slice(0,3)){delete candidate.ownProtection;delete candidate.packingEvidence;}active.O=previousActiveO;
    console.log('PASS Own-engine UI binds role, sealed format, exact output and one shared A/B/O job without claiming Windows execution');

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
    ownRunning=true;
    const pollingOwnProtection=w.showDesktopExecutableProtection();
    await waitFor(()=>byId('desktop-own-pack-selected'),'own engine before polling cleanup');
    const pendingOwn=byId('desktop-own-pack-selected').onclick();
    await waitFor(()=>[...timeouts.values()].some(x=>x.delay>=2000),'owned own-engine poll wait');
    const beforeOwnClose=calls.length;
    await close(pollingOwnProtection);await pendingOwn;
    assert.equal(calls.length,beforeOwnClose,'Closing cancels own-engine polling before another server read');
    assert.equal([...timeouts.values()].some(x=>x.delay>=2000),false);
    ownRunning=false;
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
