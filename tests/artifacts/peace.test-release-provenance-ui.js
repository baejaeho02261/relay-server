'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Production modal JS executed in a DOM model; fake HTTP responses only.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{JSDOM,VirtualConsole}=require('jsdom');
const errors=[],calls=[],vc=new VirtualConsole();let previewReasons=[];vc.on('jsdomError',e=>errors.push(e.message));
const dom=new JSDOM('<div id="modal" class="hidden"><h1 id="modal-title"></h1><div id="modal-body"></div><button id="modal-confirm"></button><button id="modal-cancel"></button></div>',{url:'https://fixture.invalid',runScripts:'outside-only',virtualConsole:vc});
const w=dom.window,d=w.document,context=dom.getInternalVMContext();
vm.runInContext("const modalEl=document.getElementById('modal'),modalBody=document.getElementById('modal-body'),modalTitle=document.getElementById('modal-title'),modalConfirm=document.getElementById('modal-confirm'),modalCancel=document.getElementById('modal-cancel');let session={csrf:'TEST_CSRF',role:'admin'};function roleIsAdmin(){return session?.role==='admin'};function esc(x){return String(x??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]))}",context);
const hash='a'.repeat(128),keyId='b'.repeat(64),manifestId='c'.repeat(128),base='/api/desktop/bootstrap/security-operations';
const policy={revision:1,mode:'enforce',dynamicCode:'observe',freshnessMs:45000,challengeMs:15000,minVersionA:'0',minVersionB:'0',minVersionO:'0',enforceLegacy:false,requireReadonlyApi:true,requireCfg:false,requireReleaseSignature:false,trustedReleaseKeys:[{keyId,publicKey:'PUBLIC ONLY'}],revokedSha512:[]};
const governance={version:1,requireManifest:false,minimumSecurityVersion:1,manifests:{[manifestId]:{manifest:{releaseName:'<img src=x onerror=bad()>',securityVersion:1,handoffVersion:3},recordedAt:1}}};
const operations={revision:7,requireBuildContract:false,requireTestEvidence:false,rollout:{enabled:false,artifactKeys:[],patch:{}},activations:[],signerStates:{},releaseGovernance:governance};
const listing=()=>({policy,operations:{active:{A:'A1',B:'B1',O:'O1'},candidates:['A','B','O'].map(component=>({id:component+'1',component,version:'1',sha512:hash,active:true})),operations,auditHealth:{status:'HEALTHY',failedWrites:0},adminProtection:{recentReauthenticationRequired:true},policySha512:hash},recentBuildObservations:[],events:[]});
w.api=async(url,options={})=>{
  const body=options.body&&JSON.parse(JSON.stringify(options.body));calls.push({url,body});
  if(url==='/api/desktop/bootstrap/security-authority')return JSON.parse(JSON.stringify(listing()));
  if(url===base+'/activation')return{status:{}};
  if(url===base+'/preview-pair')return{preview:{eligible:previewReasons.length===0,reasons:previewReasons,policyRevision:policy.revision,operationsRevision:operations.revision,release:{evidenceType:'OPERATOR_RECORDED'}}};
  if(url.startsWith(base+'/')&&body){
    assert.equal(body.expectedRevision,operations.revision);operations.revision++;
    if(url===base+'/release-governance')Object.assign(governance,{requireManifest:body.requireManifest,minimumSecurityVersion:body.minimumSecurityVersion});
    if(url===base+'/recovery/prepare')return{result:{recoveryId:'D'.repeat(24),status:'PREPARED',selection:{aId:body.aId,bId:body.bId,oId:body.oId},reason:body.reason,preparedRevision:operations.revision,policyRevision:body.expectedPolicyRevision,bypassesSecurityFloor:false}};
    return{ok:true};
  }
  throw Error('Unexpected route '+url);
};
for(const f of ['peace.admin-modal.js','peace.admin-desktop-security.js'])new vm.Script(fs.readFileSync(require('../fixtures/source/peace.project-layout').RelayFile(f),'utf8'),{filename:f}).runInContext(context);
const byId=id=>d.getElementById(id);
async function wait(check){const end=Date.now()+2000;while(Date.now()<end){if(check())return;await new Promise(r=>setTimeout(r,5));}throw Error('DOM wait timeout '+errors.join(';'));}
async function click(action){const b=d.querySelector('[data-security-action="'+action+'"]');b.click();await wait(()=>!b.isConnected||!b.disabled);}
function rawFile(id,text,size=text.length){const value={size,text:async()=>text};Object.defineProperty(byId(id),'files',{configurable:true,value:[value]});return value;}
function file(id,value,size){return rawFile(id,JSON.stringify(value),size===undefined?JSON.stringify(value).length:size);}
const last=path=>calls.filter(c=>c.url===base+'/'+path&&c.body).at(-1)?.body;
(async()=>{try{
  const modal=w.showDesktopSecurityOperations();await wait(()=>byId('sec-manifest-required'));
  assert.equal(byId('sec-manifest-required').checked,true);assert.equal(byId('sec-manifest-required').disabled,true);
  assert.equal(byId('sec-security-floor').min,'1');assert.match(byId('sec-runtime-governance').textContent,/과거 저장 정책/);
  assert.match(byId('desktop-security-root').textContent,/최근 재인증 필요/);assert.equal(byId('desktop-security-root').querySelector('img'),null);
  for(const id of ['sec-ci-required','sec-ci-file','sec-optional-ci','sec-ci-key-file','sec-ci-evidence-file','sec-ci-status','sec-ci-requirement'])assert.equal(byId(id),null);
  for(const action of ['record-ci','record-ci-key','record-ci-evidence','ci-signer'])assert.equal(d.querySelector('[data-security-action="'+action+'"]'),null);
  assert.doesNotMatch(byId('desktop-security-root').textContent,/\bCI\b/);
  assert.match(byId('sec-manual-workflow').textContent,/IDE.*빌드/);
  assert.match(byId('sec-manual-workflow').textContent,/Create_Approval.bat.*Check_Approval.bat/);
  assert.match(byId('sec-manual-workflow').textContent,/Create_Release_Manifest.bat.*Check_Release_Manifest.bat/);
  assert.ok(byId('sec-evidence-file'));assert.ok(byId('sec-compatibility-report'));assert.ok(byId('sec-mitigation-evidence'));
  assert.match(byId('sec-mitigation-evidence').closest('details').textContent,/신뢰된 EXE 승인 키의 별도 프로필 서명/);
  assert.ok(byId('signer-'+keyId));assert.ok(d.querySelector('[data-security-action="release-safety"]'));
  byId('sec-security-floor').value='2';await click('save-release-governance');
  assert.deepEqual(last('release-governance'),{expectedRevision:7,requireManifest:true,minimumSecurityVersion:2});
  await click('preview-pair');assert.equal(byId('sec-activate').disabled,false);
  previewReasons=['COZY_SERVER_POLICY_FINAL_ISSUED_SIGNING_REQUIRED'];await click('preview-pair');
  assert.equal(byId('sec-activate').disabled,true);assert.match(byId('security-status').textContent,/최종 발급 A의 서명 연결이 아직 완료되지 않았습니다/);
  previewReasons=[];await click('preview-pair');assert.equal(byId('sec-activate').disabled,false);
  const manifest={manifestId,manifest:{releaseName:'synthetic'}};file('sec-manifest-file',manifest);await click('record-manifest');
  assert.equal(last('release-manifests').manifestId,manifestId);assert.deepEqual(last('release-manifests').manifest,manifest.manifest);
  assert.match(byId('security-status').textContent,/최종 발급 A의 서명 연결은 별도 게시 조건/);assert.equal(byId('sec-activate').disabled,true);
  const before=calls.length;file('sec-manifest-file',{...manifest,privateKey:'DO_NOT_UPLOAD'});await click('record-manifest');assert.equal(calls.length,before);
  file('sec-manifest-file',manifest,65537);await click('record-manifest');assert.equal(calls.length,before);
  file('sec-manifest-file',manifest);await click('plan-manifest');assert.equal(last('plan-release').manifestId,manifestId);
  const manualReport={version:1,nativeBuild:'NOT_RUN',apiProbe:'PASS',integration:'FAIL'};
  const evidenceRevision=operations.revision;file('sec-evidence-file',manualReport);await click('record-evidence');
  assert.deepEqual(last('test-evidence'),{expectedRevision:evidenceRevision,aId:'A1',bId:'B1',oId:'O1',report:manualReport});
  const signerRevision=operations.revision;byId('signer-'+keyId).value='RETIRING';await click('signer');
  assert.deepEqual(last('signers'),{expectedRevision:signerRevision,keyId,state:'RETIRING'});
  byId('sec-recovery-reason').value='SYNTHETIC approved recovery';await click('prepare-recovery');assert.equal(last('recovery/prepare').reason,'SYNTHETIC approved recovery');assert.match(last('recovery/prepare').requestId,/^[a-f0-9-]{36}$/);assert.equal(byId('sec-recovery-apply').disabled,false);
  const priorApply=calls.filter(c=>c.url===base+'/recovery/apply').length;byId('sec-recovery-reason').value='changed';await click('apply-recovery');assert.equal(calls.filter(c=>c.url===base+'/recovery/apply').length,priorApply);byId('sec-recovery-reason').value='SYNTHETIC approved recovery';await click('apply-recovery');assert.equal(last('recovery/apply').recoveryId,'D'.repeat(24));assert.equal(byId('sec-recovery-apply').disabled,true);
  // Retained upload paths still stop when their owning administrator leaves.
  const manifestCount=()=>calls.filter(c=>c.url===base+'/release-manifests').length;
  let finishLogout;const logoutField=byId('sec-manifest-file'),logoutButton=d.querySelector('[data-security-action="record-manifest"]');Object.defineProperty(logoutField,'files',{configurable:true,value:[{size:100,text:()=>new Promise(resolve=>{finishLogout=resolve})}]});const beforeLogout=manifestCount();logoutButton.click();await wait(()=>finishLogout);vm.runInContext('session=null',context);finishLogout(JSON.stringify(manifest));await wait(()=>!logoutButton.disabled);assert.equal(manifestCount(),beforeLogout);vm.runInContext("session={csrf:'TEST_CSRF',role:'admin'}",context);
  let finishClose;const closeField=byId('sec-manifest-file');Object.defineProperty(closeField,'files',{configurable:true,value:[{size:100,text:()=>new Promise(resolve=>{finishClose=resolve})}]});const beforeClose=manifestCount();d.querySelector('[data-security-action="record-manifest"]').click();await wait(()=>finishClose);byId('modal-cancel').click();await modal;finishClose(JSON.stringify(manifest));await new Promise(resolve=>setTimeout(resolve,10));assert.equal(manifestCount(),beforeClose);
  assert.equal(byId('desktop-security-root')?.childElementCount||0,0);assert.deepEqual(errors,[]);assert.ok(!JSON.stringify(calls).includes('DO_NOT_UPLOAD'));assert.equal(calls.filter(c=>/\/ci-(?:evidence|signers)$/.test(c.url)).length,0);
  console.log('PASS Release governance UI: removed retired controls and routes, retained exact manifest registration, EXE signer retirement, manual outcomes, independent final-A hold, publication invalidation, bounded files, escaped content, reauthentication, recovery selection/reason guard and logout/modal cleanup');
}finally{w.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
