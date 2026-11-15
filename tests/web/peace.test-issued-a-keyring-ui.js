'use strict';
// Execute the shipped modal in a DOM; no simulated Windows approval evidence.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom'),source=fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-security.js'),'utf8');
async function fixture(){
 const dom=new JSDOM('<main id="host"></main>',{runScripts:'outside-only'}),w=dom.window,calls=[];let close;
 const policy={revision:1,mode:'enforce',dynamicCode:'observe',freshnessMs:45000,challengeMs:15000,minVersionA:'1',minVersionB:'1',minVersionO:'1',trustedReleaseKeys:[],revokedSha512:[]};
 const candidates=['A','B','O'].map(component=>({component,id:component+'-candidate',version:'1.0.0',sha512:component.toLowerCase().repeat(128)}));
 const data={policy,events:[],operations:{active:Object.fromEntries(candidates.map(row=>[row.component,row.id])),candidates,auditHealth:{status:'HEALTHY'},operations:{revision:1,activations:[],rollout:{enabled:false,artifactKeys:[],patch:{}},signerStates:{}}}};
 const preview={eligible:true,reasons:[]};
 const ring={managed:false,revision:0,keys:[],privateMaterialIncluded:false};w.session={csrf:'owner'};w.roleIsAdmin=()=>true;w.confirm=()=>true;
 w.esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 w.openModal=({html})=>{w.document.getElementById('host').innerHTML=html;return new Promise(r=>{close=r;});};w.modalCancel={click:()=>close()};
 w.api=async(url,options={})=>{calls.push({url,options:structuredClone(options)});
  if(url.endsWith('/issued-a-keys'))return options.method==='POST'?{ok:true,status:structuredClone(ring)}:structuredClone(ring);
  if(url.endsWith('/preview-pair'))return {preview:{...options.body,policyRevision:1,operationsRevision:1,...structuredClone(preview)}};
  if(url.endsWith('/activation'))return {status:{}};return structuredClone(data);
 };
 new vm.Script(source).runInContext(dom.getInternalVMContext());const operation=w.showDesktopSecurityOperations();await new Promise(r=>setImmediate(r));
 return {w,calls,ring,preview,async click(action){w.document.querySelector(`[data-security-action="${action}"]`).click();await new Promise(r=>setImmediate(r));},async close(){close();await operation;dom.window.close();}};
}
test('explicit public key status read does not initialize or expose private inputs',async()=>{
 const f=await fixture();try{
  assert.equal(f.calls.some(r=>r.url.endsWith('/issued-a-keys')),false);await f.click('issued-keys-load');
  assert.equal(f.calls.filter(r=>r.url.endsWith('/issued-a-keys')).length,1);assert.equal(f.calls.filter(r=>r.options.method==='POST').length,0);
  assert.match(f.w.document.querySelector('#sec-issued-key-state').textContent,/기존 단일 키/);
  assert.doesNotMatch(f.w.document.querySelector('#sec-issued-key-state').textContent,/운영 가능한 발급 서명키가 없습니다/);
  assert.match(f.w.document.querySelector('#sec-issued-public-json').placeholder,/publicBlob/);
  await f.click('issued-keys-initialize');assert.deepEqual(f.calls.find(r=>r.options.method==='POST').options.body,{action:'initialize',expectedRevision:0});
 }finally{await f.close();}
});
test('registration sends exact public JSON with the displayed key revision',async()=>{
 const f=await fixture();try{
  Object.assign(f.ring,{managed:true,revision:7});await f.click('issued-keys-load');const pub={version:1,algorithm:'RSA2048-PKCS1-SHA256',keyId:'a'.repeat(64),publicBlob:'A'.repeat(378)+'=='};
  f.w.document.querySelector('#sec-issued-public-json').value=JSON.stringify(pub);await f.click('issued-key-register');
  assert.deepEqual(f.calls.find(r=>r.options.method==='POST').options.body,{action:'register',expectedRevision:7,publicKey:pub});assert.equal(f.w.document.querySelector('#sec-issued-public-json').value,'');
 }finally{await f.close();}
});
test('retirement and irreversible revoke target explicit key; cancel sends no mutation',async()=>{
 const f=await fixture();try{
  const keyId='b'.repeat(64);Object.assign(f.ring,{managed:true,revision:9,keys:[{keyId,generation:2,state:'ACTIVE',issued:3,unused:2,liveFlows:1}]});await f.click('issued-keys-load');
  await f.click('issued-key-retire');assert.deepEqual(f.calls.find(r=>r.options.method==='POST').options.body,{action:'state',expectedRevision:9,keyId,state:'RETIRING'});
  f.calls.length=0;f.w.confirm=()=>false;await f.click('issued-key-revoke');assert.equal(f.calls.filter(r=>r.options.method==='POST').length,0);
  f.w.confirm=()=>true;await f.click('issued-key-revoke');assert.deepEqual(f.calls.find(r=>r.options.method==='POST').options.body,{action:'state',expectedRevision:9,keyId,state:'REVOKED'});
 }finally{await f.close();}
});
test('retirement confirms the exact key and irreversible loss of new issuance; cancel preserves a passed preview',async()=>{
 const f=await fixture();try{
  const keyId='d'.repeat(64),confirmations=[];Object.assign(f.ring,{managed:true,revision:5,keys:[{keyId,generation:1,state:'ACTIVE',issued:1,unused:1,liveFlows:0}]});await f.click('issued-keys-load');
  await f.click('preview-pair');assert.equal(f.w.document.querySelector('#sec-activate').disabled,false);
  f.calls.length=0;f.w.confirm=message=>{confirmations.push(message);return false;};await f.click('issued-key-retire');
  assert.equal(f.calls.filter(r=>r.options.method==='POST').length,0);assert.equal(f.w.document.querySelector('#sec-activate').disabled,false);
  assert.ok(confirmations[0].includes(keyId));assert.match(confirmations[0],/기존 발급만 허용/);assert.match(confirmations[0],/새 A를 발급할 수 없습니다/);assert.match(confirmations[0],/ACTIVE로 되돌릴 수 없/);
 }finally{await f.close();}
});
test('successful key state mutation invalidates a passed pair preview even when policy and operations revisions do not change',async()=>{
 const f=await fixture();try{
  Object.assign(f.ring,{managed:true,revision:6,keys:[{keyId:'e'.repeat(64),generation:1,state:'ACTIVE',issued:0,unused:0,liveFlows:0}]});await f.click('issued-keys-load');
  await f.click('preview-pair');assert.equal(f.w.document.querySelector('#sec-activate').disabled,false);
  await f.click('issued-key-retire');assert.equal(f.w.document.querySelector('#sec-activate').disabled,true);
  assert.equal(f.w.document.querySelector('#sec-pair-preview').textContent,'');assert.doesNotMatch(f.w.document.querySelector('#sec-pair-status').textContent,/통과/);
  assert.match(f.w.document.querySelector('#security-status').textContent,/RETIRING/);assert.match(f.w.document.querySelector('#security-status').textContent,/새 A 발급은 중단/);assert.match(f.w.document.querySelector('#security-status').textContent,/다시 검증/);
 }finally{await f.close();}
});
test('blocked pair previews explain retired, revoked and unknown issuer keys and expose the actual A public key',async()=>{
 const f=await fixture();try{
  const keyId='f'.repeat(64);Object.assign(f.preview,{eligible:false,finalIssuedSigning:{ready:false,keyId}});
  for(const [reason,expected]of [
   ['ISSUED_A_SIGNING_KEY_RETIRING',/신규 발급을 중단/],
   ['ISSUED_A_SIGNING_KEY_REVOKED',/등록 데이터 초기화로 철회가 해제되지 않습니다/],
   ['ISSUED_A_SIGNING_KEY_UNKNOWN',/세대 관리 목록에 없습니다/],
   ['ISSUED_A_KEY_REVOKED_IRREVERSIBLE',/복원할 수 없습니다/]
  ]){
   f.preview.reasons=[reason];await f.click('preview-pair');
   assert.match(f.w.document.querySelector('#sec-pair-status').textContent,expected);assert.equal(f.w.document.querySelector('#sec-activate').disabled,true);
   assert.ok(f.w.document.querySelector('#sec-issued-template-key').textContent.includes(keyId));assert.match(f.w.document.querySelector('#sec-issued-template-key').textContent,/A에 내장된 공개 키 ID/);
  }
  const selector=f.w.document.querySelector('#sec-a');selector.value='';selector.dispatchEvent(new f.w.Event('change',{bubbles:true}));assert.ok(!f.w.document.querySelector('#sec-issued-template-key').textContent.includes(keyId));
 }finally{await f.close();}
});
test('revoked-only status shows no key rows, identifiers or actions and reports no operational key',async()=>{
 const f=await fixture();try{
  const revokedKeyId='c'.repeat(64);Object.assign(f.ring,{managed:true,revision:3,configurationError:'<img src=x onerror=alert(1)>',keys:[{keyId:revokedKeyId,generation:1,state:'REVOKED',issued:1,unused:0,liveFlows:0}]});await f.click('issued-keys-load');
  assert.equal(f.w.document.querySelector('#sec-issued-key-state img'),null);assert.equal(f.w.document.querySelector('[data-security-action="issued-key-retire"]'),null);assert.equal(f.w.document.querySelector('[data-security-action="issued-key-revoke"]'),null);
  assert.equal(f.w.document.querySelectorAll('#sec-issued-key-state tbody tr').length,0);assert.ok(!f.w.document.querySelector('#desktop-security-root').innerHTML.includes(revokedKeyId));assert.match(f.w.document.querySelector('#sec-issued-key-state').textContent,/운영 가능한 발급 서명키가 없습니다/);
 }finally{await f.close();}
});
test('mixed status omits revoked rows completely while retaining active and retiring key controls',async()=>{
 const f=await fixture();try{
  const activeKeyId='a'.repeat(64),retiringKeyId='b'.repeat(64),revokedKeyId='c'.repeat(64);
  Object.assign(f.ring,{managed:true,revision:4,keys:[{keyId:revokedKeyId,generation:1,state:'REVOKED',issued:1,unused:0,liveFlows:0},{keyId:activeKeyId,generation:2,state:'ACTIVE',issued:2,unused:1,liveFlows:0},{keyId:retiringKeyId,generation:3,state:'RETIRING',issued:3,unused:2,liveFlows:1}]});await f.click('issued-keys-load');
  const table=f.w.document.querySelector('#sec-issued-key-state');assert.equal(table.querySelectorAll('tbody tr').length,2);assert.ok(!f.w.document.querySelector('#desktop-security-root').innerHTML.includes(revokedKeyId));
  assert.ok(table.textContent.includes(activeKeyId));assert.ok(table.textContent.includes(retiringKeyId));assert.ok(table.querySelector(`[data-security-action="issued-key-retire"][data-key="${activeKeyId}"]`));assert.ok(table.querySelector(`[data-security-action="issued-key-revoke"][data-key="${activeKeyId}"]`));assert.ok(table.querySelector(`[data-security-action="issued-key-revoke"][data-key="${retiringKeyId}"]`));assert.equal(table.querySelector(`[data-security-action="issued-key-retire"][data-key="${retiringKeyId}"]`),null);assert.doesNotMatch(table.textContent,/운영 가능한 발급 서명키가 없습니다/);
 }finally{await f.close();}
});
test('private fields, malformed public objects and oversized drafts are not sent',async()=>{
 const f=await fixture();try{
  Object.assign(f.ring,{managed:true,revision:1});await f.click('issued-keys-load');
  for(const value of ['{"privateKey":"not-a-real-key"}','[]','x'.repeat(4097),...['publicBlob','keyId'].map(field=>JSON.stringify({version:1,algorithm:'RSA2048-PKCS1-SHA256',keyId:'a'.repeat(64),publicBlob:'A'.repeat(378)+'==',[field]:'-----BEGIN PRIVATE KEY----- synthetic -----END PRIVATE KEY-----'})),JSON.stringify({version:1,algorithm:'RSA2048-PKCS1-SHA256',keyId:'a'.repeat(64),publicBlob:'A'.repeat(377)+'B=='})]){
   f.w.document.querySelector('#sec-issued-public-json').value=value;await f.click('issued-key-register');assert.equal(f.calls.filter(r=>r.options.method==='POST').length,0);
  }
 }finally{await f.close();}
});
