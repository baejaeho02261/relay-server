'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const source=fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-security.js'),'utf8');
const errors=require('../../services/runtime/peace.desktop-operations-errors');
async function fixture(){
 const dom=new JSDOM('<main id="host"></main>',{runScripts:'outside-only'}),w=dom.window,calls=[];
 let close,finishPreview=null,hold=false,eligible=false;
 const policy={revision:13,mode:'enforce',dynamicCode:'observe',freshnessMs:45000,challengeMs:15000,minVersionA:'1',minVersionB:'1',minVersionO:'1',enforceLegacy:true,requireReadonlyApi:true,requireCfg:false,requireReleaseSignature:true,deviceSignalsRequested:false,trustedReleaseKeys:[],revokedSha512:[]};
 const candidates=['A','B','O'].map(component=>({component,id:component.repeat(24),version:'1.0.0',sha512:component.toLowerCase().repeat(128)}));
 const data={policy,events:[],recentBuildObservations:[],operations:{active:Object.fromEntries(candidates.map(r=>[r.component,r.id])),candidates,auditHealth:{status:'HEALTHY',failedWrites:0},operations:{revision:104,activations:[],rollout:{enabled:false,artifactKeys:[],patch:{}},signerStates:{}}}};
 w.session={csrf:'fixture'};w.roleIsAdmin=()=>true;
 w.esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 w.openModal=({html})=>{w.document.getElementById('host').innerHTML=html;return new Promise(r=>{close=r;});};w.modalCancel={click:()=>close()};
 w.api=async(url,options={})=>{
  calls.push({url,options});
  if(url.endsWith('/activation'))return {status:{}};
  if(url.endsWith('/release-readiness'))return {readiness:{scope:'REGISTERED_RELEASE_BYTES',releases:candidates.map(row=>({...row,registeredSha512:row.sha512,measuredSha512:row.sha512,issues:[],checks:{fileIdentity:{status:'MATCH'},releaseApproval:{status:'VALID'},cfg:{status:'ABSENT'},authenticode:{status:'ABSENT'},issuedAApplicationSignature:{status:row.component==='A'?'READY':'NOT_APPLICABLE'}}}))}};
  if(url.endsWith('/preview')){
   const preview={eligible,readOnly:true,baseRevision:13,operationsRevision:104,releases:[...candidates.map(row=>({...row,active:true,reason:eligible?'':'SECURITY_CFG_BUILD_REQUIRED'})),{component:'A',id:'inactive',active:false,reason:'SECURITY_CFG_BUILD_REQUIRED'}]};
   if(hold)return new Promise(resolve=>{finishPreview=()=>resolve({preview});});
   return {preview};
  }
  return structuredClone(data);
 };
 new vm.Script(source).runInContext(dom.getInternalVMContext());
 const operation=w.showDesktopSecurityOperations();
 await new Promise(r=>setImmediate(r));
 async function click(action){w.document.querySelector(`[data-security-action="${action}"]`).click();await new Promise(r=>setImmediate(r));}
 return {w,calls,click,eligible(value){eligible=value;},hold(){hold=true;},release(){finishPreview();},async close(){close();await operation;dom.window.close();}};
}
test('incompatible active A/B/O are readable and cannot submit a policy mutation',async()=>{
 const f=await fixture();try{
  assert.equal(f.w.document.querySelector('#sec-policy-apply').disabled,true);
  f.w.document.querySelector('#sec-cfg').checked=true;
  await f.click('preview-policy');
  const text=f.w.document.querySelector('#sec-policy-readiness').textContent;
  for(const role of ['A','B','O'])assert.ok(text.includes(role.repeat(24)));
  assert.ok(!text.includes('inactive'));assert.match(text,/기존 정책은 유지/);assert.match(text,/CFG 계측/);
  assert.equal(f.w.document.querySelector('#sec-policy-apply').disabled,true);
  await f.click('save-policy');assert.equal(f.calls.filter(r=>r.url.endsWith('/security-authority')&&r.options.method==='POST').length,0);
  assert.equal(f.w.document.querySelector('#sec-cfg').checked,true,'no silent downgrade');
 }finally{await f.close();}
});
test('eligible current draft can save; field edits invalidate it',async()=>{
 const f=await fixture();try{
  f.eligible(true);await f.click('preview-policy');assert.equal(f.w.document.querySelector('#sec-policy-apply').disabled,false);
  const input=f.w.document.querySelector('#sec-fresh');input.value='44000';input.dispatchEvent(new f.w.Event('input',{bubbles:true}));
  assert.equal(f.w.document.querySelector('#sec-policy-apply').disabled,true);await f.click('save-policy');
  assert.equal(f.calls.filter(r=>r.options.method==='POST'&&r.url.endsWith('/security-authority')).length,0);
  await f.click('preview-policy');await f.click('save-policy');
  assert.equal(f.calls.filter(r=>r.options.method==='POST'&&r.url.endsWith('/security-authority')).length,1);
 }finally{await f.close();}
});
test('in-flight preview cannot authorize an edited draft',async()=>{
 const f=await fixture();try{
  f.eligible(true);f.hold();await f.click('preview-policy');
  const input=f.w.document.querySelector('#sec-cfg');input.checked=true;input.dispatchEvent(new f.w.Event('change',{bubbles:true}));
  f.release();await new Promise(r=>setImmediate(r));
  assert.equal(f.w.document.querySelector('#sec-policy-apply').disabled,true);assert.match(f.w.document.querySelector('#sec-policy-readiness').textContent,/검사 중 편집 내용/);
 }finally{await f.close();}
});
test('registered file audit is on demand and never presented as Windows trust',async()=>{
 const f=await fixture();try{
  assert.equal(f.calls.some(r=>r.url.endsWith('/release-readiness')),false);
  await f.click('audit-release-readiness');
  const requests=f.calls.filter(r=>r.url.endsWith('/release-readiness'));assert.equal(requests.length,1);assert.equal(requests[0].options.method,undefined);
  const box=f.w.document.querySelector('#sec-release-readiness');assert.match(box.textContent,/해시·크기 일치/);assert.match(box.textContent,/Windows 실행/);assert.ok(box.textContent.includes('a'.repeat(128)));assert.match(box.textContent,/A 발급 서명 준비 검사/);assert.match(box.textContent,/템플릿·서버 서명키 연결 확인/);assert.match(box.textContent,/A를 실제 발급하지 않으며/);assert.match(box.textContent,/최종 파일의 검증 결과가 아닙니다/);
  const markup=f.w.desktopReleaseReadinessMarkup({scope:'REGISTERED_RELEASE_BYTES',releases:[{component:'<img onerror=x>',id:'<script>bad</script>',issues:['<svg onload=x>']}]});box.innerHTML=markup;
  assert.equal(box.querySelector('img,svg,script'),null);
 }finally{await f.close();}
});
test('CFG build and runtime failures have distinct safe administrator guidance',()=>{
 const build=errors.Explain('SECURITY_CFG_BUILD_REQUIRED'),runtime=errors.Explain('CFG_UNAVAILABLE');
 assert.match(build.current,/저장하지 않았/);assert.match(build.next,/영향 미리보기/);assert.notEqual(build.title,'요청을 완료하지 못했습니다.');
 assert.match(runtime.title,/실행 중/);assert.notEqual(build.title,runtime.title);assert.match(errors.Explain('RELEASE_AUDIT_RATE_LIMITED').next,/3초 후/);
});
