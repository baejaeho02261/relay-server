'use strict';
// Execute the shipped modal in a DOM; no simulated Windows approval evidence.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom'),source=fs.readFileSync(path.resolve(__dirname,'../../public/scripts/desktop/peace.admin-desktop-security.js'),'utf8');
async function fixture(){
 const dom=new JSDOM('<main id="host"></main>',{runScripts:'outside-only'}),w=dom.window,calls=[];let close;
 const policy={revision:1,mode:'enforce',dynamicCode:'observe',freshnessMs:45000,challengeMs:15000,minVersionA:'1',minVersionB:'1',minVersionO:'1',trustedReleaseKeys:[],revokedSha512:[]};
 const data={policy,events:[],operations:{active:{},candidates:[],auditHealth:{status:'HEALTHY'},operations:{revision:1,activations:[],rollout:{enabled:false,artifactKeys:[],patch:{}},signerStates:{}}}};
 const ring={managed:false,revision:0,keys:[],privateMaterialIncluded:false};w.session={csrf:'owner'};w.roleIsAdmin=()=>true;w.confirm=()=>true;
 w.esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 w.openModal=({html})=>{w.document.getElementById('host').innerHTML=html;return new Promise(r=>{close=r;});};w.modalCancel={click:()=>close()};
 w.api=async(url,options={})=>{calls.push({url,options:structuredClone(options)});
  if(url.endsWith('/issued-a-keys'))return options.method==='POST'?{ok:true,status:structuredClone(ring)}:structuredClone(ring);
  if(url.endsWith('/activation'))return {status:{}};return structuredClone(data);
 };
 new vm.Script(source).runInContext(dom.getInternalVMContext());const operation=w.showDesktopSecurityOperations();await new Promise(r=>setImmediate(r));
 return {w,calls,ring,async click(action){w.document.querySelector(`[data-security-action="${action}"]`).click();await new Promise(r=>setImmediate(r));},async close(){close();await operation;dom.window.close();}};
}
test('explicit public key status read does not initialize or expose private inputs',async()=>{
 const f=await fixture();try{
  assert.equal(f.calls.some(r=>r.url.endsWith('/issued-a-keys')),false);await f.click('issued-keys-load');
  assert.equal(f.calls.filter(r=>r.url.endsWith('/issued-a-keys')).length,1);assert.equal(f.calls.filter(r=>r.options.method==='POST').length,0);
  assert.match(f.w.document.querySelector('#sec-issued-key-state').textContent,/기존 단일 키/);
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
test('status text is escaped and revoked rows offer no restore or further state action',async()=>{
 const f=await fixture();try{
  Object.assign(f.ring,{managed:true,revision:3,configurationError:'<img src=x onerror=alert(1)>',keys:[{keyId:'c'.repeat(64),generation:1,state:'REVOKED',issued:1,unused:0,liveFlows:0}]});await f.click('issued-keys-load');
  assert.equal(f.w.document.querySelector('#sec-issued-key-state img'),null);assert.equal(f.w.document.querySelector('[data-security-action="issued-key-retire"]'),null);assert.equal(f.w.document.querySelector('[data-security-action="issued-key-revoke"]'),null);
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
