'use strict';
// Real dispatch/time-window implementation with isolated stores and business
// mutations. This does not claim a Windows SChannel handshake or native run.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'game-network-lifecycle-'));
process.env.DATA_DIR=temporary;process.env.HA_ENABLED='0';
const {Isolated}=require("../fixtures/protocol/peace.completion-6-10-fixture");
const work=require("../../services/runtime/peace.desktop-work-queue");
let count=0;
async function check(name,run){await run();count++;console.log('PASS '+name);}
function failure(){const e=Error('TLS_PIN_SERVER_CERTIFICATE_OUTSIDE_WINDOW');e.desktopError=true;e.status=503;return e;}
function dispatchHarness(){
 const state={allowed:true,offers:0,prepared:0,executed:0,lanes:[],expireInQueue:false};
 const execute=()=>{state.executed++;return {accepted:true};};
 const m=Isolated("services/network/peace.desktop-connect.js",['Dispatch'],{
  "../licensing/peace.desktop-licenses":{messages:{},Fail(code){const e=Error(code);e.desktopError=true;throw e;},Execute:execute,Challenge:execute},
  "../bootstrap/peace.desktop-bootstrap":{Execute:execute},"../security/peace.desktop-security-authority":{Execute:execute},
  "../integrity/peace.desktop-integrity-reports":{Execute:execute},
  './peace.desktop-tls-pin-transition':{Offer(){state.offers++;if(!state.allowed)throw failure();return null;}},
  "../integrity/peace.desktop-proof-work":{Prepare(){state.prepared++;return [];},async Run(jobs,fn,options){state.lanes.push(options.renewal);if(state.expireInQueue)state.allowed=false;return fn();}},
  "../runtime/peace.desktop-runtime-diagnostics":{Record(){}},"../runtime/peace.desktop-work-queue":work,
  './peace.desktop-transport-rotation':{AssertUse(keyId){assert.equal(keyId,'test-transport-key');}}
 });
 return {state,run:(operation,body,pinVersion)=>m.__probe.Dispatch({keyId:'test-transport-key',payload:{operation,body,...(pinVersion===undefined?{}:{tlsPinVersion:pinVersion})}},10000)};
}
(async()=>{try{
 await check('retired TLS certificate blocks side effects for opted-in AND legacy envelopes',async()=>{
  for(const version of [undefined,1]){const h=dispatchHarness();h.state.allowed=false;const r=await h.run('execute',{action:'redeem'},version);assert.equal(r.ok,false);assert.equal(r.error,'TLS_PIN_SERVER_CERTIFICATE_OUTSIDE_WINDOW');assert.equal(h.state.prepared,0);assert.equal(h.state.executed,0);}
 });
 await check('proof queue wait cannot carry authorization past certificate retirement',async()=>{
  const h=dispatchHarness();h.state.expireInQueue=true;const r=await h.run('execute',{action:'verify'},1);assert.equal(r.ok,false);assert.equal(r.error,'TLS_PIN_SERVER_CERTIFICATE_OUTSIDE_WINDOW');assert.equal(h.state.prepared,1);assert.equal(h.state.executed,0);assert.equal(h.state.offers,2);
 });
 await check('B and O renewals share critical lane; ordinary work does not inherit it',async()=>{
  for(const [operation,body,reserved] of [['execute',{action:'verify'},true],['bootstrap',{action:'overlayVerify'},true],['security',{action:'submit',intent:'verify'},true],['execute',{action:'redeem'},false],['bootstrap',{action:'overlayClaim'},false],['report',{action:'challenge'},false]]){
   const h=dispatchHarness();assert.equal((await h.run(operation,body,1)).ok,true);assert.deepEqual(h.state.lanes,[reserved]);assert.equal(h.state.executed,1);assert.equal(h.state.offers,2);
  }
 });
 await check('renewal metrics and routing recognize same terminal B/O operations',()=>{
  const before=work.Snapshot().renewal;
  assert(work.RecordRenewal('execute','verify',true));assert(work.RecordRenewal('bootstrap','overlayVerify',false));
  for(const [op,action] of [['challenge','verify'],['security','challenge'],['bootstrap','overlayClaim'],['report','submit']])assert.equal(work.RecordRenewal(op,action,true),false);
  const after=work.Snapshot().renewal;assert.equal(after.attempted-before.attempted,2);assert.equal(after.failed-before.failed,1);
 });
 await check('pin retirement remains closed across wall-clock rollback in one server process',()=>{
  const savedNow=Date.now;let wall=1800000000000,tick=100;
  Date.now=()=>wall;
  try{
   const pin=c=>c.repeat(64),profile={host:'127.0.0.1',port:29131,serverKeyId:pin('a'),tlsServerName:'test.invalid',tlsCertificateSha256:pin('b')};
   const plan={version:1,generation:1,host:profile.host,port:profile.port,serverKeyId:profile.serverKeyId,tlsServerName:profile.tlsServerName,currentPin:pin('b'),nextPin:pin('c'),issuedAt:wall,notBefore:wall+60000,oldNotAfter:wall+120000};
   const row={version:1,generation:1,plan,retiredPins:[],stagedGeneration:'1'.repeat(48)};
   const module=Isolated("services/network/peace.desktop-tls-pin-transition.js",[],{
    'node:perf_hooks':{performance:{now:()=>tick}},
    "../bootstrap/peace.desktop-bootstrap-store":{Load:()=>({tlsPinTransition:row})},
    './peace.connect-transport-key':{Profile:()=>profile}
   });
   assert.deepEqual(module.Offer(),plan);
   tick+=120000;wall=plan.oldNotAfter;assert.throws(()=>module.Offer(),/TLS_PIN_SERVER_CERTIFICATE_OUTSIDE_WINDOW/);
   wall=plan.issuedAt;tick++;assert.throws(()=>module.Offer(),/TLS_PIN_SERVER_CERTIFICATE_OUTSIDE_WINDOW/);
   profile.tlsCertificateSha256=plan.nextPin;assert.deepEqual(module.Offer(),plan);
   profile.host='other.invalid';assert.throws(()=>module.Offer(),/TLS_PIN_ENDPOINT_CHANGED/);
  }finally{Date.now=savedNow;}
 });
 console.log(JSON.stringify({suite:'network-lifecycle-upgrade',groups:count,status:'PASS',actualDispatchAndPinClock:true,isolatedStores:true,nativeExecuted:false}));
}catch(e){console.error(e);process.exitCode=1;}finally{await Promise.all([work.auth,work.pe,work.proof,work.renewalProof,work.tpmAttestation].map(q=>q.close()));fs.rmSync(temporary,{recursive:true,force:true});}})();
