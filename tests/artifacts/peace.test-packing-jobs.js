'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {Isolated,PE}=require("../fixtures/protocol/peace.completion-6-10-fixture"),p=require("../../services/artifacts/peace.desktop-packing-protocol"),contract=require("../../services/integrity/peace.measurement-plan-contract");
function Setup(options={}){
 const resourceBudget=new (require("../../services/runtime/peace.server-resource-budget").Budget)({signal:()=>{}});
 const artifacts={},bytes={},body={},session={id:'TEST_ADMIN',role:'admin'},events=[];let active=true,revoked=false,calls=0;
 for(const [i,c]of ['A','B','O'].entries()){const id=String(i+1).repeat(24);body[c]=id;bytes[id]=PE(c);artifacts[id]={id,component:c,size:bytes[id].length,sha512:p.Sha512(bytes[id]),measurementPlanVersion:contract.ArtifactVersion(bytes[id]),ownMeasurementVersion:contract.ArtifactOwnVersion(bytes[id]),tlsPinVersion:contract.ArtifactVersion(bytes[id],'GAME-TLS-PIN-WINDOW-V1')};}
 const check=(s,pathname,method)=>s!==session||!active?{ok:false,reason:'ADMIN_SESSION_EXPIRED',status:401}:options.stale&&method==='POST'?{ok:false,reason:'ADMIN_REAUTH_REQUIRED',status:428}:{ok:true};
 const service=Isolated("services/artifacts/peace.desktop-packing-jobs.js",[],{
  "../runtime/peace.server-resource-budget":{Admit:(...args)=>resourceBudget.admit(...args)},
  "../authentication/peace.desktop-admin-guard":{CheckSession:check},"../../web/authentication/peace.web-auth":{IsSessionActive:()=>active},"../../storage/audit/peace.audit.js":{LogEvent:(type,text)=>events.push({type,data:JSON.parse(text)})},
  "../bootstrap/peace.desktop-bootstrap":{Initialize:()=>({artifacts}),AssertSecurityAvailable:()=>{if(revoked)p.Fail('RELEASE_REVOKED',403);},ReadArtifactBytes:row=>Buffer.from(bytes[row.id])},
  './peace.desktop-packing-client':{Status:()=>({configured:!options.unconfigured,reason:'PACKING_WORKER_NOT_CONFIGURED'}),Pack:async(c,input)=>{calls++;await new Promise(r=>setTimeout(r,10));if(options.expire)active=false;if(options.revoke)revoked=true;const out=Buffer.concat([input,Buffer.from('STAND-IN; NO VIRTUALIZATION')]);return {bytes:out,sha512:p.Sha512(out),inputSha512:p.Sha512(input),profileSha512:'a'.repeat(128),toolSha512:'b'.repeat(128)};}}
 });
 return {service,session,body,events,artifacts,bytes,calls:()=>calls};
}
async function Done(f,id){for(let i=0;i<200;i++){const j=f.service.Get(id,f.session);if(j.status!=='RUNNING')return j;await new Promise(r=>setTimeout(r,5));}throw Error('TEST_TIMEOUT');}
test('A/B/O job uses exact stored source bytes, yields only unapproved candidates',async()=>{const f=Setup(),before=JSON.stringify(f.artifacts),start=f.service.Begin(f.body,f.session),end=await Done(f,start.id),view=f.service.View(end);assert.equal(end.status,'COMPLETE');assert.deepEqual(Object.keys(view.outputs),['A','B','O']);assert.equal(view.disposition,'UNAPPROVED_CANDIDATE');assert.equal(view.activeUnchanged,true);assert.equal(view.windowsVerified,false);assert.equal(view.allSourceVirtualizationVerified,false);assert.equal(JSON.stringify(f.artifacts),before);assert.equal(f.calls(),3);for(const c of ['A','B','O'])assert.equal(view.outputs[c].inputSha512,f.artifacts[f.body[c]].sha512);});
test('missing worker configuration is not a fake packing success',()=>{const f=Setup({unconfigured:true});assert.throws(()=>f.service.Begin(f.body,f.session),/NOT_CONFIGURED/);assert.equal(f.calls(),0);});
test('old reauthentication cannot enqueue a packing job',()=>{const f=Setup({stale:true});assert.throws(()=>f.service.Begin(f.body,f.session),/REAUTH_REQUIRED/);});
test('no client-provided path, command or profile is accepted',()=>{const f=Setup();for(const x of [{...f.body,command:'x'},{...f.body,A:'../data/key'},{...f.body,A:f.body.O}])assert.throws(()=>f.service.Begin(x,f.session),/INPUT_INVALID|SOURCE_INVALID/);});
test('another admin session cannot read a job by guessing its ID',async()=>{const f=Setup(),s=f.service.Begin(f.body,f.session);assert.throws(()=>f.service.Get(s.id,{id:'OTHER_ADMIN'}),/NOT_FOUND/);await Done(f,s.id);});
test('concurrent enqueue cannot overwrite running job or bypass admission',async()=>{const f=Setup(),s=f.service.Begin(f.body,f.session);assert.throws(()=>f.service.Begin(f.body,f.session),/PACKING_BUSY/);await Done(f,s.id);});
test('session invalidated during worker await yields no candidate',async()=>{const f=Setup({expire:true}),s=f.service.Begin(f.body,f.session),j=await Done(f,s.id);assert.equal(j.status,'FAILED');assert.equal(j.error,'ADMIN_SESSION_EXPIRED');assert.deepEqual(j.outputs,{});});
test('source revoked during worker await yields no candidate',async()=>{const f=Setup({revoke:true}),s=f.service.Begin(f.body,f.session),j=await Done(f,s.id);assert.equal(j.status,'FAILED');assert.equal(j.error,'RELEASE_REVOKED');assert.deepEqual(j.outputs,{});});
test('packing may not conceal a required measurement version',()=>{const f=Setup(),row={...f.artifacts[f.body.O],measurementPlanVersion:1};const b=Buffer.from(f.bytes[f.body.O]);const marker=Buffer.from(contract.CONTRACT);for(let i=b.indexOf(marker);i>=0;i=b.indexOf(marker))b.fill(0,i,i+marker.length);assert.throws(()=>f.service.ValidateOutput(b,row),/MEASUREMENT_CONTRACT_LOST/);});
test('unparseable transformed executable is not a valid candidate',()=>{const f=Setup();assert.throws(()=>f.service.ValidateOutput(Buffer.alloc(512),f.artifacts[f.body.O]),/PE_INVALID/);});
