'use strict';
// Exhaustive server policy regression. Synthetic evidence is not a Win64 run.
// Regression: V8 causal-only gate was letting authenticated V5 DETECTED output
// remain OBSERVATION_UNRESOLVED, so the exact A/B/O cohort was not revoked.
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs');
const path=require('node:path');
const catalog=require('../../services/security/peace.security-detection-catalog');
const policy=require('../../services/security/peace.security-context-policy');
const reports=require('../../services/security/peace.security-detections');
const tick='0000000000030001',observedTick='0000000000030000';
function context(role,phase=role+'_RUNTIME',patch={}){
 return {...policy.UnknownContext(role),actorClass:'EXTERNAL',phase,...patch};
}
function record(entry,signal='DETECTED',patch={}){
 return {id:entry.id,source:'Cozy.NHW.Engine',firstTick:observedTick,lastTick:observedTick,
  count:1,families:0,confidence:0,correlation:false,localOnly:true,
  attestationSequence:'0000000000000000',signal,...patch};
}
function evaluate(entry,role='B',signal='DETECTED',ctx=context(role),patch={}){
 return policy.Evaluate(entry,record(entry,signal,patch),{tick,version:5,stage:role,context:ctx,corroborated:false});
}
const actionable=e=>e.standaloneOutput&&e.signalClass!=='UNKNOWN';

test('all 204 NHW states retained; 197 output kinds, 194 output labels; all 191 security kinds STOP in A/B/O',()=>{
 assert.equal(catalog.NHW.length,204);
 const outputs=catalog.NHW.filter(e=>e.standaloneOutput);
 assert.equal(outputs.length,197);
 assert.equal(new Set(outputs.map(e=>e.displayName)).size,194);
 assert.equal(outputs.filter(actionable).length,191);
 const ids=new Set();let verified=0;
 for(const entry of catalog.NHW){
  assert.ok(!ids.has(entry.id));ids.add(entry.id);
  for(const role of ['A','B','O']){
   const ctx=context(role,role+'_ATTESTED');
   const yes=evaluate(entry,role,'DETECTED',ctx);
   assert.equal(yes.stop,actionable(entry),role+' '+entry.id);
   if(actionable(entry)){
    verified++;
    assert.equal(yes.disposition,'DETECTION');
    assert.equal(yes.decisionReason,'V5_NATIVE_SENSOR_OUTPUT');
    assert.equal(yes.sessionStopPolicy,'STOP_ON_NATIVE_DETECTED_OUTPUT');
    assert.equal(entry.sessionStopPolicy,'STOP_ON_NATIVE_DETECTED_OUTPUT');
   }
   else assert.ok(['INTERNAL_EVIDENCE','COVERAGE_WARNING','COVERAGE_DEGRADED'].includes(yes.disposition));
   const observation=evaluate(entry,role,'OBSERVED',ctx);
   assert.equal(observation.stop,false,role+' OBSERVED '+entry.id);
   const stale=evaluate(entry,role,'DETECTED',ctx,{lastTick:'0000000000000001'});
   assert.equal(stale.stop,false,role+' stale '+entry.id);
  }
 }
 assert.equal(ids.size,204);
 assert.equal(verified,573);
});

test('Process/Thread/Token/Affinity/NoAccess/Injection standalone findings terminate at weak native confidence',()=>{
 const subset=['dkProcess','dkThread','dkTokenObject','dkTokenRights','dkTokenChange',
  'dkThreadToken','dkAffinity','dkThreadCreation','dkThreadExit','dkThreadSpawn',
  'dkNoAccess','dkRemoteThread','dkPrivateThread','dkRWX','dkWriteIntegrity',
  'dkInjectionEvidence','dkIAT','dkPECodeIntegrity'];
 for(const role of ['A','B','O'])for(const id of subset){
  const entry=catalog.Get(id),out=evaluate(entry,role,'DETECTED',context(role),{confidence:0,families:0});
  assert.equal(out.stop,true,role+' '+id);
 }
});

test('every B/O phase carries the real terminal output; a forged client phase cannot avoid stage binding',()=>{
 const phases={B:['B_BOOTSTRAP','B_ATTESTED','B_RUNTIME','B_HANDOFF_TO_O','B_SHUTDOWN'],
  O:['O_BOOTSTRAP','O_ATTESTED','O_RUNTIME','O_SHUTDOWN']};
 for(const [role,p] of Object.entries(phases))for(const phase of p){
  for(const id of ['dkThreadSpawn','dkTokenRights','dkAffinity','dkProcess','dkNoAccess'])
   assert.equal(evaluate(catalog.Get(id),role,'DETECTED',context(role,phase)).stop,true,role+' '+phase+' '+id);
 }
 for(const role of ['A','B','O'])for(const foreign of ['A_BOOTSTRAP','B_RUNTIME','O_RUNTIME'])
  assert.equal(evaluate(catalog.Get('dkProcess'),role,'DETECTED',context(role,foreign)).stop,true);
});

test('server-bound expected first-party A/B/O capability is not a native hostile output',()=>{
 for(const role of ['A','B','O'])for(const [id,cap,mask] of [
  ['dkProcess','PROCESS_ACCESS',0x20],['dkThread','THREAD_ACCESS',0x10],
  ['dkTokenRights','TOKEN_ACCESS',0x20],['dkAffinity','THREAD_ACCESS',0]]){
  const own=context(role,role+'_ATTESTED',{actorClass:'SELF',actorRole:role,
   capability:cap,accessMask:mask,capabilityDecision:'EXPECTED',
   firstPartyAttested:true,serverBound:true,sameSession:true,contextMixed:false});
  assert.equal(evaluate(catalog.Get(id),role,'DETECTED',own).stop,false,role+' '+id+' server-bound own');
  for(const broken of [{serverBound:false},{firstPartyAttested:false},{sameSession:false},{contextMixed:true}])
   assert.equal(evaluate(catalog.Get(id),role,'DETECTED',{...own,...broken}).stop,true,
    role+' '+id+' untrusted first party not an exemption');
 }
});

test('trusted SELF token initialization is retained; unbound/post-baseline token findings stop',()=>{
 for(const role of ['A','B','O'])for(const id of ['dkTokenObject','dkTokenRights','dkTokenChange','dkThreadToken']){
  const own=context(role,role+'_BOOTSTRAP',{actorClass:'SELF',actorRole:role,
   capability:'TOKEN_STATE',tokenDelta:2,baseline:true,
   firstPartyAttested:true,serverBound:true,sameSession:true,
   contextMixed:false});
  assert.equal(evaluate(catalog.Get(id),role,'DETECTED',own).stop,false);
  assert.equal(evaluate(catalog.Get(id),role,'DETECTED',{...own,baseline:false}).stop,true);
  assert.equal(evaluate(catalog.Get(id),role,'DETECTED',{...own,serverBound:false}).stop,true);
  assert.equal(evaluate(catalog.Get(id),role,'DETECTED',{...own,actorClass:'UNKNOWN'}).stop,true);
 }
});

test('V4 legacy policy is not widened; V5 only genuine standalone output, not OBSERVED',()=>{
 const scope=['dkProcess','dkThread','dkTokenRights','dkNoAccess','dkAffinity','dkPECodeIntegrity'];
 for(const id of scope){
  const entry=catalog.Get(id),r=record(entry),ctx=context('B');
  const old=policy.Evaluate(entry,r,{tick,version:4,stage:'B',context:ctx});
  assert.equal(old.stop,id==='dkPECodeIntegrity',id+' legacy V4 untouched');
  assert.equal(evaluate(entry,'B','DETECTED',ctx).stop,true,id+' V5 direct');
  assert.equal(evaluate(entry,'B','OBSERVED',ctx).stop,false,id+' V5 observations');
 }
});

test('A/B/O client stopped response, local confirmed latch and shutdown cleanup wiring preserved',t=>{
 const native=path.resolve(__dirname,'../../../Railway/Cozy.Source');
 const get=p=>fs.readFileSync(path.join(native,p),'utf8');
 if(!fs.existsSync(path.join(native,'Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas'))){
  t.skip('native sources ship in full source ZIP rather than Railway relay build context');return;
 }
 const wire=get('Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas');
 assert.equal((wire.match(/if ReadBoolean\(Reply,'stopped'\) then/g)||[]).length,3);
 assert.equal((wire.match(/if Assigned\(FServerStop\) then FServerStop\(\)/g)||[]).length,3);
 const guard=get('Cozy.Security.NHW/Cozy.NHW.Guard.pas');
 assert.match(guard,/procedure TCozyNHWGuard\.ApplyAuthenticatedServerStop;\s*begin\s*Confirm;/);
 const a=get('Cozy.Application/Cozy.Launcher.pas');
 assert.match(a,/procedure RequireLauncherWatch\(Watch: TCozyNHWGuard\)/);
 assert.match(a,/Client\.FlushNHWReports/);
 const b=get('Cozy.License/Cozy.License.Session.pas');
 assert.match(b,/if FWatch\.Confirmed then Exit\(WorkerFailed\)/);
 assert.match(b,/if \(Api <> nil\) and SecurityStopped then Api\.FinishNHWStop/);
 const o=get('Cozy.Overlay/Cozy.Overlay.pas');
 assert.match(o,/ConfirmedWatch/);
 assert.match(o,/Client\.FlushNHWReports/);
 const server=fs.readFileSync(path.resolve(__dirname,'../../services/security/peace.nhw-response-paths.js'),'utf8');
 assert.match(server,/const stopped=terminal\|\|!!decision/);
 assert.match(server,/\.Revoke\(row\.sessionId,\{reason\}/);
 assert.match(server,/accepted:true,stopped,scope:'OWNED_A_B_O'/);
});

test('server StopDecision marks real V5 detection without client confirmed bit or independent vote',()=>{
 const e=catalog.Get('dkAffinity'),ctx=context('B');
 const wire={version:5,sequence:'0000000000000001',tick,
  confirmed:false,trust:0,detections:[{
   ...record(e,'DETECTED',{}),source:'Cozy.NHW.Engine',context:Object.fromEntries(policy.CONTEXT_FIELDS.map(k=>[k,ctx[k]]))}],peer:null};
 const out=reports.StopDecision('B','integrity',wire);
 assert.ok(out&&out.reason.startsWith('NHW_DETECTED:B:integrity:'),out);
 assert.ok(out.keys.some(k=>k.startsWith('dkAffinity:Cozy.NHW.Engine')));
});
