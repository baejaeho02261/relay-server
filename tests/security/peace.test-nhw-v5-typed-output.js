'use strict';
// V5 policy-only regression. Synthetic inputs do not emulate Windows sensors.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const catalog=require('../../services/security/peace.security-detection-catalog');
const policy=require('../../services/security/peace.security-context-policy');
const reports=require('../../services/security/peace.security-detections');
const responses=require('../../services/security/peace.nhw-response-paths');
const tick='0000000000000401';
const first='0000000000000400';
function record(id,signal='DETECTED'){
 const context=policy.UnknownContext('A');
 return {id,source:'Cozy.NHW.Engine',firstTick:first,lastTick:first,count:1,
  families:0,confidence:0,correlation:false,attestationSequence:'0000000000000000',
  localOnly:true,context:Object.fromEntries(policy.CONTEXT_FIELDS.map(k=>[k,context[k]])),signal};
}
function verdict(entry,r,version=5,context=policy.UnknownContext('A'),corroborated=false){
 return policy.Evaluate(entry,r,{tick,version,context,corroborated});
}
const expectsStop=e=>e.standaloneOutput&&e.signalClass!=='UNKNOWN';
const direct=e=>['STABLE_INTEGRITY_INVARIANT','NATIVE_MULTI_SIGNAL_PROOF'].includes(policy.NativeEvidenceTier(e));
const independent={confidence:75,families:3,correlation:true,localOnly:false};

test('V5 DETECTED candidates remain admitted across the complete output catalog',()=>{
 assert.equal(catalog.NHW.length,204);
 assert.equal(catalog.NHW.filter(e=>e.standaloneOutput).length,197);
 assert.equal(catalog.Counts.nhwOutputNames,194);
 let actionable=0;
 for(const e of catalog.NHW){
  const report=record(e.id);
  assert.doesNotThrow(()=>reports.ParseRecords([report],tick,5),e.id);
  const isolated=verdict(e,report);
  assert.equal(isolated.stop,direct(e),e.id+' isolated output');
  const supported=verdict(e,{...report,...independent},5,policy.UnknownContext('A'),true);
  assert.equal(supported.stop,expectsStop(e),e.id+' supported finding');
  if(supported.stop)actionable++;
  assert.equal(verdict(e,record(e.id,'OBSERVED')).stop,false,e.id+' context-only observation');
 }
 assert.equal(actionable,191);
});

test('legacy V4 policy preserves its established direct evidence rules',()=>{
 for(const id of ['dkAffinity','dkProcess','dkTokenRights','dkThreadBurst','dkPECodeIntegrity','dkImageCOWIntegrity']){
  const e=catalog.Get(id),r=record(id);
  const expected=['dkPECodeIntegrity','dkImageCOWIntegrity'].includes(id);
  assert.equal(verdict(e,r,4).stop,expected,'legacy policy: '+id);
  assert.equal(verdict(e,r,5).stop,expected,'isolated native output: '+id);
 }
});

test('expected first-party scheduling requires authoritative binding and does not exempt corroborated changes',()=>{
 for(const id of ['dkAffinity','dkProcessPriority','dkThreadPriority']){
  const entry=catalog.Get(id),r=record(id),own={...policy.UnknownContext('B'),
   actorClass:'SELF',capability:'THREAD_ACCESS',capabilityDecision:'EXPECTED',
   serverBound:true,firstPartyAttested:true,sameSession:true,contextMixed:false};
  assert.equal(verdict(entry,r,5,own).disposition,'EXPECTED_FIRST_PARTY',id+' verified first-party');
  for(const context of [{...own,serverBound:false},{...own,contextMixed:true}]){
   const weak=verdict(entry,r,5,context);
   assert.equal(weak.stop,false,id+' isolated change');
   assert.equal(weak.disposition,'OBSERVATION_UNRESOLVED',id+' context must not grant authority');
  }
  assert.equal(verdict(entry,{...r,...independent},5,own,true).stop,true,id+' corroborated change');
 }
});

test('V5 startup token context remains recorded while corroborated later changes are actionable',()=>{
 for(const id of ['dkTokenObject','dkTokenRights','dkTokenChange','dkThreadToken']){
  const entry=catalog.Get(id),r=record(id),own={...policy.UnknownContext('A'),
   actorClass:'SELF',capability:'TOKEN_STATE',tokenDelta:2,baseline:true,
   capabilityDecision:'FORBIDDEN',serverBound:true,firstPartyAttested:true,
   sameSession:true,contextMixed:false};
  assert.equal(verdict(entry,r,5,own).stop,false,id+' verified startup');
  assert.equal(verdict(entry,r,5,own).disposition,'OBSERVATION_UNRESOLVED');
  for(const context of [{...own,serverBound:false},{...own,baseline:false},{...own,sameSession:false}]){
   assert.equal(verdict(entry,r,5,context).stop,false,id+' isolated token transition');
   assert.equal(verdict(entry,{...r,...independent},5,context,true).stop,true,id+' supported token transition');
  }
  assert.equal(verdict(entry,{...r,...independent},5,own,true).stop,true,id+' corroborated');
 }
});

test('A approval retains unattributed token state and handle output without attributing an attack',()=>{
 for(const id of ['dkTokenObject','dkTokenRights','dkTokenChange','dkThreadToken']){
  const entry=catalog.Get(id),r=record(id),unattributed={...policy.UnknownContext('A'),
   phase:'A_ISSUANCE',capability:'TOKEN_STATE',tokenDelta:2};
  for(const context of [unattributed,{...unattributed,capability:'TOKEN_ACCESS',tokenDelta:0,accessMask:0x20}]){
   assert.equal(verdict(entry,r,5,context).disposition,'OBSERVATION_UNRESOLVED',id);
   assert.equal(verdict(entry,{...r,...independent},5,context,true).stop,true,id+' supported output');
  }
  assert.equal(verdict(entry,{...r,signal:'OBSERVED'},5,unattributed).stop,false,id+' context only');
  assert.equal(verdict(entry,r,4,unattributed).stop,false,id+' V4');
 }
});

test('Native token rights detection observes startup handles while preserving post-baseline alerts',t=>{
 const native=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Security.pas');
 if(!fs.existsSync(native)){t.skip('full native source shipped separately');return;}
 const source=fs.readFileSync(native,'utf8'), part=source.split('procedure TSecurityMonitor.ExamineTokenHandles(')[1].split('procedure TSecurityMonitor.ExamineLocalState(')[0];
 assert.match(part,/if not Baseline then Include\(Detected, dkTokenObject\)/);
 assert.match(part,/if \(NewHolder or NewRights\) and not Baseline then\s*Include\(Detected, dkTokenRights\)/);
 assert.match(part,/NHWNoteAccessContext\(dkTokenRights,/);
});

test('V5 wire payload is accepted with the unchanged signed JSON schema; unknown versions rejected',()=>{
 const detections=[record('dkAffinity')];
 const digest=crypto.createHash('sha512').update(JSON.stringify(detections)).digest('hex').slice(0,16);
 const body={version:5,sequence:'0000000000000001',tick,digest,confirmed:false,trust:0,detections,peer:null};
 assert.equal(responses.Payload(JSON.stringify(body)).version,5);
 assert.equal(responses.Payload(JSON.stringify({...body,version:4})).version,4);
 assert.throws(()=>responses.Payload(JSON.stringify({...body,version:6})),/SECURITY_NHW_RESPONSE_INVALID/);
 assert.throws(()=>responses.Payload(JSON.stringify({...body,detections:[{...record('dkAffinity'),signal:'NOT_PROVEN'}]})),/SECURITY_DETECTION_INVALID|SECURITY_NHW_RESPONSE_INVALID/);
 assert.doesNotThrow(()=>reports.ParseRecords(detections,tick,5));
});

test('Delphi v5 publishes only post-filter detected output and keeps separate observation path',t=>{
 const root=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW');
 if(!fs.existsSync(path.join(root,'Cozy.NHW.Engine.pas'))){t.skip('Native source is shipped in the separate full-source archive');return;}
 const read=name=>fs.readFileSync(path.join(root,'Cozy.NHW.'+name+'.pas'),'utf8');
 const engine=read('Engine'),publisher=engine.split('procedure RecordCycleEvidence;')[1].split('procedure FinalizeSamplingAndReport;')[0];
 assert.match(publisher,/VisibleDetected\s*:=\s*FalsePositive\.FilterForOutput\(Detected/);
 assert.match(publisher,/ReportKinds\s*:=\s*VisibleDetected\s*\+\s*NHWContextObservations/);
 assert.match(publisher,/not \(Kind in VisibleDetected\)/);
 assert.doesNotMatch(publisher,/ReportKinds\s*:=\s*Detected\s*\+/);
 assert.match(read('ResponseTransport'),/Payload\.AddPair\('version', TJSONNumber\.Create\(5\)\)/);
 const finalize=engine.split('procedure FinalizeSamplingAndReport;')[1].split('procedure ReleaseSessionComponents;')[0];
 assert.match(finalize,/OnDetection\(VisibleDetected, CurrentTick/);
 assert.doesNotMatch(finalize,/OnDetection\(Detected, CurrentTick/);
});

test('repetition of one unattributed handle observation does not produce independent evidence',()=>{
 const ctx={...policy.UnknownContext('A'),phase:'A_BOOTSTRAP',capability:'TOKEN_ACCESS',
  accessMask:0x000f01ff,actorClass:'EXTERNAL',actorRole:'?',actorIdentity:'',
  targetRole:'?',targetIdentity:'a'.repeat(64),capabilityDecision:'FORBIDDEN',sameSession:false};
 for(const id of ['dkTokenObject','dkTokenRights','dkProcess']){
  const entry=catalog.Get(id),r={...record(id),confidence:10,families:32,count:27};
  assert.equal(verdict(entry,r,5,ctx).stop,false,id+' repeated native output');
  assert.equal(verdict(entry,{...r,signal:'OBSERVED'},5,ctx).stop,false,id+' raw snapshot');
  assert.equal(verdict(entry,r,4,ctx).stop,false,id+' old V4 policy');
  assert.equal(verdict(entry,{...r,...independent},5,ctx,true).stop,true,id+' supported finding');
 }
});

test('stored V5 token decision remains valid after restart; malformed tags still fail closed',()=>{
 const flowId='A'.repeat(24),epoch=1700000000000,at=1700000000020;
 const detectionId='dkTokenRights',source='Cozy.NHW.Engine',responsePath='integrity';
 const id=crypto.createHash('sha256').update([flowId,'A',flowId,String(epoch),responsePath,detectionId,source].join('\n')).digest('hex');
 const event={id,flowId,sessionId:flowId,role:'A',epoch:String(epoch),detectionId,
  category:catalog.Get(detectionId).category,sensor:source,responsePath,firstAt:at,lastAt:at,
  count:1,confirmationCount:0,firstTick:'0000000000000400',lastTick:'0000000000000400',
  producerCount:1,evidenceFamilies:0,confidence:0,correlation:false,localOnly:true,
  attestationSequence:'0000000000000000',invalidated:true,provenance:'AUTHENTICATED_CLIENT_REPORT',
  disposition:'DETECTION',decisionReason:'V5_NATIVE_SENSOR_OUTPUT',
  sessionStopPolicy:'STOP_ON_NATIVE_DETECTED_OUTPUT',coverageState:'UNKNOWN',
  context:policy.UnknownContext('A')};
 const storage={version:1,flows:{[flowId]:{flowId,updatedAt:at,events:[event]}}};
 const db={flows:{[flowId]:{createdAt:epoch}},overlays:{}};
 assert.doesNotThrow(()=>reports.Validate(storage,db));
 const tampered={...event,decisionReason:'V5-NATIVE-OUTPUT'};
 assert.throws(()=>reports.Validate({version:1,flows:{[flowId]:{flowId,updatedAt:at,events:[tampered]}}},db),/SECURITY_DETECTION_STORAGE_INVALID/);
});
