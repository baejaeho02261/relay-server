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
function verdict(entry,r,version=5,context=policy.UnknownContext('A')){
 return policy.Evaluate(entry,r,{tick,version,context,corroborated:false});
}
const expectsStop=e=>e.standaloneOutput===true&&e.contextPolicy!=='COVERAGE_HEALTH'&&e.contextPolicy!=='INTERNAL_TELEMETRY';

test('V5 explicit native DETECTED: every independently actionable output reaches stop; observations remain inert',()=>{
 assert.equal(catalog.NHW.length,204);
 assert.equal(catalog.NHW.filter(e=>e.standaloneOutput).length,197);
 assert.equal(catalog.Counts.nhwOutputNames,194);
 let actionable=0;
 for(const e of catalog.NHW){
  const actual=verdict(e,record(e.id));
  assert.equal(actual.stop,expectsStop(e),e.id+' V5 post-filter native output');
  if(actual.stop){actionable++;assert.equal(actual.disposition,'DETECTION');assert.equal(actual.decisionReason,'V5_NATIVE_SENSOR_OUTPUT');}
  assert.equal(verdict(e,record(e.id,'OBSERVED')).stop,false,e.id+' context-only observation');
 }
 assert.equal(actionable,191,'six coverage-only and seven internal telemetry IDs stay nonterminal');
});

test('legacy V4 policy does not silently inherit V5 stop rules',()=>{
 const ids=['dkAffinity','dkProcess','dkTokenRights','dkThreadBurst','dkPECodeIntegrity','dkImageCOWIntegrity'];
 for(const id of ids){const e=catalog.Get(id),r=record(id);
  const v4=verdict(e,r,4).stop;
  const expected=['dkPECodeIntegrity','dkImageCOWIntegrity'].includes(id);
  assert.equal(v4,expected,'legacy policy: '+id);
  assert.equal(verdict(e,r,5).stop,true,'new native-typed contract: '+id);
 }
});

test('server-bound expected A/B/O own scheduling stays observation; client-asserted SELF is not an exemption',()=>{
 for(const id of ['dkAffinity','dkProcessPriority','dkThreadPriority']){
  const entry=catalog.Get(id),r=record(id),own={...policy.UnknownContext('B'),
   actorClass:'SELF',capability:'THREAD_ACCESS',capabilityDecision:'EXPECTED',
   serverBound:true,firstPartyAttested:true,sameSession:true,contextMixed:false};
  assert.equal(verdict(entry,r,5,own).stop,false,id+' verified first-party');
  assert.equal(verdict(entry,r,5,{...own,serverBound:false}).stop,true,id+' unverified SELF claim');
  assert.equal(verdict(entry,r,5,{...own,contextMixed:true}).stop,true,id+' mixed attribution');
  assert.equal(verdict(entry,{...r,correlation:true,localOnly:false},5,own).stop,true,id+' changed security evidence');
 }
});

test('V5 self baseline token delta never escalates alone but unbound or corroborated deltas do',()=>{
 for(const id of ['dkTokenObject','dkTokenRights','dkTokenChange','dkThreadToken']){
  const entry=catalog.Get(id),r=record(id),own={...policy.UnknownContext('A'),
   actorClass:'SELF',capability:'TOKEN_STATE',tokenDelta:2,baseline:true,
   capabilityDecision:'FORBIDDEN',serverBound:true,firstPartyAttested:true,
   sameSession:true,contextMixed:false};
  assert.equal(verdict(entry,r,5,own).stop,false,id+' verified startup');
  assert.equal(verdict(entry,r,5,own).disposition,'OBSERVATION_UNRESOLVED',id+' does not claim a capability grant');
  assert.equal(verdict(entry,r,5,{...own,serverBound:false}).stop,true,id+' unbound claim');
  assert.equal(verdict(entry,r,5,{...own,baseline:false}).stop,true,id+' post-baseline');
  assert.equal(verdict(entry,r,5,{...own,sameSession:false}).stop,true,id+' foreign session');
  assert.equal(policy.Evaluate(entry,{...r,correlation:true,localOnly:false},{tick,version:5,context:own,corroborated:true}).stop,true,id+' corroborated');
 }
});

test('V5 initial A approval: unattributed native token deltas are retained, not false-revoked',()=>{
 for(const id of ['dkTokenObject','dkTokenRights','dkTokenChange','dkThreadToken']){
  const entry=catalog.Get(id),r=record(id),unattributed={...policy.UnknownContext('A'),
   phase:'A_ISSUANCE',capability:'TOKEN_STATE',tokenDelta:2};
  const outcome=verdict(entry,r,5,unattributed);
  assert.equal(outcome.stop,false,id+' isolated A-approval token snapshot');
  assert.equal(outcome.disposition,'OBSERVATION_UNRESOLVED');
  assert.equal(outcome.decisionReason,'TOKEN_STATE_ACTOR_UNATTRIBUTED');
  assert.equal(verdict(entry,r,4,unattributed).stop,false,id+' legacy V4 remains safe');
  assert.equal(verdict(entry,r,5,{...unattributed,capability:'TOKEN_ACCESS',accessMask:0x20,tokenDelta:0}).stop,true,id+' external token right remains actionable');
  const correlated={...r,correlation:true,localOnly:false,confidence:90,families:3};
  assert.equal(policy.Evaluate(entry,correlated,{tick,version:5,context:unattributed,corroborated:true}).stop,true,id+' independently corroborated delta');
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

test('unattributed low-confidence A bootstrap token handles are retained without terminating an innocent A',()=>{
 // Real administrator record: TOKEN_ALL_ACCESS 0x000f01ff, OBJECT_STATE only,
 // confidence 10, unbound EXTERNAL with no stable actor identity or attestation.
 const ctx={...policy.UnknownContext('A'),
  phase:'A_BOOTSTRAP',capability:'TOKEN_ACCESS',accessMask:0x000f01ff,
  actorClass:'EXTERNAL',actorRole:'?',actorIdentity:'',targetRole:'?',
  targetIdentity:'a'.repeat(64),capabilityDecision:'FORBIDDEN',sameSession:false};
 for(const id of ['dkTokenObject','dkTokenRights']){
  const entry=catalog.Get(id),r={...record(id),confidence:10,families:32,count:27};
  const observation=verdict(entry,r,5,ctx);
  assert.equal(observation.stop,false,id+' low-assurance self-startup incident');
  assert.equal(observation.disposition,'OBSERVATION_UNRESOLVED');
  assert.equal(observation.decisionReason,'UNATTRIBUTED_BOOTSTRAP_TOKEN_HANDLE');
  assert.equal(observation.sessionStopPolicy,'REQUIRE_VERIFIED_ACTOR_OR_CORROBORATION');
  // Only the precise uncertainty pattern is exempted; do not white-list a
  // name, entire bootstrap role, access rights, or the whole TOKEN_SECURITY family.
  assert.equal(verdict(entry,r,5,{...ctx,phase:'A_ATTESTED'}).stop,true,'phase');
  assert.equal(verdict(entry,r,5,{...ctx,actorIdentity:'b'.repeat(64)}).stop,true,'stable external attribution');
  assert.equal(verdict(entry,r,5,{...ctx,contextMixed:true}).stop,true,'mixed context');
  assert.equal(verdict(entry,r,5,{...ctx,serverBound:true}).stop,true,'not an unbound observation');
  assert.equal(verdict(entry,{...r,confidence:11},5,ctx).stop,true,'stronger sensor assessment');
  assert.equal(verdict(entry,{...r,families:33},5,ctx).stop,true,'independent acquisition roots');
  assert.equal(verdict(entry,{...r,correlation:true,localOnly:false,confidence:90,families:33},5,ctx).stop,true,'correlated');
  assert.equal(verdict(entry,{...r,signal:'OBSERVED'},5,ctx).stop,false,'mere observation');
  assert.equal(verdict(entry,r,4,ctx).stop,false,'legacy V4 remains unchanged');
 }
 assert.equal(verdict(catalog.Get('dkProcess'),{...record('dkProcess'),confidence:10,families:32},5,ctx).stop,true,'non-token sensors unaffected');
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
