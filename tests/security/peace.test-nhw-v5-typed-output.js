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
  assert.equal(verdict(entry,r,5,{...own,serverBound:false}).stop,true,id+' unbound claim');
  assert.equal(verdict(entry,r,5,{...own,baseline:false}).stop,true,id+' post-baseline');
  assert.equal(verdict(entry,r,5,{...own,sameSession:false}).stop,true,id+' foreign session');
  assert.equal(policy.Evaluate(entry,{...r,correlation:true,localOnly:false},{tick,version:5,context:own,corroborated:true}).stop,true,id+' corroborated');
 }
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
