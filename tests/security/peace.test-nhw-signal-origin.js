'use strict';
// Dependency-free real policy/decoder tests; synthetic observations are never
// presented as Windows execution or a hardware attestation.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const fs=require('node:fs');
const catalog=require('../../services/security/peace.security-detection-catalog');
const policy=require('../../services/security/peace.security-context-policy');
const observations=require('../../services/security/peace.security-detections');
const tick='0000000000000500';
function item(id,signal='OBSERVED',fields={}){
 const context=policy.UnknownContext('A');
 return {id,source:'Cozy.NHW.Engine',firstTick:'0000000000000400',lastTick:'0000000000000400',count:1,families:0,confidence:30,correlation:false,attestationSequence:'0000000000000000',localOnly:true,context:Object.fromEntries(policy.CONTEXT_FIELDS.map(k=>[k,context[k]])),signal,...fields};
}
function evaluate(row,record,context=policy.UnknownContext('A'),corroborated=false){return policy.Evaluate(row,record,{tick,context,corroborated});}

test('204 NHW wire ids and 122 Cozy server outcomes are neither dropped nor aliased',()=>{
 assert.equal(catalog.NHW.length,204);assert.equal(catalog.COZY.length,122);
 assert.equal(catalog.Counts.nhwOutputNames,194);
 assert.equal(new Set(catalog.NHW.map(x=>x.id)).size,204);
 for (const row of catalog.NHW){
  const raw=item(row.id);
  assert.equal(observations.ParseRecords([raw],tick,4)[0].id,row.id);
  assert.equal(evaluate(row,raw).stop,false,row.id+' observed-only must not revoke');
  assert.equal(evaluate(row,{...raw,correlation:true,localOnly:false,families:3,confidence:90},policy.UnknownContext('A'),true).stop,false,row.id+' invented correlation cannot promote observed-only');
  assert.equal(evaluate(row,{...raw,signal:'DETECTED'},{...policy.UnknownContext('A'),capability:'UNKNOWN'}).stop,
   ['EXACT_INTEGRITY_MUTATION','CONFIRMED_STRUCTURAL_INVARIANT','SENSOR_VALIDATED_CORRELATION','CONFIRMED_KERNEL_EVIDENCE','CONFIRMED_KERNEL_CONDITION'].includes(row.contextPolicy),row.id+' typed class');
 }
 assert.equal(new Set(catalog.COZY.map(x=>x.id)).size,122);
});

test('legacy v3 access and token masks do not revoke without independent evidence',()=>{
 for(const [id,capability,accessMask,tokenDelta] of [
  ['dkProcess','PROCESS_ACCESS',0x20,0],['dkThread','THREAD_ACCESS',0x10,0],
  ['dkTokenRights','TOKEN_ACCESS',0x20,0],['dkTokenObject','TOKEN_STATE',0,2]]){
  const record=item(id,'DETECTED',{context:{...item(id).context,capability,accessMask,tokenDelta}});
  delete record.signal;
  assert.equal(observations.ParseRecords([record],tick,3)[0].id,id);
  assert.equal(evaluate(catalog.Get(id),record).stop,false,id+' legacy fallback');
 }
});

test('first-party self access is allowed but verified other-peer forbidden findings are actionable',()=>{
 const entry=catalog.Get('dkProcess');const record=item('dkProcess','DETECTED',{confidence:75,families:1});
 const permitted={...policy.UnknownContext('A'),capability:'PROCESS_ACCESS',capabilityDecision:'EXPECTED',sameSession:true,firstPartyAttested:true,serverBound:true,baseline:false,contextMixed:false};
 assert.equal(evaluate(entry,{...record,context:{...record.context,accessMask:0x20}},permitted).stop,false);
 const forbidden={...permitted,capabilityDecision:'FORBIDDEN'};
 assert.equal(evaluate(entry,record,forbidden).stop,true);
 assert.equal(evaluate(entry,{...record,signal:'OBSERVED'},forbidden).stop,false);
 assert.equal(evaluate(entry,{...record,context:{...record.context,baseline:true}},forbidden).stop,true);
 assert.equal(evaluate(entry,{...record,confidence:10},forbidden).stop,false);
});

test('token state delta requires a genuine detector signal and corroboration, not a single baseline report',()=>{
 const entry=catalog.Get('dkTokenRights');
 const context={...policy.UnknownContext('A'),capability:'TOKEN_STATE',tokenDelta:2};
 const single=item('dkTokenRights','DETECTED',{context:{...item('dkTokenRights').context,capability:'TOKEN_STATE',tokenDelta:2}});
 assert.equal(evaluate(entry,single,context).stop,false);
 assert.equal(evaluate(entry,{...single,signal:'OBSERVED'},context,true).stop,false);
 assert.equal(evaluate(entry,{...single,correlation:true,localOnly:false,families:3,confidence:90},context,true).stop,true);
});

test('coverage warnings and internal evidence remain nonterminal; actual high confidence integrity detections still terminate',()=>{
 for(const id of ['dkETWLoss','dkCoverageGap','dkObservationUncertain','dkSensorPressure','dkTraceGap','dkKernelTelemetryGap','dkAllocation','dkReadGap','dkMemoryRelease']){
  const e=catalog.Get(id);assert.equal(evaluate(e,item(id,'DETECTED',{correlation:true,localOnly:false,confidence:90,families:3}),policy.UnknownContext(),true).stop,false,id);
 }
 for(const id of ['dkPECodeIntegrity','dkImageCOWIntegrity','dkWriteIntegrity','dkVulnerableDriver','dkKernelMappingEvidence']){
  const e=catalog.Get(id);assert.equal(evaluate(e,item(id,'DETECTED')).stop,true,id);assert.equal(evaluate(e,item(id,'OBSERVED')).stop,false,id);
 }
});

test('new protocol validates explicit signal identity and rejects ambiguous extra fields',()=>{
 for(const bad of [null,'DETECT','UNKNOWN','DETECTED_OBSERVED',true,42]){
  assert.throws(()=>observations.ParseRecords([item('dkProcess','OBSERVED',{signal:bad})],tick,4));
 }
 assert.throws(()=>observations.ParseRecords([item('dkProcess','OBSERVED',{rawPid:321})],tick,4));
 assert.throws(()=>observations.ParseRecords([item('dkProcess','OBSERVED',{correlation:true,localOnly:false})],tick,4));
 assert.doesNotThrow(()=>observations.ParseRecords([item('dkPECodeIntegrity','DETECTED',{correlation:true,localOnly:false,families:3,confidence:90})],tick,4));
});

test('Delphi path supplies signal source independently of the detection kind', {skip:!fs.existsSync(path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas'))?'native source is delivered separately in full ZIP':false},()=>{
 const root=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW');
 const read=name=>fs.readFileSync(path.join(root,'Cozy.NHW.'+name+'.pas'),'utf8');
 assert.match(read('Engine'),/not \(Kind in Detected\)/);
 assert.match(read('DetectionJournal'),/ObservedOnly/);
 assert.match(read('ResponseTransport'),/TJSONNumber\.Create\(4\)/);
 assert.match(read('ResponseTransport'),/Detection\.AddPair\('signal'/);
 assert.match(read('ClientGuard'),/Correlated, ObservedOnly: Boolean/);
});
