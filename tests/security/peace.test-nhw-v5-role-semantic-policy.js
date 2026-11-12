'use strict';
// All 204 sensor kinds: static catalog/wire-semantic policy coverage, NOT
// proof of native Win64 sensor operation or automatic process termination.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const catalog = require('../../services/security/peace.security-detection-catalog');
const policy = require('../../services/security/peace.security-context-policy');
const tick = '0000000000030000';
const WEAK_MAX = 20;
const STRONG_NATIVE = new Set([
 'dkRemoteThread','dkPrivateThread','dkThreadRegion','dkInjectionEvidence',
 'dkRWX','dkExecuteProtect','dkProtectTransition','dkExecutableMapping',
 'dkReadAccess','dkCanaryAccess','dkWriteBurst','dkRepeatedWrite',
 'dkDacl','dkFileSecurity','dkRegistrySecurity','dkObjectSecurity',
 'dkNetworkIntegrity','dkNetworkFilter','dkWFPCallout','dkWFPProvider'
]);
const CONTEXT_SENSITIVE = new Set([
 'PROCESS_THREAD_CAPABILITY','TOKEN_TRANSITION_OR_CAPABILITY',
 'CONTEXT_AND_INDEPENDENT_CORROBORATION'
]);
const unverified = (role,phase,capability='UNKNOWN',mask=0)=>({
 ...policy.UnknownContext(role), actorClass:'EXTERNAL',actorRole:'?',
 actorIdentity:'',targetIdentity:'a'.repeat(64),targetRole:role,phase,
 capability,accessMask:mask,serverBound:false,firstPartyAttested:false,
 sameSession:false,contextMixed:false,capabilityDecision:'FORBIDDEN',
 baseline:false,coverage:'UNKNOWN'
});
function record(id, opts={}){
 const c=unverified('B','B_BOOTSTRAP');
 return {id,source:'Cozy.NHW.Engine',firstTick:'0000000000000001',
  lastTick:'0000000000030000',count:1,families:0,confidence:10,
  correlation:false,localOnly:true,attestationSequence:'0000000000000000',
  context:Object.fromEntries(policy.CONTEXT_FIELDS.map(k=>[k,c[k]])),
  signal:'DETECTED',...opts};
}
function evalRecord(id,stage,phase,context=unverified(stage,phase),recordOverride={}){
 return policy.Evaluate(catalog.Get(id),record(id,recordOverride),
  {tick,version:5,stage,context,corroborated:false});
}
const phases={B:['B_BOOTSTRAP','B_ATTESTED','B_RUNTIME','B_HANDOFF_TO_O','B_SHUTDOWN'],
 O:['O_BOOTSTRAP','O_ATTESTED','O_RUNTIME','O_SHUTDOWN']};
const examples={
 dkThreadCreation:{families:2},dkThreadExit:{families:2},
 dkThreadSpawn:{families:0},dkLifecycle:{families:2},
 dkAffinity:{families:8},dkMultiSignal:{families:0},
 dkTokenObject:{families:32,capability:'TOKEN_ACCESS',mask:0x000f01ff},
 dkTokenRights:{families:32,capability:'TOKEN_ACCESS',mask:0x000f01ff}
};

test('B and O normal startup/runtime threads, tokens and scheduling: low-assurance context alone never revokes',()=>{
 for(const [stage,ownPhases] of Object.entries(phases))for(const phase of ownPhases)
 for(const [id,opts] of Object.entries(examples)){
  const context=unverified(stage,phase,opts.capability||'UNKNOWN',opts.mask||0);
  const r=evalRecord(id,stage,phase,context,{families:opts.families});
  assert.equal(r.stop,false,`${stage} ${phase} ${id}`);
  assert.equal(r.disposition,'OBSERVATION_UNRESOLVED',`${stage} ${phase} ${id}`);
 }
});

test('unverified identity, confidence and one sensor root never manufacture proof; causal evidence remains terminal',()=>{
 for(const stage of ['B','O']){
  const phase=stage+'_RUNTIME',weak=unverified(stage,phase,'TOKEN_ACCESS',0xf01ff);
  for(const id of ['dkTokenObject','dkTokenRights','dkThreadSpawn','dkAffinity',
    'dkThreadCreation','dkThreadExit','dkMultiSignal']){
   assert.equal(evalRecord(id,stage,phase,{...weak,capability:id.startsWith('dkToken')?'TOKEN_ACCESS':'UNKNOWN',accessMask:id.startsWith('dkToken')?0xf01ff:0}).stop,false,id+' weak');
   const ctx={...weak,capability:'UNKNOWN',accessMask:0};
   assert.equal(evalRecord(id,stage,phase,{...ctx,actorIdentity:'b'.repeat(64)}).stop,false,id+' client actor identifier is not verified');
   assert.equal(evalRecord(id,stage,phase,ctx,{confidence:WEAK_MAX+1}).stop,false,id+' confidence alone is not causal proof');
   assert.equal(evalRecord(id,stage,phase,ctx,{families:3}).stop,false,id+' bitmask without correlation is not proof');
   assert.equal(policy.Evaluate(catalog.Get(id),record(id,{confidence:80,families:3,localOnly:false,correlation:true}),
     {tick,version:5,stage,context:ctx,corroborated:true}).stop,true,id+' corroborated');
   assert.equal(evalRecord(id,stage,phase,ctx,{signal:'OBSERVED'}).stop,false,id+' observation');
   assert.equal(policy.Evaluate(catalog.Get(id),record(id),{tick,version:4,stage,context:ctx}).stop,
     policy.Evaluate(catalog.Get(id),record(id),{tick,version:4,context:ctx}).stop,id+' legacy unchanged');
  }
  for(const id of ['dkInjectionEvidence','dkPECodeIntegrity','dkWriteIntegrity','dkIAT'])
   assert.equal(evalRecord(id,stage,phase,unverified(stage,phase)).stop,true,id+' internally verified invariant');
  for(const id of ['dkRemoteThread','dkPrivateThread','dkRWX','dkDacl'])
   assert.equal(evalRecord(id,stage,phase,unverified(stage,phase)).stop,false,id+' still needs causal proof');
 }
 // Client cannot choose a different role phase to gain a benign classification.
 assert.equal(evalRecord('dkThreadSpawn','B','O_BOOTSTRAP',unverified('B','O_BOOTSTRAP')).stop,false);
 assert.equal(evalRecord('dkThreadSpawn','O','B_BOOTSTRAP',unverified('O','B_BOOTSTRAP')).stop,false);
 assert.equal(evalRecord('dkThreadSpawn','A','A_BOOTSTRAP',unverified('A','A_BOOTSTRAP')).stop,false);
 assert.equal(evalRecord('dkThreadSpawn','B','B_BOOTSTRAP',{...unverified('B','B_BOOTSTRAP'),contextMixed:true}).stop,false);
});

test('194 output names, 197 independent output kinds, 204 complete typed kinds: exhaustive B/O risk adjudication',()=>{
 assert.equal(catalog.NHW.length,204);
 assert.equal(catalog.NHW.filter(e=>e.standaloneOutput).length,197);
 assert.equal(new Set(catalog.NHW.filter(e=>e.standaloneOutput).map(e=>e.displayName)).size,194);
 const seen=new Set();let weak=0,strong=0,internal=0;
 for(const entry of catalog.NHW){
  assert.ok(!seen.has(entry.id));seen.add(entry.id);
  const cls=policy.PolicyClass(entry);
  assert.equal(typeof cls,'string');
  for(const stage of ['B','O']){
   const phase=stage+'_RUNTIME',context=unverified(stage,phase);
   const weakVerdict=evalRecord(entry.id,stage,phase,context);
   const direct=policy.NativeEvidenceTier(entry)==='STABLE_INTEGRITY_INVARIANT'||
     policy.NativeEvidenceTier(entry)==='NATIVE_MULTI_SIGNAL_PROOF';
   const weakEligible=entry.standaloneOutput&&entry.signalClass!=='UNKNOWN'&&!direct;
   if(!entry.standaloneOutput||entry.signalClass==='UNKNOWN'){
    assert.equal(weakVerdict.stop,false,entry.id+' coverage/internal');internal++;
   }else if(weakEligible){
    assert.equal(weakVerdict.stop,false,entry.id+' single-root weak observation');weak++;
   }else{
    assert.equal(weakVerdict.stop,true,entry.id+' preserved high-risk detection');strong++;
   }
   const cited={...context,actorIdentity:'b'.repeat(64)};
   const proven=policy.Evaluate(entry,record(entry.id,{confidence:85,families:3,correlation:true,localOnly:false}),
     {tick,version:5,stage,context:cited,corroborated:true});
   assert.equal(proven.stop,entry.standaloneOutput&&entry.signalClass!=='UNKNOWN',entry.id+' proven evidence');
   const mere=policy.Evaluate(entry,record(entry.id,{signal:'OBSERVED'}),{tick,version:5,stage,context});
   assert.equal(mere.stop,false,entry.id+' observed only');
  }
 }
 assert.equal(seen.size,204);
 assert.ok(weak>140 && strong>=30 && internal>0,{weak,strong,internal});
});

test('authenticated reporting stage, not caller-claimed phase alone, selects B/O adjudication',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const source=fs.readFileSync(path.join(__dirname,'../../services/security/peace.security-detections.js'),'utf8');
 assert.match(source,/contextPolicy\.Evaluate\(Entry\(r\.id\),r,\{tick:value\.tick,context,corroborated,prior,version:value\.version,stage\}\)/);
 const g={...unverified('O','O_BOOTSTRAP'),actorClass:'EXTERNAL'};
 assert.equal(evalRecord('dkThreadSpawn','B','O_BOOTSTRAP',g).stop,false);
 assert.equal(evalRecord('dkThreadSpawn','O','O_BOOTSTRAP',g).stop,false);
});


test('single unverified B/O thread-handle snapshot at confidence 30 is evidence, not a verified thread modification',()=>{
 for(const stage of ['B','O'])for(const phase of [stage+'_BOOTSTRAP',stage+'_ATTESTED',stage+'_RUNTIME']){
  // Recorded B incident: THREAD_ALL_ACCESS is a held capability; the report
  // did not identify the actor or corroborate an actual SetThreadContext.
  const ctx={...unverified(stage,phase,'THREAD_ACCESS',0x001fffff),
   actorClass:'UNKNOWN',targetRole:'?',actorIdentity:'',actorRole:'?',
   peerId:'',grantId:'',firstPartyAttested:false,serverBound:false,sameSession:false};
  const event=record('dkThread',{families:1,confidence:30,localOnly:true,correlation:false});
  const result=policy.Evaluate(catalog.Get('dkThread'),event,
   {tick,version:5,stage,context:ctx,corroborated:false});
  assert.equal(result.stop,false,stage+' '+phase+' should not revoke');
  assert.equal(result.disposition,'OBSERVATION_UNRESOLVED');
  assert.equal(result.decisionReason,'V5_UNATTRIBUTED_HANDLE_SNAPSHOT');
  // Retain exact, well-scoped sensitivity. No role-wide exemption is allowed.
  for(const change of [
    {record:{confidence:31}},
    {record:{families:3}},
    {context:{actorIdentity:'b'.repeat(64)}},
    {context:{contextMixed:true}},
    {context:{serverBound:true}},
    {context:{firstPartyAttested:true}},
    {context:{phase:stage==='B'?'O_ATTESTED':'B_ATTESTED'}}
  ]){
   const changedRecord={...event,...change.record};
   const changedContext={...ctx,...change.context};
   const decision=policy.Evaluate(catalog.Get('dkThread'),changedRecord,
    {tick,version:5,stage,context:changedContext,corroborated:false});
   assert.equal(decision.stop,false,stage+' '+phase+' '+JSON.stringify(change));
  }
  const confirmed=policy.Evaluate(catalog.Get('dkThread'),
   {...event,confidence:85,families:3,correlation:true,localOnly:false},
   {tick,version:5,stage,context:ctx,corroborated:true});
  assert.equal(confirmed.stop,true,'corroborated independent evidence remains actionable');
  for(const id of ['dkInjectionEvidence','dkWriteIntegrity'])
   assert.equal(policy.Evaluate(catalog.Get(id),event,{tick,version:5,stage,context:ctx}).stop,true,id+' internal corroboration or integrity');
  for(const id of ['dkRemoteThread','dkPrivateThread'])
   assert.equal(policy.Evaluate(catalog.Get(id),event,{tick,version:5,stage,context:ctx}).stop,false,id+' needs independent corroboration');
  assert.equal(policy.Evaluate(catalog.Get('dkThread'),event,{tick,version:4,stage,context:ctx}).stop,
   policy.Evaluate(catalog.Get('dkThread'),event,{tick,version:4,context:ctx}).stop,'legacy unchanged');
 }
});

test('native dkThread reports a handle-rights snapshot, not proof of a context write',t=>{
 const fs=require('node:fs'),path=require('node:path');
 const file=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas');
 if(!fs.existsSync(file)){t.skip('Native Win64 sources are distributed in full ZIP, not relay-only Docker context');return;}
 const source=fs.readFileSync(file,'utf8');
 for(const contract of [
  'NHWNoteAccessContext(dkThread, H.PID, H.CreateTime, LivePID,',
  'if (not InBaseline) and (H.Level >= Threshold) then',
  'if H.IsThread then Include(Detected, dkThread)',
  'High-rights capability newly observed; not an actual memory write'
 ])assert.ok(source.includes(contract),contract);
});
