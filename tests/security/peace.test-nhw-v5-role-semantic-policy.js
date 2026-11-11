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

test('suppress only weak uncertainty; stronger evidence, identity and real code violations remain terminal',()=>{
 for(const stage of ['B','O']){
  const phase=stage+'_RUNTIME',weak=unverified(stage,phase,'TOKEN_ACCESS',0xf01ff);
  for(const id of ['dkTokenObject','dkTokenRights','dkThreadSpawn','dkAffinity',
    'dkThreadCreation','dkThreadExit','dkMultiSignal']){
   assert.equal(evalRecord(id,stage,phase,{...weak,capability:id.startsWith('dkToken')?'TOKEN_ACCESS':'UNKNOWN',accessMask:id.startsWith('dkToken')?0xf01ff:0}).stop,false,id+' weak');
   const ctx={...weak,capability:'UNKNOWN',accessMask:0};
   assert.equal(evalRecord(id,stage,phase,{...ctx,actorIdentity:'b'.repeat(64)}).stop,true,id+' attributed actor');
   assert.equal(evalRecord(id,stage,phase,ctx,{confidence:WEAK_MAX+1}).stop,true,id+' stronger confidence');
   assert.equal(evalRecord(id,stage,phase,ctx,{families:3}).stop,true,id+' independent roots');
   assert.equal(policy.Evaluate(catalog.Get(id),record(id,{confidence:80,families:3,localOnly:false,correlation:true}),
     {tick,version:5,stage,context:ctx,corroborated:true}).stop,true,id+' corroborated');
   assert.equal(evalRecord(id,stage,phase,ctx,{signal:'OBSERVED'}).stop,false,id+' observation');
   assert.equal(policy.Evaluate(catalog.Get(id),record(id),{tick,version:4,stage,context:ctx}).stop,
     policy.Evaluate(catalog.Get(id),record(id),{tick,version:4,context:ctx}).stop,id+' legacy unchanged');
  }
  for(const id of ['dkInjectionEvidence','dkPECodeIntegrity','dkWriteIntegrity',
   'dkRemoteThread','dkPrivateThread','dkRWX','dkDacl','dkIAT'])
   assert.equal(evalRecord(id,stage,phase,unverified(stage,phase)).stop,true,id+' direct security evidence');
 }
 // Client cannot choose a different role phase to gain a benign classification.
 assert.equal(evalRecord('dkThreadSpawn','B','O_BOOTSTRAP',unverified('B','O_BOOTSTRAP')).stop,true);
 assert.equal(evalRecord('dkThreadSpawn','O','B_BOOTSTRAP',unverified('O','B_BOOTSTRAP')).stop,true);
 assert.equal(evalRecord('dkThreadSpawn','A','A_BOOTSTRAP',unverified('A','A_BOOTSTRAP')).stop,true);
 assert.equal(evalRecord('dkThreadSpawn','B','B_BOOTSTRAP',{...unverified('B','B_BOOTSTRAP'),contextMixed:true}).stop,true);
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
   const weakEligible=entry.standaloneOutput&&entry.signalClass!=='UNKNOWN'&&
     CONTEXT_SENSITIVE.has(cls)&&!STRONG_NATIVE.has(entry.id);
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
 assert.ok(weak>100 && strong>35 && internal>0,{weak,strong,internal});
});

test('authenticated reporting stage, not caller-claimed phase alone, selects B/O adjudication',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const source=fs.readFileSync(path.join(__dirname,'../../services/security/peace.security-detections.js'),'utf8');
 assert.match(source,/contextPolicy\.Evaluate\(Entry\(r\.id\),r,\{tick:value\.tick,context,corroborated,prior,version:value\.version,stage\}\)/);
 const g={...unverified('O','O_BOOTSTRAP'),actorClass:'EXTERNAL'};
 assert.equal(evalRecord('dkThreadSpawn','B','O_BOOTSTRAP',g).stop,true);
 assert.equal(evalRecord('dkThreadSpawn','O','O_BOOTSTRAP',g).stop,false);
});
