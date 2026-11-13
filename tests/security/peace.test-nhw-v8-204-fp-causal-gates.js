'use strict';
// Synthetic policy proofs: not equivalent to running Delphi sensors on Win64.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const catalog=require('../../services/security/peace.security-detection-catalog');
const policy=require('../../services/security/peace.security-context-policy');
const TICK='0000000000004001';
const BEFORE='0000000000004000';
function report(id,options={}){
  const c=policy.UnknownContext('A');
  return {id,source:'Cozy.NHW.Engine',firstTick:BEFORE,lastTick:BEFORE,
    count:1,families:0,confidence:0,correlation:false,
    attestationSequence:'0000000000000000',localOnly:true,
    context:Object.fromEntries(policy.CONTEXT_FIELDS.map(k=>[k,c[k]])),
    signal:'DETECTED',...options};
}
function decide(id,stage,phase,options={},overrides={}){
  const context={...policy.UnknownContext(stage),phase,...overrides};
  return policy.Evaluate(catalog.Get(id),report(id,options),
    {tick:TICK,version:5,stage,context,corroborated:false});
}
test('A reissue: native post-filter ThreadSpawn is terminal; raw OBSERVED origin snapshot is not',()=>{
 const actual=decide('dkThreadSpawn','A','A_BOOTSTRAP',{families:2,confidence:10});
 assert.equal(actual.stop,true);
 assert.equal(actual.decisionReason,'V5_NATIVE_SENSOR_OUTPUT');
 assert.equal(decide('dkThreadSpawn','A','A_BOOTSTRAP',{signal:'OBSERVED',families:2,confidence:10}).stop,false);
});
test('B runtime: native post-filter PAGE_NOACCESS finding is terminal; raw state observation stays nonterminal',()=>{
 assert.equal(decide('dkNoAccess','B','B_ATTESTED',{families:32,confidence:30}).stop,true);
 assert.equal(decide('dkNoAccess','B','B_ATTESTED',{signal:'OBSERVED',families:32,confidence:30}).stop,false);
});
test('exhaustive 204-kind sensor taxonomy stays preserved, 191 active detection states stop for all A/B/O',()=>{
 assert.equal(catalog.NHW.length,204);
 assert.equal(catalog.NHW.filter(x=>x.standaloneOutput).length,197);
 assert.equal(new Set(catalog.NHW.filter(x=>x.standaloneOutput).map(x=>x.displayName)).size,194);
 const counters={};let terminal=0;
 for(const entry of catalog.NHW){
  const tier=policy.NativeEvidenceTier(entry);
  counters[tier]=(counters[tier]||0)+1;
  for(const stage of ['A','B','O']){
   const out=decide(entry.id,stage,stage+'_ATTESTED');
   const shouldStop=entry.standaloneOutput&&entry.signalClass!=='UNKNOWN';
   assert.equal(out.stop,shouldStop,stage+'/'+entry.id+'/'+tier);
   if(shouldStop){terminal++;assert.equal(out.decisionReason,'V5_NATIVE_SENSOR_OUTPUT');}
   assert.equal(decide(entry.id,stage,stage+'_ATTESTED',{signal:'OBSERVED'}).stop,false,stage+'/'+entry.id);
  }
 }
 assert.equal(terminal,573);
 assert.deepEqual(counters,{
  REQUIRE_INDEPENDENT_CORROBORATION:159,
  STABLE_INTEGRITY_INVARIANT:31,
  NATIVE_MULTI_SIGNAL_PROOF:1,
  INTERNAL_ONLY:7,
  COVERAGE_ONLY:6
 });
});
test('a claimed risk score, count or correlation does not terminate a raw OBSERVED output',()=>{
 for(const id of ['dkThreadSpawn','dkNoAccess','dkRemoteThread','dkTokenRights']){
  for(const change of [{confidence:99},{count:25},{families:3},
   {correlation:true,localOnly:false,confidence:99,families:3}]){
   const out=decide(id,'B','B_RUNTIME',{signal:'OBSERVED',...change});
   assert.equal(out.stop,false,id+' context-only observation');
  }
 }
});
test('server-bound first-party activity is trusted only with authoritative binding',()=>{
 const own={...policy.UnknownContext('B'),phase:'B_RUNTIME',actorClass:'SELF',
  actorRole:'B',capability:'THREAD_ACCESS',capabilityDecision:'EXPECTED',
  firstPartyAttested:true,serverBound:true,sameSession:true,contextMixed:false};
 assert.equal(decide('dkThread','B','B_RUNTIME',{},own).stop,false);
 assert.equal(decide('dkThread','B','B_RUNTIME',{}, {...own,serverBound:false}).stop,true);
 for(const id of ['dkWriteIntegrity','dkPECodeIntegrity','dkIAT','dkInjectionEvidence'])
  assert.equal(decide(id,'B','B_ATTESTED').stop,true,id+' security finding remains terminal');
});
test('the two native source and fixture gates exist without deleting either detector',t=>{
  const dir=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW');
  const fixtures=path.resolve(__dirname,'../../../Railway/Cozy.Tests/Cozy.NHW/Cozy.NHW.Fixtures');
  if(!fs.existsSync(path.join(dir,'Cozy.NHW.ThreadOrigin.pas'))){t.skip('native source shipped separately');return;}
  const thread=fs.readFileSync(path.join(dir,'Cozy.NHW.ThreadOrigin.pas'),'utf8');
  const memory=fs.readFileSync(path.join(dir,'Cozy.NHW.ProtectionGuard.pas'),'utf8');
  assert.match(thread,/function QualifiesThreadSpawn\(/);
  assert.match(thread,/FLastSuspiciousOriginTick := Tick/);
  assert.match(thread,/Include\(Detected, dkThreadSpawn\)/);
  assert.match(memory,/function IsSuspiciousNoAccessTransition\(/);
  assert.match(memory,/\(Before\.RegionType <> ALLOC_MEM_IMAGE\)/);
  assert.match(memory,/Include\(Detected, dkNoAccess\)/);
  assert.match(fs.readFileSync(path.join(fixtures,'Cozy.NHW.Native10M.ThreadOrigin.inc'),'utf8'),/ordinary A\/B\/O worker burst/);
  assert.match(fs.readFileSync(path.join(fixtures,'Cozy.NHW.Native5L.ProtectionGuard.inc'),'utf8'),/ordinary private PAGE_NOACCESS transition/);
});
