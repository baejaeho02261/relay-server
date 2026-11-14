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
test('A reissue/restart: an unbound one-off ThreadSpawn snapshot is not proof of external thread injection',()=>{
  const out=decide('dkThreadSpawn','A','A_BOOTSTRAP',{families:2,confidence:10});
  assert.equal(out.stop,false);
  assert.equal(out.disposition,'OBSERVATION_UNRESOLVED');
  assert.equal(out.decisionReason,'THREAD_BURST_ORIGIN_NOT_VERIFIED');
  assert.equal(out.sessionStopPolicy,'REQUIRE_CAUSAL_OR_INDEPENDENT_EVIDENCE');
});
test('B normal runtime: PAGE_NOACCESS by itself is not proof of hostile protection change',()=>{
  const out=decide('dkNoAccess','B','B_ATTESTED',{families:32,confidence:30});
  assert.equal(out.stop,false);
  assert.equal(out.disposition,'OBSERVATION_UNRESOLVED');
  assert.equal(out.decisionReason,'MEMORY_PROTECTION_CAUSE_UNVERIFIED');
});
test('all 204 NHW classifications preserve every entry and restrict isolated unattributed output',()=>{
  assert.equal(catalog.NHW.length,204);
  assert.equal(catalog.NHW.filter(x=>x.standaloneOutput).length,197);
  const counters={};
  for(const entry of catalog.NHW){
    const tier=policy.NativeEvidenceTier(entry);
    counters[tier]=(counters[tier]||0)+1;
    for(const stage of ['A','B','O']){
      const out=decide(entry.id,stage,stage+'_ATTESTED');
      const terminal=['STABLE_INTEGRITY_INVARIANT','NATIVE_MULTI_SIGNAL_PROOF'].includes(tier);
      assert.equal(out.stop,terminal,stage+'/'+entry.id+'/'+tier);
      if(!terminal)assert.notEqual(out.disposition,'DETECTION',stage+'/'+entry.id);
    }
  }
  assert.deepEqual(counters,{
    REQUIRE_INDEPENDENT_CORROBORATION:159,
    STABLE_INTEGRITY_INVARIANT:31,
    NATIVE_MULTI_SIGNAL_PROOF:1,
    INTERNAL_ONLY:7,
    COVERAGE_ONLY:6
  });
});
test('isolated risk-score, context claims, spoofed correlation and repeated low-confidence records cannot revoke',()=>{
  for(const id of ['dkThreadSpawn','dkNoAccess','dkRemoteThread','dkTokenRights']){
    const stage=id==='dkNoAccess'?'B':'A',phase=stage+'_RUNTIME';
    for(const change of [
      {confidence:99},
      {count:25},
      {families:3},
      {correlation:true,localOnly:false,confidence:99,families:3},
    ]){
      const result=decide(id,stage,phase,change);
      assert.equal(result.stop,false,id+' without server-approved corroboration');
    }
    const forged=policy.Evaluate(catalog.Get(id),report(id,{count:2,confidence:99,families:3}),{
      tick:TICK,version:5,stage,corroborated:true,context:policy.UnknownContext(stage)});
    assert.equal(forged.stop,false,id+' boolean approval cannot bypass evidence-shape checks');
  }
});
test('confirmed independent roots, verified forbidden capabilities and native invariant cases still fail closed',()=>{
  const e=catalog.Get('dkThreadSpawn'),r=report(e.id,{correlation:true,localOnly:false,confidence:80,families:3});
  assert.equal(policy.Evaluate(e,r,{tick:TICK,version:5,stage:'A',corroborated:true}).stop,true);
  assert.equal(policy.Evaluate(e,r,{tick:TICK,version:5,stage:'A',corroborated:false}).stop,false);
  const forbidden={...policy.UnknownContext('B'),phase:'B_RUNTIME',
    actorClass:'EXTERNAL',capability:'THREAD_ACCESS',capabilityDecision:'FORBIDDEN',
    firstPartyAttested:true,serverBound:true,sameSession:true,baseline:false};
  assert.equal(policy.Evaluate(catalog.Get('dkThread'),report('dkThread',{families:1,confidence:50}),
    {tick:TICK,version:5,stage:'B',context:forbidden}).stop,true);
  for(const id of ['dkWriteIntegrity','dkPECodeIntegrity','dkIAT','dkInjectionEvidence']){
    const out=decide(id,'B','B_ATTESTED');
    assert.equal(out.stop,true,id+' verified native security invariant remains actionable');
  }
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
