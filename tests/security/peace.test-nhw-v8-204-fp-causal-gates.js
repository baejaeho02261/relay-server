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
function decide(id,stage,phase,options={},overrides={},corroborated=false){
  const context={...policy.UnknownContext(stage),phase,...overrides};
  return policy.Evaluate(catalog.Get(id),report(id,options),
    {tick:TICK,version:5,stage,context,corroborated});
}
const independent={correlation:true,localOnly:false,confidence:75,families:3};

test('isolated A startup thread activity stays recorded until a supported finding',()=>{
 const weak={families:2,confidence:10};
 const actual=decide('dkThreadSpawn','A','A_BOOTSTRAP',weak);
 assert.equal(actual.stop,false);
 assert.equal(actual.disposition,'OBSERVATION_UNRESOLVED');
 assert.equal(decide('dkThreadSpawn','A','A_BOOTSTRAP',{...weak,signal:'OBSERVED'}).stop,false);
 assert.equal(decide('dkThreadSpawn','A','A_BOOTSTRAP',independent,{},true).stop,true);
});

test('isolated B memory protection and O scheduling reports cannot revoke a session',()=>{
 for(const [id,role,phase,families] of [
  ['dkNoAccess','B','B_ATTESTED',8],['dkAffinity','O','O_RUNTIME',2]]){
  const actual=decide(id,role,phase,{families,confidence:30});
  assert.equal(actual.stop,false,id);
  assert.equal(actual.disposition,'OBSERVATION_UNRESOLVED',id);
  assert.equal(decide(id,role,phase,independent,{},true).stop,true,id);
 }
});

test('a server-side corroboration flag requires signed acquisition data for a terminal decision',()=>{
 const role='B',phase='B_RUNTIME',id='dkThread';
 const rows=[
  [{confidence:100,count:65535,families:1},true],
  [{...independent,families:1},true],
  [{...independent,confidence:49},true],
  [independent,false]
 ];
 for(const [row,corroborated] of rows)
  assert.equal(decide(id,role,phase,row,{},corroborated).stop,false);
 assert.equal(decide(id,role,phase,independent,{},true).disposition,'CORROBORATED_ANOMALY');
});

test('all evidence tiers remain populated across the 204-kind sensor taxonomy',()=>{
 assert.equal(catalog.NHW.length,204);
 assert.equal(catalog.NHW.filter(x=>x.standaloneOutput).length,197);
 assert.equal(new Set(catalog.NHW.filter(x=>x.standaloneOutput).map(x=>x.displayName)).size,194);
 const counters={};
 for(const entry of catalog.NHW){
  const tier=policy.NativeEvidenceTier(entry);
  counters[tier]=(counters[tier]||0)+1;
  const observed=decide(entry.id,'A','A_ATTESTED',{signal:'OBSERVED'});
  assert.equal(observed.stop,false,entry.id);
 }
 assert.equal(counters.INTERNAL_ONLY,7);
 assert.equal(counters.COVERAGE_ONLY,6);
 assert.equal(counters.STABLE_INTEGRITY_INVARIANT,31);
 assert.equal(counters.NATIVE_MULTI_SIGNAL_PROOF,2);
 assert.equal(counters.REQUIRE_INDEPENDENT_CORROBORATION,158);
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
 const unbound={...own,serverBound:false};
 assert.equal(decide('dkThread','B','B_RUNTIME',{},unbound).disposition,'OBSERVATION_UNRESOLVED');
 assert.equal(decide('dkThread','B','B_RUNTIME',independent,unbound,true).stop,true);
 for(const id of ['dkWriteIntegrity','dkPECodeIntegrity','dkIAT','dkInjectionEvidence','dkRemoteThread'])
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
