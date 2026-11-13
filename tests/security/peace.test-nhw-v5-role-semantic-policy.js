'use strict';
// Exhaustive server policy regression. Synthetic evidence is not a Win64 run.
// Check both an isolated sensor output and a qualifying security finding for
// each registered kind and authenticated role.
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
function evaluate(entry,role='B',signal='DETECTED',ctx=context(role),patch={},corroborated=false){
 return policy.Evaluate(entry,record(entry,signal,patch),{tick,version:5,stage:role,context:ctx,corroborated});
}
const actionable=e=>e.standaloneOutput&&e.signalClass!=='UNKNOWN';
const directTier=e=>['STABLE_INTEGRITY_INVARIANT','NATIVE_MULTI_SIGNAL_PROOF'].includes(policy.NativeEvidenceTier(e));
const independent={families:3,confidence:75,correlation:true,localOnly:false};

test('all 204 NHW states retain observation and qualifying decisions for each role',()=>{
 assert.equal(catalog.NHW.length,204);
 const outputs=catalog.NHW.filter(e=>e.standaloneOutput);
 assert.equal(outputs.length,197);
 assert.equal(new Set(outputs.map(e=>e.displayName)).size,194);
 assert.equal(outputs.filter(actionable).length,191);
 const ids=new Set();
 let qualifiedStops=0;
 for(const entry of catalog.NHW){
  assert.ok(!ids.has(entry.id));ids.add(entry.id);
  for(const role of ['A','B','O']){
   const ctx=context(role,role+'_ATTESTED');
   const name=role+' '+entry.id;
   const isolated=evaluate(entry,role,'DETECTED',ctx);
   assert.equal(isolated.stop,directTier(entry),name+' isolated output');
   if(directTier(entry)){
    assert.equal(isolated.disposition,'DETECTION',name);
    assert.equal(isolated.decisionReason,policy.NativeEvidenceTier(entry),name);
    assert.equal(isolated.sessionStopPolicy,'STOP_ON_TYPED_SECURITY_EVIDENCE',name);
   }else if(actionable(entry)){
    assert.equal(isolated.disposition,'OBSERVATION_UNRESOLVED',name);
   }else{
    assert.ok(['INTERNAL_EVIDENCE','COVERAGE_WARNING','COVERAGE_DEGRADED'].includes(isolated.disposition),name);
   }
   const supported=evaluate(entry,role,'DETECTED',ctx,independent,true);
   assert.equal(supported.stop,actionable(entry),name+' supported');
   if(supported.stop){
    qualifiedStops++;
    assert.equal(supported.disposition,directTier(entry)?'DETECTION':'CORROBORATED_ANOMALY',name);
   }
   assert.equal(evaluate(entry,role,'OBSERVED',ctx).stop,false,name+' context only');
   const stale={...independent,firstTick:'0000000000000001',lastTick:'0000000000000001'};
   assert.equal(evaluate(entry,role,'DETECTED',ctx,stale,true).stop,false,name+' stale');
  }
 }
 assert.equal(ids.size,204);
 assert.equal(qualifiedStops,573);
});

test('all phases retain weak activity and enforce verified integrity and compound findings',()=>{
 const phases={
  A:['A_BOOTSTRAP','A_ATTESTED','A_ISSUANCE','A_HANDOFF_TO_B','A_SHUTDOWN'],
  B:['B_BOOTSTRAP','B_ATTESTED','B_RUNTIME','B_HANDOFF_TO_O','B_SHUTDOWN'],
  O:['O_BOOTSTRAP','O_ATTESTED','O_RUNTIME','O_SHUTDOWN']
 };
 for(const [role,values] of Object.entries(phases))for(const phase of values){
  const ctx=context(role,phase);
  for(const id of ['dkThreadSpawn','dkTokenRights','dkAffinity','dkProcess','dkNoAccess']){
   const entry=catalog.Get(id);
   assert.equal(evaluate(entry,role,'DETECTED',ctx).stop,false,role+' '+phase+' '+id);
   assert.equal(evaluate(entry,role,'DETECTED',ctx,independent,true).stop,true,role+' '+phase+' '+id);
  }
  for(const id of ['dkPECodeIntegrity','dkWriteIntegrity','dkIAT','dkInjectionEvidence','dkRemoteThread'])
   assert.equal(evaluate(catalog.Get(id),role,'DETECTED',ctx).stop,true,role+' '+phase+' '+id);
 }
 for(const role of ['A','B','O'])for(const foreign of ['A_BOOTSTRAP','B_RUNTIME','O_RUNTIME']){
  const ctx=context(role,foreign);
  assert.equal(evaluate(catalog.Get('dkProcess'),role,'DETECTED',ctx,independent,true).stop,true);
 }
});

test('server-bound expected first-party capabilities preserve activity and qualified violations still stop',()=>{
 for(const role of ['A','B','O'])for(const [id,cap,mask] of [
  ['dkProcess','PROCESS_ACCESS',0x20],['dkThread','THREAD_ACCESS',0x10],
  ['dkTokenRights','TOKEN_ACCESS',0x20],['dkAffinity','THREAD_ACCESS',0]]){
  const entry=catalog.Get(id);
  const own=context(role,role+'_ATTESTED',{actorClass:'SELF',actorRole:role,
   capability:cap,accessMask:mask,capabilityDecision:'EXPECTED',
   firstPartyAttested:true,serverBound:true,sameSession:true,contextMixed:false});
  const allowed=evaluate(entry,role,'DETECTED',own);
  assert.equal(allowed.stop,false,role+' '+id);
  assert.equal(allowed.disposition,'EXPECTED_FIRST_PARTY',role+' '+id);
  const forbidden={...own,capabilityDecision:'FORBIDDEN'};
  const violation=evaluate(entry,role,'DETECTED',forbidden,{confidence:30});
  assert.equal(violation.stop,true,role+' '+id);
  assert.equal(violation.decisionReason,'FIRST_PARTY_CAPABILITY_MATRIX_VIOLATION',role+' '+id);
  assert.equal(evaluate(entry,role,'OBSERVED',forbidden,{confidence:30}).stop,false);
  for(const broken of [{serverBound:false},{firstPartyAttested:false},{sameSession:false},{contextMixed:true}]){
   const weak=evaluate(entry,role,'DETECTED',{...own,...broken});
   assert.equal(weak.disposition,'OBSERVATION_UNRESOLVED',role+' '+id);
   assert.equal(evaluate(entry,role,'DETECTED',{...own,...broken},independent,true).stop,true,
    role+' '+id+' independently supported');
  }
 }
});

test('initial token state is observed; later and unattributed changes need independent support',()=>{
 for(const role of ['A','B','O'])for(const id of ['dkTokenObject','dkTokenRights','dkTokenChange','dkThreadToken']){
  const entry=catalog.Get(id);
  const own=context(role,role+'_BOOTSTRAP',{actorClass:'SELF',actorRole:role,
   capability:'TOKEN_STATE',tokenDelta:2,baseline:true,
   firstPartyAttested:true,serverBound:true,sameSession:true,
   contextMixed:false});
  const initial=evaluate(entry,role,'DETECTED',own);
  assert.equal(initial.stop,false);
  assert.equal(initial.decisionReason,'SERVER_BOUND_STARTUP_TOKEN_OBSERVATION');
  for(const change of [{baseline:false},{serverBound:false},{actorClass:'UNKNOWN'}]){
   const ctx={...own,...change};
   assert.equal(evaluate(entry,role,'DETECTED',ctx).stop,false,role+' '+id);
   assert.equal(evaluate(entry,role,'DETECTED',ctx,independent,true).stop,true,role+' '+id);
  }
 }
});

test('legacy V4 keeps existing direct evidence decisions and v5 observations stay nonterminal',()=>{
 for(const id of ['dkProcess','dkThread','dkTokenRights','dkNoAccess','dkAffinity','dkPECodeIntegrity']){
  const entry=catalog.Get(id),r=record(entry),ctx=context('B');
  const old=policy.Evaluate(entry,r,{tick,version:4,stage:'B',context:ctx});
  assert.equal(old.stop,id==='dkPECodeIntegrity',id+' legacy V4');
  assert.equal(evaluate(entry,'B','DETECTED',ctx).stop,id==='dkPECodeIntegrity',id+' isolated V5');
  assert.equal(evaluate(entry,'B','OBSERVED',ctx).stop,false,id+' V5 observation');
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

test('server StopDecision ignores isolated affinity output and accepts qualified V5 evidence',()=>{
 const ctx=context('B');
 const wire=(id,patch={})=>({version:5,sequence:'0000000000000001',tick,
  confirmed:false,trust:0,detections:[{
   ...record(catalog.Get(id),'DETECTED',patch),
   context:Object.fromEntries(policy.CONTEXT_FIELDS.map(k=>[k,ctx[k]]))
  }],peer:null});
 assert.equal(reports.StopDecision('B','integrity',wire('dkAffinity')),null);
 for(const [id,patch] of [['dkAffinity',independent],['dkPECodeIntegrity',{}],['dkInjectionEvidence',{}]]){
  const out=reports.StopDecision('B','integrity',wire(id,patch));
  assert.ok(out&&out.reason.startsWith('NHW_DETECTED:B:integrity:'),id);
  assert.ok(out.keys.some(k=>k.startsWith(id+':Cozy.NHW.Engine')),id);
 }
});

test('kernel-only reports require qualified corroboration across kernel evidence classes',()=>{
 const kernelFinding=id=>record(catalog.Get(id),'DETECTED',{
  families:128,confidence:75,correlation:true,localOnly:false
 });
 const wire=detections=>({version:5,sequence:'0000000000000001',tick,
  confirmed:false,trust:0,detections,peer:null});
 const downgrade=kernelFinding('dkKernelTrustDowngrade');
 const crossView=kernelFinding('dkDriverCrossView');
 assert.equal(reports.StopDecision('B','driver',wire([downgrade])),null);
 assert.equal(reports.StopDecision('B','driver',wire([downgrade,{
  ...crossView,signal:'OBSERVED',correlation:false,localOnly:true
 }])),null);
 const decision=reports.StopDecision('B','driver',wire([downgrade,crossView]));
 assert.ok(decision?.keys.some(key=>key.startsWith('dkKernelTrustDowngrade:')));
 assert.ok(decision?.keys.some(key=>key.startsWith('dkDriverCrossView:')));
});


test('kernel aggregate bit alone cannot corroborate a non-kernel finding',()=>{
 const entry=catalog.Get('dkThread');
 const kernelBit={...independent,families:128};
 assert.equal(evaluate(entry,'B','DETECTED',context('B'),kernelBit,true).stop,false);
 assert.equal(evaluate(entry,'B','DETECTED',context('B'),independent,true).stop,true);
});

test('native reports require current per-kind roots and preserve kernel observation provenance',t=>{
 const native=path.resolve(__dirname,'../../../Railway/Cozy.Source/Cozy.Security.NHW');
 const enginePath=path.join(native,'Cozy.NHW.Engine.pas');
 if(!fs.existsSync(enginePath)){t.skip('native source ships in the full archive');return;}
 const read=name=>fs.readFileSync(path.join(native,'Cozy.NHW.'+name+'.pas'),'utf8');
 const engine=read('Engine');
 const cycle=engine.split('procedure RecordCycleEvidence;')[1].split('procedure FinalizeSamplingAndReport;')[0];
 assert.match(cycle,/FrameCurrent := Unified\.Recent\(0, Frame\) and \(Frame\.Tick = TickStart\);/);
 assert.match(cycle,/if FrameCurrent and \(Kind in VisibleDetected\) then[\s\S]*?if Kind in Frame\.RootKinds\[Root\] then\s*begin[\s\S]*?Inc\(KindRoots\)/);
 assert.match(cycle,/KindCorrelated := \(KindRoots >= 2\) and not Frame\.Incomplete and/);
 assert.doesNotMatch(cycle,/if Root in Frame\.Roots then/);
 const client=read('ClientGuard'),guard=read('Guard');
 for(const [channel,args] of [
  ['Trust',''],['Driver',''],['Integrity','ndoKernelTrust,\\s*\\$80,\\s*']
 ]){
  const observe=new RegExp('Record'+channel+'Detections\\(State\\.ObservationKinds,\\s*(Event\\.)?Tick,\\s*'+args+'0,\\s*False,\\s*True\\)','g');
  assert.equal((client.match(observe)||[]).length,2,channel+' raw observation only');
  const qualified=new RegExp('Record'+channel+'Detections\\(Eligible,\\s*Event\\.Tick,\\s*'+args+'75,\\s*True(?:,\\s*False)?\\)');
  assert.match(client,qualified,channel+' qualified output retained');
  const sink=guard.split('procedure TCozyNHWGuard.Record'+channel+'Detections(')[1].split(/\r?\nend;/)[0];
  assert.match(sink,/AppendContext\([\s\S]*?ObservedOnly\);/);
 }
});
