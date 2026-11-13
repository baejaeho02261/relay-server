'use strict';
// Executes real RSA/session/nonce handlers with synthetic sensor observations.
// No Windows sensor, PID identity, GPU or hardware attestation is simulated as fact.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-nhw-context-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../../core/peace.utilities').EnsureDirs();
const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),boot=require('../../services/bootstrap/peace.desktop-bootstrap'),authority=require('../../services/security/peace.desktop-security-authority'),paths=require('../../services/security/peace.nhw-response-paths'),reports=require('../../services/security/peace.security-detections'),catalog=require('../../services/security/peace.security-detection-catalog'),policy=require('../../services/security/peace.security-context-policy'),peers=require('../../services/security/peace.nhw-peer-context'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store'),schema=require('../../services/protocol/peace.packet-schema');
const hash=x=>crypto.createHash('sha512').update(x).digest('hex'),hex=n=>BigInt(n).toString(16).padStart(16,'0');
let checks=0;const check=(name,fn)=>{fn();checks++;console.log('PASS '+name);},reject=(fn,code)=>assert.throws(fn,e=>!code||e.message===code);
process.once('exit',()=>{boot.Stop();fs.rmSync(temp,{recursive:true,force:true});});
function row(s){return store.Load().flows[s.start.begin.flowId];}
function subject(){const device=fixture.Device(),start=fixture.Begin(device),s={device,start,ctx:{stage:'A',sessionId:start.begin.flowId,sessionToken:start.begin.downloadTicket,machineId:device.machineId}},db=store.Load(),r=row(s);s.peer={pid:100+checks,creationTime:hex(100000+checks),imageSha256:db.launchers[r.launcherId].peerImageSha256,imageSha512:r.launcherSha512,parentIdentity:'',phase:'A_BOOTSTRAP'};assert.equal(s.peer.imageSha256.length,64);return s;}
function context(patch={}){const c=policy.UnknownContext('A');return {...Object.fromEntries(policy.CONTEXT_FIELDS.map(k=>[k,c[k]])),...patch};}
function self(s,patch={}){const identity=peers.StableIdentity(s.peer);return context({actorClass:'SELF',actorRole:'A',actorIdentity:identity,targetRole:'A',targetIdentity:identity,phase:s.peer.phase,...patch});}
function record(id='dkTokenObject',patch={}){return {id,source:'Cozy.NHW.Engine',firstTick:hex(1000),lastTick:hex(1000),count:1,families:32,confidence:30,correlation:false,attestationSequence:hex(0),localOnly:true,context:context(),...patch};}
function text(records,seq=1,peer=null,tick=2000,trust=2){return JSON.stringify({version:3,sequence:hex(seq),tick:hex(tick),digest:hash(JSON.stringify(records)).slice(0,16),confirmed:false,trust,detections:records,peer});}
function request(s,channel,value){const cap=channel[0].toUpperCase()+channel.slice(1),body={...s.ctx,binding:hash(value),action:'nhw'+cap+'Challenge'},c=authority.Execute(body),submit={...body,action:'nhw'+cap+'Submit',challengeId:c.challengeId,payload:value};submit.signature=fixture.Sign(s.device,paths.Canonical(submit,c,channel));schema.ValidateEnvelope({operation:'security',body:submit});return submit;}
function send(s,channel,records,seq=1,peer=s.peer,tick=2000+seq,trust=2){return authority.Execute(request(s,channel,text(records,seq,peer,tick,trust)));}
fixture.CurrentCohort({version:'92.0.0'});
check('All 204 NHW kinds and 122 Cozy outcomes retain explicit taxonomy and actionable policy classes',()=>{
 assert.equal(catalog.NHW.length,204);assert.equal(catalog.COZY.length,122);assert.equal(catalog.Counts.nhwOutputNames,194);
 for(const e of catalog.NHW){assert.ok(e.contextPolicy,e.id);const r=record(e.id);assert.equal(reports.ParseRecords([r],hex(2000),3)[0].id,e.id);const typed=policy.Evaluate(e,r,{tick:hex(2000)});assert.ok(policy.DISPOSITIONS.includes(typed.disposition),e.id);
  if(e.category!=='KERNEL_TRUST'){
   const corroborated=policy.Evaluate(e,{...r,correlation:true,localOnly:false,confidence:75,families:3},{tick:hex(2000),corroborated:true});
   assert.equal(corroborated.stop,e.standaloneOutput&&e.signalClass!=='UNKNOWN',e.id);
  }
  assert.equal(policy.Evaluate(e,r,{tick:hex(100000),corroborated:true}).stop,false,e.id+' stale');
 }
 for(const e of catalog.COZY){assert.equal(e.sessionStopPolicy,'SERVER_DECISION');assert.ok(e.sourceUnits.length);}
});
check('Legacy token startup and all six coverage warnings stay observable without a revoke',()=>{
 const s=subject(),records=['dkTokenObject','dkTokenRights','dkAllocation','dkMemoryRelease','dkReadGap','dkETWLoss','dkCoverageGap','dkObservationUncertain','dkSensorPressure','dkTraceGap','dkKernelTelemetryGap'].map(id=>record(id,{count:4,context:context()}));
 assert.equal(send(s,'integrity',records).stopped,false);assert.equal(row(s).status,'STARTED');
 const events=reports.ForFlow(row(s).id);assert.equal(events.length,11);assert.ok(events.every(e=>!e.invalidated));
 for(const e of events)if(e.detectionId.startsWith('dkToken')){assert.equal(e.disposition,'OBSERVATION_UNRESOLVED');assert.equal(e.context.firstPartyAttested,false);}
 assert.equal(events.filter(e=>e.disposition==='COVERAGE_WARNING').length,6);
});
check('Signed approved self baseline is expected while unproven client SELF/TRUSTED claims are not grants',()=>{
 const s=subject(),r=record('dkTokenObject',{context:self(s,{capability:'TOKEN_STATE',baseline:true})});
 const reply=send(s,'integrity',[r]);assert.equal(reply.stopped,false);assert.ok(reply.peerContext);assert.equal(reply.peerContext.scope,'SERVER_BOUND_CLIENT_OBSERVATION');
 const e=reports.ForFlow(row(s).id)[0];assert.equal(e.disposition,'EXPECTED_FIRST_PARTY');assert.equal(e.context.sameSession,true);assert.equal(e.context.firstPartyAttested,true);assert.equal(e.attestation.hardwareAttested,false);
 const foreign=subject(),fake=record('dkTokenObject',{context:self(s,{capability:'TOKEN_STATE',baseline:true,actorClass:'TRUSTED_A'})});
 assert.equal(send(foreign,'integrity',[fake]).stopped,false);const f=reports.ForFlow(row(foreign).id)[0];assert.notEqual(f.disposition,'EXPECTED_FIRST_PARTY');assert.equal(f.context.firstPartyAttested,false);assert.equal(f.context.sameSession,false);
});
check('Signed exact self access is expected in each object class and on each channel',()=>{
 for(const [channel,id,capability,accessMask] of [['trust','dkProcess','PROCESS_ACCESS',0x20],['driver','dkThread','THREAD_ACCESS',0x10],['integrity','dkTokenRights','TOKEN_ACCESS',0x20]]){
  const s=subject();
  assert.equal(send(s,channel,[record(id,{context:self(s,{capability,accessMask})})]).stopped,false);
  assert.equal(row(s).status,'STARTED');
  const e=reports.ForFlow(row(s).id)[0];
  assert.equal(e.disposition,'EXPECTED_FIRST_PARTY');
  assert.equal(e.context.firstPartyAttested,true);
  assert.equal(e.invalidated,false);
 }
});
check('Uncertain access reports stay visible, while an identified risky external holder can stop its exact session',()=>{
 for(const patch of [
  {actorClass:'UNKNOWN',actorIdentity:''},
  {actorClass:'EXTERNAL',actorIdentity:''},
  {actorClass:'SELF'},
  {contextMixed:true},
  {baseline:true}
 ]){
  const s=subject(),c=context({actorClass:'EXTERNAL',actorIdentity:'e'.repeat(64),
   capability:'PROCESS_ACCESS',accessMask:0x20,...patch});
  assert.equal(send(s,'integrity',[record('dkProcess',{context:c})]).stopped,false);
  assert.equal(row(s).status,'STARTED');
  assert.equal(reports.ForFlow(row(s).id)[0].invalidated,false);
 }
 const s=subject(),other=subject();
 const c=context({actorClass:'EXTERNAL',actorIdentity:'e'.repeat(64),capability:'PROCESS_ACCESS',accessMask:0x20});
 assert.equal(send(s,'integrity',[record('dkProcess',{context:c})]).stopped,true);
 assert.equal(row(s).status,'REVOKED');assert.equal(row(other).status,'STARTED');
 assert.equal(reports.ForFlow(row(s).id)[0].invalidated,true);
});
check('Only isolated integrity elevation and restriction removal are terminal token posture changes',()=>{
 const token=(delta,patch={})=>record('dkTokenChange',{context:context({capability:'TOKEN_STATE',tokenDelta:delta,...patch})});
 for(const delta of [4,32,64]){
  const s=subject();assert.equal(send(s,'integrity',[token(delta)]).stopped,true);
  assert.equal(reports.ForFlow(row(s).id)[0].decisionReason,'TOKEN_SECURITY_TRANSITION');
 }
 for(const delta of [1,2,8,16,128,256]){
  const s=subject();assert.equal(send(s,'integrity',[token(delta)]).stopped,false);
  assert.equal(row(s).status,'STARTED');
 }
 for(const patch of [{baseline:true},{contextMixed:true}]){
  const s=subject();assert.equal(send(s,'integrity',[token(4,patch)]).stopped,false);
  assert.equal(row(s).status,'STARTED');
 }
 const s=subject(),r={...token(128),families:3,confidence:75,correlation:true,localOnly:false};
 assert.equal(send(s,'integrity',[r]).stopped,true);
 assert.equal(reports.ForFlow(row(s).id)[0].disposition,'CORROBORATED_ANOMALY');
});
check('A baseline claim and self context cannot suppress actual typed code findings',()=>{
 for(const id of ['dkPECodeIntegrity','dkHeapIntegrity','dkIAT']){
  const s=subject();assert.equal(send(s,'integrity',[record(id,{context:self(s,{capability:'SELF_MEMORY',baseline:true})})]).stopped,true,id);
  assert.notEqual(reports.ForFlow(row(s).id)[0].disposition,'EXPECTED_FIRST_PARTY');
 }
});
check('Raw kernel observations stay visible and require the existing qualified kernel quorum for invalidation',()=>{
 const s=subject(),other=subject();
 const raw=id=>record(id,{source:'Cozy.NHW.KernelTrust',families:128,confidence:0});
 const qualified=id=>record(id,{source:'Cozy.NHW.KernelTrust',families:128,confidence:75,correlation:true,localOnly:false});
 const ids=['dkBootTrust','dkVBSHVCI','dkVulnerableDriver','dkDriverCrossView','dkKernelMappingEvidence','dkDriverSignerAttestation','dkSessionTrustUntrusted'];
 assert.equal(send(s,'integrity',ids.map(raw),1,s.peer,2001,3).stopped,false);
 assert.equal(row(s).status,'STARTED');
 assert.equal(reports.ForFlow(row(s).id).length,ids.length);
 assert.equal(send(s,'driver',[qualified('dkKernelTrustDowngrade'),raw('dkBootTrust')],1,s.peer,2001,3).stopped,false);
 assert.equal(row(s).status,'STARTED');
 const supported=[qualified('dkKernelTrustDowngrade'),qualified('dkBootTrust'),raw('dkDriverCrossView')];
 assert.equal(send(s,'trust',supported,1,s.peer,2001,3).stopped,true);
 assert.equal(row(s).status,'REVOKED');assert.equal(row(other).status,'STARTED');
 const events=reports.ForFlow(row(s).id);
 for(const id of ['dkKernelTrustDowngrade','dkBootTrust'])assert.equal(events.find(e=>e.responsePath==='trust'&&e.detectionId===id).invalidated,true,id);
 for(const e of events.filter(e=>e.detectionId==='dkDriverCrossView'))assert.equal(e.invalidated,false);
});
check('Coverage episodes require fresh newer observations and server elapsed time, never count alone',()=>{
 const entry=catalog.Get('dkETWLoss'),r=record('dkETWLoss'),at=100000;
 const first=policy.Evaluate(entry,r,{tick:hex(2000),now:at});assert.equal(first.disposition,'COVERAGE_WARNING');
 let prior={lastTick:r.lastTick,coverageEpisode:first.coverageEpisode};
 const second=policy.Evaluate(entry,{...r,count:65535,lastTick:hex(1100)},{tick:hex(2000),now:at+15000,prior});assert.equal(second.disposition,'COVERAGE_WARNING');
 prior={lastTick:hex(1100),coverageEpisode:second.coverageEpisode};
 const third=policy.Evaluate(entry,{...r,count:65535,lastTick:hex(1200)},{tick:hex(2000),now:at+30000,prior});assert.equal(third.disposition,'COVERAGE_DEGRADED');assert.equal(third.stop,false);
 const reset=policy.Evaluate(entry,{...r,lastTick:hex(1300)},{tick:hex(2000),now:at+100000,prior:{lastTick:hex(1200),coverageEpisode:third.coverageEpisode}});assert.equal(reset.disposition,'COVERAGE_WARNING');
 const s=subject();send(s,'integrity',[r]);assert.equal(send(s,'integrity',[record('dkProcess',{context:context({actorClass:'EXTERNAL',actorIdentity:'e'.repeat(64),capability:'PROCESS_ACCESS',accessMask:0x20})})],2).stopped,true);const old=reports.ForFlow(row(s).id).find(e=>e.detectionId==='dkETWLoss');assert.equal(old.invalidated,false);
});
check('Context identity isolates counters and preserves the actual causative context after termination',()=>{
 const s=subject(),good=record('dkProcess',{context:self(s,{capability:'PROCESS_ACCESS',accessMask:0x1000})});
 send(s,'integrity',[good]);
 const external=record('dkProcess',{context:context({actorClass:'EXTERNAL',actorIdentity:'e'.repeat(64),capability:'PROCESS_ACCESS',accessMask:0x20})});
 assert.equal(send(s,'integrity',[external],2).stopped,true);
 let events=reports.ForFlow(row(s).id);assert.equal(events.length,2);assert.equal(events.filter(e=>e.invalidated).length,1);assert.equal(events.find(e=>e.invalidated).context.actorIdentity,'e'.repeat(64));
 send(s,'integrity',[{...external,count:2,lastTick:hex(1300),context:{...external.context,accessMask:0x1000}}],3);
 events=reports.ForFlow(row(s).id);assert.equal(events.find(e=>e.invalidated).context.accessMask,0x20);assert.equal(events.find(e=>!e.invalidated).disposition,'EXPECTED_FIRST_PARTY');reports.Validate(store.Load().securityDetections,store.Load());
});
check('V3 exact-batch recovery neither recounts observations nor renews peer enrollment; tampering fails',()=>{
 const s=subject(),records=[record('dkTokenObject',{context:self(s,{capability:'TOKEN_STATE',baseline:true})})],value=text(records,1,s.peer),req=request(s,'integrity',value),ack=authority.Execute(req),before=structuredClone(row(s).nhwPeerBindings.A),events=reports.ForFlow(row(s).id);
 assert.deepEqual(authority.Execute(req),ack);paths.Clear();assert.equal(authority.Execute(request(s,'integrity',text(records,1,s.peer,3000))).stopped,false);assert.deepEqual(row(s).nhwPeerBindings.A,before);assert.deepEqual(reports.ForFlow(row(s).id),events);
 reject(()=>authority.Execute(request(s,'integrity',text(records,1,{...s.peer,creationTime:hex(999999)},4000))),'SECURITY_EVIDENCE_REPLAY');assert.deepEqual(row(s).nhwPeerBindings.A,before);
 reject(()=>send(s,'integrity',records,2),'SECURITY_EVIDENCE_REPLAY');
});
check('Authenticated enrollment replay is recorded as a protocol rejection, not an attack or a revoke',()=>{
 const s=subject(),original=reports.RecordPath;
 reports.RecordPath=()=>{throw Error('INJECTED_DIAGNOSTIC_WRITE_FAILURE');};
 try{reject(()=>send(s,'integrity',[],1),'INJECTED_DIAGNOSTIC_WRITE_FAILURE');}finally{reports.RecordPath=original;}
 assert.ok(row(s).nhwPeerBindings.A);assert.equal(row(s).nhwResponseOrders,undefined);
 reject(()=>send(s,'integrity',[],1,{...s.peer,phase:'A_ATTESTED'}),'SECURITY_PEER_ENROLLMENT_REPLAY');
 const e=reports.ForFlow(row(s).id)[0];assert.equal(e.detectionId,'SECURITY_PEER_ENROLLMENT_REPLAY');assert.equal(e.decisionReason,'SERVER_PROTOCOL_REJECTION');assert.equal(e.sessionStopPolicy,'REJECT_REQUEST_ONLY');assert.equal(e.correlation,false);assert.equal(e.confidence,0);assert.equal(e.invalidated,false);assert.equal(row(s).status,'STARTED');
});
check('Context schema rejects raw identities/paths, unknown enums, oversized rights and fake extra authority',()=>{
 for(const patch of [{path:'C:\\private'},{pid:42},{actorIdentity:'123'},{phase:'LOGIN'},{accessMask:0x100000000},{tokenDelta:512},{firstPartyAttested:true},{capability:'PROCESS_ALL_ACCESS'}])reject(()=>reports.ParseRecords([record('dkProcess',{context:context(patch)})],hex(2000),3),'SECURITY_DETECTION_CONTEXT_INVALID');
 const s=subject(),records=Array.from({length:12},(_,i)=>record(catalog.NHW[i].id,{context:self(s,{capability:'PROCESS_ACCESS',actorIdentity:String(i).padStart(64,'a'),peerId:'a'.repeat(48),grantId:'b'.repeat(48)})})),value=text(records,1,s.peer);
 assert.ok(Buffer.byteLength(value)<16384);schema.ValidateEnvelope({operation:'security',body:request(s,'driver',value)});assert.equal(paths.Payload(value).detections.length,12);
});
check('All 204 contexts traverse each independent signed endpoint and survive bounded terminal reporting',()=>{
 const s=subject();send(s,'trust',[record('dkPECodeIntegrity')]);
 for(const channel of ['trust','driver','integrity']){let sequence=channel==='trust'?1:0;for(let i=0;i<catalog.NHW.length;i+=12){const records=catalog.NHW.slice(i,i+12).filter(e=>channel!=='trust'||e.id!=='dkPECodeIntegrity').map(e=>record(e.id));send(s,channel,records,++sequence);}
  const events=reports.ForFlow(row(s).id).filter(e=>e.responsePath===channel);assert.equal(events.length,204);assert.ok(events.every(e=>e.context&&policy.DISPOSITIONS.includes(e.disposition)));}
 assert.equal(reports.ForFlow(row(s).id).length,612);reports.Validate(store.Load().securityDetections,store.Load());
});
console.log('NHW context policy: '+checks+' groups passed; signed synthetic evidence only, Windows execution not performed');
