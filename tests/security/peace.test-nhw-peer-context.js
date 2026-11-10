'use strict';
// Production signing, authority, durable stores and A/B/O handoff handlers.
// Process IDs and Windows measurements below are synthetic test observations.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-peer-context-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../../core/peace.utilities').EnsureDirs();
const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),boot=require('../../services/bootstrap/peace.desktop-bootstrap'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store'),authority=require('../../services/security/peace.desktop-security-authority'),paths=require('../../services/security/peace.nhw-response-paths'),peers=require('../../services/security/peace.nhw-peer-context'),licenses=require('../../services/licensing/peace.desktop-licenses'),reports=require('../../services/security/peace.security-detections');
const sha=x=>crypto.createHash('sha512').update(x).digest('hex'),hex=n=>BigInt(n).toString(16).padStart(16,'0');
let checks=0,pid=10000;
function check(name,fn){fn();checks++;console.log('PASS '+name);}
process.once('exit',()=>{peers.Clear();fs.rmSync(temp,{recursive:true,force:true});});
function flow(s){return store.Load().flows[s.start.begin.flowId];}
function context(identity,role,extra={}){return {actorClass:'SELF',actorRole:role,actorIdentity:identity,targetRole:role,targetIdentity:identity,phase:role+'_BOOTSTRAP',capability:'TOKEN_STATE',accessMask:0,tokenDelta:0,coverage:'COMPLETE',peerId:'',grantId:'',baseline:true,contextMixed:false,...extra};}
function metadata(s,role,parentIdentity=''){
 const row=role==='O'?store.Load().overlays[s.prepared.overlayId]:flow(s),artifact=store.Load().artifacts[role==='A'?store.Load().launchers[row.launcherId].artifactId:row.releaseId];
 return {pid:++pid,creationTime:hex(100000+pid),imageSha256:role==='A'?store.Load().launchers[row.launcherId].peerImageSha256:artifact.legacyRevocationSha256,imageSha512:role==='A'?row.launcherSha512:artifact.sha512,parentIdentity,phase:role+'_BOOTSTRAP'};
}
function send(s,stage,peer,records=[],sequence=1,channel='integrity'){
 const device=stage==='A'?s.parent:stage==='B'?s.device:s.overlayDevice;
 const ctx=stage==='A'?{sessionId:s.start.begin.flowId,sessionToken:s.start.begin.downloadTicket}:stage==='B'?{sessionId:s.b.sessionId,sessionToken:s.b.sessionToken}:{sessionId:s.o.sessionId,sessionToken:s.o.sessionToken};
 const payload=JSON.stringify({version:3,sequence:hex(sequence),tick:hex(200000+sequence),digest:sha(JSON.stringify(records)).slice(0,16),confirmed:false,trust:0,detections:records,peer});
 const prefix='nhw'+channel[0].toUpperCase()+channel.slice(1),body={...ctx,stage,machineId:device.machineId,binding:sha(payload),action:prefix+'Challenge'},challenge=authority.Execute(body),submit={...body,action:prefix+'Submit',challengeId:challenge.challengeId,payload};
 submit.signature=fixture.Sign(device,paths.Canonical(submit,challenge,channel));return authority.Execute(submit);
}
function record(id,c,tick=200000){return {id,source:'Cozy.NHW.Engine',firstTick:hex(tick),lastTick:hex(tick),count:1,families:8,confidence:30,correlation:false,attestationSequence:hex(0),localOnly:true,context:c};}
function A(){const parent=fixture.Device(),s={parent,start:fixture.Begin(parent)};s.aPeer=metadata(s,'A');s.aIdentity=peers.StableIdentity(s.aPeer);s.aReceipt=send(s,'A',s.aPeer);return s;}
function B(s=A()){
 s.device=fixture.Child(s.parent);fixture.Download(s.start.begin);s.finish=fixture.Finish(s.parent,s.start.begin);s.b=fixture.Claim(s.parent,s.start.begin,s.finish,s.device);s.bPeer=metadata(s,'B',s.aIdentity);s.bIdentity=peers.StableIdentity(s.bPeer);s.bReceipt=send(s,'B',s.bPeer);return s;
}
function proof(device,action,payload){const body={action,requestId:crypto.randomUUID(),deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:sha(JSON.stringify(payload))},c=licenses.Challenge(body);fixture.ObserveLicense(device,action,body.requestId,body.payloadHash,payload);return licenses.Execute({...body,challengeId:c.challengeId,payloadJSON:JSON.stringify(payload),signature:fixture.Sign(device,c.canonical)});}
function O(s=B()){
 s.overlayDevice=fixture.Child(s.device);const common={...fixture.Evidence(s.device,s.b),bootstrapSessionId:s.b.sessionId,bootstrapSessionToken:s.b.sessionToken,appVersion:'93.0.0'},issue=licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID()},'PEER_TEST');
 const activation=proof(s.device,'redeem',{...common,licenseKey:issue.licenseKey});s.prepared=proof(s.device,'overlay',{...common,activationToken:activation.activationToken});
 for(let offset=0;offset<s.prepared.release.size;offset+=s.prepared.chunkSize)boot.Execute({action:'overlayChunk',overlayId:s.prepared.overlayId,overlayTicket:s.prepared.overlayTicket,offset});
 const finished=boot.Execute({action:'overlayFinish',overlayId:s.prepared.overlayId,overlayTicket:s.prepared.overlayTicket,signature:fixture.Sign(s.device,s.prepared.finishCanonical)});
 s.o=boot.Execute({action:'overlayClaim',overlayId:s.prepared.overlayId,overlayTicket:s.prepared.overlayTicket,...fixture.Delegated(s.device,s.overlayDevice,'O',finished.claimCanonical),binarySha512:s.prepared.release.sha512,crc64:s.prepared.release.crc64,oCodeSha512:s.prepared.release.codeSha512,oCodeCrc64:s.prepared.release.codeCrc64});
 fixture.Enroll(s.overlayDevice,{stage:'O',sessionId:s.o.sessionId,sessionToken:s.o.sessionToken,machineId:s.overlayDevice.machineId});
 s.oPeer=metadata(s,'O',s.bIdentity);s.oIdentity=peers.StableIdentity(s.oPeer);s.oReceipt=send(s,'O',s.oPeer);return s;
}
fixture.CurrentCohort({version:'93.0.0'});
check('Normal A signed startup binds exact issued bytes without revocation or raw PID persistence',()=>{
 const s=A(),receipt=s.aReceipt.peerContext;assert.equal(s.aReceipt.stopped,false);assert.equal(receipt.scope,'SERVER_BOUND_CLIENT_OBSERVATION');assert.equal(receipt.selfIdentity,s.aIdentity);assert(receipt.ttlMs>0&&receipt.ttlMs<=30000);assert.equal(flow(s).status,'STARTED');
 const saved=flow(s).nhwPeerBindings.A;assert.equal(saved.version,1);assert.equal(saved.versionLabel,'93.0.0');assert.equal(Object.hasOwn(saved,'pid'),false);assert.equal(Object.hasOwn(saved,'creationTime'),false);assert.equal(receipt.peers[0].pid,s.aPeer.pid);
 const c=context(s.aIdentity,'A');assert.equal(peers.ResolveContext(flow(s),'A',c).expected,true);
 assert.equal(send(s,'A',s.aPeer,[record('dkTokenObject',c)],2).stopped,false);
});
check('A to B uses actual one-use handoff grant and same-cohort parent identity',()=>{
 const s=B(),g=flow(s).nhwHandoffGrant;assert.equal(g.sourceIdentity,s.aIdentity);assert.equal(g.targetRole,'B');assert(g.consumedAt>0);assert.equal(g.childKeyId,s.device.deviceId);assert.equal(s.bReceipt.stopped,false);assert.equal(s.bReceipt.peerContext.selfIdentity,s.bIdentity);assert.equal(s.bReceipt.peerContext.peers.find(p=>p.role==='A').grantId,g.id);
 const c=context(s.aIdentity,'A',{actorClass:'TRUSTED_A',targetRole:'B',targetIdentity:s.bIdentity,phase:'A_HANDOFF_TO_B',capability:'PROCESS_ACCESS',accessMask:0x101000,peerId:s.aReceipt.peerContext.selfPeerId,grantId:g.id,baseline:false});
 const resolved=peers.ResolveContext(flow(s),'B',c);assert.equal(resolved.expected,true);assert.equal(resolved.actorClass,'TRUSTED_A');assert.equal(resolved.sameSession,true);
 const before=reports.ForFlow(s.start.begin.flowId).length;assert.deepEqual(boot.Execute(fixture.ClaimBody(s.parent,s.start.begin,s.finish,s.device)),s.b);assert.equal(reports.ForFlow(s.start.begin.flowId).length,before);
 let rejected;try{store.Atomic(db=>peers.ConsumeGrant(db,db.flows[s.start.begin.flowId],'B',{deviceId:s.device.deviceId},g.claimDigest));}catch(error){rejected=error;}assert.equal(rejected?.message,'SECURITY_HANDOFF_GRANT_REUSED');
 // Exercise the transaction-rollback diagnostic hook directly: ordinary wire
 // replay is already blocked by Claim's earlier idempotent/nonce checks.
 peers.RecordGrantRejection(rejected);const finding=reports.ForFlow(s.start.begin.flowId).find(e=>e.detectionId==='SECURITY_HANDOFF_GRANT_REUSED');assert(finding);assert.equal(finding.invalidated,false);assert.equal(finding.correlation,false);assert.equal(flow(s).status,'CLAIMED');
});
check('B to O binds separate O epoch to the same root cohort and only exact approved image',()=>{
 const s=O(),row=store.Load().overlays[s.prepared.overlayId],g=row.nhwHandoffGrant;assert.equal(s.oReceipt.stopped,false);assert.equal(g.sourceIdentity,s.bIdentity);assert.equal(g.epoch,String(row.createdAt));assert.equal(g.cohort,flow(s).nhwPeerBindings.B.cohort);assert.equal(s.oReceipt.peerContext.selfIdentity,s.oIdentity);assert.equal(s.oReceipt.peerContext.peers.find(p=>p.role==='B').grantId,g.id);
 const c=context(s.bIdentity,'B',{actorClass:'TRUSTED_B',targetRole:'O',targetIdentity:s.oIdentity,phase:'B_HANDOFF_TO_O',capability:'PROCESS_ACCESS',accessMask:0x101000,peerId:s.bReceipt.peerContext.selfPeerId,grantId:g.id,baseline:false});
 assert.equal(peers.ResolveContext(row,'O',c).expected,true);
 assert.equal(peers.ResolveContext(row,'O',{...c,accessMask:0x101001}).expected,true);
 for(const mask of [0x20,0x8,0x2,0x1fffff]){const result=peers.ResolveContext(row,'O',{...c,accessMask:mask});assert.equal(result.forbidden,true);assert.equal(result.expected,false);}
 assert.equal(send(s,'O',s.oPeer,[record('dkProcess',{...c,accessMask:0x20})],2).stopped,true);assert.equal(store.Load().overlays[s.prepared.overlayId].status,'REVOKED');assert.equal(flow(s).status,'REVOKED');
});
check('Cross-session claims, mismatched PID creation, spoofed role and phase do not inherit trust',()=>{
 const s=B(),other=B(),foreign=context(other.bIdentity,'B',{actorClass:'TRUSTED_B',targetRole:'B',targetIdentity:s.bIdentity,capability:'PROCESS_ACCESS',accessMask:0x101000,peerId:other.bReceipt.peerContext.selfPeerId,baseline:false});
 const result=peers.ResolveContext(flow(s),'B',foreign);assert.equal(result.actorClass,'EXTERNAL');assert.equal(result.firstPartyAttested,false);assert.equal(result.expected,false);
 const reused=B(),changed=B();assert.throws(()=>send(reused,'B',{...reused.bPeer,creationTime:hex(999999)},[],2),/SECURITY_PEER_IDENTITY_CHANGED/);assert.equal(flow(reused).status,'REVOKED');
 assert.throws(()=>send(changed,'B',{...changed.bPeer,imageSha256:'a'.repeat(64)},[],2),/SECURITY_PEER_IMAGE_MISMATCH/);assert.equal(flow(changed).status,'REVOKED');
 assert(reports.ForFlow(reused.start.begin.flowId).some(e=>e.detectionId==='SECURITY_PEER_IDENTITY_CHANGED'&&e.invalidated));assert(reports.ForFlow(changed.start.begin.flowId).some(e=>e.detectionId==='SECURITY_PEER_IMAGE_MISMATCH'&&e.invalidated));
 assert.equal(peers.Enroll(flow(s),'B',{...s.bPeer,phase:'B_HANDOFF_TO_O'},hex(4)),null);
 assert.equal(peers.ResolveContext(flow(s),'B',context(s.bIdentity,'B',{phase:'B_RUNTIME'})).expected,false);
 assert.equal(peers.ResolveContext(flow(s),'B',{...foreign,accessMask:0x20}).forbidden,true);
 const aliasOnly=context(s.bIdentity,'B',{actorClass:'EXTERNAL',peerId:'',capability:'PROCESS_ACCESS',accessMask:0x101000});assert.equal(peers.ResolveContext(flow(s),'B',aliasOnly).firstPartyAttested,false);assert.equal(peers.ResolveContext(flow(s),'B',{...aliasOnly,actorClass:'TRUSTED_B'}).firstPartyAttested,false);
});
check('Client role labels cannot fabricate SELF or registered target context',()=>{
 const s=B();for(const actorClass of ['SELF','TRUSTED_A','TRUSTED_B','TRUSTED_O']){const c=context('a'.repeat(64),'B',{actorClass,targetIdentity:s.bIdentity});assert.equal(peers.ResolveContext(flow(s),'B',c).firstPartyAttested,false);}
 const c=context(s.aIdentity,'A',{targetRole:'A',targetIdentity:s.aIdentity,phase:'A_HANDOFF_TO_B',capability:'TOKEN_ACCESS',accessMask:8});assert.equal(peers.ResolveContext(flow(s),'B',c).expected,false);
 assert.equal(peers.ResolveContext(flow(s),'B',context(s.bIdentity,'B',{contextMixed:true})).expected,false);
});
check('Token baseline is expected, privilege escalation remains forbidden, ordinary impersonation observation alone is not',()=>{
 const s=B(),c=context(s.bIdentity,'B');assert.equal(peers.ResolveContext(flow(s),'B',c).expected,true);
 for(const delta of [1,2,4,8,16,32,64,128])assert.equal(peers.ResolveContext(flow(s),'B',{...c,baseline:false,tokenDelta:delta}).forbidden,true);
 assert.equal(peers.ResolveContext(flow(s),'B',{...c,baseline:false,tokenDelta:256}).forbidden,false);
 assert.equal(send(s,'B',s.bPeer,[record('dkTokenRights',{...c,baseline:false,tokenDelta:2})],2).stopped,true);
});
check('Independent response paths share a monotonic server peer sequence without reusing report counters',()=>{
 const s=A(),first=s.aReceipt.peerContext;const next=send(s,'A',s.aPeer,[],1,'trust').peerContext;assert(BigInt('0x'+next.serverSequence)>BigInt('0x'+first.serverSequence));
 const before=flow(s).nhwPeerBindings.A;assert.deepEqual(peers.Enroll(flow(s),'A',s.aPeer,hex(1),{channel:'trust'}),peers.Receipt(flow(s),'A'));assert.equal(flow(s).nhwPeerBindings.A.updatedAt,before.updatedAt);assert.equal(flow(s).nhwPeerBindings.A.serverSequence,before.serverSequence);
});
check('RAM retirement and restart remove trust immediately; signed new enrollment does not resurrect a reused PID',()=>{
 const s=A(),c=context(s.aIdentity,'A');peers.Retire(flow(s),'A');assert.equal(peers.ResolveContext(flow(s),'A',c).expected,false);assert.equal(peers.Receipt(flow(s),'A'),null);
 assert.equal(send(s,'A',s.aPeer,[],2).peerContext.selfIdentity,s.aIdentity);peers.Clear();assert.equal(peers.ResolveContext(flow(s),'A',c).expected,false);assert.equal(peers.Receipt(flow(s),'A'),null);
 assert.throws(()=>send(s,'A',{...s.aPeer,creationTime:hex(999998)},[],3),/SECURITY_PEER_IDENTITY_CHANGED/);
});
check('Reported process exit tombstones the exact role identity and cannot be renewed by a later observation',()=>{
 const s=A();store.Atomic(db=>peers.ProcessExited(db,s.start.begin.flowId,'A',s.start.begin.flowId));assert(flow(s).nhwPeerBindings.A.retiredAt>0);assert.equal(peers.Receipt(flow(s),'A'),null);
 assert.equal(send(s,'A',s.aPeer,[],2).peerContext,null);assert.equal(peers.ResolveContext(flow(s),'A',context(s.aIdentity,'A')).expected,false);
});
check('Persistent identity and grants reject arbitrary extra fields and cross-flow mutation',()=>{
 const s=B(),saved=structuredClone(flow(s));
 for(const mutation of [x=>x.nhwPeerBindings.B.pid=123,x=>x.nhwPeerBindings.B.sessionId='F'.repeat(24),x=>x.nhwPeerBindings.B.imageSha256='0'.repeat(64),x=>x.nhwHandoffGrant.allowedProcessMask=0x1fffff,x=>x.nhwHandoffGrant.targetArtifactId='E'.repeat(24),x=>x.nhwHandoffGrant.extra=true]){const x=structuredClone(saved);mutation(x);assert.throws(()=>peers.Validate(x,store.Load()),/SECURITY_PEER_STORAGE_INVALID/);}
 assert.equal(reports.ForFlow(s.start.begin.flowId).some(e=>JSON.stringify(e).includes('creationTime')),false);
});
console.log('NHW peer context: '+checks+' checks passed (server/synthetic observations; Windows unexecuted).');
