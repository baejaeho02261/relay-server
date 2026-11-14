'use strict';
// Opt-in fixture for current publication and measurement contracts. It does not
// weaken production publication or first-run approval. All PEs and inventories
// below are synthetic data for a disposable HTTP server, never proof
// of a Windows build or measurements of this test machine.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const legacy=require("../bootstrap/peace.desktop-bootstrap-fixture"),integrity=require("../../../services/integrity/peace.desktop-integrity");
const measurement=require("../../../services/integrity/peace.measurement-plan-contract"),remoteEvidence=new Map();
const signing=require("../../../services/bootstrap/peace.issued-a-signing"),trustedTemplates=new Set();
let fixtureIssuer;
function Issuer(){return fixtureIssuer||(fixtureIssuer=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537}));}
function PE(component,marker='SYNTHETIC_NOT_WINDOWS'){
 const raw=legacy.PE(component,measurement.CONTRACT+' GAME-HANDOFF-V3 '+marker);
 const template=component==='A'?require('../bootstrap/peace.issued-a-fixture').WithAnchor(raw,Issuer().publicKey):raw;
 const slot=require('../../../services/artifacts/peace.server-policy-protection').CreateUnsealedSlot(),bytes=Buffer.concat([template,slot]);
 const pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20),last=table+(bytes.readUInt16LE(pe+6)-1)*40,size=bytes.readUInt32LE(last+16)+slot.length;
 bytes.writeUInt32LE(size,last+8);bytes.writeUInt32LE(size,last+16);bytes.writeUInt32LE(Math.ceil((bytes.readUInt32LE(last+12)+size)/4096)*4096,opt+56);return bytes;
}
function Config(bytes){
 // Trust comes from this test's independently registered templates and issuer,
 // not from a key or hash supplied by the downloaded executable itself.
 const expectedKeyId=signing.PublicIdentity(Issuer().publicKey).keyId;
 for(const expectedTemplateSha512 of trustedTemplates){try{return signing.VerifyFinal(bytes,{expectedTemplateSha512,expectedKeyId}).config;}catch(error){if(!error.desktopError)throw error;}}
 throw Error('FIXTURE_SIGNED_LAUNCHER_TRUST_MISMATCH');
}
function CreateSyntheticApprovalSigner(){
 // This ephemeral key signs only fixture bytes; it is not exported to disk or
 // trusted by an operator deployment. The server verifies the real signature.
 const pair=crypto.generateKeyPairSync('ed25519'),provenance=require("../../../services/artifacts/peace.desktop-release-provenance");
 const trustedKey={keyId:provenance.KeyId(pair.publicKey),publicKey:pair.publicKey.export({type:'spki',format:'pem'}).toString()};
 return {trustedKey,environment:{[signing.ENV]:Buffer.from(Issuer().privateKey.export({type:'pkcs8',format:'pem'})).toString('base64')},Approval(component,version,bytes){
  const canonical=require("../../../services/security/peace.desktop-security-authority").ReleaseCanonical(component,version,legacy.sha512(bytes));
  return {keyId:trustedKey.keyId,signature:crypto.sign(null,Buffer.from(canonical),pair.privateKey).toString('base64')};
 }};
}
async function Snapshot(profile,device,context,bytes){
 const started=Math.floor(performance.now()),file=integrity.Digests(bytes),code=integrity.CodeImage(bytes);
 const payload=JSON.stringify({version:1,hashVersion:3,check:'MODULE_INVENTORY',reason:'SYNTHETIC_TEST',snapshotId:crypto.randomUUID(),batchIndex:0,batchCount:1,
  complete:true,truncated:false,totalModules:1,measuredModules:1,scope:'current-process',trust:'client-reported',measurementContract:measurement.CONTRACT,measurementPlanVersion:1,
  measurementStartedTick:started,measurementFinishedTick:Math.floor(performance.now()),moduleGenerationStable:true,coverage:'FULL',
  modules:[{name:'synthetic-test.exe',status:'UNVERIFIED_BASELINE',codeStatus:'UNVERIFIED_BASELINE',fileSha512:file.sha512,fileCrc64:file.crc64,codeSha512:code.sha512,codeCrc64:code.crc64,
   fileXxh3_128:file.xxh3_128,fileBlake3:file.blake3,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3}]});
 const challenge=await legacy.TcpOperation(profile,'report',{...context,action:'challenge'});
 const canonical=require("../../../services/integrity/peace.desktop-integrity-reports").Canonical(context.sessionId,challenge,payload);
 const result=await legacy.TcpOperation(profile,'report',{...context,action:'submit',reportId:challenge.reportId,payload,signature:legacy.Sign(device,canonical)});
 assert.equal(result.accepted,true);assert.equal(result.terminate,false);assert.equal(result.status,'CLIENT_DIAGNOSTIC');
 return result;
}
async function RemoteSession(device,launcher,{call:adminCall,auth}={}){
 assert.equal(typeof adminCall,'function','Remote bootstrap requires explicit authenticated administrator approval');assert.ok(auth);
 const settings=Config(launcher),profile=settings.profile,call=body=>legacy.TcpBootstrap(profile,body),parent=legacy.Device(),persistent=legacy.Persistent(device);
 parent.machineId=device.machineId;
 const code=integrity.CodeImage(launcher),policy=await call({action:'keylessPolicy',version:1,launcherId:settings.launcherId,machineId:parent.machineId});
 const challenge=await call({action:'keylessChallenge',version:1,requestId:crypto.randomUUID(),launcherId:settings.launcherId,
  launcherSha512:legacy.sha512(launcher),launcherCrc64:legacy.Crc64(launcher),aCodeSha512:code.sha512,aCodeCrc64:code.crc64,machineId:parent.machineId,publicKey:parent.publicKey,deviceId:parent.deviceId,
  handoffVersion:3,persistentPublicKey:persistent.publicKey,persistentKeyId:persistent.deviceId,keyProvider:policy.keyProvider,epoch:policy.epoch,revision:policy.revision});
 const proof={version:1,challengeId:challenge.challengeId,appSignature:legacy.Sign(parent,challenge.canonical),persistentSignature:legacy.Sign(persistent,challenge.canonical)};
 const pending=await call({action:'keylessProve',...proof});assert.equal(pending.status,'PENDING_APPROVAL');
 const denied=await require('../network/peace.tls-request-fixture').Request(profile,'bootstrap',{action:'beginKeyless',...proof});
 assert.equal(denied.ok,false);assert.equal(denied.error,'KEYLESS_APPROVAL_REQUIRED');
 // This is a real HTTP admin action, including the test caller's CSRF and
 // one-use password reauthentication. Every new execution receives its own grant.
 const approved=await adminCall('/api/desktop/bootstrap/security-operations/keyless-approvals/'+challenge.challengeId+'/approve',
  {identityConfirmed:true,launcherId:settings.launcherId,persistentKeyId:persistent.deviceId},auth);
 assert.equal(approved.status,200,JSON.stringify(approved.json));assert.equal(approved.json.status,'APPROVED');assert.equal(approved.json.approvalScope,'EACH_LAUNCH_REQUEST');
 assert.ok(approved.json.approvalExpiresAt<=challenge.expiresAt);
 const begin=await call({action:'beginKeyless',...proof}),chunks=[];
 await legacy.RemoteEnroll(profile,parent,{stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:parent.machineId},persistent);
 for(let offset=0;offset<begin.release.size;){const chunk=await call({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset}),bytes=Buffer.from(chunk.data,'base64');assert.equal(chunk.offset,offset);assert(bytes.length>0&&bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
 const binary=Buffer.concat(chunks);assert.equal(binary.length,begin.release.size);assert.equal(legacy.sha512(binary),begin.release.sha512);
 const context={stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:device.machineId};
 await Snapshot(profile,parent,context,launcher);
 await legacy.RemoteObserve(profile,parent,{...context,intent:'finish',binding:require("../../../services/security/peace.desktop-security-authority").Binding(begin.flowId,begin.release.sha512)},launcher);
 const finish=await call({action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha512:begin.release.sha512,crc64:begin.release.crc64,aCodeSha512:begin.finishCanonical.split('\n')[5],aCodeCrc64:begin.finishCanonical.split('\n')[6],signature:legacy.Sign(parent,begin.finishCanonical)});
 const session=await call({action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,...legacy.Delegated(parent,device,'B',finish.claimCanonical),binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64});
 await legacy.RemoteEnroll(profile,device,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId},persistent);
 remoteEvidence.set(session.sessionId,binary);
 await Snapshot(profile,device,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId},binary);
 return session;
}
async function BindSyntheticCohort({call,auth,candidates,download,upload}){
 const prefix='/api/desktop/bootstrap/packing/jobs',start=await call(prefix,{mode:'COZY_SERVER_POLICY_V2',...Object.fromEntries(['A','B','O'].map(role=>[role,candidates[role].id]))},auth);
 assert.equal(start.status,202,JSON.stringify(start.json));let job=start.json.job;
 const deadline=Date.now()+30000;
 while(job.status==='RUNNING'&&Date.now()<deadline){await new Promise(resolve=>setTimeout(resolve,50));const result=await call(prefix+'/'+job.id,undefined,auth);assert.equal(result.status,200,JSON.stringify(result.json));job=result.json.job;}
 assert.equal(job.status,'COMPLETE',JSON.stringify(job));assert.equal(job.windowsVerified,false);
 for(const role of ['A','B','O']){
  const bytes=await download(prefix+'/'+job.id+'/'+role,auth);assert.equal(legacy.sha512(bytes),job.outputs[role].sha512);
  const registered=await upload(role,bytes,auth);assert.equal(registered.status,200,JSON.stringify(registered.json));
  candidates[role]=registered.json.artifact;assert.equal(candidates[role].ownProtection.engine,'COZY_SERVER_POLICY_V2');assert.equal(candidates[role].ownProtection.state,'BOUND');
  if(role==='A')trustedTemplates.add(legacy.sha512(bytes));
 }
 return candidates;
}
async function RemoteObserveLicense(profile,device,session,action,requestId,payloadHash){
 if(action==='release')return;
 const bytes=remoteEvidence.get(session.sessionId);assert(bytes,'Modern RemoteSession must retain its synthetic B bytes');
 const context={stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId};
 await Snapshot(profile,device,context,bytes);
 return legacy.RemoteObserve(profile,device,{...context,intent:action==='overlay'?'verify':action,binding:require("../../../services/security/peace.desktop-security-authority").Binding(requestId,payloadHash)},bytes);
}
async function RegisterSyntheticRelease({call,auth,candidates,label,afterManifest}){
 assert(/^SYNTHETIC/.test(label),'This test helper registers synthetic manifests only');
 const security='/api/desktop/bootstrap/security-authority',operations='/api/desktop/bootstrap/security-operations',provenance=require("../../../services/artifacts/peace.desktop-release-provenance");
 const settings=(await call(security,undefined,auth)).json;
 for(const role of ['A','B','O']){assert.equal(candidates[role].component,role);assert.equal(candidates[role].measurementPlanVersion,1);assert.equal(candidates[role].handoffVersion,3);}
 const manifest={version:1,releaseName:label,securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,
  sourceManifestSha512:'1'.repeat(128),policySha512:provenance.PolicyDigest(settings.policy),toolchain:{delphi:'NOT_RUN',cpp:'NOT_RUN',windowsSdk:'NOT_RUN',imgui:'SYNTHETIC'},
  artifacts:Object.fromEntries(['A','B','O'].map(k=>[k,candidates[k].sha512]))};
 async function mutation(action,body){const live=(await call(security,undefined,auth)).json,result=await call(operations+'/'+action,{expectedRevision:live.operations.operations.revision,...body},auth);assert.equal(result.status,200,JSON.stringify(result.json));return result;}
 await mutation('release-manifests',{manifest});if(afterManifest)await afterManifest();
 return manifest;
}
module.exports={...legacy,PE,Config,CreateSyntheticApprovalSigner,BindSyntheticCohort,Snapshot,RemoteSession,RemoteObserveLicense,RegisterSyntheticRelease};
