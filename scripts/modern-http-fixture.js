'use strict';
// Opt-in fixture for current publication and measurement contracts. It does not
// change the legacy fixture used to test migration. All PEs, inventories and CI
// statements below are synthetic data for a disposable HTTP server, never proof
// of a Windows build or measurements of this test machine.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const legacy=require('./desktop-bootstrap-fixture'),integrity=require('../services/desktopIntegrity');
const measurement=require('../services/measurementPlanContract'),remoteEvidence=new Map();
function PE(component,marker='SYNTHETIC_NOT_WINDOWS'){
 return legacy.PE(component,marker+' '+measurement.CONTRACT);
}
async function Snapshot(profile,device,context,bytes){
 const started=Math.floor(performance.now()),file=integrity.Digests(bytes),code=integrity.CodeImage(bytes);
 const payload=JSON.stringify({version:1,hashVersion:3,check:'MODULE_INVENTORY',reason:'SYNTHETIC_TEST',snapshotId:crypto.randomUUID(),batchIndex:0,batchCount:1,
  complete:true,truncated:false,totalModules:1,measuredModules:1,scope:'current-process',trust:'client-reported',measurementContract:measurement.CONTRACT,measurementPlanVersion:1,
  measurementStartedTick:started,measurementFinishedTick:Math.floor(performance.now()),moduleGenerationStable:true,coverage:'FULL',
  modules:[{name:'synthetic-test.exe',status:'UNVERIFIED_BASELINE',codeStatus:'UNVERIFIED_BASELINE',fileSha512:file.sha512,fileCrc64:file.crc64,codeSha512:code.sha512,codeCrc64:code.crc64,
   fileXxh3_128:file.xxh3_128,fileBlake3:file.blake3,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3}]});
 const challenge=await legacy.TcpOperation(profile,'report',{...context,action:'challenge'});
 const canonical=require('../services/desktopIntegrityReports').Canonical(context.sessionId,challenge,payload);
 const result=await legacy.TcpOperation(profile,'report',{...context,action:'submit',reportId:challenge.reportId,payload,signature:legacy.Sign(device,canonical)});
 assert.equal(result.accepted,true);assert.equal(result.terminate,false);assert.equal(result.status,'CLIENT_DIAGNOSTIC');
 return result;
}
async function RemoteSession(device,launcher){
 const settings=legacy.Config(launcher),profile=settings.profile,call=body=>legacy.TcpBootstrap(profile,body);
 const code=integrity.CodeImage(launcher),begin=await call({action:'begin',requestId:crypto.randomUUID(),launcherId:settings.launcherId,launcherTicket:settings.launcherTicket,
  launcherSha512:legacy.sha512(launcher),launcherCrc64:legacy.Crc64(launcher),aCodeSha512:code.sha512,aCodeCrc64:code.crc64,machineId:device.machineId,publicKey:device.publicKey,deviceId:device.deviceId}),chunks=[];
 for(let offset=0;offset<begin.release.size;){const chunk=await call({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset}),bytes=Buffer.from(chunk.data,'base64');assert.equal(chunk.offset,offset);assert(bytes.length>0&&bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
 const binary=Buffer.concat(chunks);assert.equal(binary.length,begin.release.size);assert.equal(legacy.sha512(binary),begin.release.sha512);
 const context={stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:device.machineId};
 await Snapshot(profile,device,context,launcher);
 await legacy.RemoteObserve(profile,device,{...context,intent:'finish',binding:require('../services/desktopSecurityAuthority').Binding(begin.flowId,begin.release.sha512)},launcher);
 const finish=await call({action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha512:begin.release.sha512,crc64:begin.release.crc64,aCodeSha512:begin.finishCanonical.split('\n')[5],aCodeCrc64:begin.finishCanonical.split('\n')[6],signature:legacy.Sign(device,begin.finishCanonical)});
 const session=await call({action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,signature:legacy.Sign(device,finish.claimCanonical),binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64});
 remoteEvidence.set(session.sessionId,binary);
 await Snapshot(profile,device,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId},binary);
 return session;
}
async function RemoteObserveLicense(profile,device,session,action,requestId,payloadHash){
 if(action==='release')return;
 const bytes=remoteEvidence.get(session.sessionId);assert(bytes,'Modern RemoteSession must retain its synthetic B bytes');
 const context={stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId};
 await Snapshot(profile,device,context,bytes);
 return legacy.RemoteObserve(profile,device,{...context,intent:action==='overlay'?'verify':action,binding:require('../services/desktopSecurityAuthority').Binding(requestId,payloadHash)},bytes);
}
async function RegisterSyntheticRelease({call,auth,candidates,label,afterManifest}){
 assert(/^SYNTHETIC/.test(label),'No deployable CI evidence may be produced by this test helper');
 const security='/api/desktop/bootstrap/security-authority',operations='/api/desktop/bootstrap/security-operations',provenance=require('../services/desktopReleaseProvenance');
 const settings=(await call(security,undefined,auth)).json;
 for(const role of ['A','B','O']){assert.equal(candidates[role].component,role);assert.equal(candidates[role].measurementPlanVersion,1);assert.equal(candidates[role].handoffVersion,1);}
 const manifest={version:1,releaseName:label,securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:1,
  sourceManifestSha512:'1'.repeat(128),policySha512:provenance.PolicyDigest(settings.policy),toolchain:{delphi:'NOT_RUN',cpp:'NOT_RUN',windowsSdk:'NOT_RUN',imgui:'SYNTHETIC'},
  artifacts:Object.fromEntries(['A','B','O'].map(k=>[k,candidates[k].sha512]))};
 async function mutation(action,body){const live=(await call(security,undefined,auth)).json,result=await call(operations+'/'+action,{expectedRevision:live.operations.operations.revision,...body},auth);assert.equal(result.status,200,JSON.stringify(result.json));return result;}
 await mutation('release-manifests',{manifest});if(afterManifest)await afterManifest();
 const pair=crypto.generateKeyPairSync('ed25519'),keyId=provenance.KeyId(pair.publicKey);
 await mutation('ci-signers',{keyId,publicKey:pair.publicKey.export({type:'spki',format:'pem'}).toString(),state:'ACTIVE',notBefore:Date.now()-60000,notAfter:Date.now()+3600000});
 const statement={version:1,purpose:provenance.CI_DOMAIN,manifestId:provenance.ManifestId(manifest),runId:'SYNTHETIC-HTTP-NOT-WINDOWS',issuedAt:Date.now(),nativeBuild:'PASS',apiProbe:'PASS',integration:'PASS',logsSha512:'2'.repeat(128)};
 await mutation('ci-evidence',{envelope:{keyId,statement,signature:crypto.sign(null,Buffer.from(provenance.Canonical(statement)),pair.privateKey).toString('base64')}});
 return manifest;
}
module.exports={...legacy,PE,Snapshot,RemoteSession,RemoteObserveLicense,RegisterSyntheticRelease};
