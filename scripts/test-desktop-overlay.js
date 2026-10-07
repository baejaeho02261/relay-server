'use strict';
// Production services with synthetic AMD64 artifacts and real ephemeral RSA proofs.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-v2-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../core/utils').EnsureDirs();
const fixture=require('./desktop-bootstrap-fixture'),bootstrap=require('../services/desktopBootstrap'),licenses=require('../services/desktopLicenses'),overlay=require('../services/desktopOverlay');
const d=fixture.Device(),other=fixture.Device(),sha512=v=>crypto.createHash('sha512').update(v).digest('hex');
let checks=0;
function check(label,fn){fn();checks++;console.log('PASS '+label);}
function reject(fn,code){assert.throws(fn,e=>code?e.message===code:/^(BOOTSTRAP|DESKTOP|SECURITY|INTEGRITY)_/.test(e.message));}
function proof(action,payload){const body={action,requestId:crypto.randomUUID(),deviceId:d.deviceId,publicKey:d.publicKey,payloadHash:sha512(JSON.stringify(payload))},c=licenses.Challenge(body);fixture.ObserveLicense(d,action,body.requestId,body.payloadHash,payload);return licenses.Execute({...body,challengeId:c.challengeId,payloadJSON:JSON.stringify(payload),signature:fixture.Sign(d,c.canonical)});}
bootstrap.Publish('A','88.0.0',fixture.PE('A'));bootstrap.Publish('B','88.0.0',fixture.PE('B'));bootstrap.Publish('O','88.0.0',fixture.PE('O'));
const begin=fixture.Begin(d).begin;fixture.Download(begin);const session=fixture.Claim(d,begin,fixture.Finish(d,begin));
const common={...fixture.Evidence(d,session),bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken,appVersion:'88.0.0'};
const issued=licenses.Create({requestId:crypto.randomUUID(),label:'overlay regression'},'TEST');
const activation=proof('redeem',{...common,licenseKey:issued.licenseKey,deviceName:'Overlay test'});
let prepared,finished,claimed;
check('Only a live licensed B session can prepare O',()=>{
 reject(()=>proof('overlay',{...common,activationToken:'0'.repeat(64)}));
 prepared=proof('overlay',{...common,activationToken:activation.activationToken});
 assert.equal(prepared.parentSessionId,session.sessionId);assert.equal(prepared.release.hashVersion,3);
 assert.match(prepared.finishCanonical,/^GAME-OVERLAY-FINISH-V2\n3\n/);
 assert.equal(prepared.finishCanonical.split('\n')[16],sha512(prepared.overlayTicket));
});
check('Standalone or cross-device O claims are rejected',()=>{
 reject(()=>bootstrap.Execute({action:'overlayClaim',overlayId:'A'.repeat(24),overlayTicket:'invalid'}));
 reject(()=>bootstrap.Execute({action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(other,prepared.finishCanonical)}),'BOOTSTRAP_PROOF_INVALID');
 reject(()=>bootstrap.Execute({action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(d,prepared.finishCanonical)}),'BOOTSTRAP_DOWNLOAD_INCOMPLETE');
});
check('Download completion authorizes O without retiring B',()=>{
 let bytes=[];for(let offset=0;offset<prepared.release.size;offset+=prepared.chunkSize){const chunk=bootstrap.Execute({action:'overlayChunk',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,offset});bytes.push(Buffer.from(chunk.data,'base64'));}
 assert.equal(sha512(Buffer.concat(bytes)),prepared.release.sha512);
 finished=bootstrap.Execute({action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(d,prepared.finishCanonical)});
 const parent=Object.values(bootstrap.Initialize().flows).find(r=>r.sessionId===session.sessionId);
 assert.equal(parent.status,'CLAIMED');assert.equal(parent.closedByOverlay,undefined);
 assert.equal(fixture.Gate(d,session).sessionId,session.sessionId);
});
const claim=()=>({action:'overlayClaim',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(d,finished.claimCanonical),binarySha512:prepared.release.sha512,crc64:prepared.release.crc64,oCodeSha512:prepared.release.codeSha512,oCodeCrc64:prepared.release.codeCrc64});
check('O claim binds SHA512 file/code and supports exact response recovery',()=>{
 reject(()=>bootstrap.Execute({...claim(),binarySha512:'0'.repeat(64)}),'BOOTSTRAP_INPUT_INVALID');
 claimed=bootstrap.Execute(claim());assert.equal(bootstrap.Execute(claim()).sessionToken,claimed.sessionToken);
 assert.notEqual(claimed.sessionId,session.sessionId);
 const auth=overlay.AuthenticateIntegrityReport({stage:'O',sessionId:claimed.sessionId,sessionToken:claimed.sessionToken,machineId:d.machineId});
 assert.equal(auth.integrityArtifact.sha512,prepared.release.sha512);assert.equal(auth.integrityArtifact.fileXxh3_128,prepared.release.xxh3_128);
});
check('O signs independent CRC/hash reports and one-use authority observations',()=>{
 const reports=require('../services/desktopIntegrityReports'),authority=require('../services/desktopSecurityAuthority');
 const context={stage:'O',sessionId:claimed.sessionId,sessionToken:claimed.sessionToken,machineId:d.machineId};
 const base=overlay.AuthenticateIntegrityReport(context).integrityArtifact;
 const payload=JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:base.codeSha512,codeCrc64:base.codeCrc64,fileXxh3_128:base.fileXxh3_128,fileBlake3:base.fileBlake3,codeXxh3_128:base.codeXxh3_128,codeBlake3:base.codeBlake3},crcLayers:base.crcLayers});
 const challenge=reports.Execute({...context,action:'challenge'});
 const request={...context,action:'submit',reportId:challenge.reportId,payload,signature:fixture.Sign(d,reports.Canonical(claimed.sessionId,challenge,payload))};
 const result=reports.Execute(request);assert.equal(result.status,'VERIFIED');assert.equal(result.terminate,false);
 reject(()=>reports.Execute(request),'INTEGRITY_REPORT_CHALLENGE_INVALID');
 const authContext={...context,intent:'verify',binding:authority.Binding(claimed.sessionId,base.sha512)};
 const observation=authority.Execute({...authContext,action:'challenge'});
 const evidence=JSON.stringify({version:1,hashVersion:3,measurement:'MEASURED',fileSha512:base.sha512,fileCrc64:base.crc64,codeSha512:base.codeSha512,codeCrc64:base.codeCrc64,codeXxh3_128:base.codeXxh3_128,codeBlake3:base.codeBlake3,crcLayers:base.crcLayers,apiSealed:true,apiSlots:100,dynamicCode:'ALLOWED',cfg:'DISABLED'});
 const signed={...authContext,action:'submit',challengeId:observation.challengeId,payload:evidence,signature:fixture.Sign(d,authority.Canonical(authContext,observation,evidence))};
 assert.equal(authority.Execute(signed).status,'PASS');
 reject(()=>authority.Execute(signed),'SECURITY_CHALLENGE_INVALID');
});
check('O refresh verifies license, session, machine and image while B remains live',()=>{
 const body={action:'overlayVerify',sessionId:claimed.sessionId,sessionToken:claimed.sessionToken,...fixture.Evidence(d,claimed)};
 reject(()=>bootstrap.Execute({...body,machineId:other.machineId}),'BOOTSTRAP_SESSION_INVALID');
 assert.equal(bootstrap.Execute(body).status,'ACTIVE');
 reject(()=>bootstrap.Execute(claim()),'BOOTSTRAP_LAUNCHER_USED');
 assert.equal(fixture.Gate(d,session).sessionId,session.sessionId);
});
check('Revoking parent B immediately invalidates child O',()=>{
 bootstrap.Revoke(session.sessionId,{reason:'TEST_PARENT_REVOKED'},'TEST');
 reject(()=>overlay.AuthenticateIntegrityReport({stage:'O',sessionId:claimed.sessionId,sessionToken:claimed.sessionToken,machineId:d.machineId}),'BOOTSTRAP_FLOW_INVALID');
});
check('Close retires O token material and store remains valid',()=>{
 bootstrap.Execute({action:'overlayClose',sessionId:claimed.sessionId,sessionToken:claimed.sessionToken});
 const row=Object.values(bootstrap.Initialize().overlays)[0];assert.equal(row.status,'CLOSED');assert.equal(row.sessionNonce,undefined);assert.equal(row.ticketNonce,undefined);
 overlay.ValidateStore(bootstrap.Initialize());
 reject(()=>overlay.AuthenticateIntegrityReport({stage:'O',sessionId:claimed.sessionId,sessionToken:claimed.sessionToken,machineId:d.machineId}));
});
console.log(`Overlay lifecycle: ${checks} checks passed`);
