'use strict';
// Actual TLS + encrypted GAME-CONNECT-3 dispatch, with test PE/keys only.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),tls=require('node:tls');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'authority-wire-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';
require('../core/utils').EnsureDirs();
const transport=require('../services/desktopConnect'),keys=require('../services/connectTransportKey');
const fixture=require('./desktop-bootstrap-fixture'),authority=require('../services/desktopSecurityAuthority');
const device=fixture.Device();let profile,server;
async function Round(body){
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),requestId=crypto.randomUUID();
 const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(transport.Aad('REQUEST',requestId,profile.serverKeyId));
 const clear=JSON.stringify({operation:'security',body}),encrypted=Buffer.concat([cipher.update(clear,'utf8'),cipher.final()]);
 const frame={v:1,keyId:profile.serverKeyId,requestId,wrappedKey:crypto.publicEncrypt({key:require('../services/desktopLicenses').ParseKey(profile.serverPublicKey).key,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext:encrypted.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
 const response=await new Promise((resolve,reject)=>{
  let text='',failed=false;
  const socket=tls.connect({host:profile.host,port:profile.port,servername:profile.tlsServerName,rejectUnauthorized:false,minVersion:'TLSv1.2'});
  function failure(error){failed=true;socket.destroy();reject(error);}
  socket.setTimeout(5000,()=>failure(Error('TEST_TIMEOUT')));
  socket.once('secureConnect',()=>{try{const cert=socket.getPeerCertificate();assert.equal(fixture.sha256(cert.raw),profile.tlsCertificateSha256);assert.equal(tls.checkServerIdentity(profile.tlsServerName,cert),undefined);assert.ok(Date.now()>=Date.parse(cert.valid_from)&&Date.now()<Date.parse(cert.valid_to));socket.write(JSON.stringify(frame)+'\n');}catch(e){failure(e);}});
  socket.on('data',chunk=>{text+=chunk.toString();if(text.length>1024*1024)failure(Error('TEST_LIMIT'));});
  socket.once('error',failure);socket.once('close',()=>{if(!failed)resolve(text);});
 });
 const out=JSON.parse(response);assert.equal(out.requestId,requestId);assert.notEqual(out.nonce,frame.nonce);
 const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(out.nonce,'base64'));decipher.setAAD(transport.Aad('RESPONSE',requestId,profile.serverKeyId));decipher.setAuthTag(Buffer.from(out.tag,'base64'));
 return JSON.parse(Buffer.concat([decipher.update(Buffer.from(out.ciphertext,'base64')),decipher.final()]).toString('utf8'));
}
(async()=>{
 try{
  server=transport.CreateServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));process.env.DESKTOP_PUBLIC_PORT=String(server.address().port);profile=keys.Profile();
  const boot=require('../services/desktopBootstrap'),ops=require('../services/desktopSecurityOperations');
  for(const component of ['A','B']){const artifact=boot.Publish(component,'88.0.0',fixture.PE(component,authority.DOMAIN));ops.SetContract({expectedRevision:ops.Revision(),artifactId:artifact.id,contract:{version:1,evidenceVersion:1,minApiSlots:167,maxApiSlots:167,requiredChecks:['ownImage','apiStorage','mitigations']}},'WIRE_TEST');}
  ops.SetControls({expectedRevision:ops.Revision(),requireBuildContract:true},'WIRE_TEST');
  const started=fixture.Begin(device);fixture.Download(started.begin);
  const aCtx={action:'challenge',stage:'A',sessionId:started.begin.flowId,sessionToken:started.begin.downloadTicket,machineId:device.machineId,intent:'finish',binding:authority.Binding(started.begin.flowId,started.begin.release.sha256)};
  const ac=await Round(aCtx);assert.equal(ac.ok,true);
  const baseline=boot.AuthenticateIntegrityReport(aCtx).integrityArtifact;
  const aPayload=JSON.stringify({version:1,measurement:'MEASURED',fileSha256:baseline.sha256,fileCrc64:baseline.crc64,codeSha256:baseline.codeSha256,codeCrc64:baseline.codeCrc64,apiSealed:true,apiSlots:167,dynamicCode:'ALLOWED',cfg:'DISABLED'});
  const aSubmit=await Round({...aCtx,action:'submit',challengeId:ac.data.challengeId,payload:aPayload,signature:fixture.Sign(device,authority.Canonical(aCtx,ac.data,aPayload))});assert.equal(aSubmit.data.status,'PASS');
  const session=fixture.Claim(device,started.begin,fixture.Finish(device,started.begin));const ctx={action:'challenge',stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId,intent:'verify',binding:authority.Binding('wire-test',fixture.sha256('payload'))};
  const first=await Round(ctx);assert.equal(first.ok,true,JSON.stringify(first));assert.equal(Object.keys(first.data).length,8);
  const payload=JSON.stringify({version:1,measurement:'MEASURED',fileSha256:session.release.sha256,fileCrc64:session.release.crc64,codeSha256:session.release.codeSha256,codeCrc64:session.release.codeCrc64,apiSealed:true,apiSlots:167,dynamicCode:'ALLOWED',cfg:'DISABLED'});
  const proof={...ctx,action:'submit',challengeId:first.data.challengeId,payload,signature:fixture.Sign(device,authority.Canonical(ctx,first.data,payload))};
  const submitted=await Round(proof);assert.equal(submitted.ok,true,JSON.stringify(submitted));assert.equal(submitted.data.status,'PASS');assert.equal(submitted.data.attested,false);
  const replay=await Round(proof);assert.equal(replay.ok,false);assert.equal(replay.error,'SECURITY_CHALLENGE_INVALID');
  const invalid=await Round({...ctx,machineId:'0'.repeat(64)});assert.equal(invalid.ok,false);assert.equal(invalid.error,'BOOTSTRAP_SESSION_INVALID');
  const wrongSlotsChallenge=await Round(ctx),wrongSlots=JSON.stringify({...JSON.parse(payload),apiSlots:1});
  const wrongSlotsResult=await Round({...ctx,action:'submit',challengeId:wrongSlotsChallenge.data.challengeId,payload:wrongSlots,signature:fixture.Sign(device,authority.Canonical(ctx,wrongSlotsChallenge.data,wrongSlots))});
  assert.equal(wrongSlotsResult.data.proceed,false);assert.equal(wrongSlotsResult.data.reason,'API_SLOT_COUNT_MISMATCH');
  console.log('Security wire PASS: new-protocol A/finish gate and B build-contract slot check, TLS pin/name/time, encrypted challenge+signed submit, replay rejection, wrong-machine rejection. No Windows binary executed.');
 }finally{if(server)await new Promise(resolve=>server.close(resolve));fs.rmSync(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
