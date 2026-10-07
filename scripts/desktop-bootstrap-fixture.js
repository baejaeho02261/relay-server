'use strict';
const sha512=value=>require('node:crypto').createHash('sha512').update(value).digest('hex');
// Synthetic executable fixtures exercise the production publisher and complete
// bootstrap protocol. They are test data, never native runtime bypasses.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const sha256=value=>crypto.createHash('sha256').update(value).digest('hex');
const {Crc64,CodeImage}=require('../services/desktopIntegrity');
const cache=new Map(),requests=new Map(),remoteEvidence=new Map();

function PE(component,marker='fixture'){const bytes=require('./crc-pe-fixture').crcPeFixture(component+':'+String(marker)+' GAME-CONNECT-4 GAME-AUTHORITY-V2'),pe=bytes.readUInt32LE(0x3c),opt=pe+24;bytes.writeUInt16LE(0x22,pe+22);bytes.writeUInt16LE(2,opt+68);bytes.writeUInt16LE(0x8160,opt+70);return bytes;}
function Device(){
 const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),bytes=require('../services/connectTransportKey').PublicBlob(publicKey);
 return {privateKey,publicKey:bytes.toString('base64'),deviceId:sha256(bytes).toUpperCase(),machineId:crypto.randomBytes(32).toString('hex').toUpperCase()};
}
function Sign(device,canonical){return crypto.sign('sha256',Buffer.from(canonical,'utf8'),{key:device.privateKey,padding:crypto.constants.RSA_PKCS1_PADDING}).toString('base64');}
function Config(bytes){
 const magic=Buffer.from('GAMEA80CONFIG!','ascii'),footerLength=magic.length+4;
 assert.deepEqual(bytes.subarray(-magic.length),magic);const length=bytes.readUInt32LE(bytes.length-footerLength);
 assert.ok(length>0&&length<bytes.length-footerLength);return JSON.parse(bytes.subarray(bytes.length-footerLength-length,bytes.length-footerLength).toString('utf8'));
}
function Publish(){
 const bootstrap=require('../services/desktopBootstrap');process.env.DESKTOP_PUBLIC_HOST||='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT||='29131';
 const overview=bootstrap.Overview();if(!overview.artifacts.A)bootstrap.Publish('A','80.0.0',PE('A'));if(!overview.artifacts.B)bootstrap.Publish('B','80.0.0',PE('B'));
 return bootstrap;
}
function Begin(device,options={}){
 const bootstrap=Publish(),issue=bootstrap.IssueLauncher({requestId:crypto.randomUUID(),label:'Bootstrap test'},'TEST'),bytes=bootstrap.LauncherBytes(issue.launcherId),config=Config(bytes);
 const body={action:'begin',requestId:crypto.randomUUID(),launcherId:issue.launcherId,launcherTicket:config.launcherTicket,launcherSha512:sha512(bytes),launcherCrc64:Crc64(bytes),aCodeSha512:CodeImage(bytes).sha512,aCodeCrc64:CodeImage(bytes).crc64,machineId:device.machineId,publicKey:device.publicKey,deviceId:device.deviceId,...options};
 return {issue,bytes,config,body,begin:bootstrap.Execute(body)};
}
function Download(begin){
 const bootstrap=require('../services/desktopBootstrap'),chunks=[];let offset=0;
 while(offset<begin.release.size){const out=bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset});assert.equal(out.offset,offset);const bytes=Buffer.from(out.data,'base64');assert.ok(bytes.length>0);assert.ok(bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
 const bytes=Buffer.concat(chunks);assert.equal(bytes.length,begin.release.size);assert.equal(sha512(bytes),begin.release.sha512);assert.equal(Crc64(bytes),begin.release.crc64);return bytes;
}
// These helpers perform the real nonce/signature exchange for synthetic
// pristine fixtures. They never disable production policy or synthesize PASS.
function AuthorityEvidence(b){return {version:1,hashVersion:3,measurement:'MEASURED',fileSha512:b.sha512,fileCrc64:b.crc64,codeSha512:b.codeSha512,codeCrc64:b.codeCrc64,codeXxh3_128:b.codeXxh3_128,codeBlake3:b.codeBlake3,crcLayers:b.crcLayers,apiSealed:true,apiSlots:60,dynamicCode:'ALLOWED',cfg:'DISABLED'};}
function Observe(device,context){
 const auth=require('../services/desktopSecurityAuthority'),b=require('../services/desktopBootstrap').AuthenticateIntegrityReport(context).integrityArtifact;
 const challenge=auth.Execute({...context,action:'challenge'}),payload=JSON.stringify(AuthorityEvidence(b));
 return auth.Execute({...context,action:'submit',challengeId:challenge.challengeId,payload,signature:Sign(device,auth.Canonical(context,challenge,payload))});
}
function ObserveFinish(device,begin){return Observe(device,{stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:device.machineId,intent:'finish',binding:require('../services/desktopSecurityAuthority').Binding(begin.flowId,begin.release.sha512)});}
function ObserveLicense(device,action,requestId,payloadHash,payload){
 if(action==='release'||!payload.bootstrapSessionId||!payload.bootstrapSessionToken)return;
 const b=require('../services/desktopBootstrap'),row=Object.values(b.Initialize().flows).find(r=>r.sessionId===payload.bootstrapSessionId);
 // Invalid/closed capabilities are left for the production authorization gate.
 if(!row||row.status!=='CLAIMED'||row.deviceId!==device.deviceId||row.machineId!==device.machineId||sha256(payload.bootstrapSessionToken)!==row.sessionHash)return;
 return Observe(device,{stage:'B',sessionId:payload.bootstrapSessionId,sessionToken:payload.bootstrapSessionToken,machineId:device.machineId,intent:action==='overlay'?'verify':action,binding:require('../services/desktopSecurityAuthority').Binding(requestId,payloadHash)});
}
function Gate(device,session){const binding=require('../services/desktopSecurityAuthority').Binding('fixture-gate',session.release.sha512);Observe(device,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId,intent:'verify',binding});return require('../services/desktopBootstrap').Gate(session.sessionId,session.sessionToken,device.deviceId,{...Evidence(device,session),securityIntent:'verify',securityBinding:binding});}
function Finish(device,begin,observe=true){if(observe)ObserveFinish(device,begin);return require('../services/desktopBootstrap').Execute({action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha512:begin.release.sha512,crc64:begin.release.crc64,aCodeSha512:begin.finishCanonical.split('\n')[5],aCodeCrc64:begin.finishCanonical.split('\n')[6],signature:Sign(device,begin.finishCanonical)});}
function Claim(device,begin,finish){return require('../services/desktopBootstrap').Execute({action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,signature:Sign(device,finish.claimCanonical),binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64});}
function Session(device,credential=''){
 // Activation proof stays on the exact A/B session that consumed its key.
 if(credential){const row=Object.values(require('../services/desktopLicenses').DB().licenses).find(item=>item.tokenHash===sha256(credential)&&item.deviceId===device.deviceId);if(row?.bootstrapSessionId){const prior=[...cache.entries()].find(([name,value])=>name.startsWith(device.deviceId+':')&&value.sessionId===row.bootstrapSessionId);assert.ok(prior,'The fixture must retain the original activation session');return prior[1];}}
 const key=device.deviceId+':'+sha256(credential);let session=cache.get(key);if(session&&session.expiresAt>Date.now()+1000){try{Gate(device,session);return session;}catch(_) {}}
 const {begin}=Begin(device);Download(begin);session=Claim(device,begin,Finish(device,begin));cache.set(key,session);return session;
}
function Evidence(device,session){return {machineId:device.machineId,binarySha512:session.release.sha512,binaryCrc64:session.release.crc64,codeSha512:session.release.codeSha512,codeCrc64:session.release.codeCrc64};}
function LicensePayload(device,payload,requestId){
 if(payload.bootstrapSessionId&&payload.bootstrapSessionToken){const row=Object.values(require('../services/desktopBootstrap').Initialize().flows).find(item=>item.sessionId===payload.bootstrapSessionId),artifact=require('../services/desktopBootstrap').Initialize().artifacts[row?.releaseId];return {machineId:device.machineId,binarySha512:artifact?.sha512||'0'.repeat(128),binaryCrc64:artifact?.crc64||'0'.repeat(16),codeSha512:artifact?.codeSha512||'0'.repeat(128),codeCrc64:artifact?.codeCrc64||'0'.repeat(16),...payload};}
 const key=requestId?device.deviceId+':'+requestId:'',session=key&&requests.get(key)||Session(device,payload.licenseKey||payload.activationToken||'');
 if(key)requests.set(key,session);return {...Evidence(device,session),...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken};
}
async function TcpOperation(profile,operation,body){
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),requestId=crypto.randomUUID(),aad=direction=>Buffer.from(['GAME-CONNECT-4',direction,requestId,profile.serverKeyId].join('\n'));
 const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(aad('REQUEST'));const clear=Buffer.from(JSON.stringify({operation,body})),ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);
 const frame={v:1,keyId:profile.serverKeyId,requestId,wrappedKey:crypto.publicEncrypt({key:require('../services/desktopLicenses').ParseKey(profile.serverPublicKey).key,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
 const raw=await new Promise((resolve,reject)=>{const tls=require('node:tls'),socket=tls.connect({port:profile.port,host:profile.host,servername:profile.tlsServerName,rejectUnauthorized:false,minVersion:'TLSv1.2'});let reply='';socket.setTimeout(5000,()=>{socket.destroy();reject(Error('BOOTSTRAP_TEST_TIMEOUT'));});socket.once('secureConnect',()=>{const cert=socket.getPeerCertificate(),at=Date.now();if(!cert.raw||sha256(cert.raw)!==profile.tlsCertificateSha256||tls.checkServerIdentity(profile.tlsServerName,cert)||at<Date.parse(cert.valid_from)||at>Date.parse(cert.valid_to)){socket.destroy();reject(Error('BOOTSTRAP_TEST_TLS_PIN'));return;}socket.write(JSON.stringify(frame)+'\n');});socket.on('data',data=>{reply+=data.toString();if(reply.length>1024*1024){socket.destroy();reject(Error('BOOTSTRAP_TEST_RESPONSE_LIMIT'));}});socket.once('error',reject);socket.once('close',()=>resolve(reply));});
 const response=JSON.parse(raw);assert.equal(response.v,1);assert.equal(response.requestId,requestId);assert.notEqual(response.nonce,frame.nonce);const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(response.nonce,'base64'));decipher.setAAD(aad('RESPONSE'));decipher.setAuthTag(Buffer.from(response.tag,'base64'));
 const result=JSON.parse(Buffer.concat([decipher.update(Buffer.from(response.ciphertext,'base64')),decipher.final()]).toString('utf8'));assert.equal(result.ok,true,JSON.stringify(result));return result.data;
}
async function TcpBootstrap(profile,body){return TcpOperation(profile,'bootstrap',body);}
async function RemoteObserve(profile,device,context,bytes){
 const auth=require('../services/desktopSecurityAuthority'),file=require('../services/desktopIntegrity').Digests(bytes),code=CodeImage(bytes);
 const evidence=AuthorityEvidence({...file,codeSha512:code.sha512,codeCrc64:code.crc64,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3,crcLayers:code.crcLayers});
 const challenge=await TcpOperation(profile,'security',{...context,action:'challenge'}),payload=JSON.stringify(evidence);
 return TcpOperation(profile,'security',{...context,action:'submit',challengeId:challenge.challengeId,payload,signature:Sign(device,auth.Canonical(context,challenge,payload))});
}
async function RemoteObserveLicense(profile,device,session,action,requestId,payloadHash){
 if(action==='release')return;
 const bytes=remoteEvidence.get(session.sessionId);assert.ok(bytes,'RemoteSession must retain measured B fixture bytes');
 return RemoteObserve(profile,device,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId,intent:action==='overlay'?'verify':action,binding:require('../services/desktopSecurityAuthority').Binding(requestId,payloadHash)},bytes);
}
async function RemoteSession(device,launcher){
 const settings=Config(launcher),call=body=>TcpBootstrap(settings.profile,body),begin=await call({action:'begin',requestId:crypto.randomUUID(),launcherId:settings.launcherId,launcherTicket:settings.launcherTicket,launcherSha512:sha512(launcher),launcherCrc64:Crc64(launcher),aCodeSha512:CodeImage(launcher).sha512,aCodeCrc64:CodeImage(launcher).crc64,machineId:device.machineId,publicKey:device.publicKey,deviceId:device.deviceId}),chunks=[];
 for(let offset=0;offset<begin.release.size;){const chunk=await call({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset}),bytes=Buffer.from(chunk.data,'base64');assert.equal(chunk.offset,offset);assert.ok(bytes.length>0&&bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
 const binary=Buffer.concat(chunks);assert.equal(binary.length,begin.release.size);assert.equal(sha512(binary),begin.release.sha512);
 await RemoteObserve(settings.profile,device,{stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:device.machineId,intent:'finish',binding:require('../services/desktopSecurityAuthority').Binding(begin.flowId,begin.release.sha512)},launcher);
 const finish=await call({action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha512:begin.release.sha512,crc64:begin.release.crc64,aCodeSha512:begin.finishCanonical.split('\n')[5],aCodeCrc64:begin.finishCanonical.split('\n')[6],signature:Sign(device,begin.finishCanonical)});
 const session=await call({action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,signature:Sign(device,finish.claimCanonical),binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64});remoteEvidence.set(session.sessionId,binary);return session;
}
module.exports={PE,Device,Sign,Config,Publish,Begin,Download,Finish,Claim,Session,LicensePayload,TcpBootstrap,RemoteSession,Observe,ObserveFinish,ObserveLicense,Gate,TcpOperation,RemoteObserve,RemoteObserveLicense,sha256,sha512,Crc64,CodeImage,Evidence};
