'use strict';
// Synthetic executable fixtures exercise the production publisher and complete
// bootstrap protocol. They are test data, never native runtime bypasses.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const sha256=value=>crypto.createHash('sha256').update(value).digest('hex');
const cache=new Map(),requests=new Map();

function PE(component,marker='fixture'){
 const bytes=Buffer.alloc(1024),pe=0x80,opt=pe+24,section=opt+240;
 bytes.write('MZ');bytes.writeUInt32LE(pe,0x3c);bytes.write('PE\0\0',pe,'binary');
 bytes.writeUInt16LE(0x8664,pe+4);bytes.writeUInt16LE(1,pe+6);bytes.writeUInt16LE(240,pe+20);bytes.writeUInt16LE(0x22,pe+22);
 bytes.writeUInt16LE(0x20b,opt);bytes.writeUInt32LE(512,opt+4);bytes.writeUInt32LE(0x1000,opt+16);bytes.writeUInt32LE(0x1000,opt+20);
 bytes.writeBigUInt64LE(0x140000000n,opt+24);bytes.writeUInt32LE(0x1000,opt+32);bytes.writeUInt32LE(0x200,opt+36);
 bytes.writeUInt16LE(6,opt+40);bytes.writeUInt16LE(6,opt+48);bytes.writeUInt32LE(0x2000,opt+56);bytes.writeUInt32LE(512,opt+60);
 bytes.writeUInt16LE(component==='A'?2:3,opt+68);bytes.writeUInt16LE(0x8160,opt+70);bytes.writeBigUInt64LE(0x100000n,opt+72);
 bytes.writeBigUInt64LE(0x1000n,opt+80);bytes.writeBigUInt64LE(0x100000n,opt+88);bytes.writeBigUInt64LE(0x1000n,opt+96);bytes.writeUInt32LE(16,opt+108);
 bytes.write('.text',section);bytes.writeUInt32LE(512,section+8);bytes.writeUInt32LE(0x1000,section+12);bytes.writeUInt32LE(512,section+16);bytes.writeUInt32LE(512,section+20);bytes.writeUInt32LE(0x60000020,section+36);
 bytes[512]=0xc3;bytes.write(String(marker).slice(0,400),528,'utf8');return bytes;
}
function Device(){
 const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),bytes=require('../services/connectTransportKey').PublicBlob(publicKey);
 return {privateKey,publicKey:bytes.toString('base64'),deviceId:sha256(bytes).toUpperCase()};
}
function Sign(device,canonical){return crypto.sign('sha256',Buffer.from(canonical,'utf8'),{key:device.privateKey,padding:crypto.constants.RSA_PKCS1_PADDING}).toString('base64');}
function Config(bytes){
 const magic=Buffer.from('MOAPLAYA80CONFIG!','ascii'),footerLength=magic.length+4;
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
 const body={action:'begin',requestId:crypto.randomUUID(),launcherId:issue.launcherId,launcherTicket:config.launcherTicket,launcherSha256:sha256(bytes),publicKey:device.publicKey,deviceId:device.deviceId,...options};
 return {issue,bytes,config,body,begin:bootstrap.Execute(body)};
}
function Download(begin){
 const bootstrap=require('../services/desktopBootstrap'),chunks=[];let offset=0;
 while(offset<begin.release.size){const out=bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset});assert.equal(out.offset,offset);const bytes=Buffer.from(out.data,'base64');assert.ok(bytes.length>0);assert.ok(bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
 const bytes=Buffer.concat(chunks);assert.equal(bytes.length,begin.release.size);assert.equal(sha256(bytes),begin.release.sha256);return bytes;
}
function Finish(device,begin){return require('../services/desktopBootstrap').Execute({action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha256:begin.release.sha256,signature:Sign(device,begin.finishCanonical)});}
function Claim(device,begin,finish){return require('../services/desktopBootstrap').Execute({action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,signature:Sign(device,finish.claimCanonical),binarySha256:begin.release.sha256});}
function Session(device,credential=''){
 const key=device.deviceId+':'+sha256(credential);let session=cache.get(key);if(session&&session.expiresAt>Date.now()+1000){try{require('../services/desktopBootstrap').Gate(session.sessionId,session.sessionToken,device.deviceId);return session;}catch(_) {}}
 const {begin}=Begin(device);Download(begin);session=Claim(device,begin,Finish(device,begin));cache.set(key,session);return session;
}
function LicensePayload(device,payload,requestId){
 if(payload.bootstrapSessionId&&payload.bootstrapSessionToken)return payload;
 const key=requestId?device.deviceId+':'+requestId:'',session=key&&requests.get(key)||Session(device,payload.licenseKey||payload.activationToken||'');
 if(key)requests.set(key,session);return {...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken};
}
async function TcpBootstrap(profile,body){
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),requestId=crypto.randomUUID(),aad=direction=>Buffer.from(['MOAPLAY-CONNECT-1',direction,requestId,profile.serverKeyId].join('\n'));
 const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(aad('REQUEST'));const clear=Buffer.from(JSON.stringify({operation:'bootstrap',body})),ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);
 const frame={v:1,keyId:profile.serverKeyId,requestId,wrappedKey:crypto.publicEncrypt({key:require('../services/desktopLicenses').ParseKey(profile.serverPublicKey).key,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
 const raw=await new Promise((resolve,reject)=>{const socket=require('node:net').connect(profile.port,profile.host);let reply='';socket.setTimeout(5000,()=>{socket.destroy();reject(Error('BOOTSTRAP_TEST_TIMEOUT'));});socket.once('connect',()=>socket.write(JSON.stringify(frame)+'\n'));socket.on('data',data=>{reply+=data.toString();if(reply.length>1024*1024){socket.destroy();reject(Error('BOOTSTRAP_TEST_RESPONSE_LIMIT'));}});socket.once('error',reject);socket.once('close',()=>resolve(reply));});
 const response=JSON.parse(raw);assert.equal(response.v,1);assert.equal(response.requestId,requestId);assert.notEqual(response.nonce,frame.nonce);const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(response.nonce,'base64'));decipher.setAAD(aad('RESPONSE'));decipher.setAuthTag(Buffer.from(response.tag,'base64'));
 const result=JSON.parse(Buffer.concat([decipher.update(Buffer.from(response.ciphertext,'base64')),decipher.final()]).toString('utf8'));assert.equal(result.ok,true,JSON.stringify(result));return result.data;
}
async function RemoteSession(device,launcher){
 const settings=Config(launcher),call=body=>TcpBootstrap(settings.profile,body),begin=await call({action:'begin',requestId:crypto.randomUUID(),launcherId:settings.launcherId,launcherTicket:settings.launcherTicket,launcherSha256:sha256(launcher),publicKey:device.publicKey,deviceId:device.deviceId}),chunks=[];
 for(let offset=0;offset<begin.release.size;){const chunk=await call({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset}),bytes=Buffer.from(chunk.data,'base64');assert.equal(chunk.offset,offset);assert.ok(bytes.length>0&&bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
 const binary=Buffer.concat(chunks);assert.equal(binary.length,begin.release.size);assert.equal(sha256(binary),begin.release.sha256);
 const finish=await call({action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha256:begin.release.sha256,signature:Sign(device,begin.finishCanonical)});
 return call({action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,signature:Sign(device,finish.claimCanonical),binarySha256:begin.release.sha256});
}
module.exports={PE,Device,Sign,Config,Publish,Begin,Download,Finish,Claim,Session,LicensePayload,TcpBootstrap,RemoteSession,sha256};
