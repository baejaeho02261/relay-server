'use strict';
// Real loopback production TLS listener, RSA/OAEP worker and AES/GCM envelopes.
// This is Node server/wire evidence; it does not execute Delphi or Schannel.
const {test}=require('node:test');
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const tls=require('node:tls'),net=require('node:net');

test('production TLS/envelope boundaries retain no socket admission after completion or rejection',async t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'peace-tls-boundaries-'));
 Object.assign(process.env,{DATA_DIR:directory,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
 require('../../core/peace.utilities').EnsureDirs();
 const transport=require('../../services/network/peace.desktop-connect');
 const keys=require('../../services/network/peace.connect-transport-key');
 const work=require('../../services/runtime/peace.desktop-work-queue');
 const boot=require('../../services/bootstrap/peace.desktop-bootstrap');
 const clients=new Set(),secrets=new Set();let server,profile;
 const pause=()=>new Promise(resolve=>setTimeout(resolve,10));
 async function AdmissionCount(expected){
  const until=performance.now()+2500;
  while(work.connections.active!==expected&&performance.now()<until)await pause();
  assert.equal(work.connections.active,expected,'all actual server socket close handlers must release admission');
 }
 function Envelope(payload={operation:'challenge',body:{}},requestId=crypto.randomUUID()){
  const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12);secrets.add(key);
  const clear=Buffer.from(JSON.stringify(payload)),cipher=crypto.createCipheriv('aes-256-gcm',key,nonce,{authTagLength:16});
  cipher.setAAD(transport.Aad('REQUEST',requestId,profile.serverKeyId));
  let ciphertext;
  try{ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);}finally{clear.fill(0);}
  const recipient=require('../../services/licensing/peace.desktop-licenses').ParseKey(profile.serverPublicKey).key;
  const frame={v:1,keyId:profile.serverKeyId,requestId,wrappedKey:crypto.publicEncrypt({key:recipient,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
  return {key,frame,wire:Buffer.from(JSON.stringify(frame)+'\n')};
 }
 function OpenResponse(envelope,bytes,{direction='RESPONSE',requestId=envelope.frame.requestId,keyId=envelope.frame.keyId}={}){
  const frame=JSON.parse(bytes.toString('utf8'));
  assert.equal(frame.v,1);assert.equal(frame.requestId,envelope.frame.requestId);
  assert.notEqual(frame.nonce,envelope.frame.nonce);
  const decipher=crypto.createDecipheriv('aes-256-gcm',envelope.key,Buffer.from(frame.nonce,'base64'),{authTagLength:16});
  decipher.setAAD(transport.Aad(direction,requestId,keyId));decipher.setAuthTag(Buffer.from(frame.tag,'base64'));
  const pieces=[];let clear;
  try{pieces.push(decipher.update(Buffer.from(frame.ciphertext,'base64')));pieces.push(decipher.final());clear=Buffer.concat(pieces);return JSON.parse(clear.toString('utf8'));}
  finally{for(const piece of pieces)piece.fill(0);clear?.fill(0);}
 }
 function Wire(bytes,{fragment=0,finishInput=false}={}){
  return new Promise((resolve,reject)=>{
   const socket=tls.connect({host:profile.host,port:profile.port,servername:profile.tlsServerName,minVersion:'TLSv1.2',maxVersion:'TLSv1.2',rejectUnauthorized:false});
   clients.add(socket);const chunks=[];let failure=null,secure=false,total=0,writes=0;
   const timer=setTimeout(()=>{failure=Error('BOUNDARY_TEST_DEADLINE');socket.destroy();},4500);
   socket.once('secureConnect',()=>{
    try{
     const cert=socket.getPeerCertificate();
     assert.equal(crypto.createHash('sha256').update(cert.raw).digest('hex'),profile.tlsCertificateSha256);
     assert.equal(tls.checkServerIdentity(profile.tlsServerName,cert),undefined);
     assert.ok(Date.now()>=Date.parse(cert.valid_from)&&Date.now()<Date.parse(cert.valid_to));
     assert.equal(socket.getProtocol(),'TLSv1.2');secure=true;
     const send=offset=>{
      if(socket.destroyed)return;
      if(offset===bytes.length){if(finishInput)socket.end();return;}
      const next=fragment?Math.min(bytes.length,offset+fragment):bytes.length;writes++;
      socket.write(bytes.subarray(offset,next),error=>{if(error){failure=error;socket.destroy();}else setImmediate(send,next);});
     };
     if(fragment)assert.equal(socket.setMaxSendFragment(512),true);
     send(0);
    }catch(error){failure=error;socket.destroy();}
   });
   socket.on('data',chunk=>{total+=chunk.length;if(total>transport.MAX_RESPONSE_FRAME){failure=Error('BOUNDARY_RESPONSE_LIMIT');socket.destroy();}else chunks.push(chunk);});
   socket.on('error',error=>{if(error.code!=='ECONNRESET')failure=error;});
   socket.once('close',()=>{clearTimeout(timer);clients.delete(socket);const bytes=Buffer.concat(chunks);for(const chunk of chunks)chunk.fill(0);failure?reject(failure):resolve({bytes,secure,writes});});
  });
 }
 async function EncryptedDenial(envelope,options){
  const result=await Wire(envelope.wire,options);assert.equal(result.secure,true);
  assert.equal(OpenResponse(envelope,result.bytes).error,'INPUT_INVALID');
  assert.equal(result.bytes.includes(Buffer.from('INPUT_INVALID')),false);
  await AdmissionCount(0);return result;
 }
 try{
  server=transport.CreateServer();
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  process.env.DESKTOP_PUBLIC_PORT=String(server.address().port);profile=keys.Profile();
  await t.test('bad authentication releases its request reservation over a real socket; accepted denial remains replay-protected',async()=>{
   const envelope=Envelope(),bad={...envelope.frame},tag=Buffer.from(bad.tag,'base64');tag[0]^=1;bad.tag=tag.toString('base64');
   assert.equal((await Wire(Buffer.from(JSON.stringify(bad)+'\n'))).bytes.length,0);await AdmissionCount(0);
   await EncryptedDenial(envelope);
   assert.equal((await Wire(envelope.wire)).bytes.length,0);await AdmissionCount(0);
  });
  await t.test('actual production response authentication binds expected request ID, response direction and server key',async()=>{
   const envelope=Envelope(),{bytes}=await EncryptedDenial(envelope);
   for(const context of [{requestId:crypto.randomUUID()},{direction:'REQUEST'},{keyId:'0'.repeat(64)}])assert.throws(()=>OpenResponse(envelope,bytes,context));
   const changed=JSON.parse(bytes.toString('utf8'));changed.requestId=crypto.randomUUID();
   assert.throws(()=>OpenResponse(envelope,Buffer.from(JSON.stringify(changed))),{code:'ERR_ASSERTION'});
   assert.equal(OpenResponse(envelope,bytes).ok,false,'failed context checks do not mutate the retained response fixture');
  });
  await t.test('one encrypted frame survives many TLS writes and a CRLF boundary',async()=>{
   const envelope=Envelope({operation:'challenge',body:{padding:'한글'.repeat(1500)}});
   envelope.wire=Buffer.from(JSON.stringify(envelope.frame)+'\r\n');
   const result=await EncryptedDenial(envelope,{fragment:127});assert.ok(result.writes>50);
  });
  await t.test('two frames in one write are rejected before either request ID is consumed',async()=>{
   const first=Envelope(),second=Envelope();
   assert.equal((await Wire(Buffer.concat([first.wire,second.wire]))).bytes.length,0);await AdmissionCount(0);
   await EncryptedDenial(first);await EncryptedDenial(second);
  });
  await t.test('truncated JSON and missing delimiter at authenticated peer EOF release admission without consuming the ID',async()=>{
   for(const trim of [1,27]){
    const envelope=Envelope();
    assert.equal((await Wire(envelope.wire.subarray(0,envelope.wire.length-trim),{finishInput:true})).bytes.length,0);
    await AdmissionCount(0);await EncryptedDenial(envelope);
   }
  });
  await t.test('response ciphertext truncation and changed tag release no parsed JSON',async()=>{
   const envelope=Envelope(),{bytes}=await EncryptedDenial(envelope),response=JSON.parse(bytes.toString('utf8'));
   for(const field of ['ciphertext','tag']){
    const value=Buffer.from(response[field],'base64'),changed={...response};
    changed[field]=(field==='ciphertext'?value.subarray(0,value.length-1):Buffer.alloc(16)).toString('base64');
    assert.throws(()=>OpenResponse(envelope,Buffer.from(JSON.stringify(changed))));
   }
  });
  await t.test('Stop closes raw pre-handshake and authenticated partial-frame sockets; a fresh connection remains usable',async()=>{
   const raw=net.connect(profile.port,profile.host);clients.add(raw);raw.on('error',()=>{});
   const rawClosed=new Promise(resolve=>raw.once('close',()=>{clients.delete(raw);resolve();}));
   await new Promise((resolve,reject)=>{raw.once('connect',resolve);raw.once('error',reject);});
   const partial=tls.connect({host:profile.host,port:profile.port,servername:profile.tlsServerName,minVersion:'TLSv1.2',maxVersion:'TLSv1.2',rejectUnauthorized:false});
   clients.add(partial);partial.on('error',()=>{});
   const partialClosed=new Promise(resolve=>partial.once('close',()=>{clients.delete(partial);resolve();}));
   await new Promise((resolve,reject)=>{partial.once('secureConnect',resolve);partial.once('error',reject);});
   partial.write('{"v":');await AdmissionCount(2);
   await transport.Stop();
   let stopTimer;
   try{await Promise.race([Promise.all([rawClosed,partialClosed]),new Promise((_,reject)=>{stopTimer=setTimeout(()=>reject(Error('STOP_DID_NOT_CLOSE_PEERS')),2500);})]);}
   finally{clearTimeout(stopTimer);}
   await AdmissionCount(0);assert.equal(clients.size,0);
   // CreateServer is caller-owned. Stop drains its registered sockets; this
   // test explicitly closes/recreates the listener instead of claiming Start.
   await new Promise(resolve=>server.close(resolve));
   server=transport.CreateServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
   process.env.DESKTOP_PUBLIC_PORT=String(server.address().port);profile=keys.Profile();
   await EncryptedDenial(Envelope());
  });
 }finally{
  for(const socket of clients)socket.destroy();
  await transport.Stop();if(server?.listening)await new Promise(resolve=>server.close(resolve));
  boot.Stop();await Promise.all([work.auth,work.pe,work.proof,work.renewalProof,work.tpmAttestation].map(queue=>queue.close()));
  for(const secret of secrets)secret.fill(0);fs.rmSync(directory,{recursive:true,force:true});
 }
});
