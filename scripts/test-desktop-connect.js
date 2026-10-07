'use strict';
const sha512=value=>require('node:crypto').createHash('sha512').update(value).digest('hex');
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net'),tls=require('node:tls');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-connect-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';process.env.HA_ENABLED='0';
for(const name of ['DESKTOP_PUBLIC_HOST','DESKTOP_PUBLIC_PORT','RAILWAY_TCP_PROXY_DOMAIN','RAILWAY_TCP_PROXY_PORT'])delete process.env[name];
require('../core/utils').EnsureDirs();
const desktop=require('../services/desktopLicenses'),transport=require('../services/desktopConnect'),keys=require('../services/connectTransportKey'),state=require('../core/state');
const bootstrapFixture=require('./desktop-bootstrap-fixture');
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
function Device(){const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),blob=keys.PublicBlob(publicKey);return {privateKey,publicKey:blob.toString('base64'),deviceId:digest(blob).toUpperCase(),machineId:crypto.randomBytes(32).toString('hex').toUpperCase()};}
const a=Device(),b=Device(),server=transport.CreateServer();let profile,port,checks=0;
function Envelope(payload,overrides={}){
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),requestId=overrides.requestId||crypto.randomUUID(),keyId=overrides.keyId||profile.serverKeyId;
 const publicKey=overrides.publicKey||desktop.ParseKey(profile.serverPublicKey).key;
 const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce,{authTagLength:16});cipher.setAAD(transport.Aad('REQUEST',requestId,keyId));
 const ciphertext=Buffer.concat([cipher.update(Buffer.from(JSON.stringify(payload))),cipher.final()]);
 const frame={v:1,keyId,requestId,wrappedKey:crypto.publicEncrypt({key:publicKey,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
 return {key,nonce,frame,wire:JSON.stringify(frame)+'\n'};
}
function Wire(raw,timeout=4000,options={}){return new Promise((resolve,reject)=>{
 const socket=tls.connect({host:'127.0.0.1',port,servername:profile.tlsServerName,rejectUnauthorized:false,minVersion:'TLSv1.2',...options});let reply='',failure;
 socket.setTimeout(timeout,()=>{failure=Error('TEST_TIMEOUT');socket.destroy();});
 socket.on('secureConnect',()=>{
  const cert=socket.getPeerCertificate(),pin=digest(cert.raw);
  if(pin!==(options.pin||profile.tlsCertificateSha256)||tls.checkServerIdentity(profile.tlsServerName,cert)||Date.now()<Date.parse(cert.valid_from)||Date.now()>=Date.parse(cert.valid_to)){failure=Error('TEST_TLS_PIN_INVALID');socket.destroy();return;}
  assert.ok(['TLSv1.2','TLSv1.3'].includes(socket.getProtocol()));assert.match(socket.getCipher().name,/GCM/);socket.write(raw);
 });
 socket.on('data',chunk=>{reply+=chunk.toString();});socket.on('error',error=>{if(error.code!=='ECONNRESET')failure=error;});socket.on('close',()=>failure?reject(failure):resolve(reply));
});}
function PlainWire(raw){return new Promise((resolve,reject)=>{const socket=net.connect(port,'127.0.0.1');let reply=Buffer.alloc(0);socket.setTimeout(4000,()=>{socket.destroy();reject(Error('TEST_TIMEOUT'));});socket.on('connect',()=>socket.write(raw));socket.on('data',chunk=>{reply=Buffer.concat([reply,chunk]);});socket.on('error',()=>{});socket.on('close',()=>resolve(reply));});}
function Decode(envelope,raw){
 const frame=JSON.parse(raw);assert.equal(frame.v,1);assert.equal(frame.requestId,envelope.frame.requestId);assert.notEqual(frame.nonce,envelope.frame.nonce);
 const decipher=crypto.createDecipheriv('aes-256-gcm',envelope.key,Buffer.from(frame.nonce,'base64'),{authTagLength:16});decipher.setAAD(transport.Aad('RESPONSE',frame.requestId,envelope.frame.keyId));decipher.setAuthTag(Buffer.from(frame.tag,'base64'));
 return JSON.parse(Buffer.concat([decipher.update(Buffer.from(frame.ciphertext,'base64')),decipher.final()]).toString('utf8'));
}
async function Round(operation,body){const envelope=Envelope({operation,body});return Decode(envelope,await Wire(envelope.wire));}
async function Proof(device,action,payload,requestId=crypto.randomUUID()){
 payload=bootstrapFixture.LicensePayload(device,payload,requestId);
 const payloadJSON=JSON.stringify(payload),base={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:sha512(payloadJSON)},challenge=await Round('challenge',base);assert.equal(challenge.ok,true,JSON.stringify(challenge));
 const c=challenge.data,canonical=['GAME-DESKTOP-V2',action,c.challengeId,c.nonce,requestId,device.deviceId,base.payloadHash,c.expiresAt].join('\n');assert.equal(c.canonical,canonical);
 bootstrapFixture.ObserveLicense(device,action,requestId,sha512(payloadJSON),payload);
 return {...base,challengeId:c.challengeId,payloadJSON,signature:crypto.sign('sha256',Buffer.from(canonical),{key:device.privateKey,padding:crypto.constants.RSA_PKCS1_PADDING}).toString('base64')};
}
async function Call(device,action,payload,requestId){return Round('execute',await Proof(device,action,payload,requestId));}
async function Check(label,fn){await fn();checks++;console.log('PASS '+label);}
async function AdminProfile(session){let status,value;const res={writeHead(code){status=code;},end(text){value=JSON.parse(text);}};await require('../web/routes/desktopLicenseRoutes').Handle({method:'GET',pathname:'/api/desktop/connect-profile',url:new URL('http://localhost/api/desktop/connect-profile'),body:{},res,session});return {status,value};}
(async()=>{
 try{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));port=server.address().port;
  await Check('Administrator-only explicit endpoint and public pin export',async()=>{
   assert.equal((await AdminProfile({role:'viewer'})).status,403);
   assert.equal((await AdminProfile({role:'admin',id:'TEST'})).value.error,'CONNECT_PUBLIC_ENDPOINT_REQUIRED');
   process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT=String(port);
   const out=await AdminProfile({role:'admin',id:'TEST'});assert.equal(out.status,200);profile=out.value.profile;assert.equal(profile.serverKeyId,digest(Buffer.from(profile.serverPublicKey,'base64')));assert.deepEqual(Object.keys(profile).sort(),['host','port','protocol','serverKeyId','serverPublicKey','tlsCertificateSha256','tlsServerName','version']);assert.equal(profile.protocol,'GAME-CONNECT-4');assert.equal(profile.version,4);assert.match(profile.tlsCertificateSha256,/^[a-f0-9]{64}$/);assert.match(profile.tlsServerName,/^[a-f0-9]{32}\.invalid$/);
   process.env.DESKTOP_PUBLIC_HOST='https://bad.example';assert.throws(()=>keys.Profile(),/CONNECT_PUBLIC_ENDPOINT_REQUIRED/);process.env.DESKTOP_PUBLIC_HOST='::1';assert.throws(()=>keys.Profile(),/CONNECT_PUBLIC_ENDPOINT_REQUIRED/);process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';
  });
  await Check('Persisted server key is stable, private, and never silently replaced',async()=>{
   if(process.platform!=='win32')assert.equal(fs.statSync(keys.KEY_FILE).mode&0o777,0o600);
   const child=require('node:child_process'),root=path.resolve(__dirname,'..'),script="const root=process.cwd();console.log(require(root+'/services/connectTransportKey').Load().keyId);";
   assert.equal(child.execFileSync(process.execPath,['-e',script],{cwd:root,env:process.env,encoding:'utf8'}).trim(),profile.serverKeyId);
   for(const kind of ['missing','changed']){const copy=fs.mkdtempSync(path.join(os.tmpdir(),'game-connect-key-'));fs.cpSync(temp,copy,{recursive:true});if(kind==='missing')fs.unlinkSync(path.join(copy,path.basename(keys.KEY_FILE)));else fs.writeFileSync(path.join(copy,path.basename(keys.ID_FILE)),'0'.repeat(64)+'\n');const result=child.spawnSync(process.execPath,['-e',script],{cwd:root,env:{...process.env,DATA_DIR:copy},encoding:'utf8'});assert.notEqual(result.status,0);assert.match(result.stderr,/CONNECT_SERVER_KEY_(MISSING|CHANGED)/);}
  });
  await Check('TLS pin, TLS versions and AEAD-only cipher negotiation fail closed',async()=>{
   await assert.rejects(Wire('anything',4000,{pin:'0'.repeat(64)}),/TEST_TLS_PIN_INVALID/);
   await assert.rejects(Wire('anything',4000,{minVersion:'TLSv1',maxVersion:'TLSv1.1',ciphers:'ALL:@SECLEVEL=0'}));
   await assert.rejects(Wire('anything',4000,{minVersion:'TLSv1.2',maxVersion:'TLSv1.2',ciphers:'AES128-GCM-SHA512'}));
   const envelope=Envelope({operation:'challenge',body:{}});assert.equal(Decode(envelope,await Wire(envelope.wire,4000,{maxVersion:'TLSv1.2'})).error,'INPUT_INVALID');
  });
  await Check('TLS certificate identity persists and missing or changed identity never regenerates',async()=>{
   const identity=require('../services/connectTls').Load(),child=require('node:child_process'),root=path.resolve(__dirname,'..');
   assert.equal(identity.fingerprint,profile.tlsCertificateSha256);if(process.platform!=='win32')assert.equal(fs.statSync(identity.keyFile).mode&0o777,0o600);
   const script="console.log(require(require('node:path').resolve('services/connectTls')).Load().fingerprint)";assert.equal(child.execFileSync(process.execPath,['-e',script],{cwd:root,env:process.env,encoding:'utf8'}).trim(),profile.tlsCertificateSha256);
   for(const kind of ['missing','changed']){const copy=fs.mkdtempSync(path.join(os.tmpdir(),'game-connect-tls-'));try{fs.cpSync(temp,copy,{recursive:true});if(kind==='missing')fs.rmSync(path.join(copy,'connect-tls'),{recursive:true});else fs.writeFileSync(path.join(copy,'connect-tls.sha256'),'0'.repeat(64)+'\n');const out=child.spawnSync(process.execPath,['-e',script],{cwd:root,env:{...process.env,DATA_DIR:copy},encoding:'utf8'});assert.notEqual(out.status,0);assert.match(out.stderr,/CONNECT_TLS_IDENTITY_(MISSING|CHANGED)/);}finally{fs.rmSync(copy,{recursive:true,force:true});}}
  });
  await Check('Plaintext, wrong pin and wrong RSA recipient never receive success',async()=>{
   for(const raw of ['HELLO|CLIENT|old\n',JSON.stringify(Envelope({operation:'challenge',body:{}}).frame)+'\n']){const reply=await PlainWire(raw);assert.ok(!reply.toString().includes('ciphertext'));assert.ok(!reply.toString().includes('ok'));}

   assert.equal(await Wire('HELLO|CLIENT|old\n'),'');assert.equal(await Wire('{"ok":true}\n'),'');
   const wrong=Envelope({operation:'challenge',body:{}},{keyId:'0'.repeat(64)});assert.equal(await Wire(wrong.wire),'');
   const recipient=Envelope({operation:'challenge',body:{}},{publicKey:crypto.createPublicKey(b.privateKey)});assert.equal(await Wire(recipient.wire),'');
  });
  await Check('GCM rejects modified ciphertext, tag, nonce, request ID and direction',async()=>{
   for(const field of ['ciphertext','tag','nonce','requestId']){const envelope=Envelope({operation:'challenge',body:{}}),frame={...envelope.frame};if(field==='requestId')frame[field]=crypto.randomUUID();else{const value=Buffer.from(frame[field],'base64');value[0]^=1;frame[field]=value.toString('base64');}assert.equal(await Wire(JSON.stringify(frame)+'\n'),'');}
   const envelope=Envelope({operation:'challenge',body:{}}),cipher=crypto.createCipheriv('aes-256-gcm',envelope.key,envelope.nonce);cipher.setAAD(transport.Aad('RESPONSE',envelope.frame.requestId,envelope.frame.keyId));envelope.frame.ciphertext=Buffer.concat([cipher.update('{}'),cipher.final()]).toString('base64');envelope.frame.tag=cipher.getAuthTag().toString('base64');assert.equal(await Wire(JSON.stringify(envelope.frame)+'\n'),'');
  });
  await Check('Authenticated validation errors remain encrypted and outer replay is rejected',async()=>{
   const envelope=Envelope({operation:'challenge',body:{}}),raw=await Wire(envelope.wire),result=Decode(envelope,raw);assert.equal(result.ok,false);assert.equal(result.error,'INPUT_INVALID');assert.ok(!raw.includes('INPUT_INVALID'));assert.equal(await Wire(envelope.wire),'');
   assert.equal(await Wire(envelope.wire+envelope.wire),'');assert.equal(await Wire(' '.repeat(transport.MAX_FRAME+1)),'');
  });
  await Check('Real A to B bootstrap and multi-chunk artifact delivery use encrypted TCP',async()=>{
   const bootstrap=bootstrapFixture.Publish(),artifact=Buffer.concat([bootstrapFixture.PE('B'),Buffer.alloc(300000,0x5a)]);bootstrap.Publish('B','80.0.1',artifact);
   const issued=bootstrap.IssueLauncher({requestId:crypto.randomUUID(),label:'Encrypted bootstrap'},'TEST'),launcher=bootstrap.LauncherBytes(issued.launcherId),config=bootstrapFixture.Config(launcher);
   const start=await Round('bootstrap',{action:'begin',requestId:crypto.randomUUID(),launcherId:issued.launcherId,launcherTicket:config.launcherTicket,launcherSha512:sha512(launcher),launcherCrc64:bootstrapFixture.Crc64(launcher),aCodeSha512:require('../services/desktopIntegrity').CodeImage(launcher).sha512,aCodeCrc64:require('../services/desktopIntegrity').CodeImage(launcher).crc64,machineId:a.machineId,deviceId:a.deviceId,publicKey:a.publicKey});assert.equal(start.ok,true,JSON.stringify(start));const begin=start.data,chunks=[];
   for(let offset=0;offset<begin.release.size;){const out=await Round('bootstrap',{action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset});assert.equal(out.ok,true,JSON.stringify(out));const bytes=Buffer.from(out.data.data,'base64');assert.equal(out.data.offset,offset);assert.ok(bytes.length>0&&bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
   assert.ok(chunks.length>1);assert.deepEqual(Buffer.concat(chunks),artifact);assert.equal(sha512(artifact),begin.release.sha512);
   bootstrapFixture.ObserveFinish(a,begin);
   const finished=await Round('bootstrap',{action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha512:begin.release.sha512,crc64:begin.release.crc64,aCodeSha512:require('../services/desktopIntegrity').CodeImage(launcher).sha512,aCodeCrc64:require('../services/desktopIntegrity').CodeImage(launcher).crc64,signature:bootstrapFixture.Sign(a,begin.finishCanonical)});assert.equal(finished.ok,true,JSON.stringify(finished));
   const claimed=await Round('bootstrap',{action:'claim',flowId:begin.flowId,handoffToken:finished.data.handoffToken,signature:bootstrapFixture.Sign(a,finished.data.claimCanonical),binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64});assert.equal(claimed.ok,true,JSON.stringify(claimed));
   const session=claimed.data,status=await Round('bootstrap',{action:'status',sessionId:session.sessionId,sessionToken:session.sessionToken});assert.equal(status.ok,true);assert.equal(status.data.status,'CLAIMED');assert.ok(!Object.hasOwn(status.data,'sessionToken'));
   const denied=Envelope({operation:'bootstrap',body:{action:'status',sessionId:session.sessionId,sessionToken:'invalid'}}),wire=await Wire(denied.wire);assert.equal(Decode(denied,wire).error,'BOOTSTRAP_SESSION_INVALID');assert.ok(!wire.includes('BOOTSTRAP_SESSION_INVALID'));
   const reportAuth={sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:a.machineId,binarySha512:begin.release.sha512,binaryCrc64:begin.release.crc64};
   const reportChallenge=(await Round('report',{...reportAuth,action:'challenge'}));assert.equal(reportChallenge.ok,true,JSON.stringify(reportChallenge));
   const evidence=JSON.stringify({version:1,hashVersion:3,crcLayers:require('../services/desktopIntegrity').CodeImage(artifact).crcLayers,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:begin.release.codeSha512,codeCrc64:begin.release.codeCrc64,fileXxh3_128:begin.release.xxh3_128,fileBlake3:begin.release.blake3,codeXxh3_128:begin.release.codeXxh3_128,codeBlake3:begin.release.codeBlake3}}),rc=reportChallenge.data;
   const reportBody={...reportAuth,action:'submit',reportId:rc.reportId,payload:evidence,signature:bootstrapFixture.Sign(a,['GAME-INTEGRITY-REPORT-V2',session.sessionId,rc.reportId,rc.nonce,String(rc.expiresAt),sha512(Buffer.from(evidence))].join('\n'))};
   const reportResult=await Round('report',reportBody);assert.equal(reportResult.ok,true,JSON.stringify(reportResult));assert.equal(reportResult.data.status,'VERIFIED');assert.equal(reportResult.data.terminate,false);assert.equal((await Round('report',reportBody)).error,'INTEGRITY_REPORT_CHALLENGE_INVALID');
   assert.equal((await Round('bootstrap',{action:'close',sessionId:session.sessionId,sessionToken:session.sessionToken})).data.status,'CLOSED');bootstrap.Publish('B','80.0.2',bootstrapFixture.PE('B'));
  });
  let first,proof,token;
  await Check('One-time registration and lost-response retry over fresh encrypted channels',async()=>{
   first=desktop.Create({label:'첫 Windows'},'TEST');proof=await Proof(a,'redeem',{licenseKey:first.licenseKey,deviceName:'한글 Windows PC',appVersion:'1.0'});const result=await Round('execute',proof);assert.equal(result.ok,true);token=result.data.activationToken;assert.equal(result.data.deviceId,a.deviceId);assert.equal(result.data.status,'USED');assert.ok(result.data.leaseExpiresAt>Date.now());
   const retry=await Round('execute',proof);assert.equal(retry.data.activationToken,token);const repeated=await Call(a,'redeem',JSON.parse(proof.payloadJSON),proof.requestId);assert.equal(repeated.data.activationToken,token);
   assert.equal((await Call(b,'redeem',{licenseKey:first.licenseKey})).error,'DESKTOP_KEY_USED');
  });
  await Check('Independent PCs hold independent licenses and cannot borrow activation tokens',async()=>{
   const second=desktop.Create({label:'두 번째 Windows'},'TEST'),tokenB=(await Call(b,'redeem',{licenseKey:second.licenseKey})).data.activationToken;
   assert.equal((await Call(a,'verify',{activationToken:token})).ok,true);assert.equal((await Call(b,'verify',{activationToken:tokenB})).ok,true);const owner=bootstrapFixture.Session(b,tokenB);assert.equal((await Call(b,'verify',{activationToken:token,bootstrapSessionId:owner.sessionId,bootstrapSessionToken:owner.sessionToken})).error,'DESKTOP_DEVICE_MISMATCH');
   const fake=await Proof(a,'verify',{activationToken:token});fake.signature=Buffer.alloc(256).toString('base64');assert.equal((await Round('execute',fake)).error,'DESKTOP_PROOF_INVALID');
  });
  await Check('Service stop and revoke are enforced by the server on encrypted requests',async()=>{
   const pending=await Proof(a,'verify',{activationToken:token});state.serviceEnabled=false;try{assert.equal((await Round('execute',pending)).error,'SERVICE_DISABLED');}finally{state.serviceEnabled=true;}
   desktop.Revoke(first.license.id,{reason:'TCP 검증 해지'},'TEST');assert.equal((await Call(a,'verify',{activationToken:token})).error,'DESKTOP_REVOKED');assert.equal((await Round('execute',proof)).error,'DESKTOP_REVOKED');
  });
  await Check('Absolute deadline closes incomplete frames even during trickle traffic',async()=>{
   const started=Date.now();await new Promise((resolve,reject)=>{const socket=tls.connect({host:'127.0.0.1',port,servername:profile.tlsServerName,rejectUnauthorized:false,minVersion:'TLSv1.2'});let timer,reply='';const deadline=setTimeout(()=>{socket.destroy();reject(Error('Absolute TCP deadline missing'));},transport.DEADLINE_MS+3000);socket.on('secureConnect',()=>{socket.write(' ');timer=setInterval(()=>socket.write(' '),500);});socket.on('data',data=>{reply+=data.toString();});socket.on('error',()=>{});socket.on('close',()=>{clearTimeout(deadline);clearInterval(timer);try{assert.equal(reply,'');resolve();}catch(error){reject(error);}});});assert.ok(Date.now()-started>=transport.DEADLINE_MS-500);
  });
  await Check('Pre-authentication TLS peers count towards per-IP socket capacity',async()=>{
   const held=[];try{for(let i=0;i<32;i++){const socket=net.connect(port,'127.0.0.1');socket.on('error',()=>{});held.push(socket);await new Promise(resolve=>socket.once('connect',resolve));}
    await new Promise((resolve,reject)=>{const overflow=net.connect(port,'127.0.0.1'),timer=setTimeout(()=>{overflow.destroy();reject(Error('TLS pre-auth capacity missing'));},2000);overflow.on('error',()=>{});overflow.once('close',()=>{clearTimeout(timer);resolve();});});
   }finally{await Promise.all(held.map(socket=>new Promise(resolve=>{if(socket.destroyed)return resolve();socket.once('close',resolve);socket.destroy();})));}
  });
  await Check('Absolute deadline also expires unauthenticated silent TLS peers',async()=>{
   const started=Date.now();await new Promise((resolve,reject)=>{const socket=net.connect(port,'127.0.0.1'),timer=setTimeout(()=>{socket.destroy();reject(Error('TLS pre-auth deadline missing'));},transport.DEADLINE_MS+3000);socket.on('error',()=>{});socket.on('close',()=>{clearTimeout(timer);resolve();});});assert.ok(Date.now()-started>=transport.DEADLINE_MS-500);
  });
  console.log(`GameConnect pinned TLS TCP: ${checks} checks passed (${process.env.STORAGE_ENGINE})`);
 }finally{await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
