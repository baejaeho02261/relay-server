'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'moa-connect-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';process.env.HA_ENABLED='0';
for(const name of ['DESKTOP_PUBLIC_HOST','DESKTOP_PUBLIC_PORT','RAILWAY_TCP_PROXY_DOMAIN','RAILWAY_TCP_PROXY_PORT'])delete process.env[name];
require('../core/utils').EnsureDirs();
const desktop=require('../services/desktopLicenses'),transport=require('../services/desktopConnect'),keys=require('../services/connectTransportKey'),state=require('../core/state');
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
function Device(){const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),blob=keys.PublicBlob(publicKey);return {privateKey,publicKey:blob.toString('base64'),deviceId:digest(blob).toUpperCase()};}
const a=Device(),b=Device(),server=transport.CreateServer();let profile,port,checks=0;
function Envelope(payload,overrides={}){
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),requestId=overrides.requestId||crypto.randomUUID(),keyId=overrides.keyId||profile.serverKeyId;
 const publicKey=overrides.publicKey||desktop.ParseKey(profile.serverPublicKey).key;
 const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce,{authTagLength:16});cipher.setAAD(transport.Aad('REQUEST',requestId,keyId));
 const ciphertext=Buffer.concat([cipher.update(Buffer.from(JSON.stringify(payload))),cipher.final()]);
 const frame={v:1,keyId,requestId,wrappedKey:crypto.publicEncrypt({key:publicKey,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
 return {key,nonce,frame,wire:JSON.stringify(frame)+'\n'};
}
function Wire(raw,timeout=4000){return new Promise((resolve,reject)=>{const socket=net.connect(port,'127.0.0.1');let reply='';socket.setTimeout(timeout,()=>{socket.destroy();reject(Error('TEST_TIMEOUT'));});socket.on('connect',()=>socket.write(raw));socket.on('data',chunk=>{reply+=chunk.toString();});socket.on('error',error=>{if(error.code!=='ECONNRESET')reject(error);});socket.on('close',()=>resolve(reply));});}
function Decode(envelope,raw){
 const frame=JSON.parse(raw);assert.equal(frame.v,1);assert.equal(frame.requestId,envelope.frame.requestId);assert.notEqual(frame.nonce,envelope.frame.nonce);
 const decipher=crypto.createDecipheriv('aes-256-gcm',envelope.key,Buffer.from(frame.nonce,'base64'),{authTagLength:16});decipher.setAAD(transport.Aad('RESPONSE',frame.requestId,envelope.frame.keyId));decipher.setAuthTag(Buffer.from(frame.tag,'base64'));
 return JSON.parse(Buffer.concat([decipher.update(Buffer.from(frame.ciphertext,'base64')),decipher.final()]).toString('utf8'));
}
async function Round(operation,body){const envelope=Envelope({operation,body});return Decode(envelope,await Wire(envelope.wire));}
async function Proof(device,action,payload,requestId=crypto.randomUUID()){
 const payloadJSON=JSON.stringify(payload),base={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:digest(payloadJSON)},challenge=await Round('challenge',base);assert.equal(challenge.ok,true,JSON.stringify(challenge));
 const c=challenge.data,canonical=['MOAPLAY-DESKTOP-V1',action,c.challengeId,c.nonce,requestId,device.deviceId,base.payloadHash,c.expiresAt].join('\n');assert.equal(c.canonical,canonical);
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
   const out=await AdminProfile({role:'admin',id:'TEST'});assert.equal(out.status,200);profile=out.value.profile;assert.equal(profile.serverKeyId,digest(Buffer.from(profile.serverPublicKey,'base64')));assert.deepEqual(Object.keys(profile).sort(),['host','port','protocol','serverKeyId','serverPublicKey','version']);assert.equal(profile.protocol,'MOAPLAY-CONNECT-1');
   process.env.DESKTOP_PUBLIC_HOST='https://bad.example';assert.throws(()=>keys.Profile(),/CONNECT_PUBLIC_ENDPOINT_REQUIRED/);process.env.DESKTOP_PUBLIC_HOST='::1';assert.throws(()=>keys.Profile(),/CONNECT_PUBLIC_ENDPOINT_REQUIRED/);process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';
  });
  await Check('Persisted server key is stable, private, and never silently replaced',async()=>{
   if(process.platform!=='win32')assert.equal(fs.statSync(keys.KEY_FILE).mode&0o777,0o600);
   const child=require('node:child_process'),root=path.resolve(__dirname,'..'),script="const root=process.cwd();console.log(require(root+'/services/connectTransportKey').Load().keyId);";
   assert.equal(child.execFileSync(process.execPath,['-e',script],{cwd:root,env:process.env,encoding:'utf8'}).trim(),profile.serverKeyId);
   for(const kind of ['missing','changed']){const copy=fs.mkdtempSync(path.join(os.tmpdir(),'moa-connect-key-'));fs.cpSync(temp,copy,{recursive:true});if(kind==='missing')fs.unlinkSync(path.join(copy,path.basename(keys.KEY_FILE)));else fs.writeFileSync(path.join(copy,path.basename(keys.ID_FILE)),'0'.repeat(64)+'\n');const result=child.spawnSync(process.execPath,['-e',script],{cwd:root,env:{...process.env,DATA_DIR:copy},encoding:'utf8'});assert.notEqual(result.status,0);assert.match(result.stderr,/CONNECT_SERVER_KEY_(MISSING|CHANGED)/);}
  });
  await Check('Plaintext, wrong pin and wrong RSA recipient never receive success',async()=>{
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
  let first,proof,token;
  await Check('One-time registration and lost-response retry over fresh encrypted channels',async()=>{
   first=desktop.Create({label:'첫 Windows'},'TEST');proof=await Proof(a,'redeem',{licenseKey:first.licenseKey,deviceName:'한글 Windows PC',appVersion:'1.0'});const result=await Round('execute',proof);assert.equal(result.ok,true);token=result.data.activationToken;assert.equal(result.data.deviceId,a.deviceId);assert.equal(result.data.status,'ACTIVE');assert.ok(result.data.leaseExpiresAt>Date.now());
   const retry=await Round('execute',proof);assert.equal(retry.data.activationToken,token);const repeated=await Call(a,'redeem',JSON.parse(proof.payloadJSON),proof.requestId);assert.equal(repeated.data.activationToken,token);
   assert.equal((await Call(b,'redeem',{licenseKey:first.licenseKey})).error,'DESKTOP_KEY_USED');
  });
  await Check('Independent PCs hold independent licenses and cannot borrow activation tokens',async()=>{
   const second=desktop.Create({label:'두 번째 Windows'},'TEST'),tokenB=(await Call(b,'redeem',{licenseKey:second.licenseKey})).data.activationToken;
   assert.equal((await Call(a,'verify',{activationToken:token})).ok,true);assert.equal((await Call(b,'verify',{activationToken:tokenB})).ok,true);assert.equal((await Call(b,'verify',{activationToken:token})).error,'DESKTOP_DEVICE_MISMATCH');
   const fake=await Proof(a,'verify',{activationToken:token});fake.signature=Buffer.alloc(256).toString('base64');assert.equal((await Round('execute',fake)).error,'DESKTOP_PROOF_INVALID');
  });
  await Check('Service stop and revoke are enforced by the server on encrypted requests',async()=>{
   const pending=await Proof(a,'verify',{activationToken:token});state.serviceEnabled=false;try{assert.equal((await Round('execute',pending)).error,'SERVICE_DISABLED');}finally{state.serviceEnabled=true;}
   desktop.Revoke(first.license.id,{reason:'TCP 검증 해지'},'TEST');assert.equal((await Call(a,'verify',{activationToken:token})).error,'DESKTOP_REVOKED');assert.equal((await Round('execute',proof)).error,'DESKTOP_REVOKED');
  });
  await Check('Absolute deadline closes incomplete frames even during trickle traffic',async()=>{
   const started=Date.now();await new Promise((resolve,reject)=>{const socket=net.connect(port,'127.0.0.1');let timer,reply='';const deadline=setTimeout(()=>{socket.destroy();reject(Error('Absolute TCP deadline missing'));},transport.DEADLINE_MS+3000);socket.on('connect',()=>{socket.write(' ');timer=setInterval(()=>socket.write(' '),500);});socket.on('data',data=>{reply+=data.toString();});socket.on('error',()=>{});socket.on('close',()=>{clearTimeout(deadline);clearInterval(timer);try{assert.equal(reply,'');resolve();}catch(error){reject(error);}});});assert.ok(Date.now()-started>=transport.DEADLINE_MS-500);
  });
  console.log(`MoaPlayConnect TCP: ${checks} checks passed (${process.env.STORAGE_ENGINE})`);
 }finally{await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
