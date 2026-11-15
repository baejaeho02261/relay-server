'use strict';
const sha512=value=>require('node:crypto').createHash('sha512').update(value).digest('hex');
// Synthetic executable fixtures exercise the production publisher and complete
// bootstrap protocol. They are test data, never native runtime bypasses.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const sha256=value=>crypto.createHash('sha256').update(value).digest('hex');
const {Crc64,CodeImage}=require("../../../services/integrity/peace.desktop-integrity");
const cache=new Map(),requests=new Map(),remoteEvidence=new Map(),persistentKeys=new Map(),claimRequests=new Map(),issuers=new Map();

function PE(component,marker='fixture'){const bytes=require("../artifacts/peace.crc-pe-fixture").crcPeFixture(component+':'+String(marker)+' GAME-CONNECT-4 GAME-AUTHORITY-V2'),pe=bytes.readUInt32LE(0x3c),opt=pe+24;bytes.writeUInt16LE(0x22,pe+22);bytes.writeUInt16LE(2,opt+68);bytes.writeUInt16LE(0x8160,opt+70);return bytes;}
function Device(){
 const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),bytes=require("../../../services/network/peace.connect-transport-key").PublicBlob(publicKey);
 return {privateKey,publicKey:bytes.toString('base64'),deviceId:sha256(bytes).toUpperCase(),machineId:crypto.randomBytes(32).toString('hex').toUpperCase()};
}
function Child(parent){const child=Device();child.machineId=parent.machineId;return child;}
function Sign(device,canonical){return crypto.sign('sha256',Buffer.from(canonical,'utf8'),{key:device.privateKey,padding:crypto.constants.RSA_PKCS1_PADDING}).toString('base64');}
// The final config is accepted only with the issuance record's independent
// template/key trust context. It never reconstructs a legacy bearer ticket.
function Config(bytes){
 const db=require("../../../services/bootstrap/peace.desktop-bootstrap-store").Load();
 const row=Object.values(db.launchers).find(item=>item.sha512===sha512(bytes));
 assert.ok(row?.finalIssuedSignature,'Use a final signed V3 issuance fixture');
 const verified=require("../../../services/bootstrap/peace.issued-a-signing").VerifyFinal(bytes,{expectedTemplateSha512:db.artifacts[row.artifactId].sha512,expectedKeyId:row.finalIssuedSignature.keyId});
 assert.equal(verified.config.launcherId,row.id);return verified.config;
}
// This builds synthetic protocol data, not a native executable approval. The
// isolated store selection below is deliberately confined to tests: no web
// publication gate or Windows execution evidence is bypassed in production.
function CurrentTemplates({marker='current bootstrap fixture',version='80.0.0',functions,paddingBytesByRole={},rawByRole,approve,rotateIssuer=false}={}){
 const bootstrap=require("../../../services/bootstrap/peace.desktop-bootstrap"),store=require("../../../services/bootstrap/peace.desktop-bootstrap-store");
 const policy=require("../../../services/artifacts/peace.server-policy-protection"),evidence=require("../../../services/artifacts/peace.desktop-packing-evidence"),registry=require("../../../services/security/peace.server-policy-registry");
 const signing=require("../../../services/bootstrap/peace.issued-a-signing"),issuerScope=String(process.env.DATA_DIR);let issuer=issuers.get(issuerScope);
 if(!issuer||rotateIssuer){issuer=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});issuers.set(issuerScope,issuer);}
 process.env[signing.ENV]=Buffer.from(issuer.privateKey.export({type:'pkcs8',format:'pem'})).toString('base64');
 const outputs={},records=[],jobId=crypto.randomBytes(16).toString('hex'),createdAt=Date.now();
 for(const role of ['A','B','O']){
  let raw=rawByRole?Buffer.from(rawByRole(role)):PE(role,marker+' '+require("../../../services/bootstrap/peace.desktop-handoff-delegation").MARKER);
  const padding=paddingBytesByRole[role]||0;assert.ok(Number.isSafeInteger(padding)&&padding>=0&&padding<=16*1024*1024);
  if(padding){raw=Buffer.concat([raw,Buffer.alloc(Math.ceil(padding/512)*512,0x5a)]);const pe=raw.readUInt32LE(60),opt=pe+24,last=opt+raw.readUInt16LE(pe+20)+(raw.readUInt16LE(pe+6)-1)*40,size=raw.length-raw.readUInt32LE(last+20);raw.writeUInt32LE(size,last+8);raw.writeUInt32LE(size,last+16);raw.writeUInt32LE(Math.ceil((raw.readUInt32LE(last+12)+size)/4096)*4096,opt+56);}
  const template=role==='A'?require('./peace.issued-a-fixture').WithAnchor(raw,issuer.publicKey):raw;
  const slot=policy.CreateUnsealedSlot(),bytes=Buffer.concat([template,slot]);
  const pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20),last=table+(bytes.readUInt16LE(pe+6)-1)*40,size=bytes.readUInt32LE(last+16)+slot.length;
  bytes.writeUInt32LE(size,last+8);bytes.writeUInt32LE(size,last+16);bytes.writeUInt32LE(Math.ceil((bytes.readUInt32LE(last+12)+size)/4096)*4096,opt+56);
  const source=bootstrap.Publish(role,version,bytes,approve?.(role,version,bytes),{activate:false});
  const out=policy.BindTemplate(bytes,role,functions?{version:1,functions}:undefined);outputs[role]=out;
  records.push({version:1,purpose:evidence.DOMAIN,jobId,component:role,sourceArtifactId:source.id,inputSha512:out.inputSha512,outputSha512:out.sha512,size:out.bytes.length,toolSha512:out.toolSha512,profileSha512:out.profileSha512,createdAt,actorHash:'af'.repeat(64)});
 }
 store.Atomic(db=>{evidence.RecordJob(db,records);registry.RecordJob(db,records,outputs);});
 return {outputs,issuerKeyId:signing.PublicIdentity(issuer.publicKey).keyId};
}
function CurrentCohort(options={}){
 const bootstrap=require("../../../services/bootstrap/peace.desktop-bootstrap"),store=require("../../../services/bootstrap/peace.desktop-bootstrap-store"),templates=CurrentTemplates(options),selected={};
 for(const role of ['A','B','O'])selected[role]=bootstrap.Publish(role,options.version||'80.0.0',templates.outputs[role].bytes,options.approve?.(role,options.version||'80.0.0',templates.outputs[role].bytes),{activate:false});
 store.Atomic(db=>{for(const role of ['A','B','O'])db.active[role]=selected[role].id;});
 return {selected,...templates};
}
function Publish(){
 const bootstrap=require("../../../services/bootstrap/peace.desktop-bootstrap");process.env.DESKTOP_PUBLIC_HOST||='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT||='29131';
 const active=bootstrap.Overview().artifacts;
 // Never silently replace an explicit selection made by a negative test.
 if(!active.A&&!active.B&&!active.O)CurrentCohort();return bootstrap;
}
function Persistent(device){
 const key=String(process.env.DATA_DIR)+':'+device.machineId;let value=persistentKeys.get(key);
 if(!value){value=Device();value.machineId=device.machineId;persistentKeys.set(key,value);}return value;
}
function IssuedBytes(value){return Buffer.isBuffer(value)?value:require("../../../services/bootstrap/peace.desktop-bootstrap").LauncherBytes(value.launcherId||value.id);}
function BeginChallenge(device,bytes,config,policy,persistent,options={}){
 const code=CodeImage(bytes),{persistent:ignored,...overrides}=options;
 return {action:'keylessChallenge',version:1,requestId:crypto.randomUUID(),launcherId:config.launcherId,launcherSha512:sha512(bytes),launcherCrc64:Crc64(bytes),aCodeSha512:code.sha512,aCodeCrc64:code.crc64,machineId:device.machineId,publicKey:device.publicKey,deviceId:device.deviceId,handoffVersion:3,persistentPublicKey:persistent.publicKey,persistentKeyId:persistent.deviceId,keyProvider:policy.keyProvider,epoch:policy.epoch,revision:policy.revision,...overrides};
}
function PrepareBegin(device,issued,options={}){
 const bootstrap=require("../../../services/bootstrap/peace.desktop-bootstrap"),bytes=IssuedBytes(issued),config=Config(bytes),persistent=options.persistent||Persistent(device);
 const policy=bootstrap.Execute({action:'keylessPolicy',version:1,launcherId:config.launcherId,machineId:device.machineId});
 const body=BeginChallenge(device,bytes,config,policy,persistent,options),c=bootstrap.Execute(body);
 const proof={version:1,challengeId:c.challengeId,appSignature:Sign(device,c.canonical),persistentSignature:Sign(persistent,c.canonical)};
 const decision=bootstrap.Execute({action:'keylessProve',...proof});
 return {device,persistent,bytes,config,policy,body,c,proof,decision};
}
function Enroll(device,auth,persistent=Persistent(device)){
 const identity=require("../../../services/devices/peace.desktop-device-identity");
 const c=identity.Handle({action:'challenge',...auth,requestId:crypto.randomUUID(),publicKey:persistent.publicKey,keyProvider:'SOFTWARE'});
 const result=identity.Handle({action:'complete',...auth,challengeId:c.challengeId,appSignature:Sign(device,c.canonical),signature:Sign(persistent,c.canonical)});
 persistentKeys.set(String(process.env.DATA_DIR)+':'+device.machineId,persistent);return result;
}
function ApproveBegin(prepared,actor='ADMIN:EXPLICIT_FIXTURE_APPROVAL'){
 const {device,persistent,config,c,proof}=prepared;
 require("../../../services/bootstrap/peace.keyless-bootstrap").Approve(c.challengeId,{identityConfirmed:true,launcherId:config.launcherId,persistentKeyId:persistent.deviceId},actor);
 const begin=require("../../../services/bootstrap/peace.desktop-bootstrap").Execute({action:'beginKeyless',...proof});
 Enroll(device,{stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:device.machineId},persistent);
 return begin;
}
function BeginIssued(device,issued,options={}){
 const prepared=PrepareBegin(device,issued,options),begin=ApproveBegin(prepared);
 return {bytes:prepared.bytes,config:prepared.config,body:{action:'beginKeyless',...prepared.proof},begin,prepared};
}
function Begin(device,options={}){
 const bootstrap=Publish(),issue=bootstrap.IssueLauncher({requestId:crypto.randomUUID(),label:'Bootstrap test'},'TEST');
 return {issue,...BeginIssued(device,issue,options)};
}
function Download(begin){
 const bootstrap=require("../../../services/bootstrap/peace.desktop-bootstrap"),chunks=[];let offset=0;
 while(offset<begin.release.size){const out=bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset});assert.equal(out.offset,offset);const bytes=Buffer.from(out.data,'base64');assert.ok(bytes.length>0);assert.ok(bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
 const bytes=Buffer.concat(chunks);assert.equal(bytes.length,begin.release.size);assert.equal(sha512(bytes),begin.release.sha512);assert.equal(Crc64(bytes),begin.release.crc64);return bytes;
}
// These helpers perform the real nonce/signature exchange for synthetic
// pristine fixtures. They never disable production policy or synthesize PASS.
function AuthorityEvidence(b){return {version:1,hashVersion:3,measurement:'MEASURED',fileSha512:b.sha512,fileCrc64:b.crc64,codeSha512:b.codeSha512,codeCrc64:b.codeCrc64,codeXxh3_128:b.codeXxh3_128,codeBlake3:b.codeBlake3,crcLayers:b.crcLayers,apiSealed:true,apiSlots:60,dynamicCode:'ALLOWED',cfg:'DISABLED'};}
function Observe(device,context){
 const auth=require("../../../services/security/peace.desktop-security-authority"),b=require("../../../services/bootstrap/peace.desktop-bootstrap").AuthenticateIntegrityReport(context).integrityArtifact;
 const challenge=auth.Execute({...context,action:'challenge'}),payload=JSON.stringify(AuthorityEvidence(b));
 return auth.Execute({...context,action:'submit',challengeId:challenge.challengeId,payload,signature:Sign(device,auth.Canonical(context,challenge,payload))});
}
function ObserveFinish(device,begin){return Observe(device,{stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:device.machineId,intent:'finish',binding:require("../../../services/security/peace.desktop-security-authority").Binding(begin.flowId,begin.release.sha512)});}
function ObserveLicense(device,action,requestId,payloadHash,payload){
 if(action==='release'||!payload.bootstrapSessionId||!payload.bootstrapSessionToken)return;
 const b=require("../../../services/bootstrap/peace.desktop-bootstrap"),row=Object.values(b.Initialize().flows).find(r=>r.sessionId===payload.bootstrapSessionId);
 // Invalid/closed capabilities are left for the production authorization gate.
 if(!row||row.status!=='CLAIMED'||row.deviceId!==device.deviceId||row.machineId!==device.machineId||sha256(payload.bootstrapSessionToken)!==row.sessionHash)return;
 return Observe(device,{stage:'B',sessionId:payload.bootstrapSessionId,sessionToken:payload.bootstrapSessionToken,machineId:device.machineId,intent:action==='overlay'?'verify':action,binding:require("../../../services/security/peace.desktop-security-authority").Binding(requestId,payloadHash)});
}
function Gate(device,session){const binding=require("../../../services/security/peace.desktop-security-authority").Binding('fixture-gate',session.release.sha512);Observe(device,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId,intent:'verify',binding});return require("../../../services/bootstrap/peace.desktop-bootstrap").Gate(session.sessionId,session.sessionToken,device.deviceId,{...Evidence(device,session),securityIntent:'verify',securityBinding:binding});}
function Finish(device,begin,observe=true){if(observe)ObserveFinish(device,begin);return require("../../../services/bootstrap/peace.desktop-bootstrap").Execute({action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha512:begin.release.sha512,crc64:begin.release.crc64,aCodeSha512:begin.finishCanonical.split('\n')[5],aCodeCrc64:begin.finishCanonical.split('\n')[6],signature:Sign(device,begin.finishCanonical)});}
function Delegated(parent,child,role,canonical){
 const delegation=require("../../../services/bootstrap/peace.desktop-handoff-delegation"),nonce=crypto.randomBytes(32).toString('hex').toUpperCase();
 return {handoffVersion:3,childPublicKey:child.publicKey,childKeyId:child.deviceId,childNonce:nonce,delegationSignature:Sign(parent,delegation.Canonical('DELEGATION',role,canonical,child.deviceId,nonce)),signature:Sign(child,delegation.Canonical('CLAIM',role,canonical,child.deviceId,nonce))};
}
function ClaimBody(parent,begin,finish,child){
 assert.ok(child,'V3 Claim requires an explicit independent B child device');assert.notEqual(child.deviceId,parent.deviceId);
 assert.equal(child.machineId,parent.machineId);
 const key=[process.env.DATA_DIR,begin.flowId,parent.deviceId,child.deviceId,sha256(finish.handoffToken)].join(':');
 let body=claimRequests.get(key);
 if(!body){body={action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,...Delegated(parent,child,'B',finish.claimCanonical),binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64};claimRequests.set(key,body);}
 return {...body};
}
function Claim(parent,begin,finish,child){
 const session=require("../../../services/bootstrap/peace.desktop-bootstrap").Execute(ClaimBody(parent,begin,finish,child));
 Enroll(child,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:child.machineId});return session;
}
function ChildClaim(parent,child,begin,finish){return Claim(parent,begin,finish,child);}
function Session(device,credential=''){
 // Activation proof stays on the exact A/B session that consumed its key.
 if(credential){const row=Object.values(require("../../../services/licensing/peace.desktop-licenses").DB().licenses).find(item=>item.tokenHash===sha256(credential)&&item.deviceId===device.deviceId);if(row?.bootstrapSessionId){const prior=[...cache.entries()].find(([name,value])=>name.startsWith(device.deviceId+':')&&value.sessionId===row.bootstrapSessionId);assert.ok(prior,'The fixture must retain the original activation session');return prior[1];}}
 const key=device.deviceId+':'+sha256(credential);let session=cache.get(key);if(session&&session.expiresAt>Date.now()+1000){try{Gate(device,session);return session;}catch(_) {}}
 const parent=Device();parent.machineId=device.machineId;const {begin}=Begin(parent);Download(begin);session=Claim(parent,begin,Finish(parent,begin),device);cache.set(key,session);return session;
}
function Evidence(device,session){return {machineId:device.machineId,binarySha512:session.release.sha512,binaryCrc64:session.release.crc64,codeSha512:session.release.codeSha512,codeCrc64:session.release.codeCrc64};}
function LicensePayload(device,payload,requestId){
 if(payload.bootstrapSessionId&&payload.bootstrapSessionToken){const row=Object.values(require("../../../services/bootstrap/peace.desktop-bootstrap").Initialize().flows).find(item=>item.sessionId===payload.bootstrapSessionId),artifact=require("../../../services/bootstrap/peace.desktop-bootstrap").Initialize().artifacts[row?.releaseId];return {machineId:device.machineId,binarySha512:artifact?.sha512||'0'.repeat(128),binaryCrc64:artifact?.crc64||'0'.repeat(16),codeSha512:artifact?.codeSha512||'0'.repeat(128),codeCrc64:artifact?.codeCrc64||'0'.repeat(16),...payload};}
 const key=requestId?device.deviceId+':'+requestId:'',session=key&&requests.get(key)||Session(device,payload.licenseKey||payload.activationToken||'');
 if(key)requests.set(key,session);return {...Evidence(device,session),...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken};
}
async function TcpOperation(profile,operation,body){
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),requestId=crypto.randomUUID(),aad=direction=>Buffer.from(['GAME-CONNECT-4',direction,requestId,profile.serverKeyId].join('\n'));
 const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(aad('REQUEST'));const clear=Buffer.from(JSON.stringify({operation,body})),ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);
 const frame={v:1,keyId:profile.serverKeyId,requestId,wrappedKey:crypto.publicEncrypt({key:require("../../../services/licensing/peace.desktop-licenses").ParseKey(profile.serverPublicKey).key,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
 const raw=await new Promise((resolve,reject)=>{const tls=require('node:tls'),socket=tls.connect({port:profile.port,host:profile.host,servername:profile.tlsServerName,rejectUnauthorized:false,minVersion:'TLSv1.2'});let reply='';socket.setTimeout(5000,()=>{socket.destroy();reject(Error('BOOTSTRAP_TEST_TIMEOUT'));});socket.once('secureConnect',()=>{const cert=socket.getPeerCertificate(),at=Date.now();if(!cert.raw||sha256(cert.raw)!==profile.tlsCertificateSha256||tls.checkServerIdentity(profile.tlsServerName,cert)||at<Date.parse(cert.valid_from)||at>Date.parse(cert.valid_to)){socket.destroy();reject(Error('BOOTSTRAP_TEST_TLS_PIN'));return;}socket.write(JSON.stringify(frame)+'\n');});socket.on('data',data=>{reply+=data.toString();if(reply.length>1024*1024){socket.destroy();reject(Error('BOOTSTRAP_TEST_RESPONSE_LIMIT'));}});socket.once('error',reject);socket.once('close',()=>resolve(reply));});
 const response=JSON.parse(raw);assert.equal(response.v,1);assert.equal(response.requestId,requestId);assert.notEqual(response.nonce,frame.nonce);const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(response.nonce,'base64'));decipher.setAAD(aad('RESPONSE'));decipher.setAuthTag(Buffer.from(response.tag,'base64'));
 const result=JSON.parse(Buffer.concat([decipher.update(Buffer.from(response.ciphertext,'base64')),decipher.final()]).toString('utf8'));assert.equal(result.ok,true,JSON.stringify(result));return result.data;
}
async function TcpBootstrap(profile,body){return TcpOperation(profile,'bootstrap',body);}
async function RemoteObserve(profile,device,context,bytes){
 const auth=require("../../../services/security/peace.desktop-security-authority"),file=require("../../../services/integrity/peace.desktop-integrity").Digests(bytes),code=CodeImage(bytes);
 const evidence=AuthorityEvidence({...file,codeSha512:code.sha512,codeCrc64:code.crc64,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3,crcLayers:code.crcLayers});
 const challenge=await TcpOperation(profile,'security',{...context,action:'challenge'}),payload=JSON.stringify(evidence);
 return TcpOperation(profile,'security',{...context,action:'submit',challengeId:challenge.challengeId,payload,signature:Sign(device,auth.Canonical(context,challenge,payload))});
}
async function RemoteObserveLicense(profile,device,session,action,requestId,payloadHash){
 if(action==='release')return;
 const bytes=remoteEvidence.get(session.sessionId);assert.ok(bytes,'RemoteSession must retain measured B fixture bytes');
 return RemoteObserve(profile,device,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId,intent:action==='overlay'?'verify':action,binding:require("../../../services/security/peace.desktop-security-authority").Binding(requestId,payloadHash)},bytes);
}
async function RemotePrepareBegin(device,issued,options={}){
 const bytes=IssuedBytes(issued),config=Config(bytes),persistent=options.persistent||Persistent(device),call=body=>TcpBootstrap(config.profile,body);
 const policy=await call({action:'keylessPolicy',version:1,launcherId:config.launcherId,machineId:device.machineId});
 const body=BeginChallenge(device,bytes,config,policy,persistent,options),c=await call(body);
 const proof={version:1,challengeId:c.challengeId,appSignature:Sign(device,c.canonical),persistentSignature:Sign(persistent,c.canonical)},decision=await call({action:'keylessProve',...proof});
 return {device,persistent,bytes,config,policy,body,c,proof,decision};
}
async function RemoteEnroll(profile,device,auth,persistent=Persistent(device)){
 const c=await TcpOperation(profile,'device',{action:'challenge',...auth,requestId:crypto.randomUUID(),publicKey:persistent.publicKey,keyProvider:'SOFTWARE'});
 const result=await TcpOperation(profile,'device',{action:'complete',...auth,challengeId:c.challengeId,appSignature:Sign(device,c.canonical),signature:Sign(persistent,c.canonical)});
 persistentKeys.set(String(process.env.DATA_DIR)+':'+device.machineId,persistent);return result;
}
async function RemoteApproveBegin(prepared,actor='ADMIN:EXPLICIT_REMOTE_FIXTURE_APPROVAL'){
 const {config,device,persistent,c,proof}=prepared;
 // Administrator-side fixture action, separate from encrypted client proofs.
 require("../../../services/bootstrap/peace.keyless-bootstrap").Approve(c.challengeId,{identityConfirmed:true,launcherId:config.launcherId,persistentKeyId:persistent.deviceId},actor);
 const begin=await TcpBootstrap(config.profile,{action:'beginKeyless',...proof});
 await RemoteEnroll(config.profile,device,{stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:device.machineId},persistent);return begin;
}
async function RemoteSession(device,launcher){
 const parent=Device();parent.machineId=device.machineId;
 const prepared=await RemotePrepareBegin(parent,launcher),settings=prepared.config,call=body=>TcpBootstrap(settings.profile,body),begin=await RemoteApproveBegin(prepared),chunks=[];
 for(let offset=0;offset<begin.release.size;){const chunk=await call({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset}),bytes=Buffer.from(chunk.data,'base64');assert.equal(chunk.offset,offset);assert.ok(bytes.length>0&&bytes.length<=begin.chunkSize);chunks.push(bytes);offset+=bytes.length;}
 const binary=Buffer.concat(chunks);assert.equal(binary.length,begin.release.size);assert.equal(sha512(binary),begin.release.sha512);
 await RemoteObserve(settings.profile,parent,{stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:parent.machineId,intent:'finish',binding:require("../../../services/security/peace.desktop-security-authority").Binding(begin.flowId,begin.release.sha512)},prepared.bytes);
 const finish=await call({action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha512:begin.release.sha512,crc64:begin.release.crc64,aCodeSha512:begin.finishCanonical.split('\n')[5],aCodeCrc64:begin.finishCanonical.split('\n')[6],signature:Sign(parent,begin.finishCanonical)});
 const session=await call({action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,...Delegated(parent,device,'B',finish.claimCanonical),binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64});
 await RemoteEnroll(settings.profile,device,{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId},prepared.persistent);
 remoteEvidence.set(session.sessionId,binary);return session;
}
module.exports={PE,Device,Child,Sign,Config,Publish,CurrentTemplates,CurrentCohort,Persistent,PrepareBegin,ApproveBegin,BeginIssued,Enroll,Delegated,ClaimBody,ChildClaim,RemotePrepareBegin,RemoteApproveBegin,RemoteEnroll,Begin,Download,Finish,Claim,Session,LicensePayload,TcpBootstrap,RemoteSession,Observe,ObserveFinish,ObserveLicense,Gate,TcpOperation,RemoteObserve,RemoteObserveLicense,sha256,sha512,Crc64,CodeImage,Evidence};
