'use strict';
// Real authentication, stores, signed requests and protected TLS dispatch.
// Synthetic PE/evidence only; not Windows sensor/TPM execution evidence.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-nhw-paths-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../../core/peace.utilities').EnsureDirs();
const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
const boot=require('../../services/bootstrap/peace.desktop-bootstrap');
const authority=require('../../services/security/peace.desktop-security-authority');
const paths=require('../../services/security/peace.nhw-response-paths');
const schema=require('../../services/protocol/peace.packet-schema');
const protocol=require('../../services/protocol/peace.desktop-request-protocol');
const protectedDispatch=require('../../services/authentication/peace.desktop-protected-dispatch');
const transport=require('../../services/network/peace.desktop-connect');
let checks=0,server;
const originalNow=Date.now;
process.once('exit',()=>{Date.now=originalNow;fs.rmSync(temp,{recursive:true,force:true});});
const hash=x=>crypto.createHash('sha512').update(x).digest('hex');
function check(label,fn){fn();checks++;console.log('PASS '+label);}
function reject(fn,code){assert.throws(fn,e=>!code||e.message===code);}
function newA(){const device=fixture.Device(),start=fixture.Begin(device);return {device,start,ctx:{stage:'A',sessionId:start.begin.flowId,sessionToken:start.begin.downloadTicket,machineId:device.machineId}};}
function newB(){const a=newA(),device=fixture.Child(a.device);fixture.Download(a.start.begin);const b=fixture.Claim(a.device,a.start.begin,fixture.Finish(a.device,a.start.begin),device);return {device,b,ctx:{stage:'B',sessionId:b.sessionId,sessionToken:b.sessionToken,machineId:device.machineId}};}
function row(s){return Object.values(boot.Initialize().flows).find(r=>r.sessionId===s.b?.sessionId||r.id===s.start?.begin.flowId);}
function payload(sequence=1,confirmed=true){return JSON.stringify({version:1,sequence:BigInt(sequence).toString(16).padStart(16,'0'),tick:BigInt(10000+sequence).toString(16).padStart(16,'0'),digest:BigInt(90000+sequence).toString(16).padStart(16,'0'),confirmed,trust:confirmed?3:2});}
function kernelV2(){
 const detections=['dkKernelTrustDowngrade','dkBootTrust'].map(id=>({id,source:'Cozy.NHW.Engine',firstTick:'0000000000001000',lastTick:'0000000000001000',count:1,families:128,confidence:75,correlation:true,attestationSequence:'0000000000000000',localOnly:false}));
 return JSON.stringify({version:2,sequence:'0000000000000001',tick:'0000000000001001',digest:hash(JSON.stringify(detections)).slice(0,16),confirmed:true,trust:3,detections});
}
function request(s,channel,text=payload()){ 
 const cap=channel[0].toUpperCase()+channel.slice(1),body={...s.ctx,binding:hash(text),action:'nhw'+cap+'Challenge'};
 const c=authority.Execute(body),submit={...body,action:'nhw'+cap+'Submit',challengeId:c.challengeId,payload:text};
 submit.signature=fixture.Sign(s.device,paths.Canonical(submit,c,channel));
 return {body,c,submit};
}
function send(s,channel,text=payload()){return authority.Execute(request(s,channel,text).submit);}
fixture.CurrentCohort({version:'89.0.0'});
const isolated=newB();
check('All six channel commands have shared wire schemas, protected routes and separate domains',()=>{
 for(const channel of ['trust','driver','integrity']){
  const req=request(isolated,channel,payload(1,false));
  for(const body of [req.body,req.submit]){
   const envelope={operation:'security',body};schema.ValidateEnvelope(envelope);
   assert.equal(protocol.Resolve('security',body.action).domain,paths.Domain(channel));
   if(body===req.body)continue;
   const ticket=protectedDispatch.Prepare(envelope);
   const value=protectedDispatch.Execute(ticket,envelope,{security:authority.Execute});
   assert.ok(value.version===1);reject(()=>protectedDispatch.Execute(ticket,envelope,{security:authority.Execute}));
  }
 }
 assert.equal(row(isolated).status,'CLAIMED');
});
check('Each path rejects a foreign channel nonce and foreign signing key',()=>{
 const s=newB(),r=request(s,'trust');
 reject(()=>authority.Execute({...r.submit,action:'nhwDriverSubmit'}),'SECURITY_CHALLENGE_INVALID');
 reject(()=>authority.Execute({...r.submit,signature:fixture.Sign(fixture.Device(),paths.Canonical(r.submit,r.c,'trust'))}),'SECURITY_SIGNATURE_INVALID');
 reject(()=>authority.Execute({...r.submit,sessionToken:isolated.ctx.sessionToken}),'BOOTSTRAP_SESSION_INVALID');
 assert.equal(authority.Execute(r.submit).stopped,false);
 assert.equal(row(s).status,'CLAIMED');
});
check('Lost replies recover exact receipt, changes and producer replays are refused',()=>{
 const s=newB(),r=request(s,'driver');
 const accepted=authority.Execute(r.submit);assert.deepEqual(authority.Execute(r.submit),accepted);
 reject(()=>authority.Execute({...r.submit,payload:r.submit.payload+' '}),'SECURITY_NHW_RESPONSE_REUSED');
 reject(()=>send(s,'driver',payload()),'SECURITY_OBSERVATION_REPLAY');
 assert.equal(send(s,'driver',payload(2)).stopped,false);
 assert.equal(row(s).status,'CLAIMED');
});
check('One channel cannot produce quorum by repeating; another valid channel ends exact B cohort',()=>{
 const s=newB(),foreign=newB();
 assert.equal(send(s,'trust',payload(1)).stopped,false);
 assert.equal(send(s,'trust',payload(2)).stopped,false);
 assert.equal(send(s,'integrity',payload(1)).stopped,true);
 assert.equal(row(s).status,'REVOKED');assert.equal(row(foreign).status,'CLAIMED');
 reject(()=>send(s,'driver'));
});
check('Two unconfirmed signals and an abandoned/expired challenge never terminate a session',()=>{
 const s=newB();assert.equal(send(s,'trust',payload(1,false)).stopped,false);assert.equal(send(s,'driver',payload(1,false)).stopped,false);
 const r=request(s,'integrity');const now=Date.now;Date.now=()=>r.c.expiresAt;
 try{reject(()=>authority.Execute(r.submit),'SECURITY_CHALLENGE_INVALID');}finally{Date.now=now;}
 assert.equal(row(s).status,'CLAIMED');
});
check('Rate limiting and supersession on one path do not consume another path nonce',()=>{
 const s=newB(),driver=request(s,'driver'),first=request(s,'trust');
 request(s,'trust');reject(()=>authority.Execute(first.submit),'SECURITY_CHALLENGE_INVALID');
 for(let i=0;i<58;i++)request(s,'trust');
 reject(()=>request(s,'trust'),'SECURITY_RATE_LIMIT');
 assert.equal(authority.Execute(driver.submit).stopped,false);assert.equal(send(s,'integrity').stopped,true);
});
// Exercise the same signed response path with ordinary and qualifying evidence.
function nativeV5(id,stage,sequence=1,fields={}){
 const policy=require('../../services/security/peace.security-context-policy');
 const c=policy.UnknownContext(stage);
 c.phase=stage+'_ATTESTED';
 const sampleTick=(0x1000+sequence).toString(16).padStart(16,'0');
 const detected=[{id,source:'Cozy.NHW.Engine',firstTick:sampleTick,
  lastTick:sampleTick,count:1,families:0,confidence:0,
  correlation:false,attestationSequence:'0000000000000000',localOnly:true,
  context:Object.fromEntries(policy.CONTEXT_FIELDS.map(k=>[k,c[k]])),signal:'DETECTED',...fields}];
 return JSON.stringify({version:5,sequence:sequence.toString(16).padStart(16,'0'),
  tick:sampleTick,digest:hash(JSON.stringify(detected)).slice(0,16),
  confirmed:false,trust:0,detections:detected,peer:null});
}
check('V5 signed A/B findings keep isolated observations and revoke only on qualified evidence',()=>{
 const a=newA(),b=newB(),foreign=newB();
 assert.equal(send(a,'integrity',nativeV5('dkProcess','A')).stopped,false);
 assert.equal(row(a).status,'STARTED');
 assert.equal(send(b,'trust',nativeV5('dkAffinity','B')).stopped,false);
 assert.equal(row(b).status,'CLAIMED');
 const aRequest=request(a,'integrity',nativeV5('dkPECodeIntegrity','A',2));
 const aStopped=authority.Execute(aRequest.submit);
 assert.equal(aStopped.accepted,true);assert.equal(aStopped.stopped,true);
 assert.deepEqual(authority.Execute(aRequest.submit),aStopped,'idempotent signed stop receipt');
 assert.equal(row(a).status,'REVOKED');
 const bStopped=send(b,'trust',nativeV5('dkPrivateThread','B',2,
  {families:10,confidence:75,correlation:true,localOnly:false}));
 assert.equal(bStopped.accepted,true);assert.equal(bStopped.stopped,true);
 assert.equal(row(b).status,'REVOKED');
 assert.equal(row(foreign).status,'CLAIMED','foreign A/B cohort untouched');
 const events=require('../../services/security/peace.security-detections').ForFlow(row(b).id);
 assert.ok(events.some(x=>x.detectionId==='dkAffinity'&&x.disposition==='OBSERVATION_UNRESOLVED'&&!x.invalidated));
 assert.ok(events.some(x=>x.detectionId==='dkPrivateThread'&&x.disposition==='CORROBORATED_ANOMALY'&&x.invalidated));
});
check('Stage A independently reports and revokes only its exact not-yet-claimed flow',()=>{
 const a=newA(),other=newA();
 assert.equal(send(a,'driver').stopped,false);assert.equal(send(a,'integrity').stopped,true);
 assert.equal(row(a).status,'REVOKED');assert.equal(row(other).status,'STARTED');
});
check('O uses its own activated key and ends only its authenticated A/B/O cohort',()=>{
 const parent=newB(),device=fixture.Child(parent.device),foreign=newB();
 const licenses=require('../../services/licensing/peace.desktop-licenses');
 const common={...fixture.Evidence(parent.device,parent.b),bootstrapSessionId:parent.b.sessionId,bootstrapSessionToken:parent.b.sessionToken,appVersion:'89.0.0'};
 const issue=licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID(),label:'NHW O test'},'TEST');
 function operation(action,body){
  const text=JSON.stringify(body),requestId=crypto.randomUUID(),base={action,requestId,deviceId:parent.device.deviceId,publicKey:parent.device.publicKey,payloadHash:hash(text)},c=licenses.Challenge(base);
  fixture.ObserveLicense(parent.device,action,requestId,base.payloadHash,body);
  return licenses.Execute({...base,challengeId:c.challengeId,payloadJSON:text,signature:fixture.Sign(parent.device,c.canonical)});
 }
 const activation=operation('redeem',{...common,licenseKey:issue.licenseKey,deviceName:'NHW channel test'});
 const prepared=operation('overlay',{...common,activationToken:activation.activationToken});
 for(let offset=0;offset<prepared.release.size;offset+=prepared.chunkSize)boot.Execute({action:'overlayChunk',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,offset});
 const finished=boot.Execute({action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:fixture.Sign(parent.device,prepared.finishCanonical)});
 const o=boot.Execute({action:'overlayClaim',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,...fixture.Delegated(parent.device,device,'O',finished.claimCanonical),binarySha512:prepared.release.sha512,crc64:prepared.release.crc64,oCodeSha512:prepared.release.codeSha512,oCodeCrc64:prepared.release.codeCrc64});
 const current={device,ctx:{stage:'O',sessionId:o.sessionId,sessionToken:o.sessionToken,machineId:device.machineId}};
 fixture.Enroll(device,current.ctx);
 assert.equal(send(current,'integrity',nativeV5('dkThreadSpawn','O')).stopped,false);
 assert.equal(row(parent).status,'CLAIMED');
 const r=request(current,'trust',kernelV2());
 reject(()=>authority.Execute({...r.submit,signature:fixture.Sign(parent.device,paths.Canonical(r.submit,r.c,'trust'))}),'SECURITY_SIGNATURE_INVALID');
 assert.equal(authority.Execute(r.submit).stopped,true);assert.equal(send(current,'driver',kernelV2()).stopped,true);
 const events=require('../../services/security/peace.security-detections').ForFlow(row(parent).id);assert.equal(events.length,5);assert.ok(events.every(e=>e.role==='O'));assert.equal(events.filter(e=>e.invalidated).length,2);assert.equal(events.filter(e=>e.responsePath==='driver'&&e.invalidated).length,0);
 assert.equal(boot.Initialize().overlays[prepared.overlayId].status,'REVOKED');assert.equal(row(parent).status,'REVOKED');assert.equal(row(foreign).status,'CLAIMED');
});
check('A signed channel payload cannot substitute a different epoch or hash',()=>{
 const s=newB(),r=request(s,'trust');
 reject(()=>authority.Execute({...r.submit,signature:fixture.Sign(s.device,paths.Canonical(r.submit,{...r.c,epoch:String(BigInt(r.c.epoch)+1n)},'trust'))}),'SECURITY_SIGNATURE_INVALID');
 reject(()=>authority.Execute({...r.submit,binding:hash('other')}),'SECURITY_CHALLENGE_INVALID');
 assert.equal(row(s).status,'CLAIMED');
});
(async()=>{
 try{
  server=transport.CreateServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));process.env.DESKTOP_PUBLIC_PORT=String(server.address().port);
  const profile=require('../../services/network/peace.connect-transport-key').Profile(),s=newB();
  const round=body=>fixture.TcpOperation(profile,'security',body);
  for(const channel of ['Trust','Driver']){
   const text=payload(),body={...s.ctx,binding:hash(text),action:'nhw'+channel+'Challenge'};
   const c=await round(body),submit={...body,action:'nhw'+channel+'Submit',challengeId:c.challengeId,payload:text};
   submit.signature=fixture.Sign(s.device,paths.Canonical(submit,c,channel.toLowerCase()));
   const result=await round(submit);assert.equal(result.stopped,channel==='Driver');
  }
  assert.equal(row(s).status,'REVOKED');checks++;console.log('PASS independent Trust/Driver nonce and RSA proof through actual TLS, AEAD, queue and protected dispatch');
  console.log('NHW response paths: '+checks+' groups passed; Windows runtime not executed');
 }finally{if(server)await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
