'use strict';
// Actual lease handlers over isolated synthetic state. This is a server
// regression, not Windows execution, rendering, or hardware attestation.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {BootFixture}=require('../fixtures/security/peace.security-state-test-fixture');
const {Isolated}=require('../fixtures/protocol/peace.completion-6-10-fixture');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const fail=code=>{const error=Error(code);error.desktopError=true;error.status=403;throw error;};

function Clock(run){
 const previous=Date.now;let wall=1800000000000;
 Date.now=()=>wall;
 try{return run({now:()=>wall,advance:ms=>{assert.ok(Number.isSafeInteger(ms)&&ms>=0);wall+=ms;}});}
 finally{Date.now=previous;}
}

function Fixture(clock){
 const parentFixture=BootFixture(),{api:bootstrap,db,row:parent}=parentFixture;
 parent.status='CLAIMED';parent.sessionId='A'.repeat(24);parent.licenseId='LICENSE';
 const license={id:'LICENSE',status:'USED',consumed:true,deviceId:parent.deviceId,bootstrapSessionId:parent.sessionId,expiresAt:0};
 db.licenses={LICENSE:license};db.secret='ab'.repeat(32);
 const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
 const publicKey=keys.publicKey.export({type:'spki',format:'pem'});
 const row={
  id:crypto.randomBytes(12).toString('hex').toUpperCase(),
  sessionId:crypto.randomBytes(12).toString('hex').toUpperCase(),
  parentFlowId:parent.id,parentSessionId:parent.sessionId,launcherId:parent.launcherId,
  releaseId:'O',licenseId:license.id,parentDeviceId:parent.deviceId,
  deviceId:parent.deviceId,machineId:parent.machineId,handoffVersion:3,
  status:'READY',createdAt:clock.now(),expiresAt:clock.now()+120000,
  ticketHash:sha('TICKET'),ticketBinding:'c'.repeat(128),ticketNonce:'d'.repeat(48),chunkOffsets:[]
 };
 db.overlays={[row.id]:row};
 const audit=[];let writes=0;
 const tracker=Isolated('services/overlay/peace.desktop-overlay-startup.js',[],{
  '../../storage/audit/peace.audit.js':{LogEvent(kind,payload){audit.push({kind,...JSON.parse(payload)});}}
 });
 const boot={
  Fail:fail,EnsureSecurityAvailable(){},AssertSecurityAvailable(){},
  EqualHash:(value,digest)=>sha(value)===digest,
  AssertFlowLifetime:bootstrap.AssertFlowLifetime,
  RetireFlow(){},
  ReadArtifactBytes:()=>parentFixture.bytes,
  Release:artifact=>({id:'F'.repeat(24),version:'1.0.0',hashVersion:3,sha512:artifact.sha512,crc64:artifact.crc64,xxh3_128:'a'.repeat(32),blake3:'b'.repeat(64),size:artifact.size,codeSha512:artifact.codeSha512,codeCrc64:artifact.codeCrc64,codeXxh3_128:'c'.repeat(32),codeBlake3:'d'.repeat(64),codeAlgorithm:'PE64-CODE-V1'}),
  CheckFile(artifact,digest,crc){if(artifact.sha512!==digest||artifact.crc64!==crc)fail('HASH_MISMATCH');},
  Verify(_row,canonical,signature){
   if(!crypto.verify('sha256',Buffer.from(canonical),keys.publicKey,Buffer.from(signature,'base64')))fail('PROOF_INVALID');
  }
 };
 const overlay=Isolated('services/overlay/peace.desktop-overlay.js',['Live'],{
  '../bootstrap/peace.desktop-bootstrap':boot,
  '../bootstrap/peace.desktop-bootstrap-store':{Load:()=>db,AfterCommit:fn=>fn()},
  '../bootstrap/peace.desktop-handoff-delegation':{
   FIELDS:require('../../services/bootstrap/peace.desktop-handoff-delegation').FIELDS,
   Parent:value=>({deviceId:value.parentDeviceId}),
   Version:()=>3,Fingerprint:()=> 'e'.repeat(64),
   // Delegation validity is a separate tested boundary. This fixture supplies
   // an accepted child identity to exercise the production Claim lease logic.
   Check:()=>({publicKey,deviceId:'CHILD_DEVICE',nonce:'F'.repeat(64)})
  },
  '../recovery/peace.desktop-recovery':{Assert(){}},
  '../devices/peace.desktop-device-registry':{AssertMachineAllowed(){},ObserveVerified(){}},
  '../devices/peace.desktop-machine-policy':{AssertAllowed(){}},
  '../devices/peace.desktop-device-identity':{AssertSession(){},RetireContext(){}},
  '../licensing/peace.desktop-licenses':{DB:()=>({licenses:{LICENSE:license}})},
  '../security/peace.desktop-security-operations':{RequireRuntimePair(){}},
  '../security/peace.desktop-security-authority':{
   RequireArtifact(){},RetireContext(){},Binding:(id,hash)=>id+'|'+hash,
   // A progress receipt cannot manufacture this missing observation.
   RenewalIdentity(){fail('SECURITY_FRESH_OBSERVATION_REQUIRED');}
  },
  '../integrity/peace.desktop-integrity-reports':{RetireContext(){},RequireSnapshot:()=>({expiresAt:clock.now()+120000})},
  '../storage/peace.desktop-operation-audit':{Run(_kind,_actor,_meta,fn){writes++;return fn(db);}},
  '../../storage/audit/peace.audit.js':{LogEvent(kind,payload){audit.push({kind,...JSON.parse(payload)});}},
  './peace.desktop-overlay-startup':tracker,
  '../../config/peace.runtime-configuration':{}
 });
 function RenewParent(){
  const at=clock.now(),expires=at+120000;
  // Project an accepted ordinary license verification through the real
  // Bootstrap handler. The fixture does not claim to run its crypto transport.
  bootstrap.TouchLicense(parent.sessionId,'SESSION_SECRET',parent.deviceId,license,'verify',{
   originalAt:at,originalExpiresAt:expires,leaseExpiresAt:expires,appVersion:'1.0.0'
  });
  return parent.sessionExpiresAt;
 }
 function Claim(){
  const artifact=db.artifacts.O;
  return overlay.Execute({action:'overlayClaim',overlayId:row.id,overlayTicket:'TICKET',signature:'DELEGATION_FIXTURE',
   binarySha512:artifact.sha512,crc64:artifact.crc64,oCodeSha512:artifact.codeSha512,oCodeCrc64:artifact.codeCrc64});
 }
 function Verify(session){
  const artifact=db.artifacts.O;
  return overlay.Execute({action:'overlayVerify',sessionId:session.sessionId,sessionToken:session.sessionToken,
   machineId:row.machineId,binarySha512:artifact.sha512,binaryCrc64:artifact.crc64,
   codeSha512:artifact.codeSha512,codeCrc64:artifact.codeCrc64});
 }
 function Progress(session,phase='AUTHORITY_BEGIN',sequence=9){
  const body={action:'overlayProgress',sessionId:session.sessionId,sessionToken:session.sessionToken,
   phase,sequence,elapsedMs:clock.now()-row.claimedAt,signature:'pending'};
  body.signature=crypto.sign('sha256',Buffer.from(tracker.Canonical(body)),keys.privateKey).toString('base64');
  return overlay.Execute(body);
 }
 RenewParent();
 return {parent,row,license,Claim,RenewParent,Verify,Progress,overlay,tracker,writes:()=>writes};
}

test('Claim close to the parent deadline inherits only its remaining startup time',()=>Clock(clock=>{
 const f=Fixture(clock),parentExpiry=f.parent.sessionExpiresAt;
 clock.advance(115000);
 const session=f.Claim();
 assert.equal(session.expiresAt,parentExpiry);
 assert.equal(session.expiresAt-clock.now(),5000);
 assert.equal(f.row.sessionExpiresAt,parentExpiry);
}));

test('fresh ordinary parent verification immediately before Claim gives a new bounded startup window',()=>Clock(clock=>{
 const f=Fixture(clock),oldParentExpiry=f.parent.sessionExpiresAt;
 clock.advance(115000);
 const freshExpiry=f.RenewParent();
 assert.equal(freshExpiry,clock.now()+120000);
 assert.ok(freshExpiry>oldParentExpiry);
 const session=f.Claim();
 assert.equal(session.expiresAt,freshExpiry);
 assert.equal(session.expiresAt-clock.now(),120000);
 // The old signed handoff deadline is not extended; it was still valid at Claim.
 assert.equal(f.row.expiresAt,oldParentExpiry);
}));

test('renewing the parent after Claim does not silently extend the existing child lease',()=>Clock(clock=>{
 const f=Fixture(clock);clock.advance(115000);
 const session=f.Claim(),childExpiry=session.expiresAt;
 clock.advance(1000);
 assert.ok(f.RenewParent()>childExpiry);
 assert.equal(f.row.sessionExpiresAt,childExpiry);
 assert.equal(f.overlay.__probe.Live(f.row).id,'O');
}));

test('expired child cannot be revived by a fresh parent, progress, Claim replay, or verify request',()=>Clock(clock=>{
 const f=Fixture(clock);clock.advance(115000);
 const session=f.Claim(),childExpiry=session.expiresAt;
 clock.advance(1000);f.RenewParent();clock.advance(4000);
 assert.equal(clock.now(),childExpiry);
 assert.ok(f.parent.sessionExpiresAt>clock.now());
 const writes=f.writes();
 for(const request of [()=>f.Progress(session),()=>f.Claim(),()=>f.Verify(session)])
  assert.throws(request,/BOOTSTRAP_EXPIRED/);
 assert.equal(f.row.sessionExpiresAt,childExpiry);
 assert.equal(f.row.status,'EXPIRED');
 assert.equal(f.parent.status,'EXPIRED');
 assert.equal(f.writes(),writes+1,'one terminal prune, no new authorization write');
}));

test('signed startup progress preserves both leases and cannot supply fresh authority',()=>Clock(clock=>{
 const f=Fixture(clock),session=f.Claim();clock.advance(56000);
 const before=JSON.stringify([f.row,f.parent,f.license]),writes=f.writes();
 assert.equal(f.Progress(session).recorded,true);
 assert.equal(JSON.stringify([f.row,f.parent,f.license]),before);
 assert.equal(f.writes(),writes);
 assert.equal(f.tracker.View(session.sessionId).attested,false);
 assert.throws(()=>f.Verify(session),/SECURITY_FRESH_OBSERVATION_REQUIRED/);
 assert.equal(f.writes(),writes);
}));

test('fresh parent verification still cannot extend O past the license expiry',()=>Clock(clock=>{
 const f=Fixture(clock);clock.advance(1000);f.RenewParent();
 f.license.expiresAt=clock.now()+15000;
 assert.equal(f.Claim().expiresAt,f.license.expiresAt);
}));
