'use strict';
// Synthetic PE bytes and real isolated durable stores; no Windows execution,
// remote service, production key, or approval evidence is synthesized here.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
test('TPM pre-bootstrap recovery requires hardware transcript plus exact one-use administrator decision',async t=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'peace-keyless-tpm-')),realNow=Date.now,oldLog=console.log;
 let clock=realNow(),boot;
 process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';Object.assign(process.env,{ADMIN_SECRET:'keyless-test-only-admin',VIEWER_SECRET:'keyless-test-only-viewer',WEB_ADMIN_TRANSPORT:'proxy',WEB_ADMIN_TRUSTED_PROXIES:'127.0.0.1/32,::1/128',WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',WEBAUTHN_RP_ID:'localhost',WEBAUTHN_ORIGIN:'https://localhost',WEB_ADMIN_LOGIN_IP_MAX:'1000',WEB_ADMIN_LOGIN_ROLE_MAX:'1000'});console.log=()=>{};
 try{
  require('../../core/peace.utilities').EnsureDirs();
  const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
  boot=require('../../services/bootstrap/peace.desktop-bootstrap');
  require('../../services/network/peace.connect-tls').Public();clock=realNow();Date.now=()=>clock;
  const policy=require('../../services/artifacts/peace.server-policy-protection'),registry=require('../../services/security/peace.server-policy-registry');
  const evidence=require('../../services/artifacts/peace.desktop-packing-evidence'),keyless=require('../../services/bootstrap/peace.keyless-bootstrap');
  const identity=require('../../services/devices/peace.desktop-device-identity'),codec=require('../../services/bootstrap/peace.launcher-public-config');
  const delegation=require('../../services/bootstrap/peace.desktop-handoff-delegation');
  const signing=require('../../services/bootstrap/peace.issued-a-signing'),issuer=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
  process.env[signing.ENV]=Buffer.from(issuer.privateKey.export({type:'pkcs8',format:'pem'})).toString('base64');
  const outputs={},records=[],selected={},jobId=crypto.randomBytes(16).toString('hex');
  for(const role of ['A','B','O']){
   const original=fixture.PE(role,'keyless-bootstrap '+delegation.MARKER),input=role==='A'?require('../fixtures/bootstrap/peace.issued-a-fixture').WithAnchor(original,issuer.publicKey):original,slot=policy.CreateUnsealedSlot(),bytes=Buffer.concat([input,slot]);
   const pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20),last=table+(bytes.readUInt16LE(pe+6)-1)*40,size=bytes.readUInt32LE(last+16)+slot.length;
   bytes.writeUInt32LE(size,last+8);bytes.writeUInt32LE(size,last+16);bytes.writeUInt32LE(Math.ceil((bytes.readUInt32LE(last+12)+size)/4096)*4096,opt+56);
   const source=boot.Publish(role,'93.0.0',bytes,undefined,{activate:false}),out=policy.BindTemplate(bytes,role);outputs[role]=out;
   records.push({version:1,purpose:evidence.DOMAIN,jobId,component:role,sourceArtifactId:source.id,inputSha512:out.inputSha512,outputSha512:out.sha512,size:out.bytes.length,toolSha512:out.toolSha512,profileSha512:out.profileSha512,createdAt:clock,actorHash:'ab'.repeat(64)});
  }
  store.Atomic(db=>{evidence.RecordJob(db,records);registry.RecordJob(db,records,outputs);});
  for(const role of ['A','B','O'])selected[role]=boot.Publish(role,'93.0.1',outputs[role].bytes,undefined,{activate:false});
  // Only the isolated protocol fixture selects these synthetic artifacts. This
  // is not PublishPair and creates no Windows/signature/release approval PASS.
  store.Atomic(db=>{for(const role of ['A','B','O'])db.active[role]=selected[role].id;});
  function invite(){clock++;const request={requestId:crypto.randomUUID()},issue=boot.IssueLauncher(request,'KEYLESS_TEST'),bytes=boot.LauncherBytes(issue.launcherId),config=signing.VerifyFinal(bytes,{expectedTemplateSha512:selected.A.sha512,expectedKeyId:signing.PublicIdentity(issuer.publicKey).keyId}).config;return {request,issue,bytes,config};}
  function challenge(inv=invite(),app=fixture.Device(),persistent=fixture.Device()){
   const p=boot.Execute({action:'keylessPolicy',version:1,launcherId:inv.issue.launcherId,machineId:app.machineId});
   const code=fixture.CodeImage(inv.bytes),body={action:'keylessChallenge',version:1,requestId:crypto.randomUUID(),launcherId:inv.issue.launcherId,launcherSha512:fixture.sha512(inv.bytes),launcherCrc64:fixture.Crc64(inv.bytes),aCodeSha512:code.sha512,aCodeCrc64:code.crc64,publicKey:app.publicKey,deviceId:app.deviceId,machineId:app.machineId,handoffVersion:3,persistentPublicKey:persistent.publicKey,persistentKeyId:persistent.deviceId,keyProvider:p.keyProvider,epoch:p.epoch,revision:p.revision};
   const c=boot.Execute(body),proof={version:1,challengeId:c.challengeId,appSignature:fixture.Sign(app,c.canonical),persistentSignature:fixture.Sign(persistent,c.canonical)};
   return {inv,app,persistent,policy:p,body,c,proof};
  }
  const call=(s,action,extra={})=>boot.Execute({action,...s.proof,...extra});
  const expect=(fn,code)=>assert.throws(fn,{message:code});
  const synthetic=require('../fixtures/devices/peace.synthetic-tpm')(temp);clock=realNow();
  identity.AdminPolicy({expectedRevision:0,requestId:crypto.randomUUID(),mode:'TPM_ATTESTED',requireForEnrolled:true,trust:synthetic.trust},'ADMIN:TEST');
  const keepAlive=setInterval(()=>{},1000);
  function recovery(s){const v=keyless.ListPending().requests.find(x=>x.id===s.c.challengeId).recovery;return {kind:v.kind,oldEnrollmentId:v.oldEnrollmentId,oldKeyId:v.oldKeyId,newKeyId:v.newKeyId,bindingId:v.bindingId,identityRevision:v.identityRevision,confirmed:true};}
  const approve=(s,r=recovery(s))=>keyless.Approve(s.c.challengeId,{identityConfirmed:true,launcherId:s.inv.issue.launcherId,persistentKeyId:s.persistent.deviceId,recovery:r},'ADMIN:TPM_TEST');
  async function attest(s,worker=false){
   assert.equal(s.c.tpmRequired,true);
   const request={action:'keylessProve',...s.proof,tpmEvidence:synthetic.evidence(s.persistent.publicKey,Buffer.from(s.c.nonce,'base64'))};
   let prepared;try{
    if(worker)prepared=await keyless.PrepareTpm(request,performance.now()+10000);
    const result=boot.Execute(request,prepared);assert.equal(result.status,'TPM_ACTIVATION_REQUIRED');assert.deepEqual(boot.Execute(request),result);
    assert.equal(keyless.ListPending().requests.some(x=>x.id===s.c.challengeId),false);
    const secret=synthetic.activate(result);
    try{
     const activation={action:'keylessTpmActivate',version:1,challengeId:s.c.challengeId,secret:secret.toString('base64'),appSignature:fixture.Sign(s.app,result.activationCanonical),persistentSignature:fixture.Sign(s.persistent,result.activationCanonical)};
     expect(()=>boot.Execute({...activation,secret:crypto.randomBytes(32).toString('base64')}),'DEVICE_TPM_ACTIVATION_INVALID');
     expect(()=>boot.Execute({...activation,appSignature:s.proof.appSignature}),'KEYLESS_PROOF_INVALID');
     assert.equal(boot.Execute(activation).status,'PENDING_APPROVAL');assert.equal(boot.Execute(activation).status,'PENDING_APPROVAL');
     assert.equal(keyless.ListPending().requests.find(x=>x.id===s.c.challengeId).hardwareAttested,true);
    }finally{secret.fill(0);}
   }finally{prepared?.secret.fill(0);}
  }
  try{
   let enrolled,first,firstFlow;
   await t.test('new TPM PC validates actual crypto in worker, explicit admin acknowledgement and atomic enrollment',async()=>{
    first=challenge();expect(()=>call(first,'keylessProve'),'DEVICE_TPM_REQUIRED');
    const bad=synthetic.evidence(first.persistent.publicKey,crypto.randomBytes(32));assert.throws(()=>call(first,'keylessProve',{tpmEvidence:bad}),/^Error: DEVICE_TPM_/);
    await attest(first,true);const acknowledgement=recovery(first);assert.equal(acknowledgement.kind,'ENROLL');assert.equal(Object.keys(identity.State().enrollments).length,0);
    expect(()=>keyless.Approve(first.c.challengeId,{identityConfirmed:true,launcherId:first.inv.issue.launcherId,persistentKeyId:first.persistent.deviceId},'ADMIN:TPM_TEST'),'DEVICE_RECOVERY_APPROVAL_REQUIRED');
    expect(()=>approve(first,{...acknowledgement,newKeyId:first.app.deviceId}),'DEVICE_RECOVERY_APPROVAL_REQUIRED');
    const ns=first.policy.keyNamespace;assert.equal(approve(first).hardwareAttested,true);firstFlow=call(first,'beginKeyless');
    enrolled=identity.State().enrollments[identity.EnrollmentId(first.persistent.publicKey)];assert.equal(enrolled.assurance,'TPM_KEY_ATTESTED');assert.equal(enrolled.status,'ACTIVE');
    assert.equal(identity.BootstrapPolicy(first.app.machineId).keyNamespace,ns);assert.deepEqual(call(first,'beginKeyless'),firstFlow);identity.Validate(identity.State());
   });
   await t.test('lost old key replacement needs no old private proof but retires old authority and exact competing candidate',async()=>{
    const app=fixture.Device();app.machineId=first.app.machineId;const next=challenge(invite(),app),other=challenge(invite(),app);
    await attest(next);await attest(other);const r=recovery(next);assert.equal(r.kind,'REPLACE');assert.equal(r.oldEnrollmentId,enrolled.id);assert.equal(r.oldKeyId,first.persistent.deviceId);
    approve(next);approve(other);const result=call(next,'beginKeyless');assert.equal(identity.State().enrollments[enrolled.id].status,'RETIRED');assert.equal(store.Load().flows[firstFlow.flowId].status,'REVOKED');
    assert.equal(store.Load().flows[result.flowId].status,'STARTED');assert.deepEqual(call(next,'beginKeyless'),result);
    expect(()=>call(other,'beginKeyless'),'DEVICE_RECOVERY_CONFLICT');assert.equal(store.Load().launchers[other.inv.issue.launcherId].status,'AVAILABLE');
    assert.equal(Object.keys(identity.State().recoveryGrants).length,0);expect(()=>identity.CheckBootstrapKey(first.persistent.publicKey,app.machineId,'PLATFORM'),'DEVICE_KEY_REVOKED');
    enrolled=identity.State().enrollments[identity.EnrollmentId(next.persistent.publicKey)];first=next;firstFlow=result;
   });
   await t.test('expired same-key attestation renews explicitly without changing OS key namespace',async()=>{
    store.Atomic(db=>{db.deviceIdentity.enrollments[enrolled.id].attestedUntil=clock-1;});
    const s=challenge(invite(),first.app,first.persistent);await attest(s);assert.equal(recovery(s).kind,'RENEW');approve(s);call(s,'beginKeyless');assert(identity.State().enrollments[enrolled.id].attestedUntil>clock);assert.equal(identity.BootstrapPolicy(s.app.machineId).keyNamespace,s.policy.keyNamespace);
   });
   await t.test('policy and current trust changes fence approved candidates without consuming issued A',async()=>{
    const s=challenge();await attest(s);approve(s);store.Atomic(db=>{db.deviceIdentity.trust.validUntil=clock-1;});
    expect(()=>call(s,'beginKeyless'),'DEVICE_TPM_TRUST_NOT_CONFIGURED');assert.equal(store.Load().launchers[s.inv.issue.launcherId].status,'AVAILABLE');store.Atomic(db=>{db.deviceIdentity.trust=synthetic.trust;});
   });
   await t.test('retired PC and consumed-license PC locks still reject approved TPM recovery',async()=>{
    const devices=require('../../services/devices/peace.desktop-device-registry'),licenses=require('../../services/licensing/peace.desktop-licenses'),machines=require('../../services/devices/peace.desktop-machine-policy');
    const retired=challenge();await attest(retired);approve(retired);
    store.Atomic(db=>{const id=devices.BindingId(retired.app.machineId,db);db.deviceRegistry||={version:1,revision:0,bindings:{},receipts:{},proofRetentionDays:30};db.deviceRegistry.bindings[id]={id,identificationScheme:'LEGACY_PC_HASH_V1',status:'RETIRED',firstSeenAt:clock,lastSeenAt:clock,retiredAt:clock,proofs:[]};});
    expect(()=>call(retired,'beginKeyless'),'DEVICE_BINDING_RETIRED');assert.equal(store.Load().launchers[retired.inv.issue.launcherId].status,'AVAILABLE');
    const locked=challenge();await attest(locked);approve(locked);
    const created=licenses.Create({requestId:crypto.randomUUID(),label:'Synthetic consumed-license PC lock'},'ADMIN:TEST'),db=licenses.DB(),row=db.licenses[created.license.id];
    // Synthetic durable-row seam: exercise real automatic-PC-lock projection;
    // do not manufacture a successful license-redeem or runtime attestation.
    Object.assign(row,{consumed:true,status:'USED',machineId:locked.app.machineId,machinePolicyGeneration:machines.Generation(locked.app.machineId),activatedAt:clock,bootstrapSessionId:'A'.repeat(24)});db.revision++;
    const before=JSON.stringify(row);assert.equal(machines.Public(locked.app.machineId).source,'SINGLE_USE');
    expect(()=>call(locked,'beginKeyless'),'DESKTOP_MACHINE_BLOCKED');assert.equal(JSON.stringify(row),before);assert.equal(store.Load().launchers[locked.inv.issue.launcherId].status,'AVAILABLE');
    expect(()=>challenge(invite(),locked.app,fixture.Device()),'DESKTOP_MACHINE_BLOCKED');
   });
   await t.test('failed storage commit leaves enrollment and issued A unconsumed; exact retry succeeds',async()=>{
    const s=challenge();await attest(s);approve(s);const before=JSON.stringify(identity.State()),disk=require('../../services/storage/peace.durable-file'),original=disk.Atomic;
    try{disk.Atomic=(file,...args)=>{if(file===path.join(store.DIR,'authority.json'))throw Error('TEST_RECOVERY_DISK_FULL');return original(file,...args);};expect(()=>call(s,'beginKeyless'),'STORAGE_SAVE_FAILED');}
    finally{disk.Atomic=original;}
    assert.equal(JSON.stringify(identity.State()),before);assert.equal(store.Load().launchers[s.inv.issue.launcherId].status,'AVAILABLE');
    assert(call(s,'beginKeyless').flowId);
   });
   await t.test('prepared TPM activation secret is wiped by cancellation before queued commit',async()=>{
    const s=challenge(),request={action:'keylessProve',...s.proof,tpmEvidence:synthetic.evidence(s.persistent.publicKey,Buffer.from(s.c.nonce,'base64'))};
    const prepared=await keyless.PrepareTpm(request,performance.now()+10000);assert(prepared.secret.some(x=>x!==0));keyless.Stop();assert(prepared.secret.every(x=>x===0));expect(()=>boot.Execute(request,prepared),'KEYLESS_REQUEST_EXPIRED');assert.equal(store.Load().launchers[s.inv.issue.launcherId].status,'AVAILABLE');
   });
   await t.test('existing TPM tombstone retains platform requirement in compatible mode and revoked key stays revoked',()=>{
    identity.AdminPolicy({expectedRevision:identity.State().revision,requestId:crypto.randomUUID(),mode:'COMPATIBLE',requireForEnrolled:true,trust:synthetic.trust},'ADMIN:TEST');
    const current=identity.State().enrollments[enrolled.id];identity.Revoke({expectedRevision:identity.State().revision,requestId:crypto.randomUUID(),enrollmentId:current.id,reasonCode:'TPM_RESET',allowReenrollment:true},'ADMIN:TEST');
    assert.equal(identity.BootstrapPolicy(first.app.machineId).keyProvider,'PLATFORM');
    expect(()=>identity.CheckBootstrapKey(first.persistent.publicKey,first.app.machineId,'PLATFORM'),'DEVICE_KEY_REVOKED');
   });
  }finally{clearInterval(keepAlive);}
 }finally{
  Date.now=realNow;console.log=oldLog;boot?.Stop?.();const queues=require('../../services/runtime/peace.desktop-work-queue');await Promise.all([queues.proof,queues.tpmAttestation].map(q=>q.close()));require('../../services/devices/peace.desktop-device-identity').ClearChallenges();require('../../services/observability/peace.desktop-performance-metrics').Close();require('../../storage/sqlite/peace.sqlite-database').Close();fs.rmSync(temp,{recursive:true,force:true});
 }
});
