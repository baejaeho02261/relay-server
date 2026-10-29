'use strict';
// Synthetic PE bytes and real isolated durable stores; no Windows execution,
// remote service, production key, or approval evidence is synthesized here.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
test('V3 public launcher requires bounded dual possession and explicit approval',async t=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'peace-keyless-bootstrap-')),realNow=Date.now,oldLog=console.log;
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
  const approve=s=>keyless.Approve(s.c.challengeId,{identityConfirmed:true,launcherId:s.inv.issue.launcherId,persistentKeyId:s.persistent.deviceId},'ADMIN:KEYLESS_TEST');
  const expect=(fn,code)=>assert.throws(fn,{message:code});
  await t.test('production preview checks actual A anchor and configured signer without issuing or bypassing approval',()=>{
   const operations=require('../../services/security/peace.desktop-security-operations'),selection={aId:selected.A.id,bId:selected.B.id,oId:selected.O.id},before=Object.keys(store.Load().launchers).length;
   let view=operations.PreviewProductionPair(selection);assert.equal(view.finalIssuedSigning.ready,true);assert.equal(view.finalIssuedSigning.authenticode,false);assert.equal(view.eligible,false);assert.equal(view.reasons.includes('COZY_SERVER_POLICY_FINAL_ISSUED_SIGNING_REQUIRED'),false);
   const saved=process.env[signing.ENV];delete process.env[signing.ENV];try{view=operations.PreviewProductionPair(selection);assert.equal(view.finalIssuedSigning.ready,false);assert.ok(view.reasons.includes('ISSUED_A_SIGNING_KEY_NOT_CONFIGURED'));}finally{process.env[signing.ENV]=saved;}
   assert.equal(Object.keys(store.Load().launchers).length,before);
  });
  await t.test('issued V3 file has only public config, no ticket, config key or private policy bytes',()=>{
   const inv=invite(),row=store.Load().launchers[inv.issue.launcherId];
   assert.equal(row.configFormat,'COZY_A_CONFIG_V3');assert.equal(row.configNonce,undefined);assert.equal(inv.config.schema,3);
   assert.deepEqual(Object.keys(inv.config).sort(),['expiresAt','launcherId','profile','schema']);
   assert.equal(inv.bytes.subarray(-signing.FOOTER.length).equals(signing.FOOTER),true);
   assert.deepEqual(boot.LauncherBytes(inv.issue.launcherId),inv.bytes);assert.equal(boot.IssueLauncher(inv.request,'KEYLESS_TEST').launcherId,inv.issue.launcherId);
   assert.equal(inv.bytes.includes(Buffer.from('launcherTicket')),false);
   for(const output of Object.values(outputs))assert.equal(inv.bytes.includes(Buffer.from(output.serverPolicy.programBase64,'base64')),false);
   expect(()=>codec.Encode({...inv.config,launcherTicket:'forbidden'}),'BOOTSTRAP_CONFIG_INVALID');
   expect(()=>codec.Encode({...inv.config,key:'forbidden'}),'BOOTSTRAP_CONFIG_INVALID');
  });
  await t.test('proof binds both distinct keys, all exact measurements, machine, policy and approval',()=>{
   const s=challenge();assert.equal(s.c.canonical.split('\n').length,16);assert.match(s.c.challengeId,/^[a-f0-9]{48}$/);
   expect(()=>call(s,'beginKeyless'),'KEYLESS_APPROVAL_REQUIRED');
   expect(()=>call(s,'keylessProve',{persistentSignature:s.proof.appSignature}),'KEYLESS_PROOF_INVALID');
   expect(()=>call(s,'keylessProve',{appSignature:s.proof.persistentSignature}),'KEYLESS_PROOF_INVALID');
   expect(()=>boot.Execute({...s.body,launcherSha512:'00'.repeat(64)}),'BOOTSTRAP_HASH_MISMATCH');
   expect(()=>boot.Execute({...s.body,machineId:'FF'.repeat(32)}),'KEYLESS_REQUEST_REUSED');
   assert.equal(call(s,'keylessProve').status,'PENDING_APPROVAL');
   const view=keyless.ListPending().requests.find(r=>r.id===s.c.challengeId);assert.equal(view.hardwareAttested,false);assert.equal(view.proof,'PERSISTENT_KEY_POSSESSION');
   for(const field of ['publicKey','persistentPublicKey','nonce','appSignature','persistentSignature','ticket','programBase64'])assert.equal(Object.hasOwn(view,field),false);
   expect(()=>keyless.Approve(s.c.challengeId,{identityConfirmed:false,launcherId:s.inv.issue.launcherId,persistentKeyId:s.persistent.deviceId},'ADMIN:T'),'KEYLESS_APPROVAL_MISMATCH');
   expect(()=>keyless.Approve(s.c.challengeId,{identityConfirmed:true,launcherId:s.inv.issue.launcherId,persistentKeyId:s.app.deviceId},'ADMIN:T'),'KEYLESS_APPROVAL_MISMATCH');
   assert.equal(approve(s).status,'APPROVED');assert.equal(call(s,'keylessStatus').status,'APPROVED');
   const legacy={action:'begin',...Object.fromEntries(Object.entries(s.body).filter(([k])=>!['action','version','persistentPublicKey','persistentKeyId','keyProvider','epoch','revision'].includes(k))),launcherTicket:'forbidden'};
   expect(()=>boot.Execute(legacy),'KEYLESS_APPROVAL_REQUIRED');
   const first=call(s,'beginKeyless'),row=store.Load().flows[first.flowId],revision=store.Load().revision;
   assert.equal(row.keylessPersistentKeyId,s.persistent.deviceId);assert.equal(store.Load().launchers[s.inv.issue.launcherId].status,'CONSUMED');
   assert.equal(row.keylessApproval.version,1);assert.equal(row.keylessApproval.flowId,first.flowId);
   assert.equal(row.keylessApproval.launcherId,s.inv.issue.launcherId);assert.equal(row.keylessApproval.appKeyId,s.app.deviceId);
   assert.equal(row.keylessApproval.persistentKeyId,s.persistent.deviceId);assert.equal(row.keylessApproval.machineId,s.app.machineId);
   assert.equal(row.keylessApproval.machinePolicyGeneration,0);assert.equal(row.keylessApproval.approvalExpiresAt-row.keylessApproval.approvedAt,60000);
   assert.equal(store.Load().launchers[s.inv.issue.launcherId].keylessApprovalVersion,1);
   for(const field of ['publicKey','persistentPublicKey','nonce','appSignature','persistentSignature','sessionToken'])assert.equal(Object.hasOwn(row.keylessApproval,field),false);
   assert.deepEqual(call(s,'beginKeyless'),first);assert.equal(store.Load().revision,revision);assert.equal(Object.keys(store.Load().flows).length,1);
   const copied=fs.mkdtempSync(path.join(os.tmpdir(),'peace-keyless-schema-')),child=require('node:child_process');
   try{
    fs.cpSync(temp,copied,{recursive:true});const env={...process.env,DATA_DIR:copied},modulePath=require.resolve('../../services/bootstrap/peace.desktop-bootstrap-store');
    const pristine=child.spawnSync(process.execPath,['-e',"require(process.argv[1]).Load();",modulePath],{env,encoding:'utf8',timeout:10000});assert.equal(pristine.status,0,pristine.stderr);
    const changed=child.spawnSync(process.execPath,['-e',"const s=require(process.argv[1]);s.Atomic(db=>{delete db.flows[process.argv[2]].keylessPersistentKeyId;});",modulePath,first.flowId],{env,encoding:'utf8',timeout:10000});assert.equal(changed.status,0,changed.stderr);
    const invalid=child.spawnSync(process.execPath,['-e',"require(process.argv[1]).Load();",modulePath],{env,encoding:'utf8',timeout:10000});assert.notEqual(invalid.status,0);assert.match(invalid.stderr,/BOOTSTRAP_STORAGE_INVALID/);
   }finally{fs.rmSync(copied,{recursive:true,force:true});}

   expect(()=>identity.AssertSession(row,'A'),'DEVICE_PERSISTENT_PROOF_REQUIRED');
   const auth={stage:'A',sessionId:first.flowId,sessionToken:first.downloadTicket,machineId:s.app.machineId};
   const same=identity.Handle({action:'policy',...auth});assert.equal(same.keyNamespace,s.policy.keyNamespace);
   expect(()=>identity.Handle({action:'challenge',...auth,requestId:crypto.randomUUID(),publicKey:s.app.publicKey,keyProvider:'SOFTWARE'}),'DEVICE_KEY_BINDING_MISMATCH');
   const c=identity.Handle({action:'challenge',...auth,requestId:crypto.randomUUID(),publicKey:s.persistent.publicKey,keyProvider:'SOFTWARE'});
   const enrolled=identity.Handle({action:'complete',...auth,challengeId:c.challengeId,appSignature:fixture.Sign(s.app,c.canonical),signature:fixture.Sign(s.persistent,c.canonical)});
   assert.equal(enrolled.assurance,'PERSISTENT_KEY_POSSESSION');assert.equal(enrolled.tpmAttested,false);identity.AssertSession(store.Load().flows[first.flowId],'A');
   clock+=30001;expect(()=>call(s,'beginKeyless'),'KEYLESS_REQUEST_EXPIRED');
  });
  await t.test('one-time launcher consumption is atomic across two approved requests',()=>{
   const inv=invite(),a=challenge(inv),b=challenge(inv);for(const s of [a,b]){call(s,'keylessProve');approve(s);}
   const first=call(a,'beginKeyless');expect(()=>call(b,'beginKeyless'),'BOOTSTRAP_LAUNCHER_USED');assert.equal(store.Load().launchers[inv.issue.launcherId].flowId,first.flowId);
  });
  await t.test('approval is a short one-flow grant, duplicate approval cannot extend it and suspension cannot resurrect it',()=>{
   const s=challenge();call(s,'keylessProve');const approved=approve(s),at=clock;
   assert.equal(approved.approvalExpiresAt,at+60000);assert.equal(approved.expiresAt,s.c.expiresAt);
   const counts={launchers:Object.keys(store.Load().launchers).length,flows:Object.keys(store.Load().flows).length};
   clock+=20000;assert.deepEqual(approve(s),approved,'Same operator retry returns the original decision without a new deadline');
   expect(()=>keyless.Approve(s.c.challengeId,{identityConfirmed:true,launcherId:s.inv.issue.launcherId,persistentKeyId:s.persistent.deviceId},'ADMIN:OTHER'),'KEYLESS_APPROVAL_MISMATCH');
   clock=at+60001;expect(()=>call(s,'beginKeyless'),'KEYLESS_REQUEST_EXPIRED');
   clock=at+1000;expect(()=>call(s,'beginKeyless'),'KEYLESS_REQUEST_EXPIRED');
   assert.equal(store.Load().launchers[s.inv.issue.launcherId].status,'AVAILABLE','Expired approval must not consume an unused launcher');
   assert.equal(Object.keys(store.Load().flows).length,counts.flows);
   assert.equal(Object.keys(store.Load().launchers).length,counts.launchers);
  });
  await t.test('PC-policy generation changes invalidate both pending and approved grants; old consumed grants do not become new approvals',()=>{
   const machinePolicy=require('../../services/devices/peace.desktop-machine-policy');
   const beforeApproval=challenge();call(beforeApproval,'keylessProve');
   machinePolicy.Set(beforeApproval.app.machineId,false,{reason:'Explicit PC recovery invalidates old approvals',requestId:crypto.randomUUID()},'ADMIN:KEYLESS_TEST');
   expect(()=>approve(beforeApproval),'DESKTOP_MACHINE_SESSION_REVOKED');
   const afterApproval=challenge();call(afterApproval,'keylessProve');approve(afterApproval);
   machinePolicy.Set(afterApproval.app.machineId,false,{reason:'Explicit PC recovery after approval',requestId:crypto.randomUUID()},'ADMIN:KEYLESS_TEST');
   expect(()=>call(afterApproval,'beginKeyless'),'DESKTOP_MACHINE_SESSION_REVOKED');
   const consumed=challenge();call(consumed,'keylessProve');approve(consumed);const first=call(consumed,'beginKeyless');
   assert.deepEqual(call(consumed,'beginKeyless'),first);
   machinePolicy.Set(consumed.app.machineId,false,{reason:'Explicit PC recovery after consumption',requestId:crypto.randomUUID()},'ADMIN:KEYLESS_TEST');
   expect(()=>call(consumed,'beginKeyless'),'DESKTOP_MACHINE_SESSION_REVOKED');
   assert.equal(store.Load().launchers[consumed.inv.issue.launcherId].status,'CONSUMED');
   assert.equal(store.Load().launchers[consumed.inv.issue.launcherId].flowId,first.flowId);
   // A different issuance needs its own new dual proof and approval. Merely
   // spending a device grant does not introduce a permanent PC lock.
   const fresh=challenge(invite(),consumed.app,consumed.persistent);
   expect(()=>call(fresh,'beginKeyless'),'KEYLESS_APPROVAL_REQUIRED');
   call(fresh,'keylessProve');approve(fresh);assert.notEqual(call(fresh,'beginKeyless').flowId,first.flowId);
  });
  await t.test('consumed receipt rejects altered binding and missing receipt after a durable restart',()=>{
   const s=challenge();call(s,'keylessProve');approve(s);const first=call(s,'beginKeyless'),row=store.Load().flows[first.flowId];
   const receipts=require('../../services/bootstrap/peace.keyless-approval-receipt'),launcher=store.Load().launchers[s.inv.issue.launcherId];
   receipts.Validate(row.keylessApproval,row,launcher);
   for(const [field,value]of Object.entries({flowId:'F'.repeat(24),launcherId:'F'.repeat(24),launcherSha512:'f'.repeat(128),appKeyId:'F'.repeat(64),persistentKeyId:'F'.repeat(64),machineId:'F'.repeat(64),machinePolicyGeneration:1,epoch:row.serverEpoch+1,consumedAt:row.keylessApproval.approvalExpiresAt,approvalExpiresAt:row.keylessApproval.approvedAt+60001,unexpected:true})){
    expect(()=>receipts.Validate({...row.keylessApproval,[field]:value},row,launcher),'KEYLESS_APPROVAL_RECEIPT_INVALID');
   }
   const copied=fs.mkdtempSync(path.join(os.tmpdir(),'peace-keyless-receipt-')),child=require('node:child_process');
   try{
    fs.cpSync(temp,copied,{recursive:true});const env={...process.env,DATA_DIR:copied},modulePath=require.resolve('../../services/bootstrap/peace.desktop-bootstrap-store');
    const changed=child.spawnSync(process.execPath,['-e',"const s=require(process.argv[1]);s.Atomic(db=>{delete db.flows[process.argv[2]].keylessApproval;});",modulePath,first.flowId],{env,encoding:'utf8',timeout:10000});assert.equal(changed.status,0,changed.stderr);
    const invalid=child.spawnSync(process.execPath,['-e',"require(process.argv[1]).Load();",modulePath],{env,encoding:'utf8',timeout:10000});assert.notEqual(invalid.status,0);assert.match(invalid.stderr,/BOOTSTRAP_STORAGE_INVALID/);
   }finally{fs.rmSync(copied,{recursive:true,force:true});}
  });
  await t.test('proof, approval and policy expiry never become reusable after a clock rollback',()=>{
   const s=challenge(),before=clock;clock=s.c.expiresAt-269999;expect(()=>call(s,'keylessProve'),'KEYLESS_REQUEST_EXPIRED');clock=before;expect(()=>call(s,'keylessProve'),'KEYLESS_REQUEST_EXPIRED');
   const p=challenge();call(p,'keylessProve');approve(p);clock=p.c.expiresAt+1;expect(()=>call(p,'beginKeyless'),'KEYLESS_REQUEST_EXPIRED');clock-=2;expect(()=>call(p,'beginKeyless'),'KEYLESS_REQUEST_EXPIRED');
   const changed=challenge();call(changed,'keylessProve');approve(changed);store.Atomic(db=>{db.deviceIdentity||=identity.Empty();db.deviceIdentity.revision++;});expect(()=>call(changed,'beginKeyless'),'KEYLESS_REQUEST_EXPIRED');
  });
  await t.test('challenge/proof work is bounded and restarting loses unconsumed approval',()=>{
   const s=challenge();for(let i=0;i<7;i++)boot.Execute({...s.body,requestId:crypto.randomUUID()});expect(()=>boot.Execute({...s.body,requestId:crypto.randomUUID()}),'KEYLESS_RATE_LIMIT');
   const p=challenge();for(let i=0;i<60;i++)assert.equal(boot.ProofTasks({action:'keylessProve',...p.proof}).length,2);expect(()=>boot.ProofTasks({action:'keylessProve',...p.proof}),'KEYLESS_RATE_LIMIT');
   call(p,'keylessProve');approve(p);keyless.Stop();expect(()=>call(p,'beginKeyless'),'KEYLESS_REQUEST_EXPIRED');assert.equal(keyless.ListPending().requests.length,0);
  });
  await t.test('queued signature verification and one-use dispatcher preserve the exact approved consume',async()=>{
   const work=require('../../services/integrity/peace.desktop-proof-work'),dispatch=require('../../services/authentication/peace.desktop-protected-dispatch'),{performance}=require('node:perf_hooks'),s=challenge();
   async function queued(action,extra={}){const payload={operation:'bootstrap',body:{action,...s.proof,...extra}},ticket=dispatch.Prepare(payload),jobs=work.Prepare(payload.operation,payload.body);return work.Run(jobs,()=>dispatch.Execute(ticket,payload,{bootstrap:boot.Execute}),{deadline:performance.now()+5000,key:s.c.challengeId});}
   await assert.rejects(queued('keylessProve',{persistentSignature:s.proof.appSignature}),{message:'KEYLESS_PROOF_INVALID'});
   assert.equal((await queued('keylessProve')).status,'PENDING_APPROVAL');approve(s);const first=await queued('beginKeyless');assert.equal(store.Load().flows[first.flowId].keylessPersistentKeyId,s.persistent.deviceId);assert.deepEqual(await queued('beginKeyless'),first);
  });
  await t.test('real HTTP approval requires admin, CSRF and a body-bound password action',async()=>{
   const http=require('node:http'),{RequestHandler}=require('../../web/http/peace.web-server');
   const server=http.createServer((req,res)=>Promise.resolve(RequestHandler(req,res)).catch(e=>{res.statusCode=500;res.end(JSON.stringify({error:e.message}));}));
   const callHttp=(url,body,actor,headers={})=>new Promise((resolve,reject)=>{const bytes=body===undefined?null:Buffer.from(JSON.stringify(body)),q=http.request({host:'127.0.0.1',port:server.address().port,path:url,method:bytes?'POST':'GET',headers:{Host:'localhost','X-Forwarded-Proto':'https',...(actor?{Cookie:actor.cookie,'X-CSRF-Token':actor.csrf}:{}),...(bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{}),...headers}},r=>{let data='';r.on('data',b=>data+=b);r.on('end',()=>{try{resolve({status:r.statusCode,data:JSON.parse(data),headers:r.headers});}catch(e){reject(e);}});});q.on('error',reject);q.setTimeout(5000,()=>q.destroy(Error('TEST_TIMEOUT')));q.end(bytes);});
   try{
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    async function login(role){const r=await callHttp('/api/login',{role,password:role==='admin'?process.env.ADMIN_SECRET:process.env.VIEWER_SECRET});assert.equal(r.status,200,JSON.stringify(r.data));return {cookie:r.headers['set-cookie'][0].split(';')[0],csrf:r.data.csrf};}
    const admin=await login('admin'),viewer=await login('viewer'),s=challenge();call(s,'keylessProve');
    const list='/api/desktop/bootstrap/security-operations/keyless-approvals',url=list+'/'+s.c.challengeId+'/approve',body={identityConfirmed:true,launcherId:s.inv.issue.launcherId,persistentKeyId:s.persistent.deviceId};
    assert.equal((await callHttp(list)).status,401);assert.equal((await callHttp(list,undefined,viewer)).status,403);assert.ok((await callHttp(list,undefined,admin)).data.requests.some(r=>r.id===s.c.challengeId));
    assert.equal((await callHttp(url,body,viewer)).status,403);assert.equal((await callHttp(url,body,admin,{'X-CSRF-Token':''})).data.error,'CSRF_FAILED');
    const pending=await callHttp(url,body,admin);assert.equal(pending.status,428,JSON.stringify(pending.data));assert.equal(pending.data.error,'ADMIN_ACTION_REQUIRED');assert.equal(call(s,'keylessStatus').status,'PENDING_APPROVAL');
    assert.equal((await callHttp('/api/session/reauthenticate',{password:process.env.ADMIN_SECRET,actionId:pending.data.action.id},admin)).status,200);
    const approved=await callHttp(url,body,admin,{'X-Admin-Action':pending.data.action.id});assert.equal(approved.status,200,JSON.stringify(approved.data));assert.equal(approved.data.status,'APPROVED');assert.equal(approved.data.hardwareAttested,false);
    assert.equal((await callHttp(url,body,admin,{'X-Admin-Action':pending.data.action.id})).data.error,'ADMIN_ACTION_INVALID');assert.equal(call(s,'keylessStatus').status,'APPROVED');
   }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  });
  await t.test('existing retirement sweep drops idle expired approval without a new keyless request',async()=>{
   const s=challenge();call(s,'keylessProve');approve(s);boot.Initialize();const before=clock;clock=s.c.expiresAt+1;
   await new Promise(resolve=>setTimeout(resolve,1100));clock=before;expect(()=>call(s,'beginKeyless'),'KEYLESS_REQUEST_EXPIRED');boot.Stop();
  });
  await t.test('TPM policy cannot be downgraded or labelled attested by possession signatures',()=>{
   const inv=invite(),app=fixture.Device();store.Atomic(db=>{db.deviceIdentity.mode='TPM_ATTESTED';db.deviceIdentity.revision++;});
   expect(()=>boot.Execute({action:'keylessPolicy',version:1,launcherId:inv.issue.launcherId,machineId:app.machineId}),'DEVICE_TPM_TRUST_NOT_CONFIGURED');
  });
 }finally{
  Date.now=realNow;console.log=oldLog;boot?.Stop?.();await require('../../services/runtime/peace.desktop-work-queue').proof.close();require('../../services/devices/peace.desktop-device-identity').ClearChallenges();require('../../services/observability/peace.desktop-performance-metrics').Close();require('../../storage/sqlite/peace.sqlite-database').Close();fs.rmSync(temp,{recursive:true,force:true});
 }
});
