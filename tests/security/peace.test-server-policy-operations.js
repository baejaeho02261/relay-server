'use strict';
// Real isolated stores, keyless enrollment, independent A/B/O keys, leases,
// cryptographic authority observations and encrypted loopback TLS. Synthetic
// PE fixtures are data only; none of these checks is a Windows execution claim.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {performance}=require('node:perf_hooks');
test('private server operations remain bound to authenticated A/B/O and exact inputs',{timeout:90000},async t=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-private-operation-')),oldLog=console.log,realNow=Date.now;
 let boot,listener,queues; console.log=()=>{};
 Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'sqlite',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1'});
 try{
  require('../../core/peace.utilities').EnsureDirs();
  const f=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
  boot=require('../../services/bootstrap/peace.desktop-bootstrap');
  const transport=require('../../services/network/peace.desktop-connect');queues=require('../../services/runtime/peace.desktop-work-queue');
  listener=transport.CreateServer();await new Promise((resolve,reject)=>{listener.once('error',reject);listener.listen(0,'127.0.0.1',resolve);});
  process.env.DESKTOP_PUBLIC_PORT=String(listener.address().port);
  const profile=require('../../services/network/peace.connect-transport-key').Profile();
  const policy=require('../../services/artifacts/peace.server-policy-protection'),registry=require('../../services/security/peace.server-policy-registry');
  const evidence=require('../../services/artifacts/peace.desktop-packing-evidence'),keyless=require('../../services/bootstrap/peace.keyless-bootstrap');
  const identity=require('../../services/devices/peace.desktop-device-identity'),delegation=require('../../services/bootstrap/peace.desktop-handoff-delegation');
  const authority=require('../../services/security/peace.desktop-security-authority'),rpc=require('../../services/security/peace.server-policy-operations');
  const proof=require('../../services/integrity/peace.desktop-proof-work'),licenses=require('../../services/licensing/peace.desktop-licenses');
  const reports=require('../../services/integrity/peace.desktop-integrity-reports');
  const outputs={},records=[],selected={},jobId=crypto.randomBytes(16).toString('hex');
  for(const role of ['A','B','O']){
   const input=f.PE(role,'private operation '+delegation.MARKER),slot=policy.CreateUnsealedSlot(),bytes=Buffer.concat([input,slot]);
   const pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20),last=table+(bytes.readUInt16LE(pe+6)-1)*40,size=bytes.readUInt32LE(last+16)+slot.length;
   bytes.writeUInt32LE(size,last+8);bytes.writeUInt32LE(size,last+16);bytes.writeUInt32LE(Math.ceil((bytes.readUInt32LE(last+12)+size)/4096)*4096,opt+56);
   const source=boot.Publish(role,'94.0.0',bytes,undefined,{activate:false});
   const out=policy.BindTemplate(bytes,role,{version:1,functions:[{id:2,args:2,body:{op:'add',left:{op:'arg',index:0},right:{op:'arg',index:1}}},{id:7,args:0,body:{op:'const',value:role.charCodeAt(0)}}]});outputs[role]=out;
   records.push({version:1,purpose:evidence.DOMAIN,jobId,component:role,sourceArtifactId:source.id,inputSha512:out.inputSha512,outputSha512:out.sha512,size:out.bytes.length,toolSha512:out.toolSha512,profileSha512:out.profileSha512,createdAt:Date.now(),actorHash:'ad'.repeat(64)});
  }
  // One exact isolated transform receipt time; no production publication gate is bypassed by a web route.
  for(const record of records)record.createdAt=records[0].createdAt;
  store.Atomic(db=>{evidence.RecordJob(db,records);registry.RecordJob(db,records,outputs);});
  for(const role of ['A','B','O'])selected[role]=boot.Publish(role,'94.0.1',outputs[role].bytes,undefined,{activate:false});
  store.Atomic(db=>{for(const role of ['A','B','O'])db.active[role]=selected[role].id;});
  const a=f.Device(),b=f.Device(),o=f.Device(),persistent=f.Device();b.machineId=a.machineId;o.machineId=a.machineId;
  const issued=boot.IssueLauncher({requestId:crypto.randomUUID()},'ISOLATED_OPERATION_TEST'),abytes=boot.LauncherBytes(issued.launcherId),code=f.CodeImage(abytes);
  const kp=boot.Execute({action:'keylessPolicy',version:1,launcherId:issued.launcherId,machineId:a.machineId});
  const kc=boot.Execute({action:'keylessChallenge',version:1,requestId:crypto.randomUUID(),launcherId:issued.launcherId,launcherSha512:f.sha512(abytes),launcherCrc64:f.Crc64(abytes),aCodeSha512:code.sha512,aCodeCrc64:code.crc64,publicKey:a.publicKey,deviceId:a.deviceId,machineId:a.machineId,handoffVersion:3,persistentPublicKey:persistent.publicKey,persistentKeyId:persistent.deviceId,keyProvider:kp.keyProvider,epoch:kp.epoch,revision:kp.revision});
  const kproof={version:1,challengeId:kc.challengeId,appSignature:f.Sign(a,kc.canonical),persistentSignature:f.Sign(persistent,kc.canonical)};
  boot.Execute({action:'keylessProve',...kproof});keyless.Approve(kc.challengeId,{identityConfirmed:true,launcherId:issued.launcherId,persistentKeyId:persistent.deviceId},'ADMIN:ISOLATED_TEST');
  const begin=boot.Execute({action:'beginKeyless',...kproof});
  const authA={stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:a.machineId};
  function enroll(app,auth){const c=identity.Handle({action:'challenge',...auth,requestId:crypto.randomUUID(),publicKey:persistent.publicKey,keyProvider:'SOFTWARE'});identity.Handle({action:'complete',...auth,challengeId:c.challengeId,appSignature:f.Sign(app,c.canonical),signature:f.Sign(persistent,c.canonical)});}
  enroll(a,authA);
  function body(auth,fn=2,args=[17,25]){return {action:'challenge',...auth,requestId:crypto.randomUUID(),policyId:outputs[auth.stage].ownProtection.policyId,functionId:fn,args};}
  function prepare(app,base,{observe=true}={}){
   const c=rpc.Execute(base);
   if(observe)assert.equal(f.Observe(app,{stage:base.stage,sessionId:base.sessionId,sessionToken:base.sessionToken,machineId:base.machineId,intent:'observe',binding:c.binding}).status,'PASS');
   return {...base,action:'invoke',challengeId:c.challengeId,signature:f.Sign(app,rpc.Canonical(base,c))};
  }
  const fail=(fn,pattern)=>assert.throws(fn,pattern);
  async function queued(input,interleave=()=>{}){const jobs=proof.Prepare('policy',input);interleave();return proof.Run(jobs,()=>rpc.Execute(input),{deadline:performance.now()+5000,key:input.sessionId});}
  await t.test('A receives only bounded int32 result through real encrypted TLS, no private program',async()=>{
   const request=body(authA),c=await f.TcpOperation(profile,'policy',request);
   assert.equal(c.binding,rpc.Binding(request));f.Observe(a,{...authA,intent:'observe',binding:c.binding});
   const input={...request,action:'invoke',challengeId:c.challengeId,signature:f.Sign(a,rpc.Canonical(request,c))},out=await f.TcpOperation(profile,'policy',input);
   assert.deepEqual(Object.keys(out).sort(),['functionId','policyId','requestId','result','version']);assert.equal(out.result,42);
   assert.equal(JSON.stringify(out).includes('programBase64'),false);assert.equal(JSON.stringify(out).includes(outputs.A.serverPolicy.programBase64),false);
   fail(()=>rpc.Execute(input),/CHALLENGE_INVALID/);
   await assert.rejects(f.TcpOperation(profile,'policy',input),/COZY_OPERATION_CHALLENGE_INVALID/);
  });
  await t.test('reserved function, unknown function, wrong policy, arity and non-int32 arguments are rejected',()=>{
   for(const patch of [{functionId:1},{functionId:6},{policyId:outputs.B.ownProtection.policyId},{args:[1]},{args:[2147483648,1]},{args:[0.25,1]},{args:Array(9).fill(0)},{args:[true,1]},{programBase64:outputs.A.serverPolicy.programBase64}])fail(()=>rpc.Execute({...body(authA),...patch}),/COZY_(OPERATION|SERVER_POLICY)_/);
  });
  await t.test('inputs, role, request and session identity are transcript-bound; wrong signer consumes attempt',()=>{
   const input=prepare(a,body(authA));
   for(const patch of [{args:[17,26]},{requestId:crypto.randomUUID()},{functionId:7,args:[]},{stage:'B'},{machineId:b.deviceId}])fail(()=>rpc.Execute({...input,...patch}),/COZY_OPERATION_|BOOTSTRAP_/);
   const wrong={...input,signature:f.Sign(b,'wrong-domain')};fail(()=>rpc.Execute(wrong),/SIGNATURE_INVALID/);fail(()=>rpc.Execute(input),/CHALLENGE_INVALID/);
  });
  await t.test('fresh measurement is mandatory and observe-mode cannot grant private operation access',()=>{
   const missing=prepare(a,body(authA),{observe:false});fail(()=>rpc.Execute(missing),/SECURITY_FRESH_OBSERVATION_REQUIRED/);
   const input=prepare(a,body(authA)),old=authority.Policy();store.Atomic(db=>{db.securityAuthorityPolicy={...old,mode:'observe'};});
   try{fail(()=>rpc.Execute(input),/COZY_SERVER_POLICY_AUTHORITY_REQUIRED/);}finally{store.Atomic(db=>{db.securityAuthorityPolicy=old;});}
  });
  await t.test('parallel duplicate proof admission and post-queue policy changes fail closed',async()=>{
   const input=prepare(a,body(authA)),jobs=proof.Prepare('policy',input);fail(()=>proof.Prepare('policy',input),/REQUEST_REUSED/);
   assert.equal((await proof.Run(jobs,()=>rpc.Execute(input),{deadline:performance.now()+5000,key:input.sessionId})).result,42);
   const changed=prepare(a,body(authA)),old=authority.Policy();
   try{await assert.rejects(queued(changed,()=>store.Atomic(db=>{db.securityAuthorityPolicy={...old,revision:old.revision+1};})),/CHALLENGE_INVALID/);}
   finally{store.Atomic(db=>{db.securityAuthorityPolicy=old;});}
  });
  await t.test('expiry and clock rollback cannot revive an operation challenge',()=>{
   const input=prepare(a,body(authA)),at=realNow();Date.now=()=>at+30001;
   try{fail(()=>rpc.Execute(input),/CHALLENGE_INVALID|BOOTSTRAP_EXPIRED|DEVICE_/);}finally{Date.now=realNow;}
   fail(()=>rpc.Execute(input),/CHALLENGE_INVALID/);
   const back=prepare(a,body(authA));Date.now=()=>at-60000;
   try{rpc.Maintain();}finally{Date.now=realNow;}
   fail(()=>rpc.Execute(back),/CHALLENGE_INVALID/);
  });
  await t.test('pending admission and per-context proof work are bounded and shutdown clears volatile state',()=>{
   rpc.Stop();const requests=Array.from({length:4},()=>body(authA)),challenges=requests.map(request=>rpc.Execute(request));
   fail(()=>rpc.Execute(body(authA)),/COZY_OPERATION_RATE_LIMIT/);
   const bad=f.Sign(b,'invalid-operation-proof');
   for(let i=0;i<requests.length;i++)fail(()=>rpc.Execute({...requests[i],action:'invoke',challengeId:challenges[i].challengeId,signature:bad}),/SIGNATURE_INVALID/);
   for(let i=0;i<27;i++){const request=body(authA),c=rpc.Execute(request);fail(()=>rpc.Execute({...request,action:'invoke',challengeId:c.challengeId,signature:bad}),/SIGNATURE_INVALID/);}
   fail(()=>rpc.Execute(body(authA)),/COZY_OPERATION_RATE_LIMIT/);
   rpc.Stop();const request=body(authA),c=rpc.Execute(request);rpc.Stop();
   fail(()=>rpc.Execute({...request,action:'invoke',challengeId:c.challengeId,signature:bad}),/CHALLENGE_INVALID/);
  });
  function delegated(parent,child,role,canonical){const nonce=crypto.randomBytes(32).toString('hex').toUpperCase();return {handoffVersion:3,childPublicKey:child.publicKey,childKeyId:child.deviceId,childNonce:nonce,delegationSignature:f.Sign(parent,delegation.Canonical('DELEGATION',role,canonical,child.deviceId,nonce)),signature:f.Sign(child,delegation.Canonical('CLAIM',role,canonical,child.deviceId,nonce))};}
  f.Download(begin);const finished=f.Finish(a,begin),bs=boot.Execute({action:'claim',flowId:begin.flowId,handoffToken:finished.handoffToken,...delegated(a,b,'B',finished.claimCanonical),binarySha512:begin.release.sha512,crc64:begin.release.crc64,bCodeSha512:begin.release.codeSha512,bCodeCrc64:begin.release.codeCrc64});
  const authB={stage:'B',sessionId:bs.sessionId,sessionToken:bs.sessionToken,machineId:b.machineId};enroll(b,authB);
  function license(app,action,payload){const text=JSON.stringify(payload),request={action,requestId:crypto.randomUUID(),deviceId:app.deviceId,publicKey:app.publicKey,payloadHash:f.sha512(text)},c=licenses.Challenge(request);f.ObserveLicense(app,action,request.requestId,request.payloadHash,payload);return licenses.Execute({...request,challengeId:c.challengeId,payloadJSON:text,signature:f.Sign(app,c.canonical)});}
  await t.test('A capability stops after handoff and B requires actual consumed license lease',()=>{fail(()=>rpc.Execute(body(authA)),/BOOTSTRAP_LAUNCHER_USED/);fail(()=>rpc.Execute(body(authB)),/COZY_OPERATION_LICENSE_REQUIRED/);});
  const common={...f.Evidence(b,bs),bootstrapSessionId:bs.sessionId,bootstrapSessionToken:bs.sessionToken,appVersion:'94.0.1'},lic=licenses.Create({requestId:crypto.randomUUID()},'ISOLATED_OPERATION_TEST');
  const activation=license(b,'redeem',{...common,licenseKey:lic.licenseKey});
  await t.test('B executes registered custom functions with int32 arithmetic and exact server record',async()=>{
   assert.equal((await queued(prepare(b,body(authB,2,[2147483647,1])))).result,-2147483648);
   assert.equal((await f.TcpOperation(profile,'policy',prepare(b,body(authB,7,[])))).result,66);
   const leaseInput=prepare(b,body(authB)),priorLease=store.Load().flows[begin.flowId].licenseLeaseExpiresAt;
   try{await assert.rejects(queued(leaseInput,()=>store.Atomic(db=>{db.flows[begin.flowId].licenseLeaseExpiresAt=Date.now()-1;})),/COZY_OPERATION_LICENSE_REQUIRED/);}
   finally{store.Atomic(db=>{db.flows[begin.flowId].licenseLeaseExpiresAt=priorLease;});}
   const input=prepare(b,body(authB)),record=store.Load().serverPolicies[input.policyId];store.Atomic(db=>{delete db.serverPolicies[input.policyId];});
   try{fail(()=>rpc.Execute(input),/COZY_SERVER_POLICY_RECORD_MISSING/);}finally{store.Atomic(db=>{db.serverPolicies[input.policyId]=record;});}
  });
  const prepared=license(b,'overlay',{...common,activationToken:activation.activationToken});
  for(let offset=0;offset<prepared.release.size;offset+=prepared.chunkSize)boot.Execute({action:'overlayChunk',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,offset});
  const ofinish=boot.Execute({action:'overlayFinish',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,signature:f.Sign(b,prepared.finishCanonical)});
  const osession=boot.Execute({action:'overlayClaim',overlayId:prepared.overlayId,overlayTicket:prepared.overlayTicket,...delegated(b,o,'O',ofinish.claimCanonical),binarySha512:prepared.release.sha512,crc64:prepared.release.crc64,oCodeSha512:prepared.release.codeSha512,oCodeCrc64:prepared.release.codeCrc64});
  const authO={stage:'O',sessionId:osession.sessionId,sessionToken:osession.sessionToken,machineId:o.machineId};enroll(o,authO);
  await t.test('O uses its own key and policy; B cannot substitute even with the same machine',async()=>{
   assert.equal((await queued(prepare(o,body(authO,7,[])))).result,79);
   const request=body(authO),c=rpc.Execute(request);f.Observe(o,{...authO,intent:'observe',binding:c.binding});
   fail(()=>rpc.Execute({...request,action:'invoke',challengeId:c.challengeId,signature:f.Sign(b,rpc.Canonical(request,c))}),/SIGNATURE_INVALID/);
  });
  const baseline=boot.AuthenticateIntegrityReport(authO).integrityArtifact;
  const image=JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:baseline.codeSha512,codeCrc64:baseline.codeCrc64,fileXxh3_128:baseline.fileXxh3_128,fileBlake3:baseline.fileBlake3,codeXxh3_128:baseline.codeXxh3_128,codeBlake3:baseline.codeBlake3},crcLayers:baseline.crcLayers}),ic=reports.Execute({action:'challenge',...authO});
  reports.Execute({action:'submit',...authO,reportId:ic.reportId,payload:image,signature:f.Sign(o,reports.Canonical(osession.sessionId,ic,image))});
  f.Observe(o,{...authO,intent:'verify',binding:authority.Binding(osession.sessionId,baseline.sha512)});
  boot.Execute({action:'overlayVerify',sessionId:osession.sessionId,sessionToken:osession.sessionToken,...f.Evidence(o,osession)});
  boot.Execute({action:'overlayCommit',handoffVersion:1,sessionId:bs.sessionId,sessionToken:bs.sessionToken,overlayId:prepared.overlayId,signature:f.Sign(b,['GAME-OVERLAY-TRANSFER-V1',bs.sessionId,prepared.overlayId].join('\n'))});
  await t.test('transferred O remains valid while retired B cannot call; no lease renewal occurs',async()=>{
   fail(()=>rpc.Execute(body(authB)),/BOOTSTRAP_/);
   const before=store.Load().overlays[prepared.overlayId].sessionExpiresAt;
   assert.equal((await queued(prepare(o,body(authO)))).result,42);
   assert.equal(store.Load().overlays[prepared.overlayId].sessionExpiresAt,before);
  });
  await t.test('revocation between queued proof and commit wins and retires pending contexts',async()=>{
   const input=prepare(o,body(authO));
   await assert.rejects(queued(input,()=>require('../../services/overlay/peace.desktop-overlay').Revoke(osession.sessionId,{reason:'OPERATION_TEST'},'TEST')),/BOOTSTRAP_REVOKED|BOOTSTRAP_SESSION/);
   fail(()=>rpc.Execute(input),/BOOTSTRAP_REVOKED|BOOTSTRAP_SESSION/);
  });
 }finally{
  Date.now=realNow;console.log=oldLog;boot?.Stop();
  if(listener)await new Promise(resolve=>listener.close(resolve));
  if(queues)await Promise.all(['auth','proof','renewalProof','pe','tpmAttestation'].map(k=>queues[k].close()));
  require('../../services/observability/peace.desktop-performance-metrics').Close();require('../../storage/sqlite/peace.sqlite-database').Close();
  fs.rmSync(temp,{recursive:true,force:true});
 }
});
