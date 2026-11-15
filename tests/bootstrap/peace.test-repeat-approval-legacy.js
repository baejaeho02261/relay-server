'use strict';
// Historical schema-5 data compatibility only. These synthetic PEs are never
// executed; no current issuance/approval gate is disabled to create this data.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const phase=process.argv[2],root=path.resolve(__dirname,'../..');
if(!phase){
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-repeat-approval-legacy-'));
 try{
  for(const engine of ['json','sqlite']){
   const data=path.join(temporary,engine),env={...process.env,DATA_DIR:data,STORAGE_ENGINE:engine,HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'};
   for(const step of ['seed','verify','reload']){
    const result=spawnSync(process.execPath,[__filename,step],{cwd:root,env,encoding:'utf8',timeout:30000});
    assert.equal(result.status,0,result.stderr||'Historical compatibility child failed');
    for(const line of result.stdout.split('\n'))if(line.startsWith('PASS '))console.log(line+' ('+engine+')');
   }
  }
  console.log('REPEAT APPROVAL LEGACY: schema-5 reload, new legacy issuance/start rejection, exact retry and active-session renewal passed under JSON and SQLite. Synthetic data only.');
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
}else{
 require('../../core/peace.utilities').EnsureDirs();
 const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),boot=require('../../services/bootstrap/peace.desktop-bootstrap'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
 const licenses=require('../../services/licensing/peace.desktop-licenses'),integrity=require('../../services/integrity/peace.desktop-integrity');
 const contextFile=path.join(process.env.DATA_DIR,'synthetic-legacy-context.json'),authorityFile=path.join(store.DIR,'authority.json');
 const hash=value=>crypto.createHash('sha256').update(value).digest('hex'),id=()=>crypto.randomBytes(12).toString('hex').toUpperCase(),nonce=()=>crypto.randomBytes(24).toString('hex');
 const token=(secret,domain,value,salt)=>crypto.createHmac('sha256',Buffer.from(secret,'hex')).update(['GAME-A80',domain,value,salt].join('|')).digest('base64url');
 function LicenseCall(context,action,payload){
  const device=context.device,flow=store.Load().flows[context.claimed.flowId],artifact=store.Load().artifacts[flow.releaseId];
  const requestId=crypto.randomUUID(),bodyPayload={...payload,machineId:device.machineId,binarySha512:artifact.sha512,binaryCrc64:artifact.crc64,codeSha512:artifact.codeSha512,codeCrc64:artifact.codeCrc64,
   bootstrapSessionId:flow.sessionId,bootstrapSessionToken:context.claimed.sessionToken};
  const payloadJSON=JSON.stringify(bodyPayload),body={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:fixture.sha512(payloadJSON)},challenge=licenses.Challenge(body);
  fixture.ObserveLicense(device,action,requestId,body.payloadHash,bodyPayload);
  return licenses.Execute({...body,challengeId:challenge.challengeId,payloadJSON,signature:fixture.Sign(device,challenge.canonical)});
 }
 function HistoryUnchanged(fn){
  const before=JSON.stringify(store.Load()),bytes=fs.readFileSync(authorityFile);fn();
  assert.ok(JSON.stringify(store.Load())===before,'Rejection/recovery must not mutate historical authority in memory');
  assert.ok(fs.readFileSync(authorityFile).equals(bytes),'Rejection/recovery must not rewrite persisted history');
 }
 function Seed(){
  const device=fixture.Device(),artifacts={};
  for(const role of ['A','B','O'])artifacts[role]=boot.Publish(role,'70.0.0',fixture.PE(role,'SYNTHETIC HISTORICAL TICKET FORMAT'));
  const secret=store.Load().secret,profile=require('../../services/network/peace.connect-transport-key').Profile(),template=boot.ReadArtifactBytes(store.Load().artifacts[artifacts.A.id]);
  const at=Date.now()-1000,epoch=require('../../services/recovery/peace.desktop-recovery').Epoch(store.Load()),records=[];
  function Historical(status,device=fixture.Device()){
   const launcher={serverEpoch:epoch,id:id(),downloadName:crypto.randomBytes(16).toString('hex')+'.exe',label:'Synthetic historical '+status,artifactId:artifacts.A.id,profile,
    ticketNonce:nonce(),status:'AVAILABLE',issuedAt:at,expiresAt:at+boot.LAUNCHER_MS,issuedBy:'ADMIN:SYNTHETIC_HISTORY',flowId:''};
   const ticket=token(secret,'LAUNCHER',launcher.id,launcher.ticketNonce);
   launcher.ticketHash=hash(ticket);
   // Exact retained schema-1 personalized envelope inside a schema-5 store.
   const config=Buffer.from(JSON.stringify({schema:1,profile,launcherId:launcher.id,launcherTicket:ticket,expiresAt:launcher.expiresAt})),size=Buffer.alloc(4);size.writeUInt32LE(config.length);
   const bytes=Buffer.concat([template,config,size,boot.FOOTER]);Object.assign(launcher,integrity.Digests(bytes));
   const body={action:'begin',requestId:crypto.randomUUID(),launcherId:launcher.id,launcherTicket:ticket,launcherSha512:launcher.sha512,launcherCrc64:launcher.crc64,aCodeSha512:artifacts.A.codeSha512,aCodeCrc64:artifacts.A.codeCrc64,
    machineId:device.machineId,deviceId:device.deviceId,publicKey:device.publicKey};
   if(status==='AVAILABLE'){records.push({launcher});return {body,launcherId:launcher.id};}
   const flow={serverEpoch:epoch,id:id(),sessionId:id(),launcherId:launcher.id,launcherSha512:launcher.sha512,launcherCrc64:launcher.crc64,aCodeSha512:artifacts.A.codeSha512,aCodeCrc64:artifacts.A.codeCrc64,
    codeIntegrityStatus:'VERIFIED',lastCodeVerifiedAt:at,machineId:device.machineId,machinePolicyGeneration:require('../../services/devices/peace.desktop-machine-policy').Generation(device.machineId),
    releaseId:artifacts.B.id,overlayReleaseId:artifacts.O.id,deviceId:device.deviceId,publicKey:device.publicKey,handoffVersion:1,
    beginFingerprint:hash(JSON.stringify({requestId:body.requestId,launcherId:launcher.id,sha512:launcher.sha512,crc64:launcher.crc64,aCodeSha512:body.aCodeSha512,aCodeCrc64:body.aCodeCrc64,machineId:device.machineId,deviceId:device.deviceId,publicKey:device.publicKey})),
    status,createdAt:at,expiresAt:at+boot.FLOW_MS,downloadNonce:nonce(),finishNonce:nonce(),chunkOffsets:status==='CLAIMED'?[0]:[],licenseId:'',lastVerifiedAt:0};
   const downloadTicket=token(secret,'DOWNLOAD',flow.id,flow.downloadNonce);flow.downloadHash=hash(downloadTicket);
   launcher.status='CONSUMED';launcher.flowId=flow.id;launcher.retiredAt=at;delete launcher.profile;delete launcher.ticketNonce;
   let sessionToken;
   if(status==='CLAIMED'){
    Object.assign(flow,{downloadedAt:at,handoffNonce:nonce(),claimNonce:nonce(),handoffExpiresAt:at+boot.HANDOFF_MS,claimedAt:at,sessionNonce:nonce(),sessionExpiresAt:at+boot.SESSION_MS,
     bCodeSha512:artifacts.B.codeSha512,bCodeCrc64:artifacts.B.codeCrc64});
    flow.handoffHash=hash(token(secret,'HANDOFF',flow.id,flow.handoffNonce));sessionToken=token(secret,'SESSION',flow.sessionId,flow.sessionNonce);flow.sessionHash=hash(sessionToken);
   }
   records.push({launcher,flow});return {body,launcherId:launcher.id,flowId:flow.id,downloadTicket,sessionId:flow.sessionId,...(sessionToken?{sessionToken}:{})};
  }
  const context={device:{...device,privateKey:device.privateKey.export({type:'pkcs8',format:'pem'}).toString()},available:Historical('AVAILABLE'),started:Historical('STARTED'),claimed:Historical('CLAIMED',device),issueRequestId:crypto.randomUUID()};
  // Persist a historical fixture through the normal durable writer. A separate
  // process below invokes the complete unmodified schema/token validator.
  store.Atomic(db=>{
   for(const record of records){db.launchers[record.launcher.id]=record.launcher;if(record.flow)db.flows[record.flow.id]=record.flow;}
   db.issueReceipts[hash('ADMIN:SYNTHETIC_HISTORY')+'|'+context.issueRequestId]={fingerprint:hash(JSON.stringify({label:'Existing historical issuance'})),launcherId:context.available.launcherId};
  });
  const created=licenses.Create({productId:'cleaner.pubg',requestId:crypto.randomUUID(),label:'Existing legacy session license'},'ADMIN:SYNTHETIC_HISTORY');
  const redeemed=LicenseCall(context,'redeem',{licenseKey:created.licenseKey,appVersion:'70.0.0'});
  assert.equal(redeemed.status,'USED');context.licenseId=created.license.id;context.activationToken=redeemed.activationToken;
  fs.writeFileSync(contextFile,JSON.stringify(context),{mode:0o600});template.fill(0);
 }
 function Verify(){
  // This first Load reads the on-disk authority, validates schema 5, every
  // historical HMAC, role, key identity and independent journal head.
  assert.equal(store.Load().schema,5);
  const audit=require('../../storage/audit/peace.audit');audit.LoadRecentAudit();assert.equal(audit.VerifyAuditChain().ok,true);
  const context=JSON.parse(fs.readFileSync(contextFile,'utf8'));
  assert.equal(Object.keys(store.Load().launchers).length,3);assert.equal(Object.keys(store.Load().flows).length,2);
  HistoryUnchanged(()=>assert.throws(()=>boot.IssueLauncher({requestId:crypto.randomUUID(),label:'New legacy issuance'},'ADMIN:SYNTHETIC_HISTORY'),{message:'BOOTSTRAP_APPROVAL_UPGRADE_REQUIRED'}));
  HistoryUnchanged(()=>assert.throws(()=>boot.IssueLauncher({requestId:context.issueRequestId,label:'Existing historical issuance'},'ADMIN:SYNTHETIC_HISTORY'),{message:'BOOTSTRAP_APPROVAL_UPGRADE_REQUIRED'}));
  HistoryUnchanged(()=>assert.throws(()=>boot.Execute(context.available.body),{message:'BOOTSTRAP_APPROVAL_UPGRADE_REQUIRED'}));
  console.log('PASS New legacy issuance, old issuance receipt and unused legacy A reject without mutating history');
  for(const key of ['started']){
   const historical=context[key];
   HistoryUnchanged(()=>{const result=boot.Execute(historical.body);assert.equal(result.flowId,historical.flowId);assert.ok(result.downloadTicket===historical.downloadTicket,'Exact historical retry must recover its existing ticket only');assert.equal(result.release.id,store.Load().flows[historical.flowId].releaseId);});
   HistoryUnchanged(()=>assert.throws(()=>boot.Execute({...historical.body,requestId:crypto.randomUUID()}),{message:'BOOTSTRAP_LAUNCHER_USED'}));
  }
  // Existing PC-use policy has always denied Begin after license redemption,
  // including an old A retry. Preserve this independent restriction as well.
  HistoryUnchanged(()=>assert.throws(()=>boot.Execute(context.claimed.body),{message:'DESKTOP_MACHINE_BLOCKED'}));
  console.log('PASS Consumed legacy A exact retry preserves its STARTED flow; new request and used-PC begin remain blocked');
  const original=structuredClone(store.Load().flows[context.claimed.flowId]),available=JSON.stringify(store.Load().launchers[context.available.launcherId]);
  const result=LicenseCall(context,'verify',{activationToken:context.activationToken,appVersion:'70.0.1'}),renewed=store.Load().flows[context.claimed.flowId];
  assert.equal(result.status,'USED');assert.equal(result.licenseId,context.licenseId);assert.ok(result.leaseExpiresAt>Date.now());
  assert.equal(renewed.status,'CLAIMED');assert.equal(renewed.id,original.id);assert.equal(renewed.sessionId,original.sessionId);assert.equal(renewed.createdAt,original.createdAt);
  assert.ok(renewed.sessionHash===original.sessionHash,'Renewal must preserve the original capability');assert.ok(renewed.sessionExpiresAt>=original.sessionExpiresAt);assert.ok(renewed.lastVerifiedAt>original.lastVerifiedAt);
  assert.ok(JSON.stringify(store.Load().launchers[context.available.launcherId])===available);assert.equal(Object.keys(store.Load().flows).length,2);assert.equal(Object.keys(store.Load().launchers).length,3);
  assert.equal(licenses.DB().licenses[context.licenseId].consumed,true);assert.equal(licenses.DB().licenses[context.licenseId].bootstrapSessionId,original.sessionId);
  console.log('PASS Existing legacy active B session renews through real signed license and authority proofs');
 }
 function Reload(){
  const context=JSON.parse(fs.readFileSync(contextFile,'utf8'));assert.equal(store.Load().schema,5);
  const flow=store.Load().flows[context.claimed.flowId];assert.equal(flow.status,'CLAIMED');assert.equal(flow.licenseId,context.licenseId);assert.equal(flow.appVersion,'70.0.1');assert.equal(licenses.DB().licenses[context.licenseId].consumed,true);
  assert.equal(boot.Execute({action:'status',sessionId:flow.sessionId,sessionToken:context.claimed.sessionToken}).status,'CLAIMED');
  console.log('PASS Fresh-process reload preserves historical consumed state and renewed active session');
 }
 try{if(phase==='seed')Seed();else if(phase==='verify')Verify();else if(phase==='reload')Reload();else throw Error('UNKNOWN_TEST_PHASE');}
 finally{require('../../storage/sqlite/peace.sqlite-database').Close();}
}
