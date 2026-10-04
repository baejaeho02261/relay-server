'use strict';
// Exercises the production pinned TLS envelope, durable A/B flow, license
// proof, completion transaction and independent declarative overlay lease.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';
process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';
require('../core/utils').EnsureDirs();
const fixture=require('./desktop-bootstrap-fixture'),licenses=require('../services/desktopLicenses'),boot=require('../services/desktopBootstrap'),store=require('../services/desktopBootstrapStore'),overlay=require('../services/desktopOverlay'),state=require('../core/state');
const transport=require('../services/desktopConnect'),keys=require('../services/connectTransportKey'),wire=require('./tls-request-fixture'),server=transport.CreateServer();
const plugins=require('../services/desktopOverlayPlugin');
let profile,checks=0;
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const request=(operation,body)=>wire.Request(profile,operation,body);
async function ok(operation,body){const reply=await request(operation,body);assert.equal(reply.ok,true,JSON.stringify(reply));return reply.data;}
async function denied(code,operation,body){const reply=await request(operation,body);assert.equal(reply.ok,false);assert.equal(reply.error,code,JSON.stringify(reply));}
function reject(code,fn){assert.throws(fn,error=>error.message===code);}
async function check(label,fn){await fn();checks++;console.log('PASS '+label);}
async function observation(device,context){
 const authority=require('../services/desktopSecurityAuthority'),challenge=await ok('security',{...context,action:'challenge'}),baseline=boot.AuthenticateIntegrityReport(context).integrityArtifact;
 const payload=JSON.stringify({version:1,measurement:'MEASURED',fileSha256:baseline.sha256,fileCrc64:baseline.crc64,codeSha256:baseline.codeSha256,codeCrc64:baseline.codeCrc64,apiSealed:true,apiSlots:167,dynamicCode:'ALLOWED',cfg:'DISABLED'});
 const submitted=await ok('security',{...context,action:'submit',challengeId:challenge.challengeId,payload,signature:fixture.Sign(device,authority.Canonical(context,challenge,payload))});assert.equal(submitted.status,'PASS');
}
async function newSession(strict=false){
 const device=fixture.Device();fixture.Publish();
 if(strict){
  const started=fixture.Begin(device);fixture.Download(started.begin);
  await observation(device,{stage:'A',sessionId:started.begin.flowId,sessionToken:started.begin.downloadTicket,machineId:device.machineId,intent:'finish',binding:require('../services/desktopSecurityAuthority').Binding(started.begin.flowId,started.begin.release.sha256)});
  const session=fixture.Claim(device,started.begin,fixture.Finish(device,started.begin));return {device,session,strict};
 }
 const issue=boot.IssueLauncher({requestId:crypto.randomUUID(),label:'Overlay regression'},'TEST');
 const session=await fixture.RemoteSession(device,boot.LauncherBytes(issue.launcherId));
 return {device,session};
}
async function proof(item,action,payload){
 const full={...fixture.Evidence(item.device,item.session),...payload,bootstrapSessionId:item.session.sessionId,bootstrapSessionToken:item.session.sessionToken},payloadJSON=JSON.stringify(full);
 const base={action,requestId:crypto.randomUUID(),deviceId:item.device.deviceId,publicKey:item.device.publicKey,payloadHash:sha(payloadJSON)},challenge=await ok('challenge',base);
 return {...base,challengeId:challenge.challengeId,payloadJSON,signature:fixture.Sign(item.device,challenge.canonical)};
}
async function authorize(item){
 item.issued=licenses.Create({label:'Overlay regression'},'TEST');
 item.redeemProof=await proof(item,'redeem',{licenseKey:item.issued.licenseKey,appVersion:'88.0.0'});
 if(item.strict)await observation(item.device,{stage:'B',sessionId:item.session.sessionId,sessionToken:item.session.sessionToken,machineId:item.device.machineId,intent:'redeem',binding:require('../services/desktopSecurityAuthority').Binding(item.redeemProof.requestId,item.redeemProof.payloadHash)});
 item.license=await ok('execute',item.redeemProof);
 item.completion={action:'completeLicense',requestId:crypto.randomUUID(),sessionId:item.session.sessionId,sessionToken:item.session.sessionToken,deviceId:item.device.deviceId,activationToken:item.license.activationToken};
 return item;
}
async function complete(item){
 item.grant=await ok('bootstrap',item.completion);item.auth={action:'poll',sessionId:item.grant.sessionId,sessionToken:item.grant.sessionToken,deviceId:item.device.deviceId};
 await denied('OVERLAY_PLUGIN_NOT_READY','overlay',item.auth);
 const manifest=await ok('overlay',{...item.auth,action:'plugin-manifest'}),own={status:'MEASURED'},module={name:'overlay.bin',status:'MATCH_LOCAL_FILE',codeStatus:'MATCH_LOCAL_FILE',exportTableStatus:'MEASURED'};
 for(const key of ['sha256','crc64','xxh64','blake3']){const name='file'+key[0].toUpperCase()+key.slice(1);own[name]=manifest.host[key];module[name]=manifest[key];}
 for(const key of ['codeSha256','codeCrc64','codeXxh64','codeBlake3']){own[key]=manifest.host[key];module[key]=manifest[key];}
 for(const key of ['exportTableSha256','exportTableCrc64','exportTableXxh64','exportTableBlake3'])module[key]=manifest[key];
 const payload=JSON.stringify({version:1,hashVersion:2,check:'MODULE_INVENTORY',reason:'PERIODIC',scope:'current-process',trust:'client-reported',snapshotId:manifest.reportId,batchIndex:0,batchCount:1,complete:true,truncated:false,totalModules:1,measuredModules:1,own,modules:[module]});
 item.pluginReady=await ok('overlay',{...item.auth,action:'plugin-report',pluginId:manifest.pluginId,reportId:manifest.reportId,payload});assert.equal(item.pluginReady.status,'READY');return item;
}
const flowFor=item=>Object.values(store.Load().flows).find(row=>row.sessionId===item.session.sessionId);
async function admin(method,pathname,body={},session={role:'admin',id:'TEST',csrf:'csrf-token'},headers={}){
 let status,result,responseHeaders;
 const res={writeHead(value,values){status=value;responseHeaders=values;},end(text){result=text;}};
 await require('../web/routes/desktopBootstrapRoutes').Handle({method,pathname,url:new URL(pathname,'https://admin.invalid'),body,req:{headers},res,session});
 return {status,headers:responseHeaders,raw:result,value:typeof result==='string'?JSON.parse(result):null};
}
(async()=>{
 try{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));process.env.DESKTOP_PUBLIC_PORT=String(server.address().port);profile=keys.Profile();
  const pluginBytes=require('./test-desktop-pe-exports').Fixture();pluginBytes.writeUInt32LE(8400,1072);pluginBytes.write('GameOverlayRunV1\0',1232,'ascii');
  const plugin=plugins.Stage('1.0.0',pluginBytes,undefined,'TEST');plugins.Activate({id:plugin.id,expectedRevision:plugins.Overview().revision},'TEST');
  let item=await newSession();
  await check('No overlay capability before successful license redemption',async()=>{
   await denied('OVERLAY_NOT_AUTHORIZED','bootstrap',{action:'completeLicense',requestId:crypto.randomUUID(),sessionId:item.session.sessionId,sessionToken:item.session.sessionToken,deviceId:item.device.deviceId,activationToken:'0'.repeat(64)});
   await denied('OVERLAY_SESSION_INVALID','overlay',{action:'poll',sessionId:item.session.sessionId,sessionToken:item.session.sessionToken,deviceId:item.device.deviceId});
   assert.equal(flowFor(item).status,'CLAIMED');
  });
  await authorize(item);
  await check('Wrong activation or device cannot complete another B session',async()=>{
   await denied('DESKTOP_ACTIVATION_INVALID','bootstrap',{...item.completion,activationToken:'0'.repeat(64)});
   await denied('OVERLAY_NOT_AUTHORIZED','bootstrap',{...item.completion,deviceId:'0'.repeat(64)});
  });
  await check('Completion atomically closes B and returns a separate data-only capability',async()=>{
   await complete(item);
   assert.notEqual(item.grant.sessionId,item.session.sessionId);assert.notEqual(item.grant.sessionToken,item.session.sessionToken);
   assert.equal(item.grant.documentSha256,sha(item.grant.documentText));assert.equal(JSON.parse(item.grant.documentText).format,overlay.FORMAT);
   assert.ok(item.grant.leaseExpiresAt-item.grant.serverTime<=30000);assert.ok(item.grant.pollAfterMs>0&&item.grant.pollAfterMs<=10000);
   const flow=flowFor(item);assert.equal(flow.status,'CLOSED');assert.equal(flow.closedByLicenseCompletion,true);assert.equal(flow.sessionNonce,undefined);
   assert.equal(flow.lastSecurityIntent,'redeem');assert.match(flow.lastSecurityBinding,/^[a-f0-9]{64}$/);
   assert.ok(!JSON.stringify(overlay.Overview()).includes(item.grant.sessionToken));assert.ok(!fs.readFileSync(path.join(store.DIR,'authority.json'),'utf8').includes(item.grant.sessionToken));
  });
  await check('Lost completion response retries recover the same capability and cannot mint another',async()=>{
   const recovered=await ok('bootstrap',item.completion);assert.equal(recovered.sessionId,item.grant.sessionId);assert.equal(recovered.sessionToken,item.grant.sessionToken);
   assert.equal(Object.keys(store.Load().overlayState.sessions).length,1);
   await denied('OVERLAY_REQUEST_REUSED','bootstrap',{...item.completion,requestId:crypto.randomUUID()});
  });
  await check('Completed B tokens cannot verify, report, inspect or reclose the bootstrap session',async()=>{
   await denied('DESKTOP_CHALLENGE_EXPIRED','execute',item.redeemProof);
   await denied('BOOTSTRAP_SESSION_CLOSED','execute',await proof(item,'verify',{activationToken:item.license.activationToken}));
   for(const action of ['status','close'])await denied('BOOTSTRAP_SESSION_CLOSED','bootstrap',{action,sessionId:item.session.sessionId,sessionToken:item.session.sessionToken});
   await denied('BOOTSTRAP_SESSION_CLOSED','report',{action:'challenge',stage:'B',sessionId:item.session.sessionId,sessionToken:item.session.sessionToken});
  });
  await check('Overlay polling is separately authenticated, updates data and survives B pruning',async()=>{
   await denied('OVERLAY_SESSION_INVALID','overlay',{...item.auth,deviceId:'0'.repeat(64)});
   await denied('OVERLAY_SESSION_INVALID','overlay',{...item.auth,sessionToken:item.session.sessionToken});
   const before=overlay.Overview(),updated=overlay.Update({expectedVersion:before.version,enabled:true,document:{...before.document,title:'Updated server overlay',lines:['새 표시 내용']}},'TEST');
   boot.Overview();const polled=await ok('overlay',item.auth);assert.equal(polled.documentVersion,updated.version);assert.equal(JSON.parse(polled.documentText).title,'Updated server overlay');assert.equal(sha(polled.documentText),polled.documentSha256);
   assert.equal(require('../services/desktopMachinePolicy').Public(item.device.machineId).allowedSessionId,item.session.sessionId);
  });
  await check('Live capability and closed B state survive authoritative restart',async()=>{
   const source="const load=require('node:module').createRequire(require('node:path').join(process.cwd(),'server.js'));load('./storage/database').LoadDatabase();const o=load('./services/desktopOverlay');const auth=JSON.parse(process.env.OVERLAY_TEST_AUTH);const result=o.Execute(auth);if(!result.documentText)process.exit(3);const b=load('./services/desktopBootstrap');let denied=false;try{b.Execute(JSON.parse(process.env.OVERLAY_TEST_B));}catch(e){denied=e.message==='BOOTSTRAP_SESSION_CLOSED';}if(!denied)process.exit(4);console.log('OVERLAY_RESTART_OK')";
   const restart=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-restart-'));try{
    fs.cpSync(temp,restart,{recursive:true});
    const output=child.execFileSync(process.execPath,['-e',source],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:restart,OVERLAY_TEST_AUTH:JSON.stringify(item.auth),OVERLAY_TEST_B:JSON.stringify({action:'status',sessionId:item.session.sessionId,sessionToken:item.session.sessionToken})},encoding:'utf8'});
    assert.match(output,/OVERLAY_RESTART_OK/);
   }finally{fs.rmSync(restart,{recursive:true,force:true});}
  });
  await check('Independent close is idempotent, destroys the capability nonce and never releases a consumed license',async()=>{
   const body={...item.auth,action:'close'};assert.equal((await ok('overlay',body)).status,'CLOSED');assert.equal((await ok('overlay',body)).status,'CLOSED');
   assert.equal(store.Load().overlayState.sessions[item.grant.sessionId].nonce,undefined);assert.equal(licenses.Detail(item.issued.license.id).license.consumed,true);
   await denied('OVERLAY_SESSION_CLOSED','overlay',item.auth);await denied('OVERLAY_SESSION_CLOSED','bootstrap',item.completion);
  });
  await check('Disconnected overlays expire and cannot be revived by polling',async()=>{
   item=await complete(await authorize(await newSession()));const original=Date.now,after=item.pluginReady.leaseExpiresAt+1;Date.now=()=>after;
   try{await denied('OVERLAY_EXPIRED','overlay',item.auth);}finally{Date.now=original;}
   await denied('OVERLAY_SESSION_CLOSED','overlay',item.auth);
  });
  await check('A retried expired redemption receipt cannot authorize a new overlay lease',async()=>{
   const pending=await authorize(await newSession()),real=Date.now,at=pending.license.leaseExpiresAt+1;Date.now=()=>at;
   try{
    const old=pending.redeemProof,challenge=licenses.Challenge({action:old.action,requestId:old.requestId,deviceId:old.deviceId,publicKey:old.publicKey,payloadHash:old.payloadHash});
    const replay={...old,challengeId:challenge.challengeId,signature:fixture.Sign(pending.device,challenge.canonical)};
    assert.ok(licenses.Execute(replay).leaseExpiresAt<at);
    reject('OVERLAY_NOT_AUTHORIZED',()=>boot.Execute(pending.completion));assert.equal(flowFor(pending).status,'CLAIMED');
   }finally{Date.now=real;}
  });
  await check('License revocation and machine policy changes immediately reject overlay polling',async()=>{
   item=await complete(await authorize(await newSession()));licenses.Revoke(item.issued.license.id,{reason:'Overlay regression revoke'},'TEST');await denied('DESKTOP_REVOKED','overlay',item.auth);
   item=await complete(await authorize(await newSession()));require('../services/desktopMachinePolicy').Set(item.device.machineId,false,{requestId:crypto.randomUUID(),reason:'New machine policy generation'},'TEST');await denied('DESKTOP_MACHINE_SESSION_REVOKED','overlay',item.auth);
  });
  await check('Service disable, template disable and admin revoke terminate active capabilities',async()=>{
   item=await complete(await authorize(await newSession()));state.serviceEnabled=false;try{await denied('SERVICE_DISABLED','overlay',item.auth);}finally{state.serviceEnabled=true;}
   await denied('OVERLAY_SESSION_CLOSED','overlay',item.auth);
   item=await complete(await authorize(await newSession()));let s=overlay.Overview();overlay.Update({expectedVersion:s.version,enabled:false,document:s.document},'TEST');await denied('OVERLAY_DISABLED','overlay',item.auth);
   s=overlay.Overview();overlay.Update({expectedVersion:s.version,enabled:true,document:s.document},'TEST');await denied('OVERLAY_SESSION_CLOSED','overlay',item.auth);
   item=await complete(await authorize(await newSession()));overlay.Revoke(item.grant.sessionId,{reason:'Operator revoked overlay'},'TEST');await denied('OVERLAY_SESSION_CLOSED','overlay',item.auth);
  });
  await check('Security revision changes require a new authorization instead of extending stale trust',async()=>{
   item=await complete(await authorize(await newSession()));const authority=require('../services/desktopSecurityAuthority'),policy=authority.Policy();authority.SetPolicy({expectedRevision:policy.revision},'TEST');
   await denied('SECURITY_FRESH_OBSERVATION_REQUIRED','overlay',item.auth);
  });
  await check('No executable/script fields, unknown instructions or invalid text enter the data module',async()=>{
   const current=overlay.Overview(),base={expectedVersion:current.version,enabled:true,document:current.document};
   for(const extra of [{script:'alert(1)'},{executable:'GameOverlay.exe'},{url:'https://example.invalid'}])reject('OVERLAY_INPUT_INVALID',()=>overlay.Update({...base,document:{...base.document,...extra}},'TEST'));
   reject('OVERLAY_INPUT_INVALID',()=>overlay.Update({...base,document:'MZ'},'TEST'));
   reject('OVERLAY_INPUT_INVALID',()=>overlay.Update({...base,document:{...base.document,title:'x\u0000y'}},'TEST'));
   reject('OVERLAY_TEMPLATE_CONFLICT',()=>overlay.Update({...base,expectedVersion:0},'TEST'));
   assert.deepEqual(JSON.parse(overlay.ModuleBytes().toString('utf8')),current.document);
  });
  await check('Admin routes enforce role, CSRF and session lifetime; download is inert .dat',async()=>{
   const route='/api/desktop/bootstrap/overlay',current=overlay.Overview();
   assert.equal((await admin('GET',route,{},null)).status,403);
   assert.equal((await admin('GET',route,{}, {role:'viewer',id:'TEST'})).status,403);
   assert.equal((await admin('GET',route,{}, {role:'admin',id:'TEST',expiresAt:1})).status,401);
   assert.equal((await admin('POST',route,{expectedVersion:current.version,enabled:true,document:current.document})).status,403);
   assert.equal((await admin('GET',route)).status,200);
   const download=await admin('GET',route+'/module.dat');assert.equal(download.status,200);assert.match(download.headers['Content-Disposition'],/overlay\.dat/);assert.equal(download.headers['X-Content-Type-Options'],'nosniff');assert.deepEqual(JSON.parse(download.raw),current.document);
   const auth=require('../web/webAuth'),session=auth.CreateSession({headers:{host:'admin.invalid'},socket:{remoteAddress:'127.0.0.1'}},'admin');
   assert.equal((await admin('POST',route,{expectedVersion:current.version,enabled:true,document:current.document},session,{host:'admin.invalid',origin:'http://admin.invalid','x-csrf-token':session.csrf})).status,200);
  });
  await check('Corrupt durable lease extensions fail validation',async()=>{
   const db=structuredClone(store.Load()),s=db.overlayState,first=Object.values(s.sessions)[0];first.leaseExpiresAt=first.lastSeenAt+overlay.LEASE_MS+1;
   assert.throws(()=>overlay.ValidateState(s,db),/OVERLAY_STORAGE_INVALID/);
  });
  await check('Clock rollback and expiry during authorization never persist invalid lease chronology',async()=>{
   item=await complete(await authorize(await newSession()));let original=Date.now;Date.now=()=>store.Load().overlayState.sessions[item.grant.sessionId].createdAt-1;
   try{reject('OVERLAY_EXPIRED',()=>overlay.Execute(item.auth));}finally{Date.now=original;}
   overlay.ValidateState(store.Load().overlayState,store.Load());
   item=await complete(await authorize(await newSession()));
   const authority=require('../services/desktopSecurityAuthority'),requireArtifact=authority.RequireArtifact,at=original(),before=structuredClone(licenses.DB()),license=licenses.DB().licenses[item.issued.license.id];
   license.expiresAt=at+1000;licenses.DB().revision++;require('../services/desktopJournal').Commit(before,licenses.DB());
   Date.now=()=>at;
   authority.RequireArtifact=function(artifact){Date.now=()=>at+1001;return requireArtifact(artifact);};
   try{reject('DESKTOP_EXPIRED',()=>overlay.Execute(item.auth));}finally{Date.now=original;authority.RequireArtifact=requireArtifact;}
   overlay.ValidateState(store.Load().overlayState,store.Load());
  });
  await check('Strict A/B signed observations authorize completion; restart cannot reuse missing fresh decisions',async()=>{
   const authority=require('../services/desktopSecurityAuthority'),ops=require('../services/desktopSecurityOperations');
   for(const component of ['A','B']){const artifact=boot.Publish(component,'88.0.0',fixture.PE(component,authority.DOMAIN));ops.SetContract({expectedRevision:ops.Revision(),artifactId:artifact.id,contract:{version:1,evidenceVersion:1,minApiSlots:167,maxApiSlots:167,requiredChecks:['ownImage','apiStorage','mitigations']}},'TEST');}
   ops.SetControls({expectedRevision:ops.Revision(),requireBuildContract:true},'TEST');
   item=await authorize(await newSession(true));
   const restart=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-freshness-'));try{
    fs.cpSync(temp,restart,{recursive:true});
    const source="const load=require('node:module').createRequire(require('node:path').join(process.cwd(),'server.js'));load('./storage/database').LoadDatabase();try{load('./services/desktopBootstrap').Execute(JSON.parse(process.env.OVERLAY_TEST_COMPLETE));process.exit(3);}catch(e){if(e.message!=='SECURITY_FRESH_OBSERVATION_REQUIRED')throw e;console.log('FRESHNESS_REQUIRED')}";
    const output=child.execFileSync(process.execPath,['-e',source],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:restart,OVERLAY_TEST_COMPLETE:JSON.stringify(item.completion)},encoding:'utf8'});assert.match(output,/FRESHNESS_REQUIRED/);
   }finally{fs.rmSync(restart,{recursive:true,force:true});}
   await complete(item);assert.equal((await ok('overlay',item.auth)).sessionId,item.grant.sessionId);
  });
  console.log('Desktop overlay: '+checks+' production-wire and authority checks passed');
 }finally{await new Promise(resolve=>server.close(resolve));fs.rmSync(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
