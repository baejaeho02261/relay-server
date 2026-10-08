'use strict';
// Real bootstrap/session capabilities and RSA signatures; no Windows execution.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-overlay-diagnostics-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../core/utils').EnsureDirs();
const fixture=require('./desktop-bootstrap-fixture'),bootstrap=require('../services/desktopBootstrap');
const licenses=require('../services/desktopLicenses'),reports=require('../services/desktopIntegrityReports');
const authority=require('../services/desktopSecurityAuthority'),workspace=require('../services/desktopWorkspace'),state=require('../core/state');
const reasons=['OVERLAY_PREPARE_FAILED','OVERLAY_LAUNCH_FAILED','OVERLAY_TRANSFER_FAILED','HANDOFF_KEY_EXPORT_FAILED','HANDOFF_PROCESS_CREATE_FAILED','HANDOFF_PIPE_TIMEOUT','HANDOFF_PIPE_FAILED','HANDOFF_CHILD_EXITED','HANDOFF_READY_TIMEOUT','HANDOFF_WAIT_FAILED'];
let checks=0;
function check(label,fn){fn();checks++;console.log('PASS '+label);}
function reject(code,fn){assert.throws(fn,error=>error.message===code);}
function context(){const device=fixture.Device(),session=fixture.Session(device);return {device,session,auth:{stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:device.machineId}};}
function payload(reason='HANDOFF_CHILD_EXITED'){return {version:1,hashVersion:3,check:'OVERLAY_START',reason};}
function signed(ctx,value=payload()){
 const challenge=reports.Execute({...ctx.auth,action:'challenge'}),text=JSON.stringify(value);
 return {...ctx.auth,action:'submit',reportId:challenge.reportId,payload:text,signature:fixture.Sign(ctx.device,reports.Canonical(ctx.auth.sessionId,challenge,text))};
}
function authorityState(){const x=authority.List();return {events:x.events,observations:x.recentBuildObservations,decisions:x.decisionCount,pending:x.pendingCount};}
function redeem(ctx){
 const issued=licenses.Create({requestId:crypto.randomUUID(),label:'Overlay diagnostics'},'TEST');
 const value={...fixture.Evidence(ctx.device,ctx.session),bootstrapSessionId:ctx.session.sessionId,bootstrapSessionToken:ctx.session.sessionToken,licenseKey:issued.licenseKey,deviceName:'Diagnostic fixture',appVersion:'88.0.0'};
 const text=JSON.stringify(value),body={action:'redeem',requestId:crypto.randomUUID(),deviceId:ctx.device.deviceId,publicKey:ctx.device.publicKey,payloadHash:fixture.sha512(text)},challenge=licenses.Challenge(body);
 fixture.ObserveLicense(ctx.device,body.action,body.requestId,body.payloadHash,value);
 const activation=licenses.Execute({...body,challengeId:challenge.challengeId,payloadJSON:text,signature:fixture.Sign(ctx.device,challenge.canonical)});
 return {issued,activation};
}
try{
 const ctx=context(),licensed=redeem(ctx);
 const authContext={...ctx.auth,intent:'verify',binding:authority.Binding('diagnostic-preserve',ctx.session.release.sha512)};
 fixture.Observe(ctx.device,authContext);
 const own=bootstrap.AuthenticateIntegrityReport(ctx.auth).integrityArtifact;
 assert.equal(reports.Execute(signed(ctx,{version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',crcLayers:own.crcLayers,own:{status:'MEASURED',codeSha512:own.codeSha512,codeCrc64:own.codeCrc64,fileXxh3_128:own.fileXxh3_128,fileBlake3:own.fileBlake3,codeXxh3_128:own.codeXxh3_128,codeBlake3:own.codeBlake3}})).status,'VERIFIED');
 let acceptedRequest;
 check('Licensed B diagnostics never change bootstrap, license, hashes or authority',()=>{
  const bootBefore=structuredClone(bootstrap.Initialize()),licenseBefore=structuredClone(licenses.DB()),authorityBefore=structuredClone(authorityState());
  const recordsBefore=reports.List({sessionId:ctx.session.sessionId}).items,observationsBefore=JSON.parse(fs.readFileSync(reports.FILE)).data.observations;
  for(const reason of reasons){
   const request=signed(ctx,payload(reason)),result=reports.Execute(request);acceptedRequest=request;
   assert.equal(result.accepted,true);assert.equal(result.status,'CLIENT_DIAGNOSTIC');assert.equal(result.terminate,false);
   const record=reports.List({sessionId:ctx.session.sessionId}).items.find(row=>row.id===result.reportId);
   assert.equal(record.check,'OVERLAY_START');assert.equal(record.reason,reason);assert.equal(record.source,'SIGNED_CLIENT_REPORT');assert.equal(record.attested,false);assert.equal(record.extendedHashesVerified,false);
  }
  assert.deepEqual(bootstrap.Initialize(),bootBefore);assert.deepEqual(licenses.DB(),licenseBefore);assert.deepEqual(authorityState(),authorityBefore);
  assert.deepEqual(reports.List({sessionId:ctx.session.sessionId}).items.filter(row=>row.check!=='OVERLAY_START'),recordsBefore);
  assert.deepEqual(JSON.parse(fs.readFileSync(reports.FILE)).data.observations,observationsBefore);
  authority.RequireFresh(bootstrap.AuthenticateIntegrityReport(ctx.auth),'B','verify',authContext.binding);
 });
 check('Authenticated failure is visible in its license timeline without credentials',()=>{
  const detail=workspace.Detail(licensed.issued.license.id),events=detail.timeline.filter(row=>row.type==='DESKTOP_OVERLAY_START_FAILED');
  assert.equal(events.length,reasons.length);assert.deepEqual(new Set(events.map(row=>row.reason)),new Set(reasons));
  for(const event of events){assert.equal(event.problem.code,event.reason);assert.notEqual(event.problem.title,'요청을 완료하지 못했습니다.');}
  const auditEvents=state.events.filter(row=>row.type==='DESKTOP_OVERLAY_START_FAILED');
  for(const event of auditEvents){const value=JSON.parse(event.detail);assert.equal(value.sessionId,ctx.session.sessionId);assert.equal(value.flowId,bootstrap.AuthenticateIntegrityReport(ctx.auth).id);assert.equal(value.source,'SIGNED_CLIENT_REPORT');assert.equal(value.attested,false);}
  for(const text of [JSON.stringify(detail),JSON.stringify(auditEvents),fs.readFileSync(reports.FILE,'utf8')])for(const secret of [ctx.session.sessionToken,licensed.issued.licenseKey,licensed.activation.activationToken,ctx.device.publicKey])assert.ok(!text.includes(secret));
 });
 check('A used report challenge cannot be replayed',()=>reject('INTEGRITY_REPORT_CHALLENGE_INVALID',()=>reports.Execute(acceptedRequest)));
 check('A changed diagnostic still requires the actual B signing key',()=>{
  const request=signed(ctx);request.payload=JSON.stringify(payload('HANDOFF_PIPE_FAILED'));
  reject('INTEGRITY_REPORT_SIGNATURE_INVALID',()=>reports.Execute(request));
  const wrong=signed(ctx);wrong.signature=Buffer.alloc(256).toString('base64');reject('INTEGRITY_REPORT_SIGNATURE_INVALID',()=>reports.Execute(wrong));
 });
 check('Diagnostics reject measurements, snapshot fields, free text and unknown codes',()=>{
  const before=reports.List().revision;
  for(const field of ['own','modules','crcLayers','snapshotId','batchIndex','batchCount','complete','truncated','totalModules','measuredModules','scope','trust','message','status','trusted'])reject('INTEGRITY_REPORT_INVALID',()=>reports.Execute(signed(ctx,{...payload(),[field]:null})));
  for(const reason of ['BASELINE_MATCH','PASS','HANDOFF_UNKNOWN','C:\\private\\token'])reject('INTEGRITY_REPORT_INVALID',()=>reports.Execute(signed(ctx,payload(reason))));
  assert.equal(reports.List().revision,before);assert.equal(bootstrap.AuthenticateIntegrityReport(ctx.auth).status,'CLAIMED');
 });
 check('An authenticated A flow cannot submit B overlay diagnostics',()=>{
  const device=fixture.Device(),began=fixture.Begin(device),a={device,auth:{stage:'A',sessionId:began.begin.flowId,sessionToken:began.begin.downloadTicket,machineId:device.machineId}};
  const before=reports.List().revision;reject('INTEGRITY_REPORT_INVALID',()=>reports.Execute(signed(a)));assert.equal(reports.List().revision,before);
  assert.equal(bootstrap.Initialize().flows[began.begin.flowId].status,'STARTED');
 });
 check('A diagnostic cannot create a missing authority decision',()=>{
  const fresh=context(),before=structuredClone(authorityState());reports.Execute(signed(fresh));assert.deepEqual(authorityState(),before);
  reject('SECURITY_FRESH_OBSERVATION_REQUIRED',()=>authority.RequireFresh(bootstrap.AuthenticateIntegrityReport(fresh.auth),'B','verify',authority.Binding('not-observed',fresh.session.release.sha512)));
  assert.equal(bootstrap.AuthenticateIntegrityReport(fresh.auth).status,'CLAIMED');
 });
 check('Expired challenges and unauthenticated sessions cannot create diagnostics',()=>{
  const stale=signed(ctx),now=Date.now;Date.now=()=>now()+31000;
  try{reject('INTEGRITY_REPORT_CHALLENGE_INVALID',()=>reports.Execute(stale));}finally{Date.now=now;}
  reject('BOOTSTRAP_SESSION_INVALID',()=>reports.Execute({...ctx.auth,action:'challenge',sessionToken:'x'.repeat(43)}));
 });
 check('Diagnostic storage failure does not revoke B or invalidate authority',()=>{
  const request=signed(ctx),before=structuredClone(authorityState()),bootBefore=structuredClone(bootstrap.Initialize()),rename=fs.renameSync;
  fs.renameSync=(from,to)=>{if(to===reports.FILE)throw Error('TEST_DIAGNOSTIC_DISK_FULL');return rename(from,to);};
  try{reject('TEST_DIAGNOSTIC_DISK_FULL',()=>reports.Execute(request));}finally{fs.renameSync=rename;}
  assert.deepEqual(authorityState(),before);assert.deepEqual(bootstrap.Initialize(),bootBefore);
 });
 console.log(`Overlay startup diagnostics: ${checks} checks passed`);
}finally{workspace.Stop();fs.rmSync(temp,{recursive:true,force:true});}
