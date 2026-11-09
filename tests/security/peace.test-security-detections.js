'use strict';
// Real server authority/proof/storage. Synthetic sensor evidence only; no
// Windows or hardware-backed runtime result is claimed by this suite.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-detections-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../../core/peace.utilities').EnsureDirs();
const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),boot=require('../../services/bootstrap/peace.desktop-bootstrap'),authority=require('../../services/security/peace.desktop-security-authority'),paths=require('../../services/security/peace.nhw-response-paths'),reports=require('../../services/security/peace.security-detections'),catalog=require('../../services/security/peace.security-detection-catalog'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
const hash=s=>crypto.createHash('sha512').update(s).digest('hex'),hex=n=>BigInt(n).toString(16).padStart(16,'0');
let checks=0;function check(name,fn){fn();checks++;console.log('PASS '+name);}
function reject(fn,code){assert.throws(fn,e=>!code||e.message===code);}
function reloadedCause(flowId,expected){
 const script="const d=require('./services/security/peace.security-detections');const e=d.ForFlow(process.argv[1])[0];if(!e||e.invalidated!==(process.argv[2]==='true'))throw Error('PERSISTED_CAUSALITY_MISMATCH');process.stdout.write('PERSISTED_CAUSALITY_VALID');";
 const result=require('node:child_process').spawnSync(process.execPath,['-e',script,flowId,String(expected)],{cwd:path.resolve(__dirname,'../..'),env:process.env,encoding:'utf8',timeout:15000});
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/PERSISTED_CAUSALITY_VALID/);
}

process.once('exit',()=>{boot.Stop();fs.rmSync(temp,{recursive:true,force:true});});
function subject(){const device=fixture.Device(),start=fixture.Begin(device);return {device,start,ctx:{stage:'A',sessionId:start.begin.flowId,sessionToken:start.begin.downloadTicket,machineId:device.machineId}};}
function subjectB(){const a=subject(),device=fixture.Child(a.device);fixture.Download(a.start.begin);const b=fixture.Claim(a.device,a.start.begin,fixture.Finish(a.device,a.start.begin),device);return {...a,device,b,ctx:{stage:'B',sessionId:b.sessionId,sessionToken:b.sessionToken,machineId:device.machineId}};}
function row(s){return store.Load().flows[s.start.begin.flowId];}
function detection(id='dkWriteWatch',options={}){return {id,source:'Cozy.NHW.Engine',firstTick:hex(1000),lastTick:hex(1000),count:1,families:8,confidence:0,correlation:false,attestationSequence:hex(0),localOnly:true,...options};}
function payload(records,sequence=1,options={}){return JSON.stringify({version:2,sequence:hex(sequence),tick:hex(2000+sequence),digest:hash(JSON.stringify(records)).slice(0,16),confirmed:false,trust:2,detections:records,...options});}
function request(s,channel,text){const name=channel[0].toUpperCase()+channel.slice(1),body={...s.ctx,binding:hash(text),action:'nhw'+name+'Challenge'},c=authority.Execute(body),submit={...body,action:'nhw'+name+'Submit',challengeId:c.challengeId,payload:text};submit.signature=fixture.Sign(s.device,paths.Canonical(submit,c,channel));return {c,submit};}
function send(s,channel,records,sequence=1,options={}){return authority.Execute(request(s,channel,payload(records,sequence,options)).submit);}
fixture.CurrentCohort({version:'90.0.0'});
check('Every NHW kind has one strict server mapping and accepts minimized unconfirmed observation',()=>{
 assert.equal(catalog.NHW.length,204);assert.equal(new Set(catalog.NHW.map(x=>x.id)).size,204);
 for(const e of catalog.NHW)assert.equal(reports.ParseRecords([detection(e.id)],hex(2000))[0].id,e.id);
 reject(()=>reports.ParseRecords([detection('dkUndocumented')],hex(2000)),'SECURITY_DETECTION_INVALID');
});
check('All 204 kinds traverse real signed server handler and remain per session',()=>{
 const s=subject(),other=subject();let sequence=0;
 for(let i=0;i<catalog.NHW.length;i+=32)assert.equal(send(s,'integrity',catalog.NHW.slice(i,i+32).map(e=>detection(e.id)),++sequence).stopped,false);
 const events=reports.ForFlow(row(s).id);assert.equal(events.length,204);assert.equal(reports.ForFlow(row(other).id).length,0);assert.equal(row(s).status,'STARTED');
 assert.ok(events.every(e=>e.localOnly&&!e.invalidated&&!e.sessionInvalidated&&e.attestation.status==='NOT_BOUND'));
 assert.equal(new Set(events.map(e=>e.detectionId)).size,204);
});
check('Strict privacy/schema rejects raw PID/path and forged sensor/category/boolean ranges',()=>{
 for(const patch of [{path:'C:\\secret'},{pid:42},{source:'unregistered.sensor'},{families:256},{confidence:101},{localOnly:false},{firstTick:hex(5000)},{attestationSequence:'0'}])reject(()=>reports.ParseRecords([detection('dkProcess',patch)],hex(2000)),'SECURITY_DETECTION_INVALID');
 reject(()=>reports.ParseRecords(Array.from({length:33},(_,i)=>detection(catalog.NHW[i].id)),hex(2000)));
 reject(()=>reports.ParseRecords([detection(),detection()],hex(2000)));
});
check('Cumulative same-event reports aggregate without duplicate confirmation; exact receipt replay is idempotent',()=>{
 const s=subject(),r=request(s,'integrity',payload([detection()],1));const first=authority.Execute(r.submit);assert.deepEqual(authority.Execute(r.submit),first);
 send(s,'integrity',[detection('dkWriteWatch',{count:3,lastTick:hex(1300)})],2);
 reject(()=>send(s,'integrity',[detection('dkWriteWatch',{count:3,lastTick:hex(1300)})],3),'SECURITY_EVIDENCE_REPLAY');
 send(s,'integrity',[detection('dkWriteWatch',{count:3,lastTick:hex(1400)})],4);
 const events=reports.ForFlow(row(s).id);assert.equal(events.length,1);assert.equal(events[0].count,3);assert.equal(events[0].confirmationCount,0);
});
check('Producer sequence replay is rejected after volatile path state is cleared',()=>{
 const s=subject();send(s,'driver',[detection()],1);paths.Clear();
 reject(()=>send(s,'driver',[detection()],1),'SECURITY_EVIDENCE_REPLAY');
 assert.equal(send(s,'driver',[detection('dkWriteWatch',{count:2,lastTick:hex(1200)})],2).stopped,false);
});
check('FP1 observations and unknowns never become attacks from client confirmed flag alone',()=>{
 for(const id of ['dkMappedView','dkExecutableMapping','dkWriteWatch','dkWriteBurst','dkProcess','dkOwnership','dkKernelTelemetryGap']){
  const kind=catalog.Get(id);if(!kind)throw Error('Missing FP1 kind '+id);const s=subject();
  assert.equal(send(s,'integrity',[detection(id,{families:127,confidence:100,correlation:true,localOnly:false})],1,{confirmed:true,trust:3}).stopped,false);assert.equal(row(s).status,'STARTED');
 }
});
check('Strong execution evidence needs two independent acquisition roots and acts on exact cohort',()=>{
 const s=subject(),other=subject();
 assert.equal(send(s,'integrity',[detection('dkRemoteThread',{families:2,confidence:100,correlation:true,localOnly:false})],1,{confirmed:true,trust:3}).stopped,false);
 assert.equal(send(s,'integrity',[detection('dkRemoteThread',{families:3,confidence:75,correlation:true,localOnly:false,count:2,lastTick:hex(1400)})],2,{confirmed:true,trust:3}).stopped,true);
 assert.equal(row(s).status,'REVOKED');assert.equal(row(other).status,'STARTED');assert.match(row(s).reason,/dkRemoteThread/);
 assert.equal(reports.ForFlow(row(s).id)[0].invalidated,true);
});
check('Kernel aggregate cannot masquerade as independent acquisition roots; semantic policy needs separate path quorum',()=>{
 const s=subject(),kernel=[detection('dkKernelTrustDowngrade',{families:128,confidence:75,correlation:true,localOnly:false}),detection('dkBootTrust',{families:128,confidence:75,correlation:true,localOnly:false})];
 assert.equal(send(s,'trust',kernel,1,{confirmed:true,trust:3}).stopped,false);
 assert.equal(send(s,'driver',kernel,1,{confirmed:true,trust:3}).stopped,true);assert.equal(row(s).status,'REVOKED');
 assert.equal(reports.UserModeVote([detection('dkRemoteThread',{families:128,confidence:100,correlation:true,localOnly:false})],hex(2000)),false);
});
check('Unrelated local observations are not relabeled causative when another event revokes session',()=>{
 const s=subject();send(s,'integrity',[detection('dkWriteWatch')],1);
 send(s,'integrity',[detection('dkRemoteThread',{families:3,confidence:75,correlation:true,localOnly:false})],2,{trust:3});
 const old=reports.ForFlow(row(s).id).find(e=>e.detectionId==='dkWriteWatch');assert.equal(old.invalidated,false);assert.equal(old.sessionInvalidated,true);
});
check('Server reason capture survives retirement and retains explicit source without raw identity',()=>{
 const s=subject(),original=row(s);boot.Revoke(original.sessionId,{reason:'INTEGRITY_CODE_HASH_MISMATCH'},'INTEGRITY_REPORT');
 reports.RecordServer({row:original,stage:'A',id:'CODE_HASH_MISMATCH',source:'peace.desktop-integrity-reports',invalidated:true});
 const e=reports.ForFlow(original.id)[0];assert.equal(e.detectionId,'CODE_HASH_MISMATCH');assert.equal(e.evidenceLevel,'SERVER_COMPARISON');assert.equal(e.invalidated,true);assert.equal(e.handoff.A,'REVOKED');
 for(const key of ['machineId','deviceId','path','pid','user'])assert.equal(Object.hasOwn(e,key),false);
 reports.Validate(store.Load().securityDetections,store.Load());
});
check('Cumulative counter regression, raw stored fields and mismatched path digest are rejected',()=>{
 const s=subject();send(s,'integrity',[detection('dkWriteWatch',{count:10})]);
 reject(()=>send(s,'integrity',[detection('dkWriteWatch',{count:1,lastTick:hex(1200)})],2),'SECURITY_DETECTION_COUNTER_REPLAY');
 assert.equal(reports.ForFlow(row(s).id)[0].count,10);
 reject(()=>send(s,'integrity',[detection('dkWriteWatch',{count:11,lastTick:hex(1300)})],3,{digest:hex(99)}),'SECURITY_DETECTION_DIGEST_INVALID');
 const db=structuredClone(store.Load());db.securityDetections.flows[row(s).id].events[0].rawPath='private';reject(()=>reports.Validate(db.securityDetections,db),'SECURITY_DETECTION_STORAGE_INVALID');
 const idle=subject();assert.equal(send(idle,'trust',[],1).stopped,false);assert.equal(send(idle,'trust',[],2).stopped,false);
});
check('Exact attestation sequence binds only this role and survives recent-attestation eviction',()=>{
 const s=subject(),r=row(s);send(s,'trust',[detection('dkWriteWatch',{attestationSequence:hex(50)})]);
 reports.RecordAttestation({row:r,stage:'A',sequence:hex(50),status:'TPM_QUOTE_ONLY',hardwareAttested:true});
 let e=reports.ForFlow(r.id)[0];assert.equal(e.attestation.status,'TPM_QUOTE_ONLY');assert.equal(e.attestation.hardwareAttested,true);assert.equal(e.attestation.bootHealthVerified,false);
 for(let n=51;n<=70;n++)reports.RecordAttestation({row:r,stage:'A',sequence:hex(n),status:'VERIFIED_BINDING'});
 e=reports.ForFlow(r.id)[0];assert.equal(e.attestation.status,'TPM_QUOTE_ONLY');reports.ValidateAttestations(row(s).nhwAttestations);
 reject(()=>reports.RecordAttestation({row:r,stage:'A',sequence:hex(0),status:'VERIFIED_BINDING'}));
 reject(()=>reports.RecordAttestation({row:r,stage:'A',sequence:hex(70),status:'REJECTED'}),'SECURITY_ATTESTATION_REPLAY');
 reports.Validate(store.Load().securityDetections,store.Load());
});
check('Deleted flow diagnostics retire without losing high-watermarks of other live sessions',()=>{
 const s=subject(),other=subject();send(s,'trust',[detection()]);send(other,'trust',[detection()]);const db=structuredClone(store.Load());delete db.flows[row(s).id];reports.ObserveTransitions(store.Load(),db);assert.equal(db.securityDetections.flows[row(s).id],undefined);assert.ok(db.flows[row(other).id].nhwResponseOrders['A:trust']);reports.Validate(db.securityDetections,db);
});
check('B v2 actual signing key reports and revokes only its cohort',()=>{
 const b=subjectB(),other=subjectB();send(b,'integrity',[detection('dkWriteIntegrity',{families:24,confidence:60,correlation:true,localOnly:false})]);
 assert.equal(row(b).status,'REVOKED');assert.equal(row(other).status,'CLAIMED');const e=reports.ForFlow(row(b).id)[0];assert.equal(e.role,'B');assert.equal(e.sessionId,b.b.sessionId);assert.equal(e.invalidated,true);assert.match(row(b).reason,/dkWriteIntegrity/);
});
check('Optional persisted observation and attestation state reloads through actual bootstrap validation',()=>{
 const result=require('node:child_process').spawnSync(process.execPath,['-e',"const s=require("+JSON.stringify(require.resolve('../../services/bootstrap/peace.desktop-bootstrap-store'))+").Load(); const d=require("+JSON.stringify(require.resolve('../../services/security/peace.security-detections'))+"); d.Validate(s.securityDetections,s); for(const r of Object.values(s.flows)){d.ValidateOrder(r.nhwResponseOrders);d.ValidateAttestations(r.nhwAttestations);} process.stdout.write('PERSISTED_VALID');"],{cwd:path.resolve(__dirname,'../..'),env:process.env,encoding:'utf8',timeout:15000});
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/PERSISTED_VALID/);
});
check('A Revoke exception never marks a prior observation as causing invalidation',()=>{
 const s=subject(),originalRevoke=boot.Revoke,strong=detection('dkRemoteThread',{families:3,confidence:75,correlation:true,localOnly:false});
 boot.Revoke=()=>{throw Error('INJECTED_REVOKE_WRITE_FAILURE');};
 try{reject(()=>send(s,'integrity',[strong],1),'INJECTED_REVOKE_WRITE_FAILURE');}finally{boot.Revoke=originalRevoke;}
 let e=reports.ForFlow(row(s).id)[0];assert.equal(e.invalidated,false);assert.equal(e.sessionInvalidated,false);assert.equal(row(s).status,'STARTED');assert.equal(row(s).nhwTerminalReport,undefined);reloadedCause(row(s).id,false);
 assert.equal(send(s,'integrity',[{...strong,count:2,lastTick:hex(1500)}],2).stopped,true);
 e=reports.ForFlow(row(s).id)[0];assert.equal(e.invalidated,true);assert.equal(e.sessionInvalidated,true);assert.equal(row(s).status,'REVOKED');reloadedCause(row(s).id,true);
 reports.Validate(store.Load().securityDetections,store.Load());
});
check('Thirty-second terminal diagnostic grace drains remaining kinds without restoring authority',()=>{
 const s=subject(),other=subject(),strong=detection('dkRemoteThread',{families:3,confidence:75,correlation:true,localOnly:false});
 const req=request(s,'integrity',payload([strong],1));const stop=authority.Execute(req.submit);assert.equal(stop.stopped,true);assert.deepEqual(authority.Execute(req.submit),stop);
 reject(()=>boot.AuthenticateIntegrityReport(s.ctx));
 let sequence=1;
 const terminalStrong=detection('dkWriteIntegrity',{families:24,confidence:75,correlation:true,localOnly:false});
 assert.equal(send(s,'integrity',[terminalStrong],++sequence).stopped,true);
 const afterStop=reports.ForFlow(row(s).id).find(e=>e.detectionId==='dkWriteIntegrity');assert.equal(afterStop.invalidated,false);assert.equal(afterStop.sessionInvalidated,true);
 for(let i=0;i<catalog.NHW.length;i+=32){const rows=catalog.NHW.slice(i,i+32).filter(e=>e.id!=='dkRemoteThread').map(e=>detection(e.id));assert.equal(send(s,'integrity',rows,++sequence).stopped,true);}
 assert.equal(reports.ForFlow(row(s).id).length,204);assert.equal(row(s).status,'REVOKED');assert.equal(row(other).status,'STARTED');
 const wrong={...s,ctx:{...s.ctx,sessionToken:other.ctx.sessionToken}};reject(()=>request(wrong,'driver',payload([detection()],1)));
 const now=Date.now;Date.now=()=>row(s).nhwTerminalReport.expiresAt;try{reject(()=>request(s,'driver',payload([detection()],1)));}finally{Date.now=now;}
 const admin=subject();boot.Revoke(row(admin).sessionId,{reason:'ADMIN_REQUEST'},'ADMIN');reject(()=>request(admin,'trust',payload([detection()],1)));
});
console.log('Security detection server: '+checks+' groups passed (synthetic evidence, no Windows execution)');
