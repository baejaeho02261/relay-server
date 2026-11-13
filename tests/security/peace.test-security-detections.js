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
 const script="const d=require("+JSON.stringify(require.resolve('../../services/security/peace.security-detections'))+");const e=d.ForFlow(process.argv[1])[0];if(!e||e.invalidated!==(process.argv[2]==='true'))throw Error('PERSISTED_CAUSALITY_MISMATCH');process.stdout.write('PERSISTED_CAUSALITY_VALID');";
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
check('All 204 kinds traverse signed handler; initial detections stop exact session and terminal drain preserves every name',()=>{
 const s=subject(),other=subject();let sequence=0;
 for(let i=0;i<catalog.NHW.length;i+=32)assert.equal(send(s,'integrity',catalog.NHW.slice(i,i+32).map(e=>detection(e.id,e.id==='dkProcess'?{families:3,confidence:75,correlation:true,localOnly:false}:{})),++sequence).stopped,true);
 const events=reports.ForFlow(row(s).id);assert.equal(events.length,204);assert.equal(reports.ForFlow(row(other).id).length,0);assert.equal(row(s).status,'REVOKED');assert.equal(row(other).status,'STARTED');
 assert.ok(events.every(e=>e.sessionInvalidated&&e.attestation.status==='NOT_BOUND'));
 assert.equal(events.filter(e=>e.invalidated).length,1);assert.equal(new Set(events.map(e=>e.detectionId)).size,204);
});
check('Strict privacy/schema rejects raw PID/path and forged sensor/category/boolean ranges',()=>{
 for(const patch of [{path:'C:\\secret'},{pid:42},{source:'unregistered.sensor'},{families:256},{confidence:101},{localOnly:false},{firstTick:hex(5000)},{attestationSequence:'0'}])reject(()=>reports.ParseRecords([detection('dkProcess',patch)],hex(2000)),'SECURITY_DETECTION_INVALID');
 reject(()=>reports.ParseRecords(Array.from({length:33},(_,i)=>detection(catalog.NHW[i].id)),hex(2000)));
 reject(()=>reports.ParseRecords([detection(),detection()],hex(2000)));
});
check('Cumulative same-event reports aggregate without duplicate confirmation; exact receipt replay is idempotent',()=>{
 const s=subject(),r=request(s,'integrity',payload([detection('dkNamespace')],1));const first=authority.Execute(r.submit);assert.deepEqual(authority.Execute(r.submit),first);
 send(s,'integrity',[detection('dkNamespace',{count:3,lastTick:hex(1300)})],2);
 reject(()=>send(s,'integrity',[detection('dkNamespace',{count:3,lastTick:hex(1300)})],3),'SECURITY_EVIDENCE_REPLAY');
 send(s,'integrity',[detection('dkNamespace',{count:3,lastTick:hex(1400)})],4);
 const events=reports.ForFlow(row(s).id);assert.equal(events.length,1);assert.equal(events[0].count,3);assert.equal(events[0].confirmationCount,0);
});
check('Exact accepted batch recovers after volatile state is cleared; changed sequence cannot reuse evidence',()=>{
 const s=subject();send(s,'driver',[detection('dkNamespace')],1);paths.Clear();
 assert.equal(send(s,'driver',[detection('dkNamespace')],1).stopped,false);
 reject(()=>send(s,'driver',[detection('dkNamespace')],2),'SECURITY_EVIDENCE_REPLAY');
 assert.equal(send(s,'driver',[detection('dkNamespace',{count:2,lastTick:hex(1200)})],2).stopped,false);
});
check('All 204 semantic states have explicit context policy; warnings/internal evidence never stop alone',()=>{
 let warning=0,internal=0,actionable=0,kernel=0;
 for(const kind of catalog.NHW){
  assert.ok(kind.contextPolicy,kind.id);
  const strong=detection(kind.id,{families:3,confidence:75,correlation:true,localOnly:false});
  const result=reports.StopRecords([strong],hex(2000));
  if(!kind.standaloneOutput){assert.equal(result.length,0,kind.id);internal++;}
  else if(kind.signalClass==='UNKNOWN'){assert.equal(result.length,0,kind.id);warning++;}
  else if(kind.category==='KERNEL_TRUST'){assert.equal(result.length,0,kind.id);kernel++;}
  else {assert.equal(result.length,1,kind.id);actionable++;}
  assert.equal(reports.StopRecords([strong],hex(100000)).length,0,kind.id+' stale');
 }
 assert.equal(actionable+kernel,191);
 assert.equal(kernel,catalog.NHW.filter(k=>k.category==='KERNEL_TRUST'&&k.standaloneOutput&&k.signalClass!=='UNKNOWN').length);
 assert.deepEqual({warning,internal},{warning:6,internal:7});
 const s=subject();assert.equal(send(s,'integrity',catalog.NHW.filter(k=>!k.standaloneOutput).map(e=>detection(e.id)),1,{confirmed:true,trust:3}).stopped,false);assert.equal(row(s).status,'STARTED');
});
check('Each response channel independently stops an actual typed finding without inventing correlation or hardware trust',()=>{
 for(const [channel,id]of [['trust','dkPECodeIntegrity'],['driver','dkIAT'],['integrity','dkWriteIntegrity']]){
  const s=subject(),other=subject();assert.equal(send(s,channel,[detection(id)]).stopped,true);
  assert.equal(row(s).status,'REVOKED');assert.equal(row(other).status,'STARTED');const e=reports.ForFlow(row(s).id)[0];assert.equal(e.invalidated,true);assert.equal(e.localOnly,true);assert.equal(e.confidence,0);assert.equal(e.attestation.hardwareAttested,false);assert.ok(['EXACT_INTEGRITY_MUTATION','CONFIRMED_STRUCTURAL_INVARIANT'].includes(e.decisionReason));
 }
});
check('Every coverage warning requests recovery without revoking; worker availability remains diagnostic',()=>{
 for(const id of ['dkETWLoss','dkCoverageGap','dkObservationUncertain','dkSensorPressure','dkTraceGap','dkKernelTelemetryGap']){
  const s=subject();assert.equal(send(s,'integrity',[detection(id)]).stopped,false);const e=reports.ForFlow(row(s).id)[0];assert.equal(e.signalClass,'UNKNOWN');assert.equal(e.decisionReason,'TRANSIENT_COVERAGE_GAP_RECOVERY_REQUIRED');assert.equal(e.confirmationCount,0);assert.equal(e.confidence,0);
 }
 for(const source of ['Cozy.NHW.Handles','Cozy.NHW.Guard']){
  const s=subject(),r=detection('dkObservationUncertain',{source,families:0});
  assert.equal(send(s,'integrity',[r]).stopped,false);let e=reports.ForFlow(row(s).id)[0];assert.equal(e.sessionStopPolicy,'RECOVER_AND_REVALIDATE');assert.equal(e.observationClass,'SENSOR_AVAILABILITY');assert.equal(e.invalidated,false);
  reject(()=>send(subject(),'trust',[r]),'SECURITY_DETECTION_INVALID');
  reject(()=>reports.ParseRecords([{...r,confidence:1}],hex(2000)),'SECURITY_DETECTION_INVALID');
  assert.equal(send(s,'integrity',[{...r,count:2,lastTick:hex(1200)},detection('dkPECodeIntegrity')],2).stopped,true);
  e=reports.ForFlow(row(s).id).find(x=>x.sensor===source);assert.equal(e.invalidated,false);assert.equal(e.sessionInvalidated,true);
 }
});
check('Unknown low-confidence local state stays unresolved; typed code corruption remains actionable',()=>{
 const s=subject(),other=subject();assert.equal(send(s,'integrity',[detection('dkRemoteThread',{families:2})]).stopped,false);
 const e=reports.ForFlow(row(s).id)[0];assert.equal(e.correlation,false);assert.equal(e.confirmationCount,0);assert.equal(e.evidenceLevel,'CLIENT_LOCAL_OBSERVATION');assert.equal(e.invalidated,false);assert.equal(e.disposition,'OBSERVATION_UNRESOLVED');assert.equal(row(other).status,'STARTED');
 assert.equal(send(s,'integrity',[detection('dkPECodeIntegrity')],2).stopped,true);
});
check('Kernel findings need qualifying evidence on each contributing record',()=>{
 const s=subject();
 const raw=['dkKernelTrustDowngrade','dkBootTrust'].map(id=>detection(id,{families:128}));
 assert.equal(send(s,'trust',raw).stopped,false);assert.equal(row(s).status,'STARTED');
 const qualified=raw.map(r=>({...r,count:2,lastTick:hex(1200),confidence:75,correlation:true,localOnly:false}));
 const bystander=detection('dkDriverCrossView',{families:128});
 assert.equal(send(s,'trust',[...qualified,bystander],2).stopped,true);assert.equal(row(s).status,'REVOKED');
 const events=reports.ForFlow(row(s).id);
 assert.deepEqual(events.filter(e=>e.invalidated).map(e=>e.detectionId).sort(),['dkBootTrust','dkKernelTrustDowngrade']);
 assert.equal(events.find(e=>e.detectionId===bystander.id).localOnly,true);
 assert.ok(events.every(e=>e.evidenceFamilies.join(',')==='KERNEL_AGGREGATE'&&!e.attestation.hardwareAttested));
 assert.equal(reports.UserModeVote([detection('dkRemoteThread',{families:128,confidence:100,correlation:true,localOnly:false})],hex(2000)),false);
});
check('Unrelated local observations are not relabeled causative when another event revokes session',()=>{
 const s=subject();send(s,'integrity',[detection('dkNamespace')],1);
 send(s,'integrity',[detection('dkRemoteThread',{families:3,confidence:75,correlation:true,localOnly:false})],2,{trust:3});
 const old=reports.ForFlow(row(s).id).find(e=>e.detectionId==='dkNamespace');assert.equal(old.invalidated,false);assert.equal(old.sessionInvalidated,true);
});
check('Server reason capture survives retirement and retains explicit source without raw identity',()=>{
 const s=subject(),original=row(s);boot.Revoke(original.sessionId,{reason:'INTEGRITY_CODE_HASH_MISMATCH'},'INTEGRITY_REPORT');
 reports.RecordServer({row:original,stage:'A',id:'CODE_HASH_MISMATCH',source:'peace.desktop-integrity-reports',invalidated:true});
 const e=reports.ForFlow(original.id)[0];assert.equal(e.detectionId,'CODE_HASH_MISMATCH');assert.equal(e.evidenceLevel,'SERVER_COMPARISON');assert.equal(e.invalidated,true);assert.equal(e.handoff.A,'REVOKED');
 for(const key of ['machineId','deviceId','path','pid','user'])assert.equal(Object.hasOwn(e,key),false);
 reports.Validate(store.Load().securityDetections,store.Load());
});
check('All Cozy catalog outcomes persist named per-session records with their exact classified sources',()=>{
 const s=subject();for(const entry of catalog.COZY)reports.RecordServer({row:row(s),stage:'A',id:entry.id,source:entry.sourceUnits[0],confidence:0,correlation:false});
 const events=reports.ForFlow(row(s).id);assert.equal(events.length,122);assert.ok(events.every(e=>e.origin==='COZY'&&e.displayName.endsWith(' Detect')&&!e.invalidated));reports.Validate(store.Load().securityDetections,store.Load());
});
check('CRC algorithm labels come only from actual failing comparisons; unavailable reads remain UNKNOWN',()=>{
 const crc=require('../../services/runtime/peace.desktop-crc-policy'),registry=require('../../services/cryptography/peace.crc-layers').registry;
 for(const [role,spec]of Object.entries(registry)){
  const s=subject(),baseline=boot.AuthenticateIntegrityReport(s.ctx).integrityArtifact.crcLayers,observed=structuredClone(baseline);
  assert.ok(observed[role].digest);observed[role].digest=(observed[role].digest[0]==='0'?'1':'0')+observed[role].digest.slice(1);
  const comparison=crc.Compare(observed,baseline);assert.equal(comparison.reason,'CRC_ROLE_MISMATCH');
  reports.RecordServer({row:row(s),stage:'A',id:comparison.reason,source:'peace.desktop-integrity-reports',crcComparison:comparison});
  const e=reports.ForFlow(row(s).id)[0];assert.deepEqual(e.algorithms,[spec.name]);assert.equal(e.displayName,spec.name+' Detect');assert.deepEqual(e.crcFindings,[{role,status:'MISMATCH'}]);
 }
 const s=subject(),baseline=boot.AuthenticateIntegrityReport(s.ctx).integrityArtifact.crcLayers,observed=structuredClone(baseline);
 observed.crc8_smbus={algorithm:registry.crc8_smbus.name,role:baseline.crc8_smbus.role,status:'failed',reason:'READ_ERROR'};
 const comparison=crc.Compare(observed,baseline);reports.RecordServer({row:row(s),stage:'A',id:comparison.reason,source:'peace.desktop-integrity-reports',crcComparison:comparison,confidence:0,correlation:false});
 const e=reports.ForFlow(row(s).id)[0];assert.deepEqual(e.algorithms,[]);assert.equal(e.signalClass,'UNKNOWN');assert.equal(e.observationClass,'UNAVAILABLE_OR_INCOMPLETE');assert.equal(e.confirmationCount,0);reports.Validate(store.Load().securityDetections,store.Load());
});
check('An authenticated mitigation mismatch reaches the detection store before the authority rejects it',()=>{
 const s=subject(),context={...s.ctx,intent:'observe',binding:hash('mitigation finding')},b=boot.AuthenticateIntegrityReport(context).integrityArtifact;
 const d={version:2,requestedMode:'observe',profileId:'a'.repeat(128),setAttempted:false,setSucceeded:false,setError:0,strictSetAttempted:false,strictSetSucceeded:false,strictSetError:0,imageSetAttempted:false,imageSetSucceeded:false,imageSetError:0};
 for(const n of ['dynamic','cfg','strictHandle','imageLoad']){d[n+'Queried']=true;d[n+'Flags']=0;d[n+'Error']=0;}
 const value={version:1,hashVersion:3,measurement:'MEASURED',fileSha512:b.sha512,fileCrc64:b.crc64,codeSha512:b.codeSha512,codeCrc64:b.codeCrc64,codeXxh3_128:b.codeXxh3_128,codeBlake3:b.codeBlake3,crcLayers:b.crcLayers,apiSealed:true,apiSlots:60,dynamicCode:'ALLOWED',cfg:'DISABLED',mitigationDiagnostics:d};
 const c=authority.Execute({...context,action:'challenge'}),text=JSON.stringify(value),body={...context,action:'submit',challengeId:c.challengeId,payload:text,signature:fixture.Sign(s.device,authority.Canonical(context,c,text))};
 reject(()=>authority.Execute(body),'SECURITY_MITIGATION_PROFILE_UNEXPECTED');const e=reports.ForFlow(row(s).id)[0];assert.equal(e.detectionId,'SECURITY_MITIGATION_PROFILE_UNEXPECTED');assert.equal(e.sensor,'peace.desktop-mitigation-profiles');assert.equal(e.signalClass,'POLICY_REJECTION');assert.equal(e.invalidated,false);assert.equal(row(s).status,'STARTED');
});
check('Cumulative counter regression, raw stored fields and mismatched path digest are rejected',()=>{
 const s=subject();send(s,'integrity',[detection('dkNamespace',{count:10})]);
 reject(()=>send(s,'integrity',[detection('dkNamespace',{count:1,lastTick:hex(1200)})],2),'SECURITY_DETECTION_COUNTER_REPLAY');
 assert.equal(reports.ForFlow(row(s).id)[0].count,10);
 reject(()=>send(s,'integrity',[detection('dkNamespace',{count:11,lastTick:hex(1300)})],3,{digest:hex(99)}),'SECURITY_DETECTION_DIGEST_INVALID');
 const db=structuredClone(store.Load());db.securityDetections.flows[row(s).id].events[0].rawPath='private';reject(()=>reports.Validate(db.securityDetections,db),'SECURITY_DETECTION_STORAGE_INVALID');
 const idle=subject();assert.equal(send(idle,'trust',[],1).stopped,false);assert.equal(send(idle,'trust',[],2).stopped,false);
});
check('Exact attestation sequence binds only this role and survives recent-attestation eviction',()=>{
 const s=subject(),r=row(s);send(s,'trust',[detection('dkNamespace',{attestationSequence:hex(50)})]);
 reports.RecordAttestation({row:r,stage:'A',sequence:hex(50),status:'TPM_QUOTE_ONLY',hardwareAttested:true});
 let e=reports.ForFlow(r.id)[0];assert.equal(e.attestation.status,'TPM_QUOTE_ONLY');assert.equal(e.attestation.hardwareAttested,true);assert.equal(e.attestation.bootHealthVerified,false);
 for(let n=51;n<=70;n++)reports.RecordAttestation({row:r,stage:'A',sequence:hex(n),status:'VERIFIED_BINDING'});
 e=reports.ForFlow(r.id)[0];assert.equal(e.attestation.status,'TPM_QUOTE_ONLY');reports.ValidateAttestations(row(s).nhwAttestations);
 reject(()=>reports.RecordAttestation({row:r,stage:'A',sequence:hex(0),status:'VERIFIED_BINDING'}));
 reject(()=>reports.RecordAttestation({row:r,stage:'A',sequence:hex(70),status:'REJECTED'}),'SECURITY_ATTESTATION_REPLAY');
 reports.Validate(store.Load().securityDetections,store.Load());
});
check('Deleted flow diagnostics retire without losing high-watermarks of other live sessions',()=>{
 const s=subject(),other=subject();send(s,'trust',[detection('dkNamespace')]);send(other,'trust',[detection('dkNamespace')]);const db=structuredClone(store.Load());delete db.flows[row(s).id];reports.ObserveTransitions(store.Load(),db);assert.equal(db.securityDetections.flows[row(s).id],undefined);assert.ok(db.flows[row(other).id].nhwResponseOrders['A:trust']);reports.Validate(db.securityDetections,db);
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
