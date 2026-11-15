'use strict';
// Validator/storage-contract tests use a test-owned in-memory store. No Windows
// execution, TPM attestation or production approval is asserted by this suite.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-manual-verification-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-MANUAL-TEST'});
const svc=require("../../services/runtime/peace.desktop-manual-verification"),store=require("../../services/bootstrap/peace.desktop-bootstrap-store"),audit=require("../../services/storage/peace.desktop-operation-audit");
let db={artifacts:{a:{component:'A',sha512:'a'.repeat(128)},b:{component:'B',sha512:'b'.repeat(128)},o:{component:'O',sha512:'c'.repeat(128)}},active:{A:'a',B:'b',O:'o'}},writes=0;
const manifestId='f'.repeat(128);
for(const row of Object.values(db.artifacts))row.deploymentManifestId=manifestId;
db.securityOperations={releaseGovernance:{manifests:{}}};
db.securityOperations.releaseGovernance.manifests[manifestId]={registration:'REGISTERED',manifest:{sourceManifestSha512:'d'.repeat(128),artifacts:{A:'a'.repeat(128),B:'b'.repeat(128),O:'c'.repeat(128)}}};
const load=store.Load,run=audit.Run;store.Load=()=>db;audit.Run=(kind,actor,details,fn)=>{assert.equal(kind,'MANUAL_VERIFICATION_IMPORT');const next=structuredClone(db),result=fn(next);db=next;writes++;return result;};
const report=()=>({version:1,kind:'MANUAL_VERIFICATION',runId:'windows-synthetic',startedAt:'2026-01-01T00:00:00.000Z',finishedAt:'2026-01-01T00:01:00.000Z',platform:'win32',architecture:'x64',sourceManifestSha512:'d'.repeat(128),sourceManifestUnchanged:true,artifacts:{A:{sha512:'a'.repeat(128),unchanged:true},B:{sha512:'b'.repeat(128),unchanged:true},O:{sha512:'c'.repeat(128),unchanged:true}},stages:svc.STAGES.map(id=>({id,outcome:'PASS'})),nativeBuild:'NOT_RUN',hardwareAttested:false,publicationApproval:false});
const upload=r=>svc.Import({reportText:JSON.stringify(r)},'ADMIN:SYNTHETIC');let checks=0;function test(name,fn){fn();checks++;console.log('PASS '+name);}
(async()=>{try{
 test('An empty store has no reported execution',()=>assert.equal(svc.Status(db).status,'NOT_RECORDED'));
 test('Only exact schema, outcomes and all distinct stage IDs are accepted',()=>{
  for(const change of [r=>r.privateKey='NEVER_STORE',r=>r.hardwareAttested=true,r=>r.ciEvidenceCreated=true,r=>r.publicationApproval=true,r=>r.nativeBuild='PASS',r=>r.platform='linux',r=>r.architecture='ia32',r=>r.stages.pop(),r=>r.stages[1]=r.stages[0],r=>r.stages[0].outcome='APPROVED',r=>r.artifacts.A.sha512='A'.repeat(128),r=>r.startedAt='2026-02-30T00:00:00.000Z',r=>r.finishedAt='2025-01-01T00:00:00.000Z',r=>r.artifacts.A.path='C:/secret',r=>r.sourceManifestSha512=['d'.repeat(128)]]){const r=report();change(r);assert.throws(()=>svc.ValidateReport(r));}
 });
 test('V1 receipts retain their digest; V2 requires full PE CRC comparison',()=>{
  const old=report(),legacy=svc.ValidateReport(old);assert.equal(legacy.version,1);assert.equal(legacy.stages.length,svc.STAGES.length);
  const current={...old,version:2,stages:svc.CURRENT_STAGES.map(id=>({id,outcome:id==='independent-crc-pe'?'NOT_RUN':'PASS'}))};
  assert.equal(svc.ValidateReport(current).stages.find(x=>x.id==='independent-crc-pe').outcome,'NOT_RUN');
  assert.throws(()=>svc.ValidateReport({...current,stages:old.stages}));assert.throws(()=>svc.ValidateReport({...old,stages:current.stages}));
 });
 test('Duplicate JSON keys, unknown body fields and excessive input fail before store writes',()=>{
  assert.throws(()=>svc.Import({reportText:'{"version":1,"version":1}'},'admin'));
  assert.throws(()=>svc.Import({reportText:' '.repeat(32769)},'admin'));
  assert.throws(()=>svc.Import({reportText:JSON.stringify(report()),approved:true},'admin'));assert.equal(writes,0);
 });
 test('Upload binds role-specific registered hashes and rejects future timestamps',()=>{
  const bad=report();bad.artifacts.A.sha512=bad.artifacts.B.sha512;assert.throws(()=>upload(bad),/ARTIFACT_NOT_REGISTERED/);
  const future=report();future.finishedAt=new Date(Date.now()+3600000).toISOString();assert.throws(()=>upload(future),/FUTURE_TIME/);
 });
 test('Registered same-manifest tuple and source hash are required',()=>{const r=report();r.sourceManifestSha512='e'.repeat(128);assert.throws(()=>upload(r),/MANIFEST_MISMATCH/);db.securityOperations.releaseGovernance.manifests[manifestId].registration='PLANNED';assert.throws(()=>upload(report()),/MANIFEST_MISMATCH/);db.securityOperations.releaseGovernance.manifests[manifestId].registration='REGISTERED';db.artifacts.o.deploymentManifestId='e'.repeat(128);assert.throws(()=>upload(report()),/MANIFEST_MISMATCH/);db.artifacts.o.deploymentManifestId=manifestId;});
 test('PASS is explicitly operator-reported; no publication/hardware/build approval appears',()=>{
  const r=upload(report());assert.equal(r.replayed,false);assert.equal(r.record.outcome,'PASS_REPORTED');assert.equal(r.record.evidenceType,'OPERATOR_RECORDED');assert.equal(r.record.publicationApproval,false);assert.equal(r.record.hardwareAttested,false);assert.equal(r.record.nativeBuild,'NOT_RUN');assert.equal(svc.Status(db).usedForPublicationAuthorization,false);svc.Validate(db.manualVerifications);
 });
 test('Reordered reports replay without another write, and changed artifacts do not inherit status',()=>{
  const r=report();r.stages.reverse();const n=writes;assert.equal(upload(r).replayed,true);assert.equal(writes,n);
  db.artifacts.o.sha512='e'.repeat(128);assert.equal(svc.Status(db).status,'NOT_RECORDED');db.artifacts.o.sha512='c'.repeat(128);
 });
 test('Incomplete or changed inputs cannot be reported as PASS',()=>{
  const incomplete=report();incomplete.runId='incomplete';incomplete.stages[0].outcome='NOT_RUN';assert.equal(upload(incomplete).record.outcome,'INCOMPLETE');
  const changed=report();changed.runId='changed';changed.artifacts.O.unchanged=false;assert.equal(upload(changed).record.outcome,'FAIL');
  const source=report();source.runId='source-changed';source.sourceManifestUnchanged=false;assert.equal(upload(source).record.outcome,'FAIL');
 });
 test('Persisted report tampering and over-capacity stores are rejected',()=>{
  const copy=structuredClone(db.manualVerifications),id=Object.keys(copy)[0];copy[id].report.stages[0].outcome='FAIL';assert.throws(()=>svc.Validate(copy));
  const lots=Object.fromEntries(Array.from({length:65},(_,i)=>[String(i),{}]));assert.throws(()=>svc.Validate(lots));
 });
 // Route authorization is exercised with real session/CSRF code, while only the
 // record store above is replaced by the test-owned state.
 const route=require("../../web/routes/web/peace.desktop-server-state-routes"),auth=require("../../web/authentication/peace.web-auth");
 const req={headers:{},socket:{remoteAddress:'127.0.0.1',encrypted:true}};
 async function post(session,headers={}){let code,body;const res={writeHead(c){code=c;},end(s){body=JSON.parse(s);}};await route.Handle({method:'POST',pathname:'/api/desktop/bootstrap/server-state/manual-verification',req:{...req,headers},res,session,body:{reportText:JSON.stringify(report())}});return {code,body};}
 assert.equal((await post(null)).code,403);assert.equal((await post({id:'viewer',role:'viewer'})).code,403);
 const admin=auth.CreateSession(req,'admin');const noCsrf=await post(admin);assert([403,428].includes(noCsrf.code));
 const realNow=Date.now,start=realNow();try{Date.now=()=>start+auth.REAUTH_MS+1;const stale=await post(admin,{'x-csrf-token':admin.csrf});assert.equal(stale.code,428);}finally{Date.now=realNow;}
 auth.RevokeAllSessions();assert.equal((await post(admin,{'x-csrf-token':admin.csrf})).code,401);
 checks++;console.log('PASS Import route rejects non-admin, stale reauthentication, invalid CSRF and revoked sessions');
 console.log('Manual verification contracts: '+checks+' groups PASS; Windows execution NOT_RUN.');
}finally{store.Load=load;audit.Run=run;fs.rmSync(temp,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
