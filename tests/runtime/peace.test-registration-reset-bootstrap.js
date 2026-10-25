'use strict';
// Real authority files, chained audit writes and controlled process restarts.
// These synthetic records never execute a Windows executable or report PASS.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {execFileSync}=require('node:child_process'),assert=require('node:assert/strict');
const RESET='a'.repeat(64),SECOND='b'.repeat(64),THIRD='c'.repeat(64),A='A'.repeat(24),B='B'.repeat(24),G='C'.repeat(24),FRESH='D'.repeat(24);
function Child(mode){
 const store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
 const reset=require('../../services/bootstrap/peace.desktop-registration-reset');
 const config=require('../../config/peace.runtime-configuration');
 require('../../core/peace.utilities').EnsureDirs();
 const audit=require('../../storage/audit/peace.audit');audit.LoadRecentAudit();
 const operations=require('../../services/security/peace.desktop-security-operations');
 const security=require('../../services/security/peace.desktop-security-authority');
 const safety=require('../../services/artifacts/peace.desktop-release-safety');
 const crypto=require('node:crypto');
 const raw=file=>fs.readFileSync(file),sha=b=>crypto.createHash('sha512').update(b).digest('hex');
 function Authorize(id=RESET){process.env.COZY_REGISTRATION_RESET_ID=id;process.env.COZY_REGISTRATION_RESET_SCOPE=reset.SCOPE;}
 function Artifact(id,component='A'){
  const {registry}=require('../../services/cryptography/peace.crc-layers');
  return {id,component,protocol:'GAME-CONNECT-4',version:'1.0.0',hashVersion:3,sha512:'1'.repeat(128),size:24,createdAt:Date.now(),crc64:'1'.repeat(16),codeSha512:'2'.repeat(128),codeCrc64:'2'.repeat(16),codeAlgorithm:'PE64-CODE-V1',xxh3_128:'3'.repeat(32),codeXxh3_128:'3'.repeat(32),blake3:'4'.repeat(64),codeBlake3:'4'.repeat(64),crcLayers:{version:'CRC-LAYERS-V1',...Object.fromEntries(Object.entries(registry).map(([key,value])=>[key,{algorithm:value.name,role:'SYNTHETIC_UNAVAILABLE',status:'unavailable',reason:'LINKER_RANGES_REQUIRED'}]))}};
 }
 function Seed(){
  const publicKey=crypto.generateKeyPairSync('rsa',{modulusLength:2048}).publicKey.export({type:'spki',format:'der'}),binding='e'.repeat(64),enrollment='d'.repeat(64);
  store.Load();store.Atomic(db=>{
   db.artifacts={[A]:Artifact(A),[B]:Artifact(B,'B')};db.active={A,B};
   db.workspaceGarbage={[G]:{sha512:'5'.repeat(128),size:24,createdAt:Date.now()}};
   const ops=operations.Defaults();ops.revision=7;ops.requireBuildContract=true;ops.requireTestEvidence=true;ops.requirePackingEvidence=true;ops.requireCozyProtection=true;
   ops.signerStates['f'.repeat(64)]={state:'REVOKED',changedAt:Date.now(),changedBy:'SYNTHETIC_OPERATOR'};
   ops.releaseGovernance.minimumSecurityVersion=9;ops.releaseGovernance.requireManifest=true;db.securityOperations=ops;
   db.securityAuthorityPolicy={...security.Defaults(),minVersionA:'2.0.0',minVersionB:'3.0.0',minVersionO:'4.0.0',revokedSha512:['6'.repeat(128)]};
   db.releaseSafety={...safety.Defaults(),revision:4,revokedCohorts:{['7'.repeat(128)]:{at:Date.now(),actorHash:'8'.repeat(128),reason:'SYNTHETIC_REVOKED_COHORT'}}};
   db.serverRecovery={version:1,epoch:6,receipts:{}};
   db.deviceRegistry={version:1,revision:3,proofRetentionDays:30,receipts:{},bindings:{[binding]:{id:binding,identificationScheme:'LEGACY_PC_HASH_V1',status:'RETIRED',firstSeenAt:1,lastSeenAt:2,retiredAt:3,proofs:[]}}};
   db.deviceIdentity={version:2,revision:5,mode:'PERSISTENT',requireForEnrolled:true,enrollments:{[enrollment]:{id:enrollment,bindingId:binding,keyId:crypto.createHash('sha256').update(publicKey).digest('hex').toUpperCase(),publicKey:publicKey.toString('base64'),status:'REVOKED',assurance:'PERSISTENT_KEY_POSSESSION',enrolledAt:1,lastSeenAt:2}},receipts:{},adminReceipts:{},keyGenerations:{[binding]:6},legacyFlows:{},recoveryGrants:{},proofRetentionDays:30};
   db.adminCredentialRevocations={syntheticPreserved:true};
   db.workspaceJournal={version:1,current:{revision:0,sha512:'9'.repeat(128)}};
  });
  for(const id of [A,B,G])fs.writeFileSync(store.ArtifactPath(id),'SYNTHETIC NONEXECUTED FILE',{mode:0o600});
  fs.writeFileSync(path.join(config.DATA_DIR,'connect-transport-key.pem'),'SYNTHETIC KEY MUST SURVIVE',{mode:0o600});
  return {secret:store.Load().secret,policy:structuredClone(store.Load().securityAuthorityPolicy),journal:structuredClone(store.Load().workspaceJournal)};
 }
 function Applied(){Authorize();const before=Seed();reset.Prepare(RESET);reset.Apply(RESET);return before;}
 if(mode==='guard'){
  const before=Seed(),file=path.join(store.DIR,'authority.json'),fingerprint=sha(raw(file));
  assert.throws(()=>reset.Prepare(RESET),/NOT_AUTHORIZED/);
  process.env.COZY_REGISTRATION_RESET_ID=RESET;process.env.COZY_REGISTRATION_RESET_SCOPE='WRONG_SCOPE';assert.throws(()=>reset.Prepare(RESET),/NOT_AUTHORIZED/);
  Authorize();assert.throws(()=>reset.Prepare('../invalid'),/ID_INVALID/);assert.equal(sha(raw(file)),fingerprint);assert.equal(store.Load().secret,before.secret);
 }else if(mode==='prepare'){
  Authorize();Seed();const job=reset.Prepare(RESET),revision=store.Load().revision;
  assert.equal(job.phase,'PREPARED');assert.deepEqual(job.artifactIds,[A,B,G]);assert.equal(job.counts.artifacts,2);assert.equal(job.counts.deviceBindings,1);assert.equal(job.counts.deviceEnrollments,1);assert.equal(job.epoch,7);
  assert.deepEqual(reset.Prepare(RESET),job);assert.equal(store.Load().revision,revision);
  Authorize(SECOND);assert.throws(()=>reset.Prepare(SECOND),/IN_PROGRESS/);
 }else if(mode==='apply'){
  const before=Applied(),db=store.Load();
  for(const key of ['artifacts','active','launchers','flows','overlays','issueReceipts'])assert.deepEqual(db[key],{});
  assert.equal(db.secret,before.secret);assert.deepEqual(db.securityAuthorityPolicy,before.policy);assert.deepEqual(db.workspaceJournal,before.journal);assert.deepEqual(db.adminCredentialRevocations,{syntheticPreserved:true});
  assert.equal(db.serverRecovery.epoch,7);assert.equal(db.securityOperations.requireCozyProtection,true);assert.equal(db.securityOperations.requirePackingEvidence,true);assert.equal(db.securityOperations.releaseGovernance.minimumSecurityVersion,9);assert.equal(db.securityOperations.signerStates['f'.repeat(64)].state,'REVOKED');assert.equal(db.securityOperations.requireBuildContract,false);assert.equal(db.releaseSafety.revokedCohorts['7'.repeat(128)].reason,'SYNTHETIC_REVOKED_COHORT');
  assert.deepEqual(db.deviceRegistry.bindings,{});assert.deepEqual(db.deviceIdentity.enrollments,{});assert.equal(db.deviceIdentity.mode,'PERSISTENT');assert.equal(db.deviceIdentity.keyGenerations['e'.repeat(64)],6);
  const revision=db.revision;assert.equal(reset.Apply(RESET).phase,'APPLIED');assert.equal(store.Load().revision,revision);assert.ok(fs.existsSync(store.ArtifactPath(A)));assert.equal(reset.Status().phase,'APPLIED');
 }else if(mode==='cleanup'){
  Authorize();Seed();reset.Prepare(RESET);assert.throws(()=>reset.Cleanup(RESET),/NOT_APPLIED/);assert.ok(fs.existsSync(store.ArtifactPath(A)));reset.Apply(RESET);
  const key=path.join(config.DATA_DIR,'connect-transport-key.pem'),before=sha(raw(key));
  fs.unlinkSync(store.ArtifactPath(A));fs.symlinkSync(key,store.ArtifactPath(A));
  assert.throws(()=>reset.Cleanup(RESET),/ARTIFACT_FILE_INVALID/);assert.equal(sha(raw(key)),before);assert.equal(reset.Status().cleanedAt,0);
  fs.unlinkSync(store.ArtifactPath(A));fs.writeFileSync(store.ArtifactPath(A),'SYNTHETIC ORIGINAL');
  assert.equal(reset.Cleanup(RESET).deletedFiles,3);for(const id of [A,B,G])assert.equal(fs.existsSync(store.ArtifactPath(id)),false);assert.equal(sha(raw(key)),before);assert.equal(reset.Status().phase,'APPLIED');assert.equal(reset.Finish(RESET).phase,'COMPLETE');assert.equal(audit.VerifyAuditChain().ok,true);
 }else if(mode==='history'){
  Applied();assert.throws(()=>reset.Finish(RESET),/NOT_CLEANED/);reset.Cleanup(RESET);const complete=reset.Finish(RESET);
  store.Atomic(db=>{db.artifacts[FRESH]=Artifact(FRESH);});fs.writeFileSync(store.ArtifactPath(FRESH),'SYNTHETIC NEW REGISTRATION');const revision=store.Load().revision;
  assert.deepEqual(reset.Prepare(RESET),complete);assert.deepEqual(reset.Apply(RESET),complete);assert.deepEqual(reset.Cleanup(RESET),complete);assert.deepEqual(reset.Finish(RESET),complete);assert.equal(store.Load().revision,revision);assert.ok(store.Load().artifacts[FRESH]);assert.ok(fs.existsSync(store.ArtifactPath(FRESH)));
  Authorize(SECOND);reset.Prepare(SECOND);Authorize(RESET);assert.equal(reset.Prepare(RESET).phase,'COMPLETE');assert.equal(store.Load().registrationResetJob.id,SECOND);assert.ok(store.Load().artifacts[FRESH]);
 }else if(mode==='finish-guard'){
  Applied();reset.Cleanup(RESET);store.Atomic(db=>{db.artifacts[FRESH]=Artifact(FRESH);});assert.throws(()=>reset.Finish(RESET),/REGISTRATIONS_CHANGED/);assert.equal(reset.Status().phase,'APPLIED');
 }else if(mode==='restart'){
  Authorize();store.Load();const secret=store.Load().secret;reset.Prepare(RESET);reset.Apply(RESET);reset.Cleanup(RESET);
  // A new process must authenticate the resulting authority/head before Finish.
  const child=execFileSync(process.execPath,[__filename,'restart-finish'],{env:{...process.env,EXPECTED_RESET_SECRET:secret},encoding:'utf8',timeout:10000});assert.match(child,/CHILD_OK/);
 }else if(mode==='restart-finish'){
  Authorize();assert.equal(store.Load().secret,process.env.EXPECTED_RESET_SECRET);assert.equal(reset.Status().phase,'APPLIED');assert.equal(reset.Finish(RESET).phase,'COMPLETE');
 }else if(mode==='tamper'){
  Authorize();Seed();reset.Prepare(RESET);store.Atomic(db=>{db.registrationResetJob.artifactIds.push('../outside');});assert.throws(()=>reset.Status(),/STORAGE_INVALID/);
 }else throw Error('UNKNOWN_TEST_MODE');
 console.log('CHILD_OK');
}
if(process.env.COZY_RESET_BOOTSTRAP_TEST_CHILD==='1')Child(process.argv[2]);
else{
 const test=require('node:test');
 const cases={guard:'reset requires exact environment scope and ID before mutation',prepare:'prepare captures bounded file plan and cannot overlap another reset',apply:'forward apply clears registrations while retaining keys, floors and revocations',cleanup:'cleanup rejects links, resumes and removes only captured EXE files',history:'completed IDs cannot reset newly registered data or replace a different pending job','finish-guard':'completion refuses registrations added after cleanup',restart:'authenticated authority survives process restart between apply and finish',tamper:'persisted reset plans reject path traversal before cleanup'};
 for(const [mode,name]of Object.entries(cases))test(name,()=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-reset-bootstrap-'));
  try{const output=execFileSync(process.execPath,[__filename,mode],{env:{...process.env,NODE_ENV:'test',DATA_DIR:directory,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_RECOVERY_WITNESS_DIR:'',DESKTOP_RECOVERY_WITNESS_URL:'',DESKTOP_RECOVERY_WITNESS_REQUIRED:'0',COZY_RESET_BOOTSTRAP_TEST_CHILD:'1',COZY_REGISTRATION_RESET_ID:'',COZY_REGISTRATION_RESET_SCOPE:''},encoding:'utf8',timeout:10000,maxBuffer:1024*1024});assert.match(output,/CHILD_OK/);}finally{fs.rmSync(directory,{recursive:true,force:true});}
 });
}
