'use strict';
// Explicit startup maintenance only. This is a forward authority transaction,
// never deletion/re-enrolment of authenticated heads, witness state or keys.
const fs=require('node:fs');
const store=require('./peace.desktop-bootstrap-store');
const audit=require('../storage/peace.desktop-operation-audit');
const SCOPE='ABO_LICENSES_ISSUANCE_OPERATIONS_V1',MAX_RESETS=1024;
const ID=/^[a-f0-9]{64}$/,ARTIFACT=/^(?:DA-)?[A-F0-9]{24}$/;
const COUNT_KEYS=['artifacts','launchers','flows','overlays','issueReceipts','packingEvidence','manifests','workspaceGarbage','deviceBindings','deviceEnrollments'];
const JOB_FIELDS=['version','id','phase','preparedAt','appliedAt','cleanedAt','completedAt','artifactIds','counts','epoch','deletedFiles'];
function Fail(code){throw Error('REGISTRATION_RESET_'+code);}
function Plain(v){return !!v&&Object.getPrototypeOf(v)===Object.prototype;}
function Exact(v,keys){return Plain(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));}
function Time(n){return Number.isSafeInteger(n)&&n>0;}
function Identifier(id){if(typeof id!=='string'||!ID.test(id))Fail('ID_INVALID');return id;}
function Authorized(id){Identifier(id);require('../operations/peace.registration-reset-authorization').Assert(id);}
function Count(v){return Object.keys(v||{}).length;}
function Counts(db){return {artifacts:Count(db.artifacts),launchers:Count(db.launchers),flows:Count(db.flows),overlays:Count(db.overlays),issueReceipts:Count(db.issueReceipts),packingEvidence:Count(db.packingEvidence),manifests:Count(db.securityOperations?.releaseGovernance?.manifests),workspaceGarbage:Count(db.workspaceGarbage),deviceBindings:Count(db.deviceRegistry?.bindings),deviceEnrollments:Count(db.deviceIdentity?.enrollments)};}
function ValidateJob(j){
 if(!Exact(j,JOB_FIELDS)||j.version!==1||!ID.test(j.id||'')||!['PREPARED','APPLIED','COMPLETE'].includes(j.phase)||!Time(j.preparedAt)||!Array.isArray(j.artifactIds)||j.artifactIds.length>100000||new Set(j.artifactIds).size!==j.artifactIds.length||j.artifactIds.some(id=>typeof id!=='string'||!ARTIFACT.test(id))||!Exact(j.counts,COUNT_KEYS)||COUNT_KEYS.some(k=>!Number.isSafeInteger(j.counts[k])||j.counts[k]<0)||!Number.isSafeInteger(j.epoch)||j.epoch<1||!Number.isSafeInteger(j.deletedFiles)||j.deletedFiles<0)Fail('STORAGE_INVALID');
 if(j.phase==='PREPARED'){if(j.appliedAt!==0||j.cleanedAt!==0||j.completedAt!==0||j.deletedFiles!==0)Fail('STORAGE_INVALID');}
 else if(!Time(j.appliedAt)||j.appliedAt<j.preparedAt||j.cleanedAt!==0&&(!Time(j.cleanedAt)||j.cleanedAt<j.appliedAt))Fail('STORAGE_INVALID');
 if(j.phase==='APPLIED'&&(j.completedAt!==0||j.deletedFiles!==(j.cleanedAt?j.artifactIds.length:0)))Fail('STORAGE_INVALID');
 if(j.phase==='COMPLETE'&&(!Time(j.cleanedAt)||!Time(j.completedAt)||j.completedAt<j.cleanedAt||j.artifactIds.length!==0))Fail('STORAGE_INVALID');
 return j;
}
function State(db=store.Load()){
 const receipts=db.registrationResetReceipts||{};
 if(!Plain(receipts)||Count(receipts)>MAX_RESETS)Fail('STORAGE_INVALID');
 for(const [id,r]of Object.entries(receipts))if(!ID.test(id)||ValidateJob(r).id!==id||r.phase!=='COMPLETE')Fail('STORAGE_INVALID');
 const job=db.registrationResetJob;
 if(job){ValidateJob(job);if(job.phase==='COMPLETE'){if(JSON.stringify(receipts[job.id])!==JSON.stringify(job))Fail('STORAGE_INVALID');}else if(receipts[job.id])Fail('STORAGE_INVALID');}
 return {job,receipts};
}
function Status(id){
 if(id!==undefined)Identifier(id);const {job,receipts}=State();
 return structuredClone(id?(receipts[id]||(job?.id===id?job:null)):job||null);
}
function Pending(id){
 Authorized(id);const {job,receipts}=State();if(receipts[id])return receipts[id];
 if(!job||job.id!==id)Fail('NOT_PREPARED');return job;
}
function Prepare(id){
 Authorized(id);const db=store.Load(),{job,receipts}=State(db);
 if(receipts[id])return structuredClone(receipts[id]);
 if(job&&job.phase!=='COMPLETE'){if(job.id!==id)Fail('IN_PROGRESS');return structuredClone(job);}
 if(Count(receipts)>=MAX_RESETS)Fail('RECEIPT_CAPACITY');
 const epoch=(db.serverRecovery?.epoch||0)+1;if(!Number.isSafeInteger(epoch))Fail('EPOCH_CAPACITY');
 const artifactIds=[...new Set([...Object.keys(db.artifacts),...Object.keys(db.workspaceGarbage||{})])].sort();
 if(artifactIds.length>100000||artifactIds.some(id=>!ARTIFACT.test(id)))Fail('STORAGE_INVALID');
 const prepared={version:1,id,phase:'PREPARED',preparedAt:Date.now(),appliedAt:0,cleanedAt:0,completedAt:0,artifactIds,counts:Counts(db),epoch,deletedFiles:0};
 ValidateJob(prepared);
 audit.Run('REGISTRATION_RESET_PREPARE','SERVER_MAINTENANCE',{subject:id,count:artifactIds.length},next=>{State(next);next.registrationResetReceipts||={};next.registrationResetJob=prepared;});
 return Status(id);
}
function ResetOperations(db){
 if(db.securityOperations){
  const operations=require('../security/peace.desktop-security-operations'),provenance=require('../artifacts/peace.desktop-release-provenance');
  const old=operations.ValidateState(db.securityOperations),governance=old.releaseGovernance||provenance.Defaults();
  db.securityOperations={...operations.Defaults(),revision:old.revision+1,requireBuildContract:old.requireBuildContract===true,requireTestEvidence:old.requireTestEvidence===true,requirePackingEvidence:old.requirePackingEvidence===true,requireCozyProtection:old.requireCozyProtection===true,signerStates:structuredClone(old.signerStates),releaseGovernance:{...provenance.Defaults(),requireManifest:governance.requireManifest,minimumSecurityVersion:governance.minimumSecurityVersion,releaseKeyIds:structuredClone(governance.releaseKeyIds||[])}};
  operations.ValidateState(db.securityOperations);
 }
 if(db.releaseSafety){const safety=require('../artifacts/peace.desktop-release-safety'),old=safety.ValidateState(db.releaseSafety);db.releaseSafety={...safety.Defaults(),revision:old.revision+1,revokedCohorts:structuredClone(old.revokedCohorts)};safety.ValidateState(db.releaseSafety);}
}
function Apply(id){
 const job=Pending(id);if(job.phase!=='PREPARED')return structuredClone(job);
 audit.Run('REGISTRATION_RESET_APPLY','SERVER_MAINTENANCE',{subject:id,count:job.counts.artifacts,epoch:job.epoch},db=>{
  const current=db.registrationResetJob;if(current?.id!==id||current.phase!=='PREPARED'||(db.serverRecovery?.epoch||0)+1!==current.epoch)Fail('CONFLICT');
  ResetOperations(db);
  for(const name of ['artifacts','active','launchers','flows','overlays','issueReceipts'])db[name]={};
  for(const name of ['lifecycleTrace','packingEvidence','workspaceGarbage','manualVerifications','mitigationProfiles','mitigationCompatibility','securityActivation'])delete db[name];
  if(db.deviceRegistry){db.deviceRegistry={...db.deviceRegistry,revision:db.deviceRegistry.revision+1,bindings:{},receipts:{}};require('../devices/peace.desktop-device-registry').Validate(db.deviceRegistry);}
  if(db.deviceIdentity){db.deviceIdentity={...db.deviceIdentity,revision:db.deviceIdentity.revision+1,enrollments:{},receipts:{},adminReceipts:{},legacyFlows:{},recoveryGrants:{}};require('../devices/peace.desktop-device-identity').Validate(db.deviceIdentity);}
  db.serverRecovery={version:1,epoch:current.epoch,receipts:db.serverRecovery?.receipts||{}};
  current.phase='APPLIED';current.appliedAt=Math.max(Date.now(),current.preparedAt);ValidateJob(current);require('../recovery/peace.desktop-recovery').Validate(db);
 });
 return Status(id);
}
function Cleanup(id){
 const job=Pending(id);if(job.phase==='COMPLETE'||job.cleanedAt)return structuredClone(job);if(job.phase!=='APPLIED')Fail('NOT_APPLIED');
 const directory=fs.lstatSync(store.DIR);if(!directory.isDirectory()||directory.isSymbolicLink())Fail('DIRECTORY_INVALID');
 for(const artifactId of job.artifactIds){
  const db=store.Load();if(db.artifacts[artifactId]||Object.values(db.active).includes(artifactId))Fail('ARTIFACT_REFERENCED');
  const file=store.ArtifactPath(artifactId);let stat;try{stat=fs.lstatSync(file);}catch(error){if(error.code==='ENOENT')continue;throw error;}
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1)Fail('ARTIFACT_FILE_INVALID');
  fs.unlinkSync(file);
 }
 if(process.platform!=='win32'){const fd=fs.openSync(store.DIR,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 audit.Run('REGISTRATION_RESET_CLEANUP','SERVER_MAINTENANCE',{subject:id,count:job.artifactIds.length},db=>{const current=db.registrationResetJob;if(current?.id!==id||current.phase!=='APPLIED')Fail('CONFLICT');current.cleanedAt=Math.max(Date.now(),current.appliedAt);current.deletedFiles=current.artifactIds.length;});
 return Status(id);
}
function Finish(id){
 const job=Pending(id);if(job.phase==='COMPLETE')return structuredClone(job);if(job.phase!=='APPLIED'||!job.cleanedAt)Fail('NOT_CLEANED');
 audit.Run('REGISTRATION_RESET_COMPLETE','SERVER_MAINTENANCE',{subject:id,count:job.counts.artifacts,epoch:job.epoch},db=>{
  const current=db.registrationResetJob;if(current?.id!==id||current.phase!=='APPLIED'||!current.cleanedAt)Fail('CONFLICT');
  if(['artifacts','active','launchers','flows','overlays','issueReceipts'].some(k=>Count(db[k])))Fail('REGISTRATIONS_CHANGED');
  current.phase='COMPLETE';current.completedAt=Math.max(Date.now(),current.cleanedAt);current.artifactIds=[];
  db.registrationResetReceipts||={};db.registrationResetReceipts[id]=structuredClone(current);
 });
 return Status(id);
}
module.exports={SCOPE,MAX_RESETS,Prepare,Apply,Cleanup,Finish,Status};
