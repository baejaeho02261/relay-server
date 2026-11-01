'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Execution-only recovery drill. The input backup/witness are always read-only.
// This prepares an isolated copy, not a new authority or a publication approval.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const drill=require('./peace.recovery-drill'),durable=require("../../services/storage/peace.durable-file");
const SHA=b=>crypto.createHash('sha512').update(b).digest('hex');
const CODE=e=>/^[A-Z][A-Z0-9_]{2,100}$/.test(e?.message||'')?e.message:'RECOVERY_WINDOWS_FAILED';
function Fail(code){throw Error(code);}
function Read(file,max=8*1024*1024){return durable.ReadRegular(file,max);}
function Json(file,max){return require("../../services/protocol/peace.strict-json").Parse(Read(file,max),{maxBytes:max||8*1024*1024});}
function Write(file,value){durable.Atomic(file,Buffer.from(JSON.stringify(value,null,2)+'\n'),{createOnly:true});}
function Config(c){
 const keys=['version','backupDirectory','witnessSnapshotDirectory','storageEngine','enrollmentId','machineId','provider','nativeProbe','artifacts','allowIsolatedPcUnlock','allowIsolatedRequestApproval','issuedASigningKeyFile','verificationContextFile'];
 if(!c||Object.getPrototypeOf(c)!==Object.prototype||Object.keys(c).some(k=>!keys.includes(k))||c.version!==1||!/^[a-f0-9]{64}$/.test(c.enrollmentId||'')||!/^[A-F0-9]{64}$/.test(c.machineId||'')||!['SOFTWARE','PLATFORM'].includes(c.provider)||c.allowIsolatedPcUnlock!==true)Fail('RECOVERY_WINDOWS_INPUT_INVALID');
 if(typeof c.witnessSnapshotDirectory!=='string'||!c.witnessSnapshotDirectory)Fail('RECOVERY_WINDOWS_WITNESS_SNAPSHOT_REQUIRED');
 if(c.allowIsolatedRequestApproval!==true)Fail('RECOVERY_REQUEST_APPROVAL_CONSENT_REQUIRED');
 if(typeof c.issuedASigningKeyFile!=='string'||!path.isAbsolute(c.issuedASigningKeyFile))Fail('RECOVERY_ISSUED_A_SIGNER_PATH_REQUIRED');
 const base=drill.Validate({version:1,backupDirectory:c.backupDirectory,witnessSnapshotDirectory:c.witnessSnapshotDirectory,storageEngine:c.storageEngine});
 if(!base.witnessSnapshotDirectory)Fail('RECOVERY_WINDOWS_WITNESS_SNAPSHOT_REQUIRED');
 if(!c.artifacts||Object.keys(c.artifacts).sort().join(',')!=='A,B,O')Fail('RECOVERY_WINDOWS_A_B_O_REQUIRED');
 for(const file of [c.nativeProbe,...Object.values(c.artifacts)])if(typeof file!=='string'||!path.isAbsolute(file))Fail('RECOVERY_WINDOWS_ABSOLUTE_PATH_REQUIRED');
 if(c.verificationContextFile!==undefined&&(typeof c.verificationContextFile!=='string'||!path.isAbsolute(c.verificationContextFile)))Fail('RECOVERY_WINDOWS_ABSOLUTE_PATH_REQUIRED');
 return {...c,...base};
}
// The operator supplies the matching server issuer outside source and backup.
// Neither its bytes nor its digest are copied to plan/report/native child state.
function IssuancePrerequisites(config,root){
 if(config.allowIsolatedRequestApproval!==true)Fail('RECOVERY_REQUEST_APPROVAL_CONSENT_REQUIRED');
 if(config.provider==='PLATFORM')Fail('RECOVERY_TPM_REENROLLMENT_CHANNEL_REQUIRED');
 const file=config.issuedASigningKeyFile;
 if(typeof file!=='string'||!path.isAbsolute(file))Fail('RECOVERY_ISSUED_A_SIGNER_PATH_REQUIRED');
 try{let at=path.dirname(file);while(true){const stat=fs.lstatSync(at);if(!stat.isDirectory()||stat.isSymbolicLink())Fail('RECOVERY_ISSUED_A_SIGNER_PATH_INVALID');const parent=path.dirname(at);if(parent===at)break;at=parent;}}catch(_){Fail('RECOVERY_ISSUED_A_SIGNER_PATH_INVALID');}
 if([path.resolve(__dirname,'../../../..'),config.backupDirectory,config.witnessSnapshotDirectory,root].filter(Boolean).some(dir=>drill.Inside(dir,file)))Fail('RECOVERY_ISSUED_A_SIGNER_MUST_BE_OUTSIDE_SOURCE_AND_BACKUP');
 return file;
}
function LoadIssuedSigner(config,root,expectedKeyId,install=false){
 const file=IssuancePrerequisites(config,root);let bytes;
 try{
  bytes=Read(file,8192);const signing=require('../../services/bootstrap/peace.issued-a-signing'),privateKey=crypto.createPrivateKey(bytes),identity=signing.PublicIdentity(crypto.createPublicKey(privateKey));
  if(expectedKeyId&&identity.keyId!==expectedKeyId)Fail('RECOVERY_ISSUED_A_SIGNER_MISMATCH');
  if(install)process.env[signing.ENV]=bytes.toString('base64');return {keyId:identity.keyId};
 }catch(error){if(/^RECOVERY_/.test(error.message))throw error;Fail('RECOVERY_ISSUED_A_SIGNER_INVALID');}finally{bytes?.fill(0);}
}
function Root(root){if(typeof root!=='string'||!path.isAbsolute(root))Fail('RECOVERY_WINDOWS_PRIVATE_ROOT_REQUIRED');let at=path.resolve(root);while(true){const stat=fs.lstatSync(at);if(!stat.isDirectory()||stat.isSymbolicLink())Fail('RECOVERY_WINDOWS_PRIVATE_ROOT_REQUIRED');const parent=path.dirname(at);if(parent===at)break;at=parent;}root=fs.realpathSync(root);if(!path.basename(root).startsWith('game-recovery-drill-')||!fs.existsSync(path.join(root,'test-owned-marker'))||Read(path.join(root,'test-owned-marker'),64).toString()!=='GAME_WINDOWS_TEST_V1')Fail('RECOVERY_WINDOWS_PRIVATE_ROOT_REQUIRED');return root;}
function LoadPlan(root){
 const p=Json(path.join(root,'plan.json'));
 if(p.version!==1||p.kind!=='RECOVERY_WINDOWS_PRODUCT_DRILL'||!/^[a-f0-9]{32}$/.test(p.runId||'')||!/^[a-f0-9]{64}$/.test(p.token||'')||Read(path.join(root,'owner'),64).toString()!==p.token)Fail('RECOVERY_WINDOWS_PLAN_INVALID');
 for(const [key,name]of Object.entries({data:'server-data',witness:'witness',rollback:'rollback'}))if(p[key]!==path.join(root,name))Fail('RECOVERY_WINDOWS_PLAN_PATH_INVALID');
 if(!p.files||Object.keys(p.files).sort().join(',')!=='A,B,O,probe')Fail('RECOVERY_WINDOWS_PLAN_INVALID');
 for(const [role,row]of Object.entries(p.files))if(row.executedCopy!==path.join(root,role==='probe'?'cozy.RecoveryDeviceProbe.exe':role+'.template.exe')||!/^[a-f0-9]{128}$/.test(row.sha512||'')||typeof row.source!=='string'||!path.isAbsolute(row.source))Fail('RECOVERY_WINDOWS_PLAN_PATH_INVALID');
 return p;
}
function Prepare(input,root){
 root=Root(root);const c=Config(Json(input,32768));IssuancePrerequisites(c,root);
 if([c.backupDirectory,c.witnessSnapshotDirectory].some(d=>drill.Inside(d,root)||drill.Inside(root,d)))Fail('RECOVERY_WINDOWS_INPUT_OVERLAP');
 const runId=crypto.randomBytes(16).toString('hex'),token=crypto.randomBytes(32).toString('hex');
 fs.writeFileSync(path.join(root,'owner'),token,{flag:'wx',mode:0o600});
 const backup=drill.Tree(c.backupDirectory),witness=drill.Tree(c.witnessSnapshotDirectory);
 const data=path.join(root,'server-data'),witnessCopy=path.join(root,'witness'),rollback=path.join(root,'rollback');
 if(drill.Tree(c.backupDirectory,data).sha256!==backup.sha256||drill.Tree(c.witnessSnapshotDirectory,witnessCopy).sha256!==witness.sha256)Fail('RECOVERY_WINDOWS_INPUT_CHANGED');
 drill.Tree(data,rollback);
 const files={};for(const [role,source]of Object.entries({...c.artifacts,probe:c.nativeProbe})){
  const bytes=Read(source,64*1024*1024);require("../runtime/peace.manual-windows-tests").Pe64(bytes);
  if(role!=='probe')require("../../services/artifacts/peace.pe-build-configuration").AssertProductionConfiguration(bytes);
  const executedCopy=path.join(root,role==='probe'?'cozy.RecoveryDeviceProbe.exe':role+'.template.exe');
  fs.writeFileSync(executedCopy,bytes,{flag:'wx',mode:0o600});files[role]={source,executedCopy,sha512:SHA(bytes)};
 }
 const anchor=require('../../services/bootstrap/peace.issued-a-signing').InspectTemplate(Read(files.A.executedCopy,64*1024*1024)),issuer=LoadIssuedSigner(c,root,anchor.keyId);
 const plan={issuer,version:1,kind:'RECOVERY_WINDOWS_PRODUCT_DRILL',runId,token,startedAt:new Date().toISOString(),config:c,data,witness:witnessCopy,rollback,backup,witnessSnapshot:witness,files,sourceManifestSha512:SHA(Read(path.join(MODULE_RESOURCE_ROOT,'../maintenance/source-manifest.json')))};
 if(c.verificationContextFile){const raw=Read(c.verificationContextFile,256*1024),binding=require("../artifacts/peace.verification-report").Binding(Json(c.verificationContextFile,256*1024));if(binding.sourceManifestSha512!==plan.sourceManifestSha512||['A','B','O'].some(r=>binding.artifacts[r]!==files[r].sha512))Fail('RECOVERY_WINDOWS_VERIFICATION_BINDING_MISMATCH');plan.verification={binding,contextSha512:SHA(raw)};}
 Write(path.join(root,'plan.json'),plan);return {runId,prepared:true};
}
const PRODUCT_CHECKS=['licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed','ownedProcessesVerified','noOwnedProcessesRemain','serverStopped'];
function Evaluate(plan,status,execution){
 if(!status||status.runId!==plan.runId||execution?.runId!==plan.runId)Fail('RECOVERY_WINDOWS_RUN_BINDING_MISMATCH');
 if(execution.windowsExecuted!==true||execution.platform!=='win32'||execution.architecture!=='x64')Fail('RECOVERY_WINDOWS_EXECUTION_REQUIRED');
 if(status.error||execution.error)Fail(status.error||execution.error);
 if(execution.cleanupHadToTerminateOwnedProcess!==false||PRODUCT_CHECKS.some(k=>execution[k]!==true))Fail('RECOVERY_WINDOWS_PRODUCT_FLOW_INCOMPLETE');
 const proof=status.recovery;
 if(!proof||proof.originalProofAccepted!==true||proof.originalReplayDenied!==true||proof.oldKeyChallengeDenied!==true||proof.originalKeyStillPresent!==true||proof.originalKeyDeleted!==false||proof.replacementDeleted!==true||proof.replacementExclusiveCreated!==true||proof.replacementPrivateExportBlocked!==true||proof.originalPrivateExportBlocked!==true||proof.policyUnchanged!==true||proof.oldLicensesUnchanged!==true||proof.spentLicenseIssueRejected!==true||proof.recoveryEpochBefore+1!==proof.recoveryEpochAfter)Fail('RECOVERY_WINDOWS_ORIGINAL_DEVICE_PROOF_INCOMPLETE');
 if(proof.nativeCleanup?.processExited!==true||proof.nativeCleanup?.processExitCode!==0||proof.nativeCleanup?.forcedTermination!==false||proof.nativeCleanup?.gracefulInputClosed!==true)Fail('RECOVERY_WINDOWS_NATIVE_CLEANUP_UNCONFIRMED');
 if(!status.product||status.product.machineBindingMatched!==true||status.product.replacementEnrollmentMatched!==true||status.product.allRolesProvedReplacement!==true||status.product.runtimeRetired!==true||status.product.epoch!==proof.recoveryEpochAfter||status.product.consumedNewLicense!==true)Fail('RECOVERY_WINDOWS_REPLACEMENT_PRODUCT_BINDING_MISSING');
 if(plan.config.provider==='PLATFORM'&&(proof.originalTpmAttested!==true||status.product.replacementTpmAttested!==true))Fail('RECOVERY_WINDOWS_TPM_ATTESTATION_REQUIRED');
 for(const role of ['A','B','O'])if(status.artifacts?.[role]!==plan.files[role].sha512)Fail('RECOVERY_WINDOWS_ARTIFACT_BINDING_MISMATCH');
 return 'PASS';
}
function Finalize(root,output,publicResultFile=output){
 root=Root(root);const plan=LoadPlan(root),execution=Json(path.join(root,'execution.json')),status=Json(path.join(root,'status.json'));
 const requested=path.resolve(output),out=path.join(fs.realpathSync(path.dirname(requested)),path.basename(requested));if(drill.Inside(root,out)||[plan.config.backupDirectory,plan.config.witnessSnapshotDirectory].some(d=>drill.Inside(d,out)))Fail('RECOVERY_WINDOWS_REPORT_MUST_BE_OUTSIDE_INPUT');
 if(fs.existsSync(out))Fail('RECOVERY_WINDOWS_RESULT_MUST_BE_NEW');
 const requestedPublic=path.resolve(publicResultFile),published=path.join(fs.realpathSync(path.dirname(requestedPublic)),path.basename(requestedPublic));if(drill.Inside(root,published)||[plan.config.backupDirectory,plan.config.witnessSnapshotDirectory].some(d=>drill.Inside(d,published)))Fail('RECOVERY_WINDOWS_REPORT_MUST_BE_OUTSIDE_INPUT');if(published!==out&&fs.existsSync(published))Fail('RECOVERY_WINDOWS_RESULT_MUST_BE_NEW');
 const result={version:1,kind:plan.kind,runId:plan.runId,outcome:'FAIL',windowsExecuted:execution.windowsExecuted===true,nativeBuild:'NOT_RUN',publicationApproval:false,hardwareAttested:false,sourceManifestSha512:plan.sourceManifestSha512,sourceBackup:plan.backup,sourceWitnessSnapshot:plan.witnessSnapshot,scope:'Original device CNG/TPM proof and the exact active production A/B/O in an isolated recovered copy; no live server state or original key is changed.',originalKeyDeleted:false,physicalWitnessIndependenceAttested:false,artifacts:Object.fromEntries(['A','B','O'].map(r=>[r,plan.files[r].sha512])),probeSha512:plan.files.probe.sha512,checks:status.recovery||{},product:status.product||{},execution};
 try{
  Evaluate(plan,status,execution);
  if(SHA(Read(path.join(MODULE_RESOURCE_ROOT,'../maintenance/source-manifest.json')))!==plan.sourceManifestSha512)Fail('RECOVERY_WINDOWS_SOURCE_CHANGED');
  for(const row of Object.values(plan.files))if(SHA(Read(row.source,64*1024*1024))!==row.sha512||SHA(Read(row.executedCopy,64*1024*1024))!==row.sha512)Fail('RECOVERY_WINDOWS_ARTIFACT_CHANGED');
  const reload=drill.Worker(root,plan.token,'inspect',plan.data,plan.witness,plan.config.storageEngine);
  if(!reload.ok||reload.details.epoch!==status.recovery.recoveryEpochAfter)Fail('RECOVERY_WINDOWS_RELOAD_FAILED');
  result.freshProcessReload=true;
  const rollback=drill.Worker(root,plan.token,'inspect',plan.rollback,plan.witness,plan.config.storageEngine);
  if(rollback.ok||rollback.error!=='RECOVERY_ROLLBACK_DETECTED')Fail('RECOVERY_WINDOWS_ROLLBACK_NOT_REJECTED');
  result.oldBackupAgainstAdvancedWitnessRejected=true;result.outcome='PASS';
 }catch(e){result.error=CODE(e);}
 finally{
  try{result.originalBackupUnchanged=drill.Tree(plan.config.backupDirectory).sha256===plan.backup.sha256;result.originalWitnessUnchanged=drill.Tree(plan.config.witnessSnapshotDirectory).sha256===plan.witnessSnapshot.sha256;if(!result.originalBackupUnchanged||!result.originalWitnessUnchanged)Fail('RECOVERY_WINDOWS_SOURCE_CHANGED');}catch(e){result.outcome='FAIL';result.error=CODE(e);}
  try{fs.rmSync(root,{recursive:true,force:true});result.isolatedCopiesRemoved=!fs.existsSync(root);if(!result.isolatedCopiesRemoved)Fail('RECOVERY_WINDOWS_CLEANUP_FAILED');}catch(e){result.outcome='FAIL';result.error=CODE(e);result.isolatedCopiesRemoved=false;}
 }
 if(plan.verification&&result.outcome==='PASS')result.publicVerificationFile=VerificationName(published);
 Write(out,result);
 if(plan.verification&&result.outcome==='PASS'){
  try{ExportVerification(plan,result,out);}catch(e){result.outcome='FAIL';result.error=CODE(e);delete result.publicVerificationFile;fs.rmSync(VerificationName(out),{force:true});durable.Atomic(out,Buffer.from(JSON.stringify(result,null,2)+'\n'));}
 }
 return result;
}
function VerificationName(report){return path.join(path.dirname(report),path.basename(report,'.json')+'-verification.json');}
function ExportVerification(plan,result,report){
 if(result.outcome!=='PASS'||result.windowsExecuted!==true||!plan.verification)Fail('RECOVERY_WINDOWS_VERIFICATION_NOT_EXECUTED');
 const output=VerificationName(report),temporary=report+'.verification-input-'+crypto.randomBytes(8).toString('hex')+'.json';
 if(SHA(Read(plan.config.verificationContextFile,256*1024))!==plan.verification.contextSha512)Fail('RECOVERY_WINDOWS_VERIFICATION_CONTEXT_CHANGED');
 const check=(id,scope)=>({id,outcome:'PASS',scope,reasonCode:'RECOVERY_DRILL_EXECUTED',evidenceFile:report,subjectArtifacts:scope==='SELECTED_FINAL_ABO'?plan.verification.binding.artifacts:null});
 const input={version:1,kind:'OPERATOR_VERIFICATION_INPUT',binding:plan.verification.binding,sourceManifestFile:path.resolve(MODULE_RESOURCE_ROOT,'../maintenance/source-manifest.json'),artifactFiles:plan.config.artifacts,runId:'recovery-'+plan.runId,startedAt:plan.startedAt,platform:process.platform,architecture:process.arch,domains:[{id:'11',checks:[check('backup-restore','ISOLATED_SERVICE'),check('old-session-rejection','ISOLATED_SERVICE'),check('spent-license-rejection','ISOLATED_SERVICE'),check('witness-rollback','ISOLATED_SERVICE'),check('device-key-rotation','ISOLATED_SERVICE'),check('original-device-recovery','WINDOWS_PROBE'),check('recovered-abo-integration','SELECTED_FINAL_ABO')]}]};
 try{Write(temporary,input);require("../artifacts/peace.verification-report").Finalize(temporary,output);}finally{fs.rmSync(temporary,{force:true});}
 return output;
}
if(require.main===module){try{const [action,...args]=process.argv.slice(2);let r;if(action==='prepare'&&args.length===2)r=Prepare(...args);else if(action==='finalize'&&[2,3].includes(args.length))r=Finalize(...args);else Fail('RECOVERY_WINDOWS_ARGUMENTS_INVALID');console.log(JSON.stringify({runId:r.runId,outcome:r.outcome||'PREPARED'}));if(r.outcome==='FAIL'){if(r.error)console.error(r.error);process.exitCode=1;}}catch(e){console.error(CODE(e));process.exitCode=1;}}
module.exports={Config,IssuancePrerequisites,LoadIssuedSigner,Root,LoadPlan,Prepare,Evaluate,Finalize,ExportVerification,Read,Json,Write,SHA,CODE,PRODUCT_CHECKS};
