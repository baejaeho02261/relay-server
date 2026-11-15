'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Entirely synthetic server snapshots. These tests do not certify any user's
// backup, a Windows process, named CNG key persistence, or physical TPM hardware.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),cp=require('node:child_process');
const drill=require("../../tools/recovery/peace.recovery-drill"),temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-recovery-drill-test-')),owner=crypto.randomBytes(32).toString('hex');
fs.writeFileSync(path.join(temp,'owner'),owner);let count=0;
function Check(name,fn){fn();count++;console.log('PASS '+name);}
function Worker(command,data,witness=null,extra={}){
 const output=path.join(temp,crypto.randomBytes(8).toString('hex')+'.json');
 const run=cp.spawnSync(process.execPath,[path.resolve(MODULE_RESOURCE_ROOT,"../tools/recovery/peace.recovery-drill-worker.js")],{input:JSON.stringify({command,data,witness,output,...extra}),env:drill.ChildEnvironment(temp,owner,data,witness,'json'),encoding:'utf8',timeout:60000});
 assert.equal(run.status,0,run.stderr+(fs.existsSync(output)?fs.readFileSync(output):''));const result=JSON.parse(fs.readFileSync(output));assert.equal(result.ok,true);fs.unlinkSync(output);return result;
}
function Passed(report,name){assert.equal(report.checks.find(c=>c.name===name)?.status,'PASS',JSON.stringify(report));}
try{
 for(const storageEngine of ['json','sqlite'])Check('complete isolated real-service regression on '+storageEngine,()=>{
  const result=drill.Run('selftest',{storageEngine});assert.equal(result.ok,true,JSON.stringify(result));assert.equal(result.isolatedCopiesRemoved,true);assert.equal(result.scope.physicalTpm,'NOT_TESTED');assert.equal(result.scope.windowsRuntime,'NOT_TESTED');
  const r=result.syntheticRegression;assert.equal(r.source,'SYNTHETIC_SERVICE_FIXTURE');assert.equal(r.coverage,'SCOPED_SERVICE_CHECKS_COMPLETE');
  for(const name of ['restore_and_reconcile','recovery_epoch_apply_and_retry','old_session_rejection','spent_license_preservation_and_unconsume_refusal','spent_license_signed_redeem_rejection','device_key_revoke_and_reregister','fresh_process_recovery_reload','older_copy_against_advanced_witness'])Passed(r,name);
  assert.ok(r.checks.find(c=>c.name==='old_session_rejection').acceptedBeforeRecovery>0);
  assert.equal(r.witness.productionRollbackProtectionVerified,false);
 });
 const data=path.join(temp,'seed'),backup=path.join(temp,'backup'),witness=path.join(temp,'witness'),witnessSnapshot=path.join(temp,'witness-snapshot');fs.mkdirSync(data);fs.mkdirSync(witness);Worker('seed',data);Worker('enroll',data,null,{enrollWitness:witness});drill.Tree(data,backup);drill.Tree(witness,witnessSnapshot);
 const config={version:1,backupDirectory:backup,witnessSnapshotDirectory:witnessSnapshot,storageEngine:'json'},before=drill.Tree(backup),beforeWitness=drill.Tree(witnessSnapshot);
 Check('operator-input path copies a snapshot, checks real state, and labels missing hardware/credential coverage',()=>{
  const result=drill.Run('backup',config);assert.equal(result.ok,true,JSON.stringify(result));assert.equal(result.originalBackupUnchanged,true);assert.equal(result.originalWitnessUnchanged,true);assert.equal(result.isolatedCopiesRemoved,true);assert.deepEqual(drill.Tree(backup),before);assert.deepEqual(drill.Tree(witnessSnapshot),beforeWitness);
  assert.equal(result.backup.source,'OPERATOR_SUPPLIED_BACKUP');assert.equal(result.backup.coverage,'PARTIAL_BACKUP_EXERCISE');assert.equal(result.backup.witness.origin,'COPIED_OPERATOR_WITNESS_SNAPSHOT');
  for(const name of ['restore_and_reconcile','old_session_rejection','spent_license_preservation_and_unconsume_refusal','older_copy_against_advanced_witness'])Passed(result.backup,name);
  assert.equal(result.backup.checks.find(c=>c.name==='device_key_revoke_and_reregister').status,'NOT_TESTED');assert.equal(result.backup.checks.find(c=>c.name==='spent_license_signed_redeem_rejection').status,'NOT_TESTED');
  const text=JSON.stringify(result);assert(!/PRIVATE KEY|sessionToken|licenseKey|signingSecret|issuanceNonce/.test(text),'report must not contain credentials');
 });
 Check('newer supplied witness refuses old entire backup without enrollment or source mutation',()=>{
  Worker('recover',data,witness,{synthetic:false});const witnessBefore=drill.Tree(witness),result=drill.Run('backup',{...config,witnessSnapshotDirectory:witness});
  assert.equal(result.ok,false);assert.equal(result.backup.error,'RECOVERY_ROLLBACK_DETECTED');assert.equal(result.syntheticRegression.ok,true);assert.equal(result.originalBackupUnchanged,true);assert.equal(result.originalWitnessUnchanged,true);assert.deepEqual(drill.Tree(witness),witnessBefore);
 });
 Check('corrupt backup journal fails instead of initializing empty recovered authority',()=>{
  const corrupt=path.join(temp,'corrupt');drill.Tree(backup,corrupt);const journal=path.join(corrupt,'desktop-license-journal.jsonl'),lines=fs.readFileSync(journal,'utf8').trimEnd().split('\n'),last=JSON.parse(lines.at(-1));last.mac='0'.repeat(64);lines[lines.length-1]=JSON.stringify(last);fs.writeFileSync(journal,lines.join('\n')+'\n');
  const bytes=drill.Tree(corrupt),result=drill.Run('backup',{...config,backupDirectory:corrupt});assert.equal(result.ok,false);assert.equal(result.backup.error,'DESKTOP_JOURNAL_CORRUPT');assert.deepEqual(drill.Tree(corrupt),bytes);assert.equal(result.originalBackupUnchanged,true);
 });
 Check('invalid JSON snapshot is refused before fallback can initialize an empty database',()=>{
  const corrupt=path.join(temp,'corrupt-json');drill.Tree(backup,corrupt);fs.writeFileSync(path.join(corrupt,'relay-identities.json'),'invalid JSON');
  const result=drill.Run('backup',{...config,backupDirectory:corrupt});assert.equal(result.ok,false);assert.equal(result.backup.error,'DRILL_BACKUP_DATABASE_INVALID');assert.equal(result.originalBackupUnchanged,true);
 });
 Check('source symlinks and hardlinks rejected; native coordination file never copied',()=>{
  const source=path.join(temp,'link-test'),dest=path.join(temp,'link-copy');fs.mkdirSync(source);fs.writeFileSync(path.join(source,'file'),'original');fs.writeFileSync(path.join(source,'.desktop-single-writer.sqlite'),'do not restore lock');drill.Tree(source,dest);assert(!fs.existsSync(path.join(dest,'.desktop-single-writer.sqlite')));
  fs.linkSync(path.join(source,'file'),path.join(source,'hardlink'));assert.throws(()=>drill.Tree(source),/DRILL_SOURCE_LINK_REFUSED/);fs.unlinkSync(path.join(source,'hardlink'));
  if(process.platform!=='win32'){fs.symlinkSync(path.join(source,'file'),path.join(source,'symlink'));assert.throws(()=>drill.Tree(source),/DRILL_SOURCE_LINK_REFUSED/);fs.unlinkSync(path.join(source,'symlink'));}
 });
 Check('production environment and unsafe worker paths cannot redirect a drill',()=>{
  const old=process.env.CONNECT_TLS_KEY_FILE;process.env.CONNECT_TLS_KEY_FILE='/production/private.pem';try{const env=drill.ChildEnvironment(temp,owner,data,null,'json');assert.equal(env.CONNECT_TLS_KEY_FILE,undefined);assert.equal(env.NODE_OPTIONS,undefined);assert.equal(env.DATA_DIR,data);assert.equal(env.DESKTOP_RECOVERY_WITNESS_DIR,undefined);}finally{if(old===undefined)delete process.env.CONNECT_TLS_KEY_FILE;else process.env.CONNECT_TLS_KEY_FILE=old;}
  const outside=path.join(os.tmpdir(),'game-drill-outside-'+crypto.randomBytes(12).toString('hex')+'.json');const result=cp.spawnSync(process.execPath,[path.resolve(MODULE_RESOURCE_ROOT,"../tools/recovery/peace.recovery-drill-worker.js")],{input:JSON.stringify({command:'seed',data,witness:null,output:outside}),env:drill.ChildEnvironment(temp,owner,data,null,'json'),encoding:'utf8'});assert.notEqual(result.status,0);assert(!fs.existsSync(outside));
 });
 Check('CLI refuses report overwrite and report creation inside the original backup',()=>{
  const input=path.join(temp,'input.json');fs.writeFileSync(input,JSON.stringify(config));const output=path.join(temp,'exists.json');fs.writeFileSync(output,'preserve');
  for(const [target,error]of [[output,'DRILL_REPORT_ALREADY_EXISTS'],[path.join(backup,'report.json'),'DRILL_REPORT_MUST_BE_OUTSIDE_INPUT']]){const r=cp.spawnSync(process.execPath,[path.resolve(MODULE_RESOURCE_ROOT,"../tools/recovery/peace.recovery-drill.js"),'backup',input,target],{encoding:'utf8'});assert.equal(r.status,1);assert.match(r.stderr,new RegExp(error));}assert.equal(fs.readFileSync(output,'utf8'),'preserve');assert.deepEqual(drill.Tree(backup),before);
 });
 console.log('RECOVERY DRILL PASS: '+count+' checks. Synthetic server-service evidence only; no actual user backup, Windows/CNG or hardware TPM validated.');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
