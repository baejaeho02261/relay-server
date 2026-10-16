'use strict';
// Offline operator drill. No listeners, live-server endpoints, source writes,
// lock bypasses, policy weakening, or user/device private-key imports.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),cp=require('node:child_process');
const LOCK='.desktop-single-writer.sqlite';
const SHA=b=>crypto.createHash('sha256').update(b).digest('hex');
function Fail(code){throw Error(code);}
function Inside(parent,child){const r=path.relative(parent,child);return r===''||r!=='..'&&!r.startsWith('..'+path.sep)&&!path.isAbsolute(r);}
function Directory(input){if(typeof input!=='string'||!path.isAbsolute(input))Fail('DRILL_ABSOLUTE_DIRECTORY_REQUIRED');const st=fs.lstatSync(input);if(!st.isDirectory()||st.isSymbolicLink())Fail('DRILL_DIRECTORY_INVALID');return fs.realpathSync(input);}
function Validate(input){
 if(!input||Object.getPrototypeOf(input)!==Object.prototype||Object.keys(input).some(k=>!['version','backupDirectory','witnessSnapshotDirectory','storageEngine'].includes(k))||input.version!==1||!['json','sqlite'].includes(input.storageEngine)||Object.hasOwn(input,'witnessSnapshotDirectory')&&(typeof input.witnessSnapshotDirectory!=='string'||!input.witnessSnapshotDirectory))Fail('DRILL_INPUT_INVALID');
 const backupDirectory=Directory(input.backupDirectory),witnessSnapshotDirectory=input.witnessSnapshotDirectory?Directory(input.witnessSnapshotDirectory):null;
 if(witnessSnapshotDirectory&&(Inside(backupDirectory,witnessSnapshotDirectory)||Inside(witnessSnapshotDirectory,backupDirectory)))Fail('DRILL_WITNESS_MUST_BE_SEPARATE');
 if(!fs.existsSync(path.join(backupDirectory,'desktop-bootstrap','authority.json')))Fail('DRILL_BACKUP_AUTHORITY_REQUIRED');
 if(!fs.existsSync(path.join(backupDirectory,input.storageEngine==='sqlite'?'relay.db':'relay-identities.json')))Fail('DRILL_BACKUP_DATABASE_REQUIRED');
 return {version:1,backupDirectory,witnessSnapshotDirectory,storageEngine:input.storageEngine};
}
// Source files are opened read-only, without following links; copied bytes are
// fresh files. Reject all nonregular objects/hardlinks, and change during read.
// Never copy SQLite coordination locks or SQLite transient lock companions.
function Tree(source,destination){
 const hash=crypto.createHash('sha256');let bytes=0,count=0;
 function visit(dir,relative=''){
  const before=fs.lstatSync(dir);if(!before.isDirectory()||before.isSymbolicLink())Fail('DRILL_SOURCE_LINK_REFUSED');
  if(destination)fs.mkdirSync(path.join(destination,relative),{recursive:true,mode:0o700});
  for(const name of fs.readdirSync(dir).sort()){
   if(name===LOCK||name.startsWith(LOCK+'-'))continue;
   const absolute=path.join(dir,name),rel=path.join(relative,name),stat=fs.lstatSync(absolute);
   if(stat.isSymbolicLink()||!stat.isFile()&&!stat.isDirectory()||stat.isFile()&&stat.nlink!==1)Fail('DRILL_SOURCE_LINK_REFUSED');
   if(stat.isDirectory()){visit(absolute,rel);continue;}
   if(++count>100000||stat.size>1024*1024*1024||(bytes+=stat.size)>8*1024*1024*1024)Fail('DRILL_BACKUP_SIZE_LIMIT');
   const fd=fs.openSync(absolute,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));let data;
   try{const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.nlink!==1||opened.ino!==stat.ino||opened.dev!==stat.dev)Fail('DRILL_SOURCE_CHANGED');data=fs.readFileSync(fd);const after=fs.fstatSync(fd);if(after.size!==stat.size||after.mtimeMs!==stat.mtimeMs||after.ctimeMs!==stat.ctimeMs||data.length!==stat.size)Fail('DRILL_SOURCE_CHANGED');}finally{fs.closeSync(fd);}
   const row=[rel.split(path.sep).join('/'),data.length,SHA(data)];hash.update(JSON.stringify(row)+'\n');
   if(destination)fs.writeFileSync(path.join(destination,rel),data,{flag:'wx',mode:0o600});
   data.fill(0);
  }
  const after=fs.lstatSync(dir);if(after.ino!==before.ino||after.dev!==before.dev||after.mtimeMs!==before.mtimeMs)Fail('DRILL_SOURCE_CHANGED');
 }
 visit(source);return {sha256:hash.digest('hex'),files:count,bytes};
}
function ChildEnvironment(root,token,data,witness,engine){
 const env={};for(const key of ['PATH','Path','SystemRoot','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','TEMP','TMP','TMPDIR','HOME','USERPROFILE','LANG','LC_ALL','NODE_PATH'])if(process.env[key])env[key]=process.env[key];
 // Environment-derived production paths, keys and network configuration are not inherited.
 Object.assign(env,{DATA_DIR:data,STORAGE_ENGINE:engine,HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131',RECOVERY_DRILL_ROOT:root,RECOVERY_DRILL_TOKEN:token,PYTHONDONTWRITEBYTECODE:'1'});
 if(witness)Object.assign(env,{DESKTOP_RECOVERY_WITNESS_DIR:witness,DESKTOP_RECOVERY_WITNESS_REQUIRED:'1'});
 return env;
}
function Worker(root,token,command,data,witness,engine,extra={}){
 const out=path.join(root,'worker-'+crypto.randomBytes(8).toString('hex')+'.json');
 const run=cp.spawnSync(process.execPath,[path.join(__dirname,'recovery-drill-worker.js')],{input:JSON.stringify({command,data,witness,output:out,...extra}),env:ChildEnvironment(root,token,data,witness,engine),encoding:'utf8',timeout:60000,maxBuffer:1024*1024,windowsHide:true});
 // Service logging may include identifiers; it is deliberately not forwarded.
 if(!fs.existsSync(out))return {ok:false,error:run.error?.code==='ETIMEDOUT'?'DRILL_WORKER_TIMEOUT':'DRILL_WORKER_FAILED'};
 const result=JSON.parse(fs.readFileSync(out,'utf8'));fs.unlinkSync(out);return result;
}
function AssertResult(result){if(!result.ok)Fail(result.error||'DRILL_WORKER_FAILED');return result;}
function Scenario(root,token,prefix,engine,source,witnessSource){
 const data=path.join(root,prefix+'-data'),witness=path.join(root,prefix+'-witness'),rollback=path.join(root,prefix+'-rollback');
 fs.mkdirSync(data,{mode:0o700});fs.mkdirSync(witness,{mode:0o700});
 const result={source:source?'OPERATOR_SUPPLIED_BACKUP':'SYNTHETIC_SERVICE_FIXTURE',storageEngine:engine,checks:[],ok:false};
 try{
  if(source)result.copied=Tree(source,data);else{const seed=path.join(root,prefix+'-seed');fs.mkdirSync(seed,{mode:0o700});AssertResult(Worker(root,token,'seed',seed,null,engine));result.copied=Tree(seed,data);}
  if(witnessSource)Tree(witnessSource,witness);
  const restored=AssertResult(Worker(root,token,'inspect',data,witnessSource?witness:null,engine));
  result.checks.push({name:'restore_and_reconcile',status:'PASS',...restored.details});
  if(!witnessSource)AssertResult(Worker(root,token,'enroll',data,null,engine,{enrollWitness:witness}));
  result.witness={origin:witnessSource?'COPIED_OPERATOR_WITNESS_SNAPSHOT':'NEW_ISOLATED_DRILL_WITNESS',physicalIndependenceVerified:false,productionRollbackProtectionVerified:false};
  Tree(data,rollback);
  const recovered=AssertResult(Worker(root,token,'recover',data,witness,engine,{synthetic:!source}));
  result.checks.push(...recovered.checks);
  const reload=AssertResult(Worker(root,token,'inspect',data,witness,engine));
  if(reload.details.epoch!==recovered.epoch||reload.details.consumedLicenses!==recovered.consumedLicenses)Fail('DRILL_RECOVERY_NOT_DURABLE');
  result.checks.push({name:'fresh_process_recovery_reload',status:'PASS',epoch:reload.details.epoch,consumedLicenses:reload.details.consumedLicenses});
  const rejected=Worker(root,token,'inspect',rollback,witness,engine);
  if(rejected.ok||rejected.error!=='RECOVERY_ROLLBACK_DETECTED')Fail('DRILL_WITNESS_ROLLBACK_NOT_REFUSED');
  result.checks.push({name:'older_copy_against_advanced_witness',status:'PASS',error:rejected.error,scope:'ISOLATED_SIMULATION'});
  result.ok=true;result.coverage=result.checks.some(c=>c.status==='NOT_TESTED')?'PARTIAL_BACKUP_EXERCISE':'SCOPED_SERVICE_CHECKS_COMPLETE';
 }catch(error){result.error=Code(error);}
 return result;
}
function Code(error){return /^[A-Z][A-Z0-9_]{2,100}$/.test(error?.message||'')?error.message:'DRILL_FAILED';}
function Run(mode,input){
 if(!['backup','selftest'].includes(mode))Fail('DRILL_COMMAND_INVALID');
 const config=mode==='backup'?Validate(input):{storageEngine:input?.storageEngine||'json'};
 if(!['json','sqlite'].includes(config.storageEngine))Fail('DRILL_INPUT_INVALID');
 const result={version:1,kind:'ISOLATED_RECOVERY_DRILL',mode,startedAt:new Date().toISOString(),ok:false,scope:{offline:true,productionStateModified:false,privateKeysInReport:false,originalPrivateKeysModified:false,windowsRuntime:'NOT_TESTED',cngKeyPersistence:'NOT_TESTED',physicalTpm:'NOT_TESTED',fixtureIsBackupProof:false,productionDeploymentApproval:false},limitations:['A directory snapshot must be complete and taken while the server is stopped or by a coherent snapshot mechanism.','A copied witness cannot attest physical independence or establish the newest production head.','Synthetic PE/software-key tests establish server-service behavior only; Windows/CNG/TPM execution requires separate operator evidence.']};
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'game-recovery-drill-')));fs.chmodSync(root,0o700);const token=crypto.randomBytes(32).toString('hex');fs.writeFileSync(path.join(root,'owner'),token,{flag:'wx',mode:0o600});
 let beforeSource,beforeWitness;
 try{
  if(mode==='backup'){
   if(Inside(config.backupDirectory,root)||config.witnessSnapshotDirectory&&Inside(config.witnessSnapshotDirectory,root))Fail('DRILL_TEMP_MUST_BE_OUTSIDE_INPUT');
   beforeSource=Tree(config.backupDirectory);if(config.witnessSnapshotDirectory)beforeWitness=Tree(config.witnessSnapshotDirectory);
   result.backup=Scenario(root,token,'backup',config.storageEngine,config.backupDirectory,config.witnessSnapshotDirectory);
  }
  // The supplement always lives in a separate directory and is never represented
  // as evidence about the operator backup or its production device credentials.
  result.syntheticRegression=Scenario(root,token,'synthetic',config.storageEngine,null,null);
  result.ok=result.syntheticRegression.ok&&(mode==='selftest'||result.backup.ok);
 }catch(error){result.error=Code(error);}
 finally{
  if(beforeSource)try{result.originalBackupUnchanged=Tree(config.backupDirectory).sha256===beforeSource.sha256;result.sourceComparisonScope='REGULAR_FILES_EXCLUDING_NATIVE_COORDINATION_LOCK';if(!result.originalBackupUnchanged){result.ok=false;result.error='DRILL_SOURCE_CHANGED_DURING_RUN';}}catch(_){result.originalBackupUnchanged=false;result.ok=false;result.error='DRILL_SOURCE_RECHECK_FAILED';}
  if(beforeWitness)try{result.originalWitnessUnchanged=Tree(config.witnessSnapshotDirectory).sha256===beforeWitness.sha256;if(!result.originalWitnessUnchanged){result.ok=false;result.error='DRILL_WITNESS_CHANGED_DURING_RUN';}}catch(_){result.originalWitnessUnchanged=false;result.ok=false;result.error='DRILL_WITNESS_RECHECK_FAILED';}
  try{fs.rmSync(root,{recursive:true,force:true});result.isolatedCopiesRemoved=true;}catch(_){result.isolatedCopiesRemoved=false;result.ok=false;result.error='DRILL_CLEANUP_FAILED';result.cleanupDirectory=root;}
  result.finishedAt=new Date().toISOString();
 }
 return result;
}
function Main(){
 const [mode,inputName,outputName]=process.argv.slice(2);let result,input,output;
 try{
  if(mode==='selftest'){if(outputName)Fail('DRILL_ARGUMENTS_INVALID');output=inputName;}
  else if(mode==='backup'){if(!inputName||process.argv.length>5)Fail('DRILL_ARGUMENTS_INVALID');input=require('../services/strictJson').Parse(require('../services/durableFile').ReadRegular(path.resolve(inputName),8192),{maxBytes:8192});Validate(input);output=outputName;}
  else Fail('DRILL_COMMAND_INVALID');
  output=path.resolve(output||path.join(__dirname,'recovery-drill-'+Date.now()+'-'+crypto.randomBytes(4).toString('hex')+'.json'));
  const parent=fs.realpathSync(path.dirname(output));output=path.join(parent,path.basename(output));
  if(input&&(Inside(fs.realpathSync(input.backupDirectory),output)||input.witnessSnapshotDirectory&&Inside(fs.realpathSync(input.witnessSnapshotDirectory),output)))Fail('DRILL_REPORT_MUST_BE_OUTSIDE_INPUT');
  if(fs.existsSync(output))Fail('DRILL_REPORT_ALREADY_EXISTS');
  result=Run(mode,input);
  require('../services/durableFile').Atomic(output,Buffer.from(JSON.stringify(result,null,2)+'\n'),{createOnly:true});console.log(output);process.exitCode=result.ok?0:1;
 }catch(error){console.error(JSON.stringify({version:1,kind:'ISOLATED_RECOVERY_DRILL',ok:false,error:Code(error)}));console.error('Usage: node recovery-drill.js selftest [new-result.json] | backup input.json [new-result.json]');process.exitCode=1;}
}
if(require.main===module)Main();
module.exports={Run,Validate,Tree,Inside,ChildEnvironment,Worker};
