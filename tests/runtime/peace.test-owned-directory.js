/* Test-only process ownership. Production lock modules are not modified.
 * Application fixtures hold lifetime SQLite locks. Their directory must only
 * be removed by a parent which never imported those modules, AFTER child exit.
 */
'use strict';
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const cp=require('node:child_process'),crypto=require('node:crypto');
const CHILD='--owned-test-directory-child';
const OWNER='.test-directory-owner.json',DONE='.test-directory-complete.json';
function fail(code){throw Error(code);}
function identity(directory){const s=fs.lstatSync(directory);if(!s.isDirectory()||s.isSymbolicLink())fail('TEST_DIRECTORY_NOT_REGULAR');return {dev:s.dev,ino:s.ino};}
function verifyDirectory(directory,owner,prefix,expectedIdentity){
 const root=fs.realpathSync(os.tmpdir()),resolved=path.resolve(directory);
 if(path.dirname(resolved)!==root||!path.basename(resolved).startsWith(prefix)||fs.realpathSync(resolved)!==resolved)fail('TEST_DIRECTORY_SCOPE_INVALID');
 const current=identity(resolved);
 if(expectedIdentity&&(current.dev!==expectedIdentity.dev||current.ino!==expectedIdentity.ino))fail('TEST_DIRECTORY_IDENTITY_CHANGED');
 const file=path.join(resolved,OWNER),s=fs.lstatSync(file);
 if(!s.isFile()||s.isSymbolicLink()||s.size>4096)fail('TEST_DIRECTORY_OWNER_INVALID');
 const actual=JSON.parse(fs.readFileSync(file,'utf8'));
 if(actual.nonce!==owner.nonce||actual.script!==owner.script||actual.parentPid!==owner.parentPid)fail('TEST_DIRECTORY_OWNER_MISMATCH');
 return resolved;
}
function ChildEnvironment(directory){
 // Do not inherit operating credentials or NODE_OPTIONS/NODE_PATH from an IDE.
 const env={};
 for(const key of ['PATH','Path','SystemRoot','SYSTEMROOT','WINDIR','COMSPEC','ComSpec','PATHEXT','TEMP','TMP','TMPDIR','USERPROFILE','HOME','APPDATA','LOCALAPPDATA','LANG','LC_ALL','NUMBER_OF_PROCESSORS'])
  if(process.env[key])env[key]=process.env[key];
 return {...env,NODE_ENV:'test',DATA_DIR:directory,STORAGE_ENGINE:'json',HA_ENABLED:'0'};
}
async function Main(script,prefix,run,options={}){
 try{
  script=fs.realpathSync(script);
  if(!/^[a-z][a-z0-9-]{2,64}-$/.test(prefix)||typeof run!=='function')fail('TEST_DIRECTORY_CONFIGURATION_INVALID');
  const args=process.argv.slice(2);
  if(args[0]===CHILD){
   if(args.length!==4||! /^[a-f0-9]{48}$/.test(args[2])||! /^[1-9][0-9]*$/.test(args[3]))fail('TEST_DIRECTORY_CHILD_ARGUMENTS_INVALID');
   const [_,directory,nonce,parent]=args;
   if(Number(parent)!==process.ppid)fail('TEST_DIRECTORY_PARENT_MISMATCH');
   const owner={script,nonce,parentPid:Number(parent)};
   verifyDirectory(directory,owner,prefix);
   // No deletion in the process holding production-style SQLite connections.
   // Main catches and prints the primary assertion BEFORE parent cleanup runs.
   await run(directory);
   if(process.exitCode&&process.exitCode!==0)return process.exitCode;
   fs.writeFileSync(path.join(directory,DONE),JSON.stringify({nonce,completed:true}),{flag:'wx',mode:0o600});
   return 0;
  }
  if(args.length)fail('TEST_DIRECTORY_ARGUMENTS_INVALID');
  const timeout=options.timeoutMs??240000;
  if(!Number.isInteger(timeout)||timeout<50||timeout>240000)fail('TEST_DIRECTORY_TIMEOUT_INVALID');
  const directory=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),prefix));
  const id=identity(directory),owner={script,nonce:crypto.randomBytes(24).toString('hex'),parentPid:process.pid};
  fs.writeFileSync(path.join(directory,OWNER),JSON.stringify(owner),{flag:'wx',mode:0o600});
  console.log('[TEST_SANDBOX] '+directory);
  const child=cp.spawnSync(process.execPath,[script,CHILD,directory,owner.nonce,String(process.pid)],{
   cwd:process.cwd(),env:ChildEnvironment(directory),stdio:['ignore','inherit','inherit'],
   shell:false,windowsHide:true,timeout,killSignal:'SIGTERM'
  });
  let result=Number.isInteger(child.status)&&child.status===0&&!child.error?0:1;
  if(child.error)console.error('[TEST_CHILD_ERROR] '+(child.error.code||child.error.message));
  if(child.status!==0)console.error('[TEST_CHILD_EXIT] status='+child.status+' signal='+(child.signal||''));
  if(result===0){
   try{
    const receipt=JSON.parse(fs.readFileSync(path.join(directory,DONE),'utf8'));
    if(receipt.nonce!==owner.nonce||receipt.completed!==true)fail('TEST_BODY_NOT_COMPLETED');
   }catch(e){console.error('[TEST_BODY_NOT_COMPLETED] '+e.message);result=1;}
  }
  // A spawn failure with no process has no lock owner. If exit is ambiguous,
  // retain the diagnostic directory instead of touching potentially live data.
  const ended=Number.isInteger(child.status)||!!child.signal||(!child.pid&&!!child.error);
  if(ended){
   try{
    verifyDirectory(directory,owner,prefix,id);
    fs.rmSync(directory,{recursive:true,force:false,maxRetries:6,retryDelay:100});
    if(fs.existsSync(directory))fail('TEST_DIRECTORY_STILL_PRESENT');
    console.log('[TEST_CLEANUP_OK] owned directory removed after child exit.');
   }catch(e){
    console.error('[TEST_CLEANUP_FAILED] '+(e.code||e.message)+' '+directory);
    result=1;
   }
  }else{
   console.error('[TEST_CLEANUP_NOT_ATTEMPTED] child termination not confirmed: '+directory);
   result=1;
  }
  process.exitCode=result;return result;
 }catch(error){console.error('[TEST_PRIMARY_FAILURE]',error);process.exitCode=1;return 1;}
}
module.exports={Main,ChildEnvironment};
