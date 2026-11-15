'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
if(!process.argv[2]){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-retired-support-'));
 try{
  const env={};for(const name of ['PATH','Path','SystemRoot','SYSTEMROOT','WINDIR','PATHEXT','COMSPEC','LANG','LC_ALL','TZ','NODE_PATH'])if(process.env[name]!==undefined)env[name]=process.env[name];
  Object.assign(env,{DATA_DIR:directory,HA_ENABLED:'0',STORAGE_ENGINE:'sqlite',COZY_DESKTOP_MODE:'1'});
  for(const step of ['seed','migrate','reload','lock-owner']){const result=spawnSync(process.execPath,[__filename,step],{env,encoding:'utf8',timeout:20000});assert.equal(result.status,0,result.stdout+result.stderr);}
  console.log('RETIRED SUPPORT STORAGE PASS: exact owned files removed, durable state removal, restart and partial-deletion recovery, unrelated state/files retained, symlink/hardlink/foreign-path refusal.');
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
}else{
 const config=require('../../config/peace.runtime-configuration'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
 const retirement=require('../../services/storage/peace.retire-support-captures');
 const directory=path.join(config.DATA_DIR,'support-captures'),outside=path.join(config.DATA_DIR,'unrelated-data');
 const name='A'.repeat(24)+'.enc',temp=name+'.'+'b'.repeat(32)+'.tmp';
 const authority=()=>JSON.parse(fs.readFileSync(path.join(store.DIR,'authority.json'),'utf8'));
 if(process.argv[2]==='read-only'){
  const bytes=fs.readFileSync(path.join(store.DIR,'authority.json'));
  assert.deepEqual(retirement.Retire(),{removedState:false,removedFiles:0});
  assert.deepEqual(fs.readFileSync(path.join(store.DIR,'authority.json')),bytes);process.exit(0);
 }
 if(process.argv[2]==='blocked-retirement'){
  assert.throws(()=>retirement.Retire(),/DESKTOP_DATA_DIR_ALREADY_IN_USE/);assert.equal(fs.readFileSync(path.join(directory,name),'utf8'),'orphan');process.exit(0);
 }
 if(process.argv[2]==='lock-owner'){
  require('../../services/storage/peace.desktop-single-writer').Acquire(config.DATA_DIR);
  // A fresh process can initialize the absent feature while a writer exists.
  // The same process must not retire real orphan files without that lease.
  for(const step of ['read-only','blocked-retirement']){
   if(step==='blocked-retirement'){fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,name),'orphan');}
   const child=spawnSync(process.execPath,[__filename,step],{env:process.env,encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stdout+child.stderr);
  }
  assert.deepEqual(retirement.Retire(),{removedState:false,removedFiles:1});process.exit(0);
 }
 if(process.argv[2]==='reload'){
  const db=store.Load();assert.equal(db.retirementTestPreserved,'preserve');assert.equal(Object.hasOwn(db,'supportCaptures'),false);assert.equal(fs.readFileSync(outside,'utf8'),'unrelated');
  const before=db.revision;assert.deepEqual(retirement.Retire(),{removedState:false,removedFiles:0});assert.equal(store.Load().revision,before);process.exit(0);
 }
 require('../../services/storage/peace.desktop-single-writer').Acquire(config.DATA_DIR);
 if(process.argv[2]==='seed'){
  fs.writeFileSync(outside,'unrelated');store.Atomic(db=>{db.retirementTestPreserved='preserve';db.supportCaptures={obsolete:true,items:{private:'synthetic'}};});
  fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,name),'encrypted');fs.writeFileSync(path.join(directory,temp),'temporary');process.exit(0);
 }
 // A cold start must accept obsolete capture metadata only for retirement,
 // without loading the deleted feature validator or requiring its old schema.
 const before=structuredClone(store.Load());
 // A failed durable commit must not unlink image files or mutate the loaded DB.
 const atomic=store.Atomic;store.Atomic=()=>{throw Error('TEST_COMMIT_FAILURE');};
 try{assert.throws(()=>retirement.Retire(),/TEST_COMMIT_FAILURE/);assert.deepEqual(store.Load(),before);assert.equal(fs.readdirSync(directory).length,2);}finally{store.Atomic=atomic;}
 // Simulate a crash after commit, before the second file can be unlinked.
 const unlink=fs.unlinkSync;let count=0;fs.unlinkSync=function(file){if(path.dirname(file)===directory&&++count===2)throw Error('TEST_DELETE_FAILURE');return unlink.apply(this,arguments);};
 try{assert.throws(()=>retirement.Retire(),/TEST_DELETE_FAILURE/);}finally{fs.unlinkSync=unlink;}
 assert.equal(Object.hasOwn(authority(),'supportCaptures'),false);assert.equal(authority().retirementTestPreserved,'preserve');assert.equal(fs.readdirSync(directory).length,1);
 const expected={...before,revision:before.revision+1};delete expected.supportCaptures;assert.deepEqual(store.Load(),expected);
 assert.deepEqual(retirement.Retire(),{removedState:false,removedFiles:1});assert.equal(fs.existsSync(directory),false);assert.equal(fs.readFileSync(outside,'utf8'),'unrelated');
 assert.deepEqual(retirement.Retire(),{removedState:false,removedFiles:0});
 // Orphan files are cleaned on startup even if no state entry survived a crash.
 fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,name),'orphan');assert.deepEqual(retirement.Retire(),{removedState:false,removedFiles:1});
 // Never traverse links, delete a foreign filename, or unlink a hardlinked file.
 if(process.platform!=='win32'){
  fs.symlinkSync(config.DATA_DIR,directory,'dir');assert.throws(()=>retirement.Retire(),/RETIRED_SUPPORT_STORAGE_INVALID/);fs.unlinkSync(directory);
  fs.mkdirSync(directory);fs.symlinkSync(outside,path.join(directory,name));assert.throws(()=>retirement.Retire(),/RETIRED_SUPPORT_STORAGE_INVALID/);assert.equal(fs.readFileSync(outside,'utf8'),'unrelated');fs.unlinkSync(path.join(directory,name));fs.rmdirSync(directory);
 }
 fs.mkdirSync(directory);fs.linkSync(outside,path.join(directory,name));assert.throws(()=>retirement.Retire(),/RETIRED_SUPPORT_STORAGE_INVALID/);fs.unlinkSync(path.join(directory,name));fs.rmdirSync(directory);
 fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,name),'encrypted');fs.writeFileSync(path.join(directory,'keep.txt'),'foreign');assert.throws(()=>retirement.Retire(),/RETIRED_SUPPORT_STORAGE_INVALID/);assert.equal(fs.readFileSync(path.join(directory,name),'utf8'),'encrypted');assert.equal(fs.readFileSync(path.join(directory,'keep.txt'),'utf8'),'foreign');fs.unlinkSync(path.join(directory,'keep.txt'));retirement.Retire();
 assert.equal(fs.existsSync(directory),false);assert.equal(fs.readFileSync(outside,'utf8'),'unrelated');
}
