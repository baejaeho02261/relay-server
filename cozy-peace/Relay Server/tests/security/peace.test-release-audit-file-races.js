'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {spawnSync}=require('node:child_process');
const reader=require.resolve('../../services/artifacts/peace.bounded-artifact-read');
// Run each real pathname swap in a killable subprocess so a regression to a
// blocking FIFO open cannot hang the server test runner itself.
for(const kind of ['fifo','symlink'])test('lstat/open '+kind+' replacement cannot block or read substituted bytes',
 {skip:process.platform==='win32'},()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'peace-bounded-read-race-'));
 try{
  const file=path.join(dir,'release'),replacement=path.join(dir,'replacement'),target=path.join(dir,'target');
  fs.writeFileSync(file,Buffer.alloc(32,1));fs.writeFileSync(target,Buffer.alloc(32,2));
  if(kind==='fifo'){const made=spawnSync('mkfifo',[replacement],{encoding:'utf8',timeout:1000});assert.equal(made.status,0,made.stderr);}
  else fs.symlinkSync(target,replacement);
  const code=`const assert=require('node:assert/strict'),fs=require('node:fs');
  const [modulePath,file,replacement,kind]=process.argv.slice(1),read=require(modulePath).Read;
  const open=fs.openSync,close=fs.closeSync;let swapped=false,closed=false;
  fs.openSync=(name,flags,...rest)=>{if(name===file&&!swapped){swapped=true;fs.renameSync(file,file+'.old');fs.renameSync(replacement,file);}return open(name,flags,...rest);};
  fs.closeSync=fd=>{closed=true;return close(fd);};
  assert.throws(()=>read(file),e=>e.message==='AUDIT_FILE_CHANGED'||e.code==='ELOOP');
  assert.equal(swapped,true);if(kind==='fifo')assert.equal(closed,true);process.stdout.write('REJECTED');`;
  const result=spawnSync(process.execPath,['-e',code,reader,file,replacement,kind],{encoding:'utf8',timeout:2000});
  assert.equal(result.error,undefined,result.error?.message);assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,'REJECTED');
  assert.deepEqual(fs.readFileSync(target),Buffer.alloc(32,2));
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
