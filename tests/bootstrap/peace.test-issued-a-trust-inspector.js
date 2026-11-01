'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const inspect=require('../../tools/security/peace.inspect-issued-a-trust');
const signing=require('../../services/bootstrap/peace.issued-a-signing');
const {WithAnchor}=require('../fixtures/bootstrap/peace.issued-a-fixture');
const {crcPeFixture}=require('../fixtures/artifacts/peace.crc-pe-fixture');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-public-inspect-'));
const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
const keyId=signing.PublicIdentity(pair.publicKey).keyId;
const original=WithAnchor(crcPeFixture(),pair.publicKey);
const file=path.join(temp,'A 한글 with spaces.exe');
fs.writeFileSync(file,original);
const tool=path.resolve(__dirname,'../../tools/security/peace.inspect-issued-a-trust.js');
test.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
function Run(args,extraEnv={}){
 const child=spawnSync(process.execPath,[tool,...args],{encoding:'utf8',timeout:15000,env:{...process.env,...extraEnv}});
 assert.equal(child.error,undefined);
 assert.equal(child.signal,null);
 assert.equal(child.stderr,'');
 return {status:child.status,result:JSON.parse(child.stdout)};
}
test('matching public key is inspected without executing or changing the executable',()=>{
 const before=fs.statSync(file),args=['--launcher',file,'--expected-key-id',keyId];
 // A malformed configured signer must not be read by a static inspection.
 const output=Run(args,{DESKTOP_ISSUED_A_SIGNING_PRIVATE_KEY_B64:'sentinel-private-key-not-for-inspection',DESKTOP_ISSUED_A_SIGNING_KEYS_JSON:'sentinel-private-key-map'});
 assert.equal(output.status,0);
 assert.deepEqual(output.result,{
  ok:true,keyId,expectedKeyId:keyId,matchesExpected:true,comparison:'MATCH',
  sizeBytes:original.length,sha512:crypto.createHash('sha512').update(original).digest('hex'),
  windowsExecution:'NOT_RUN',serverState:'NOT_CHECKED'
 });
 assert.deepEqual(fs.readFileSync(file),original);
 const after=fs.statSync(file);
 assert.equal(after.mtimeMs,before.mtimeMs);
 assert.equal(JSON.stringify(output.result).includes('sentinel-private'),false);
});
test('mismatch exits unsuccessfully and inspection-only mode makes no comparison claim',()=>{
 const other='0'.repeat(64)===keyId?'1'.repeat(64):'0'.repeat(64);
 const mismatch=Run(['--launcher',file,'--expected-key-id',other]);
 assert.equal(mismatch.status,1);
 assert.equal(mismatch.result.error,'ISSUED_A_EXPECTED_KEY_MISMATCH');
 assert.equal(mismatch.result.keyId,keyId);
 assert.equal(mismatch.result.matchesExpected,false);
 assert.equal(mismatch.result.comparison,'MISMATCH');
 const only=Run(['--launcher',file]);
 assert.equal(only.status,0);
 assert.equal(only.result.expectedKeyId,null);
 assert.equal(only.result.matchesExpected,null);
 assert.equal(only.result.comparison,'NOT_REQUESTED');
 assert.equal(only.result.serverState,'NOT_CHECKED');
});
test('malformed inputs and ambiguous public anchors fail without a chosen key',()=>{
 const noAnchor=path.join(temp,'no-anchor.exe'),ambiguous=path.join(temp,'ambiguous.exe');
 fs.writeFileSync(noAnchor,crcPeFixture());
 const duplicate=Buffer.from(original);signing.AnchorBytes(pair.publicKey).copy(duplicate,600);fs.writeFileSync(ambiguous,duplicate);
 for(const [name,expected] of [[noAnchor,'ISSUED_A_BUILD_UPGRADE_REQUIRED'],[ambiguous,'ISSUED_A_TRUST_ANCHOR_AMBIGUOUS']]){
  const output=Run(['--launcher',name,'--expected-key-id',keyId]);
  assert.equal(output.status,1);
  assert.equal(output.result.error,expected);
  assert.equal(Object.hasOwn(output.result,'keyId'),false);
 }
 for(const args of [
  [],['--launcher','relative.exe'],['--launcher',file,'--expected-key-id','ABC'],
  ['--launcher',file,'--launcher',file],['--launcher',file,'--private-key-file',file],
  ['--launcher',file,'--expected-key-id']
 ]){
  const output=Run(args);
  assert.equal(output.status,1);
  assert.equal(output.result.ok,false);
  assert.equal(Object.hasOwn(output.result,'keyId'),false);
 }
});
test('the static reader rejects directories and files above the artifact size limit',()=>{
 const directory=Run(['--launcher',temp]);assert.equal(directory.status,1);assert.equal(directory.result.error,'AUDIT_FILE_INVALID');
 const oversized=path.join(temp,'oversized.exe'),fd=fs.openSync(oversized,'wx');
 try{fs.ftruncateSync(fd,64*1024*1024+1);}finally{fs.closeSync(fd);}
 const output=Run(['--launcher',oversized]);assert.equal(output.status,1);assert.equal(output.result.error,'AUDIT_FILE_INVALID');
});
test('file and parent-directory symlinks are refused',t=>{
 const link=path.join(temp,'linked.exe'),realDirectory=path.join(temp,'real'),linkedDirectory=path.join(temp,'linked-directory');
 fs.mkdirSync(realDirectory);fs.writeFileSync(path.join(realDirectory,'A.exe'),original);
 try{fs.symlinkSync(file,link,'file');fs.symlinkSync(realDirectory,linkedDirectory,process.platform==='win32'?'junction':'dir');}
 catch(error){if(['EPERM','EACCES','ENOSYS'].includes(error.code)){t.skip('Host does not permit symbolic-link creation');return;}throw error;}
 for(const name of [link,path.join(linkedDirectory,'A.exe')]){
  const output=Run(['--launcher',name]);
  assert.equal(output.status,1);assert.equal(output.result.error,'ISSUED_A_INSPECT_SYMLINK_DENIED');
 }
});

