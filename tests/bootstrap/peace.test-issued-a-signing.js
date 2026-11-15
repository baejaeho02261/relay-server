'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
// The signing process intentionally keeps the SQLite single-writer lock until
// process exit. Its parent owns the temporary directory and removes it only
// after spawnSync has observed that exit (also portable to Windows locks).
if(process.argv[2]!=='--issued-a-child'){
 test('isolated signer cases release process-owned locks before directory cleanup',{timeout:45000},()=>{
  const owned=fs.mkdtempSync(path.join(os.tmpdir(),'peace-issued-signature-'));
  const env={...process.env,COZY_ISSUED_A_TEST_DIR:owned};delete env.NODE_TEST_CONTEXT;
  try{
   const result=require('node:child_process').spawnSync(process.execPath,['--test-reporter=tap',__filename,'--issued-a-child'],{env,encoding:'utf8',timeout:35000,maxBuffer:4*1024*1024,windowsHide:true});
   if(result.stdout)process.stdout.write(result.stdout);
   assert.equal(result.error,undefined,result.error?.message);assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr||result.stdout);
   assert.match(result.stdout,/# tests 6\b/);assert.match(result.stdout,/# pass 6\b/);assert.match(result.stdout,/# fail 0\b/);
  }finally{fs.rmSync(owned,{recursive:true,force:true});}
  assert.equal(fs.existsSync(owned),false);
 });
}else{
const temp=process.env.COZY_ISSUED_A_TEST_DIR;
assert.ok(typeof temp==='string'&&path.isAbsolute(temp)&&path.basename(temp).startsWith('peace-issued-signature-'));
assert.equal(fs.lstatSync(temp).isDirectory(),true);
process.env.DATA_DIR=temp;process.env.HA_ENABLED='0';process.env.STORAGE_ENGINE='json';
const signing=require('../../services/bootstrap/peace.issued-a-signing'),keyTool=require('../../tools/security/peace.issued-a-signing-key'),{WithAnchor}=require('../fixtures/bootstrap/peace.issued-a-fixture');
const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537}),identity=signing.PublicIdentity(pair.publicKey),pem=pair.privateKey.export({type:'pkcs8',format:'pem'});
const fixture=require('../fixtures/artifacts/peace.crc-pe-fixture'),template=WithAnchor(fixture.crcPeFixture('GAME-CONNECT-4 GAME-AUTHORITY-V2'),pair.publicKey);
const sha=b=>crypto.createHash('sha512').update(b).digest('hex'),trusted={expectedTemplateSha512:sha(template),expectedKeyId:identity.keyId};
const profile={version:4,protocol:'GAME-CONNECT-4',host:'example.test',port:443,serverKeyId:identity.keyId,serverPublicKey:identity.blob.toString('base64'),tlsServerName:'example.test',tlsCertificateSha256:'ab'.repeat(32)};
const config={schema:3,profile,launcherId:'AB'.repeat(12),expiresAt:1800000000000};
function SetKey(key=pem){process.env[signing.ENV]=Buffer.from(key).toString('base64');}
function Reject(fn,code){assert.throws(fn,error=>error.desktopError&&(!code||error.message===code));}
test.after(()=>{delete process.env[signing.ENV];});
test('wire constants and public trust anchor are exact and section bounded',()=>{
 assert.deepEqual([signing.DOMAIN.length,signing.FOOTER.length,signing.HEADER_SIZE,signing.TAIL_SIZE,signing.ANCHOR_SIZE],[16,13,184,453,331]);
 assert.equal(signing.InspectTemplate(template).keyId,identity.keyId);
 Reject(()=>signing.InspectTemplate(fixture.crcPeFixture()),'ISSUED_A_BUILD_UPGRADE_REQUIRED');
 Reject(()=>signing.InspectTemplate(Buffer.concat([fixture.crcPeFixture(),signing.AnchorBytes(pair.publicKey)])),'ISSUED_A_BUILD_UPGRADE_REQUIRED');
 const writable=Buffer.from(template);writable.writeUInt32LE(0xc0000040,508);Reject(()=>signing.InspectTemplate(writable),'ISSUED_A_BUILD_UPGRADE_REQUIRED');
 const duplicate=Buffer.from(template);signing.AnchorBytes(pair.publicKey).copy(duplicate,600);Reject(()=>signing.InspectTemplate(duplicate),'ISSUED_A_TRUST_ANCHOR_AMBIGUOUS');
 const overlap=Buffer.from(template);overlap.writeUInt32LE(512,492);Reject(()=>signing.InspectTemplate(overlap),'ISSUED_A_TEMPLATE_INVALID');
});
test('configured signer is required, RSA parameters and immutable anchor must match',()=>{
 delete process.env[signing.ENV];assert.equal(signing.Readiness(template).reason,'ISSUED_A_SIGNING_KEY_NOT_CONFIGURED');
 process.env[signing.ENV]='not-base64';assert.equal(signing.Readiness(template).reason,'ISSUED_A_SIGNING_KEY_INVALID');
 SetKey(crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537}).privateKey.export({type:'pkcs8',format:'pem'}));assert.equal(signing.Readiness(template).reason,'ISSUED_A_SIGNING_KEY_MISMATCH');
 SetKey(crypto.generateKeyPairSync('rsa',{modulusLength:1024}).privateKey.export({type:'pkcs8',format:'pem'}));assert.equal(signing.Readiness(template).reason,'ISSUED_A_SIGNING_KEY_INVALID');
 SetKey();assert.equal(signing.Readiness(template).ready,true);assert.equal(signing.Readiness(template).authenticode,false);
});
test('whole final issued bytes and public settings are signed, frozen and independently trusted',()=>{
 SetKey();const made=signing.Create(template,config),row={id:config.launcherId,expiresAt:config.expiresAt,profile:config.profile,sha512:sha(made.bytes)};
 const result=signing.VerifyFinal(made.bytes,trusted);assert.deepEqual(result.config,config);assert.equal(result.sha512,made.receipt.finalSha512);
 assert.deepEqual(signing.Materialize(template,made.receipt,row),made.bytes);
 Reject(()=>signing.VerifyFinal(made.bytes),'ISSUED_A_TRUST_CONTEXT_REQUIRED');Reject(()=>signing.VerifyFinal(made.bytes,{...trusted,expectedKeyId:'cd'.repeat(32)}),'ISSUED_A_TRUST_CONTEXT_MISMATCH');
 const header=made.bytes.length-signing.TAIL_SIZE;for(const offset of [0,600,template.length+20,header,header+16,header+20,header+24,header+56,header+120,header+184,made.bytes.length-1]){
  const changed=Buffer.from(made.bytes);changed[offset]^=1;Reject(()=>signing.VerifyFinal(changed,trusted));
 }
 Reject(()=>signing.VerifyFinal(Buffer.concat([made.bytes,Buffer.from([0])]),trusted));Reject(()=>signing.VerifyFinal(made.bytes.subarray(0,-1),trusted));
 for(const mutate of [r=>r.expiresAt++,r=>r.id='CD'.repeat(12),r=>r.profile.port=444,r=>r.sha512='ef'.repeat(64)]){const changed=structuredClone(row);mutate(changed);Reject(()=>signing.Materialize(template,made.receipt,changed));}
 const bad=structuredClone(made.receipt);bad.envelope=Buffer.alloc(500).toString('base64');Reject(()=>signing.Materialize(template,bad,row));
 // Old immutable output does not depend on retaining the old private key.
 SetKey(crypto.generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({type:'pkcs8',format:'pem'}));assert.deepEqual(signing.Materialize(template,made.receipt,row),made.bytes);delete process.env[signing.ENV];assert.deepEqual(signing.Materialize(template,made.receipt,row),made.bytes);
 const retired={...row,status:'EXPIRED',expiresAt:row.expiresAt-1000};delete retired.profile;assert.equal(signing.ValidateReceiptShape(made.receipt,retired),made.receipt);
 made.bytes.fill(0);
});
test('distinct purpose reservation prevents transport key reuse',()=>{
 const other=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),otherTemplate=WithAnchor(fixture.crcPeFixture(),other.publicKey);
 require('../../services/security/peace.desktop-key-purposes').Reserve(other.publicKey,'SERVER_TRANSPORT');SetKey(other.privateKey.export({type:'pkcs8',format:'pem'}));assert.equal(signing.Readiness(otherTemplate).reason,'SECURITY_KEY_PURPOSE_CONFLICT');SetKey();
});
test('public export and Pascal include carry no private material; generation validates before writing',()=>{
 const pub=keyTool.PublicJSON(identity);assert.equal(keyTool.ParsePublic(pub).keyId,identity.keyId);const inc=keyTool.Include(identity);assert.ok(inc.startsWith('\uFEFF'));assert.match(inc,/\{\$J-\}/);assert.match(inc,/array\[0\.\.330\]/);assert.equal(inc.includes('PRIVATE KEY'),false);
 const out=path.join(temp,'new-private.pem');assert.throws(()=>keyTool.main(['--action','generate','--private-key-file',out]),{message:'ISSUED_A_KEY_OUTPUT_REQUIRED'});assert.equal(fs.existsSync(out),false);
 const pubPath=path.join(temp,'public.json'),incPath=path.join(temp,'public.inc');fs.writeFileSync(pubPath,JSON.stringify(pub));const result=keyTool.main(['--action','include','--public-json-file',pubPath,'--include-out',incPath]);assert.equal(result.keyId,identity.keyId);assert.equal(fs.readFileSync(incPath,'utf8'),inc);
 assert.throws(()=>keyTool.main(['--action','include','--public-json-file',pubPath,'--include-out',incPath]),{message:'ISSUED_A_OUTPUT_NEW_ABSOLUTE_PATH_REQUIRED'});
});
test('external key output is private and a later output failure removes only owned files',()=>{
 const privateFile=path.join(temp,'owned-private.pem'),publicFile=path.join(temp,'owned-public.json'),includeFile=path.join(temp,'owned-public.inc'),kept=path.join(temp,'operator-existing.txt');
 fs.writeFileSync(kept,'retain');const write=fs.writeFileSync;let writes=0;
 fs.writeFileSync=function(...args){writes++;if(writes===2)throw Error('injected public output failure');return write.apply(this,args);};
 try{assert.throws(()=>keyTool.main(['--action','generate','--private-key-file',privateFile,'--public-json-out',publicFile,'--include-out',includeFile]),{message:'injected public output failure'});}finally{fs.writeFileSync=write;}
 for(const file of [privateFile,publicFile,includeFile])assert.equal(fs.existsSync(file),false);assert.equal(fs.readFileSync(kept,'utf8'),'retain');
 const result=keyTool.main(['--action','generate','--private-key-file',privateFile,'--public-json-out',publicFile,'--include-out',includeFile]);assert.equal(result.privateKeyPrinted,false);assert.equal(result.publicIncludeWritten,true);
 if(process.platform!=='win32')assert.equal(fs.statSync(privateFile).mode&0o777,0o600);
 const exported=keyTool.ParsePublic(JSON.parse(fs.readFileSync(publicFile,'utf8'))),privateKey=crypto.createPrivateKey(fs.readFileSync(privateFile));assert.equal(signing.PublicIdentity(crypto.createPublicKey(privateKey)).keyId,exported.keyId);
 for(const file of [privateFile,publicFile,includeFile])fs.unlinkSync(file);
});

}
