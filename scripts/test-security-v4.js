'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-v4-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';
const hashes=require('../services/extendedHashes'),integrity=require('../services/desktopIntegrity'),crc=require('../services/desktopCrcPolicy');
const fixture=require('./desktop-bootstrap-fixture'),vectors=require('./fixtures/blake3-full-official-vectors.json');
let checks=0;
function check(label,run){run();checks++;console.log('PASS '+label);}
try{
 check('BLAKE3 keyed, derive-key, XOF and incremental match all official test vectors',()=>{
  for(const row of vectors.cases){const input=Buffer.from(Array.from({length:row.input_len},(_,i)=>i%251)),length=row.hash.length/2;
   assert.equal(hashes.Blake3Xof(input,length).toString('hex'),row.hash);
   assert.equal(hashes.Blake3Keyed(Buffer.from(vectors.key),input,length).toString('hex'),row.keyed_hash);
   assert.equal(hashes.Blake3DeriveKey(vectors.context_string,input,length).toString('hex'),row.derive_key);
   const stream=hashes.Blake3Incremental({context:vectors.context_string,length});for(let i=0;i<input.length;i+=173)stream.update(input.subarray(i,i+173));assert.equal(stream.digest().toString('hex'),row.derive_key);assert.throws(()=>stream.update(input),/FINALIZED/);
  }
 });
 check('CRC roles reject a wrong role, a missing role and false checker coverage',()=>{
  const baseline=integrity.CodeImage(fixture.PE('A')).crcLayers;assert.equal(crc.Compare(baseline,baseline).matched,true);
  const missing=structuredClone(baseline);delete missing.nvme;assert.equal(crc.Compare(missing,baseline).matched,false);
  const changed=structuredClone(baseline);changed.we.digest='0'.repeat(16);assert.equal(crc.Compare(changed,baseline).matched,false);
  const wrong=structuredClone(baseline);wrong.nvme.role='normalized-code';assert.equal(crc.Compare(wrong,baseline).matched,false);
 });
 check('Old or mislabeled digest reports cannot become hashVersion3',()=>{
  const report=require('../services/desktopIntegrityReports'),code=integrity.CodeImage(fixture.PE('A')),file=integrity.Digests(fixture.PE('A'));
  const payload={version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',own:{status:'MEASURED',codeSha512:code.sha512,codeCrc64:code.crc64,fileXxh3_128:file.xxh3_128,fileBlake3:file.blake3,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3},crcLayers:code.crcLayers};
  assert.equal(report.Payload(JSON.stringify(payload)).hashVersion,3);
  for(const patch of [{hashVersion:2},{hashVersion:undefined},{own:{...payload.own,codeSha512:'a'.repeat(64)}},{own:{...payload.own,fileXxh3_128:'a'.repeat(16)}},{crcLayers:undefined}])assert.throws(()=>report.Payload(JSON.stringify({...payload,...patch})),/INTEGRITY_REPORT_INVALID/);
 });
 check('Default authority denies an otherwise matching image with incomplete checker coverage',()=>{
  const auth=require('../services/desktopSecurityAuthority'),bytes=fixture.PE('A'),anchor=Buffer.from('47435243414e4348038d47912a60b5ec','hex'),at=bytes.indexOf(anchor);if(at>=0)bytes.fill(0,at,at+anchor.length);
  const file=integrity.Digests(bytes),code=integrity.CodeImage(bytes),baseline={hashVersion:3,sha512:file.sha512,crc64:file.crc64,codeSha512:code.sha512,codeCrc64:code.crc64,codeXxh3_128:code.xxh3_128,codeBlake3:code.blake3,crcLayers:code.crcLayers};
  const value={version:1,hashVersion:3,measurement:'MEASURED',fileSha512:baseline.sha512,fileCrc64:baseline.crc64,codeSha512:baseline.codeSha512,codeCrc64:baseline.codeCrc64,codeXxh3_128:baseline.codeXxh3_128,codeBlake3:baseline.codeBlake3,crcLayers:baseline.crcLayers,apiSealed:true,apiSlots:80,dynamicCode:'ALLOWED',cfg:'DISABLED'};
  assert.equal(auth.Evaluate(value,baseline,auth.Defaults()).reason,'CRC_COVERAGE_INCOMPLETE');
  const corrupt=structuredClone(value);corrupt.crcLayers.ecma182.digest='0'.repeat(16);assert.equal(auth.Evaluate(corrupt,baseline,auth.Defaults()).status,'MISMATCH');
  const old={...value,hashVersion:2};assert.equal(auth.Evaluate(old,baseline,auth.Defaults()).reason,'HASH_VERSION_MISMATCH');
 });
 check('Schema4 capabilities are archived without promoting old hashes or consuming new licenses',()=>{
  const dir=path.join(temp,'migration'),boot=path.join(dir,'desktop-bootstrap');fs.mkdirSync(boot,{recursive:true});
  const old={schema:4,revision:7,secret:'a'.repeat(64),artifacts:{},active:{},launchers:{},flows:{},issueReceipts:{}};fs.writeFileSync(path.join(boot,'authority.json'),JSON.stringify(old));
  const run=child.spawnSync(process.execPath,['-e',`const s=require(${JSON.stringify(require.resolve('../services/desktopBootstrapStore'))}).Load();process.stdout.write(JSON.stringify(s));`],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:dir},encoding:'utf8'});assert.equal(run.status,0,run.stderr);const migrated=JSON.parse(run.stdout);assert.equal(migrated.schema,5);assert.deepEqual(migrated.active,{});assert.equal(migrated.secret,old.secret);const archive=fs.readFileSync(path.join(boot,migrated.legacyArchive.file));assert.deepEqual(JSON.parse(archive),old);assert.equal(crypto.createHash('sha512').update(archive).digest('hex'),migrated.legacyArchive.sha512);
  const second=child.spawnSync(process.execPath,['-e',`process.stdout.write(JSON.stringify(require(${JSON.stringify(require.resolve('../services/desktopBootstrapStore'))}).Load()));`],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:dir},encoding:'utf8'});assert.equal(second.status,0,second.stderr);assert.equal(JSON.parse(second.stdout).revision,migrated.revision);
 });
 console.log('Security v4: '+checks+' checks passed');
}finally{fs.rmSync(temp,{recursive:true,force:true});}
