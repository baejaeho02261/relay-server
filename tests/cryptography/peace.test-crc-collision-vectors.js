'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
const fixture=require('../fixtures/integrity/peace.crc32c-collision-vectors.json');
const crc=require('../../services/cryptography/peace.crc-layers');
const sha=bytes=>crypto.createHash('sha512').update(bytes).digest('hex');
function bytes(prefix,size){const out=Buffer.alloc(size);Buffer.from(prefix,'hex').copy(out);return out;}
function frame(payload,rva=fixture.codeRva){const header=Buffer.alloc(25);header.write('GAME-CODE-V1\0','ascii');header.writeUInt32LE(1,13);header.writeUInt32LE(rva,17);header.writeUInt32LE(payload.length,21);return Buffer.concat([header,payload]);}
function pageReference(payload,rva=fixture.codeRva){const row=Buffer.alloc(8);row.writeUInt32LE(rva);row.writeUInt32LE(payload.length,4);const prefix=Buffer.from('COZY-CODE-PAGES-SHA512-V1\0'),head=Buffer.alloc(prefix.length+8);prefix.copy(head);head.writeUInt32LE(4096,prefix.length);head.writeUInt32LE(1,prefix.length+4);return Buffer.concat([head,row,crypto.createHash('sha512').update(Buffer.concat([Buffer.from('COZY-CODE-PAGE-SHA512-V1\0'),row,payload])).digest()]);}
// Independent bit-at-a-time implementation, without the production CRC tables.
function crc32cReference(data){let value=0xffffffff;for(const byte of data){value^=byte;for(let bit=0;bit<8;bit++)value=(value>>>1)^((value&1)?0x82f63b78:0);}return ((value^0xffffffff)>>>0).toString(16).toUpperCase().padStart(8,'0');}
test('public CRC collision fixture has pinned exact construction and CRC32C check',()=>{
  assert.equal(fixture.schema,1);assert.equal(fixture.name,'COZY-CRC32C-COLLISION-V1');
  assert.equal(fixture.leftPrefixHex,'487059d7b605e9ff');assert.equal(fixture.rightPrefixHex,'48cc3ce6ab789b5c');
  assert.deepEqual(fixture.cases.map(x=>x.byteCount),[8,4096]);
  assert.equal(crc32cReference(Buffer.from('123456789')),fixture.algorithm.check123456789);
});
for(const row of fixture.cases)test(row.id+': different public bytes, same pinned CRC and different pinned SHA512',()=>{
  const left=bytes(fixture.leftPrefixHex,row.byteCount),right=bytes(fixture.rightPrefixHex,row.byteCount);
  assert.notDeepEqual(left,right);
  for(const value of [left,right]){assert.equal(crc32cReference(value),row.crc32c);assert.equal(crc.crcHex('crc32c',value),row.crc32c);}
  assert.equal(sha(left),row.leftSha512);assert.equal(sha(right),row.rightSha512);assert.notEqual(row.leftSha512,row.rightSha512);
  const a=frame(left),b=frame(right);
  assert.equal(sha(a),row.leftCodeSha512);assert.equal(sha(b),row.rightCodeSha512);assert.notEqual(row.leftCodeSha512,row.rightCodeSha512);
  assert.deepEqual(crc.codePageManifest(a),crc.codePageManifest(b));
  const pageA=crc.codePageSha512Manifest(a),pageB=crc.codePageSha512Manifest(b);
  assert.deepEqual(pageA,pageReference(left));assert.deepEqual(pageB,pageReference(right));
  assert.equal(sha(pageA),row.leftPageManifestSha512);assert.equal(sha(pageB),row.rightPageManifestSha512);
  assert.notDeepEqual(pageA,pageB);assert.notDeepEqual(pageA,crc.codePageSha512Manifest(frame(left,0x2000)));
});
const native=path.resolve(__dirname,'../../../Railway');
test('native dedicated mode consumes the public known answers without changing normal checksum output',{skip:!fs.existsSync(native)},()=>{
  const read=p=>fs.readFileSync(path.join(native,p),'utf8').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n');
  const source=read('Cozy.Tests/Cozy.Integrity/Cozy.CrcProbe.dpr'),inc=read('Cozy.Tests/Cozy.Integrity/Cozy.CrcCollisionVectors.inc');
  for(const field of ['crc32c','leftSha512','rightSha512','leftCodeSha512','rightCodeSha512','leftPageManifestSha512','rightPageManifestSha512']){
    const name='CrcCollision'+field[0].toUpperCase()+field.slice(1);
    const match=inc.match(new RegExp(name+": array\\[0\\.\\.1\\] of string = \\(([\\s\\S]*?)\\);"));assert(match,name);
    assert.deepEqual([...match[1].matchAll(/'([^']+)'/g)].map(x=>x[1]),fixture.cases.map(x=>x[field]),name);
    assert(source.includes(name+'[I]'),name+' must be exercised, not just stored');
  }
  for(const marker of ["{$I Cozy.CrcCollisionVectors.inc}","--collision-vectors",'CRC_COLLISION_CONTENT_DIFFERS','CRC_COLLISION_LEFT_KNOWN_ANSWER','CRC_COLLISION_RIGHT_KNOWN_ANSWER','PAGE_SHA512_REJECTS_CRC_COLLISION','signatureVerificationExercised":false','authorizationGranted":false'])assert(source.includes(marker),marker);
  assert(source.includes('if PublishVectors then'),'normal output remains unchanged for existing parity drivers');
});
test('actual compiled portable probe reports all dedicated vector assertions when explicitly supplied',{skip:!process.env.CRC_PROBE},()=>{
  const result=cp.spawnSync(process.env.CRC_PROBE,['--collision-vectors'],{encoding:'utf8',timeout:30000,maxBuffer:32768,windowsHide:true});
  assert.ifError(result.error);assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr||result.stdout);
  const report=JSON.parse(result.stdout);assert.equal(report.name,fixture.name);assert.equal(report.schema,1);
  assert.equal(report.scope,'PORTABLE_CRC_AND_SHA512_PROBE');assert.equal(report.signatureVerificationExercised,false);assert.equal(report.outcome,'PASS');
  assert.equal(report.cases.length,fixture.cases.length);
  report.cases.forEach((actual,i)=>{
    const expected=fixture.cases[i];for(const field of ['byteCount','crc32c','leftSha512','rightSha512','leftCodeSha512','rightCodeSha512'])assert.equal(actual[field],expected[field],field);
    assert.equal(actual.contentDifferent,true);assert.equal(actual.crcEqual,true);assert.equal(actual.pageSha512Different,true);assert.equal(actual.authorizationGranted,false);
  });
});
