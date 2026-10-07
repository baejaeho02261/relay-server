'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const c=require('../services/crcLayers');
function reference(spec,bytes){
 const mask=(1n<<BigInt(spec.width))-1n,top=1n<<BigInt(spec.width-1);let value=spec.init;
 // Direct left-shifting polynomial division with explicit byte reflection;
 // independent of the production right-shifting table implementation.
 function reflect(value,width){let out=0n;for(let i=0;i<width;i++){out=(out<<1n)|(value&1n);value>>=1n;}return out;}
 if(spec.reflected)value=reflect(value,spec.width);
 for(let byte of bytes){if(spec.reflected)byte=Number(reflect(BigInt(byte),8));value^=BigInt(byte)<<BigInt(spec.width-8);for(let bit=0;bit<8;bit++)value=((value<<1n)^((value&top)?spec.poly:0n))&mask;}
 if(spec.reflected)value=reflect(value,spec.width);return (value^spec.xorout).toString(16).padStart(spec.width/4,'0').toUpperCase();
}
for(const spec of Object.values(c.registry)){
 assert.equal(c.crcHex(spec.id,Buffer.from('123456789')),spec.check.toString(16).padStart(spec.width/4,'0').toUpperCase(),spec.name);
 for(const length of [0,1,7,8,31,32,255,256,257,4097]){
  const data=Buffer.from(Array.from({length},(_,i)=>(i*131+17)&255));
  const expected=reference(spec,data),state=new c.CrcStream(spec.id);
  for(let at=0;at<data.length;){const end=Math.min(data.length,at+(at%13)+1);state.update(data.subarray(at,end));state.digest();at=end;}
  assert.equal(state.update(Buffer.alloc(0)).digest(),expected,`${spec.id}/${length}`);
  assert.equal(c.crcHex(spec.id,data),expected);
 }
}
assert.equal(c.crcHex('nvme',Buffer.alloc(4096)),'6482D367EB22B64E');
assert.equal(c.crcHex('nvme',Buffer.alloc(4096,255)),'C0DDBA7302ECA3AC');
assert.equal(c.crcHex('nvme',Buffer.from(Array.from({length:4096},(_,i)=>i&255))),'3E729F5F6750449C');
assert.equal(c.crcHex('nvme',Buffer.from(Array.from({length:4096},(_,i)=>(4095-i)&255))),'9A2DF64B8E9E517E');
assert.throws(()=>c.crcHex('other',Buffer.alloc(0)));
assert.throws(()=>c.crcHex('nvme','unencoded'));
const prefix=Buffer.from('GAME-CODE-V1\0'),head=Buffer.alloc(prefix.length+4+8);prefix.copy(head);head.writeUInt32LE(1,prefix.length);head.writeUInt32LE(0x1800,prefix.length+4);head.writeUInt32LE(0x1801,prefix.length+8);
const code=Buffer.concat([head,Buffer.alloc(0x1801,17)]),manifest=c.codePageManifest(code),start=Buffer.byteLength('CRC-PAGES-V1\0');
assert.equal(manifest.readUInt32LE(start),4096);assert.equal(manifest.readUInt32LE(start+4),3);
assert.deepEqual([manifest.readUInt32LE(start+8),manifest.readUInt32LE(start+12)],[0x1800,0x800]);
assert.deepEqual([manifest.readUInt32LE(start+20),manifest.readUInt32LE(start+24)],[0x2000,0x1000]);
assert.deepEqual([manifest.readUInt32LE(start+32),manifest.readUInt32LE(start+36)],[0x3000,1]);
assert.throws(()=>c.codePageManifest(code.subarray(0,-1)));assert.throws(()=>c.codePageManifest(Buffer.concat([code,Buffer.from([0])])));
const report=c.measureCrcLayers({code,headers:Buffer.from('headers')});
assert.equal(report.jones.status,'unavailable');assert.equal(report.iso.status,'unavailable');assert.equal(report.crc32c.pages,3);
const changed=Buffer.from(code);changed[changed.length-1]^=1;
const changedReport=c.measureCrcLayers({code:changed,headers:Buffer.from('headers')});
assert.notEqual(changedReport.ecma182.digest,report.ecma182.digest);assert.notEqual(changedReport.crc32c.digest,report.crc32c.digest);assert.equal(changedReport.nvme.digest,report.nvme.digest);assert.equal(changedReport.xz.digest,report.xz.digest);
if(process.env.CRC_PROBE){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'crc-vectors-'));
 try{
  for(const length of [0,1,255,4096,65539]){
   const data=Buffer.from(Array.from({length},(_,i)=>(i*131+17)&255)),file=path.join(dir,'input.bin');fs.writeFileSync(file,data);
   const result=spawnSync(process.env.CRC_PROBE,[file],{encoding:'utf8'});assert.equal(result.status,0,result.stdout+result.stderr);
   const actual=Object.fromEntries(result.stdout.trim().split(/\r?\n/).map(line=>line.split('=')));
   for(const spec of Object.values(c.registry))assert.equal(actual[spec.name],c.crcHex(spec.id,data),`Delphi ${spec.id}/${length}`);
   assert.equal(actual.parameters,c.crcHex('we',c.parameterBytes()));assert.equal(actual.tables,c.crcHex('we',c.allTableBytes()));
  }
  const pageFile=path.join(dir,'code.bin');fs.writeFileSync(pageFile,code);
  const pageResult=spawnSync(process.env.CRC_PROBE,['--pages',pageFile],{encoding:'utf8'});
  assert.equal(pageResult.status,0,pageResult.stdout+pageResult.stderr);
  assert.equal(pageResult.stdout.trim(),'pages='+manifest.toString('hex').toUpperCase());
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
 console.log('CRC Node / portable Delphi parity passed.');
}
console.log('CRC official vectors, independent reference, streaming, page boundaries and role separation passed.');
