'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const {CodeImage,Crc64}=require('../services/desktopIntegrity');
function Fixture(){
 const b=Buffer.alloc(3072),pe=128,opt=152,table=392;b.write('MZ');b.writeUInt32LE(pe,60);b.write('PE\0\0',pe,'binary');b.writeUInt16LE(0x8664,pe+4);b.writeUInt16LE(4,pe+6);b.writeUInt16LE(240,pe+20);b.writeUInt16LE(0x20b,opt);b.writeUInt32LE(0x6000,opt+56);b.writeUInt32LE(1024,opt+60);b.writeUInt32LE(16,opt+108);b.writeUInt32LE(0x4000,opt+152);b.writeUInt32LE(16,opt+156);
 const specs=[[0x3000,64,512,2048,0x60000020],[0x1000,520,512,1024,0x60000020],[0x2000,512,512,1536,0xc0000040],[0x4000,16,512,2560,0x42000040]];
 specs.forEach(([rva,span,rawSize,raw,flags],i)=>{const p=table+i*40;b.writeUInt32LE(span,p+8);b.writeUInt32LE(rva,p+12);b.writeUInt32LE(rawSize,p+16);b.writeUInt32LE(raw,p+20);b.writeUInt32LE(flags,p+36);for(let x=0;x<rawSize;x++)b[raw+x]=(i*17+x)%256;});
 b.writeUInt32LE(0x1000,2560);b.writeUInt32LE(16,2564);b.writeUInt16LE(0xa018,2568);b.writeUInt16LE(0x3030,2570);b.writeUInt16LE(0,2572);b.writeUInt16LE(0,2574);return b;
}
const original=Fixture(),result=CodeImage(original),first=Buffer.alloc(520);original.copy(first,0,1024,1536);first.fill(0,24,32);first.fill(0,48,52);const prefix=Buffer.from('47414d452d434f44452d56310002000000','hex'),meta1=Buffer.from('0010000008020000','hex'),meta2=Buffer.from('0030000040000000','hex'),normalized=Buffer.concat([prefix,meta1,first,meta2,original.subarray(2048,2112)]);
assert.equal(result.sha256,crypto.createHash('sha256').update(normalized).digest('hex'));assert.equal(result.crc64,Crc64(normalized));assert.deepEqual(result.sections,[{rva:4096,span:520},{rva:12288,span:64}]);assert.equal(result.relocations,2);
const relocated=Buffer.from(original);relocated.writeBigUInt64LE(0x777788889999aaaan,1048);
relocated.writeUInt32LE(0x12345678,1072);assert.equal(CodeImage(relocated).sha256,result.sha256);assert.equal(CodeImage(relocated).crc64,result.crc64);
const dataChange=Buffer.from(original);dataChange[1550]^=255;assert.equal(CodeImage(dataChange).sha256,result.sha256);
const codeChange=Buffer.from(original);codeChange[1064]^=1;assert.notEqual(CodeImage(codeChange).sha256,result.sha256);assert.notEqual(CodeImage(codeChange).crc64,result.crc64);
const invalid=fn=>{const b=Buffer.from(original);fn(b);assert.throws(()=>CodeImage(b),/^Error: BOOTSTRAP_PE_INVALID$/);};
invalid(b=>b.writeUInt16LE(0x5018,2568)); // unknown relocation into protected code
invalid(b=>b.writeUInt16LE(0xa204,2568)); // DIR64 crossing end of protected code
invalid(b=>b.writeUInt16LE(0x301c,2570)); // overlapping relocation slots
invalid(b=>b.writeUInt32LE(15,2564)); // odd relocation block
invalid(b=>b.writeUInt32LE(0xffffffff,152+56));
invalid(b=>b.writeUInt32LE(0x1000,392+12)); // overlapping virtual sections
invalid(b=>b.writeUInt32LE(1024,392+20)); // overlapping raw sections
invalid(b=>b.writeUInt32LE(0,152+156)); // half-specified relocation directory
invalid(b=>b.writeUInt16LE(97,128+6));
console.log('PE64 code integrity vector:',JSON.stringify(result));
console.log('PE64 code integrity tests passed: normalization, code tamper, safe bounds, relocation rejection');
module.exports={Fixture};
