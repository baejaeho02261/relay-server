'use strict';
// Synthetic PE extension for wire/crypto tests. It is never executed on Windows.
const signing=require('../../../services/bootstrap/peace.issued-a-signing');
function WithAnchor(input,publicKey){
 const bytes=Buffer.concat([input,Buffer.alloc(512)]),pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20),count=bytes.readUInt16LE(pe+6),at=table+count*40;
 if(at+40>bytes.readUInt32LE(opt+60))throw Error('FIXTURE_SECTION_CAPACITY');
 const last=table+(count-1)*40,rva=Math.ceil((bytes.readUInt32LE(last+12)+Math.max(bytes.readUInt32LE(last+8),bytes.readUInt32LE(last+16)))/4096)*4096;
 bytes.fill(0,at,at+40);bytes.write('.issuer',at);bytes.writeUInt32LE(512,at+8);bytes.writeUInt32LE(rva,at+12);bytes.writeUInt32LE(512,at+16);bytes.writeUInt32LE(input.length,at+20);bytes.writeUInt32LE(0x40000040,at+36);bytes.writeUInt16LE(count+1,pe+6);bytes.writeUInt32LE(rva+4096,opt+56);
 signing.AnchorBytes(publicKey).copy(bytes,input.length);return bytes;
}
module.exports={WithAnchor};
