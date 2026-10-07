'use strict';
// CRC64-ECMA-182: non-reflected, init=0, xorout=0. This checksum detects
// accidental corruption only; SHA-512 + authenticated transport/signatures
// remain mandatory for security. No client memory attestation is implied.
const crypto=require('node:crypto'),high=new Uint32Array(256),low=new Uint32Array(256);
const {ExtendedDigests}=require('./extendedHashes');
for(let i=0;i<256;i++){
 let value=BigInt(i)<<56n;
 for(let bit=0;bit<8;bit++)value=BigInt.asUintN(64,(value<<1n)^((value&0x8000000000000000n)?0x42F0E1EBA9EA3693n:0n));
 high[i]=Number(value>>32n);low[i]=Number(value&0xffffffffn);
}
function Crc64(bytes){
 if(!Buffer.isBuffer(bytes)&&!(bytes instanceof Uint8Array))throw TypeError('INTEGRITY_BYTES_REQUIRED');
 let hi=0,lo=0;
 for(let i=0;i<bytes.length;i++){const index=(hi>>>24)^bytes[i];hi=(((hi<<8)|(lo>>>24))^high[index])>>>0;lo=((lo<<8)^low[index])>>>0;}
 return hi.toString(16).padStart(8,'0').toUpperCase()+lo.toString(16).padStart(8,'0').toUpperCase();
}
function Digests(bytes){return {hashVersion:3,sha512:crypto.createHash('sha512').update(bytes).digest('hex'),crc64:Crc64(bytes),...ExtendedDigests(bytes)};}
// A server-generated baseline from pristine uploaded PE bytes. A client report
// is evidence, not hardware attestation: a compromised verifier can lie.
const CODE_PREFIX=Buffer.from('GAME-CODE-V1\0','ascii');
function CodeImage(bytes){
 const bad=()=>{throw Error('BOOTSTRAP_PE_INVALID');};
 if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>64*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad();
 const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad();
 const count=bytes.readUInt16LE(pe+6),opt=pe+24,optSize=bytes.readUInt16LE(pe+20),table=opt+optSize;
 if(count<1||count>96||optSize<160||table+count*40>bytes.length||bytes.readUInt16LE(opt)!==0x20b)bad();
 const imageSize=bytes.readUInt32LE(opt+56),headerSize=bytes.readUInt32LE(opt+60),dirCount=bytes.readUInt32LE(opt+108);
 if(imageSize<4096||imageSize>128*1024*1024||headerSize<table+count*40||headerSize>bytes.length||dirCount>16||112+dirCount*8>optSize)bad();
 const sections=[];let total=0;
 for(let i=0;i<count;i++){
  const at=table+i*40,virtualSize=bytes.readUInt32LE(at+8),rva=bytes.readUInt32LE(at+12),rawSize=bytes.readUInt32LE(at+16),raw=bytes.readUInt32LE(at+20),flags=bytes.readUInt32LE(at+36),span=virtualSize||rawSize,mapped=Math.max(span,rawSize);
  if(!span||rva<headerSize||rva+mapped>imageSize||rawSize&&(raw<headerSize||raw+rawSize>bytes.length)||sections.some(s=>rva<s.rva+s.mapped&&rva+mapped>s.rva||rawSize&&s.rawSize&&raw<s.raw+s.rawSize&&raw+rawSize>s.raw))bad();
  const protectedCode=!!(flags&0x20000000)&&!(flags&0x80000000);if(protectedCode){total+=span;if(total>64*1024*1024)bad();}
  sections.push({rva,span,mapped,raw,rawSize,protectedCode});
 }
 const protectedSections=sections.filter(s=>s.protectedCode).sort((a,b)=>a.rva-b.rva);if(!protectedSections.length)bad();
 for(const section of protectedSections){section.bytes=Buffer.alloc(section.span);bytes.copy(section.bytes,0,section.raw,section.raw+Math.min(section.rawSize,section.span));}
 const rawAt=(rva,length)=>{if(!Number.isSafeInteger(length)||length<0)bad();if(rva<headerSize&&rva+length<=headerSize)return rva;const s=sections.find(s=>rva>=s.rva&&rva+length<=s.rva+s.rawSize);if(!s)bad();return s.raw+(rva-s.rva);};
 const relocRva=dirCount>5?bytes.readUInt32LE(opt+112+5*8):0,relocSize=dirCount>5?bytes.readUInt32LE(opt+116+5*8):0;
 if(!!relocRva!==!!relocSize||relocSize>16*1024*1024)bad();
 let relocations=0;
 if(relocSize){
  let cursor=rawAt(relocRva,relocSize),end=cursor+relocSize;const seen=[];
  while(cursor<end){
   if(cursor+8>end)bad();const page=bytes.readUInt32LE(cursor),block=bytes.readUInt32LE(cursor+4);if(block<8||block%2||cursor+block>end||page>=imageSize)bad();
   for(let at=cursor+8;at<cursor+block;at+=2){
    const entry=bytes.readUInt16LE(at),type=entry>>>12,target=page+(entry&0xfff);if(type===0)continue;
    const width=type===10?8:type===3?4:1,section=protectedSections.find(s=>target<s.rva+s.span&&target+width>s.rva);
    if(!section)continue;if(type!==10&&type!==3||target<section.rva||target+width>section.rva+section.span)bad();
    section.bytes.fill(0,target-section.rva,target-section.rva+width);seen.push([target,target+width]);if(++relocations>1000000)bad();
   }
   cursor+=block;
  }
  seen.sort((a,b)=>a[0]-b[0]);for(let i=1;i<seen.length;i++)if(seen[i][0]<seen[i-1][1])bad();
 }
 const head=Buffer.alloc(CODE_PREFIX.length+4);CODE_PREFIX.copy(head);head.writeUInt32LE(protectedSections.length,CODE_PREFIX.length);const chunks=[head];
 for(const s of protectedSections){const meta=Buffer.alloc(8);meta.writeUInt32LE(s.rva);meta.writeUInt32LE(s.span,4);chunks.push(meta,s.bytes);}
 const normalized=Buffer.concat(chunks),crc=require('./crcLayers'),exports=require('./desktopPeExports').ExportTable(bytes);
 const crcLayers=crc.measureCrcLayers({code:normalized,headers:crc.headerMetadata(bytes),exports:exports.normalized||Buffer.alloc(0),checkers:crc.checkerStreams(normalized,crc.checkerPlan(bytes))});
 return {...Digests(normalized),crcLayers,algorithm:'PE64-CODE-V1',sections:protectedSections.map(({rva,span})=>({rva,span})),relocations};
}
module.exports={Crc64,Digests,CodeImage};
